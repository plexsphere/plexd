//go:build windows

package cmd

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// --- Fake event reporter ---

type fakeEventReporter struct {
	mu       sync.Mutex
	err      error
	infos    []string
	warnings []string
	errs     []string
}

func (f *fakeEventReporter) Info(_ uint32, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.infos = append(f.infos, msg)
	return f.err
}

func (f *fakeEventReporter) Warning(_ uint32, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.warnings = append(f.warnings, msg)
	return f.err
}

func (f *fakeEventReporter) Error(_ uint32, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, msg)
	return f.err
}

func (f *fakeEventReporter) counts() (info, warn, errCount int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.infos), len(f.warnings), len(f.errs)
}

// runService drives an agentService the way the SCM does and returns the
// statuses it reported alongside the handler's result.
func runService(t *testing.T, s *agentService, send []svc.ChangeRequest) ([]svc.Status, bool, uint32) {
	t.Helper()

	r := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status, 16)

	type result struct {
		svcSpecific bool
		exitCode    uint32
	}
	res := make(chan result, 1)
	go func() {
		ok, code := s.Execute(nil, r, changes)
		res <- result{ok, code}
	}()

	go func() {
		for _, c := range send {
			r <- c
		}
	}()

	var got result
	select {
	case got = <-res:
	case <-time.After(10 * time.Second):
		t.Fatal("Execute did not return within 10s")
	}

	close(changes)
	var statuses []svc.Status
	for st := range changes {
		statuses = append(statuses, st)
	}
	return statuses, got.svcSpecific, got.exitCode
}

func hasState(statuses []svc.Status, want svc.State) bool {
	for _, st := range statuses {
		if st.State == want {
			return true
		}
	}
	return false
}

// --- agentService ---

func TestAgentService_StopCancelsAndReturnsClean(t *testing.T) {
	rep := &fakeEventReporter{}
	s := &agentService{
		run: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		rep: rep,
	}

	statuses, svcSpecific, code := runService(t, s, []svc.ChangeRequest{{Cmd: svc.Stop}})

	if svcSpecific || code != 0 {
		t.Errorf("Execute() = (%v, %d), want (false, 0) for a clean stop", svcSpecific, code)
	}
	if !hasState(statuses, svc.StopPending) {
		t.Errorf("statuses = %v, want a StopPending among them", statuses)
	}
	for _, st := range statuses {
		if st.State == svc.StopPending && st.WaitHint == 0 {
			t.Error("StopPending carried WaitHint 0; the SCM would kill the drain")
		}
	}
	if _, _, errCount := rep.counts(); errCount != 0 {
		t.Errorf("reported %d errors, want 0 for a clean stop", errCount)
	}
}

func TestAgentService_StopWithRunError(t *testing.T) {
	rep := &fakeEventReporter{}
	s := &agentService{
		run: func(ctx context.Context) error {
			<-ctx.Done()
			return errors.New("teardown failed")
		},
		rep: rep,
	}

	_, svcSpecific, code := runService(t, s, []svc.ChangeRequest{{Cmd: svc.Stop}})

	if !svcSpecific || code != 1 {
		t.Errorf("Execute() = (%v, %d), want (true, 1) when the run fails on the way out", svcSpecific, code)
	}
	if _, _, errCount := rep.counts(); errCount != 1 {
		t.Errorf("reported %d errors, want 1", errCount)
	}
}

// A startup failure ends the run before any stop request. Exiting non-zero is
// what makes the SCM's recovery actions restart the service.
func TestAgentService_RunErrorReportsFailure(t *testing.T) {
	rep := &fakeEventReporter{}
	s := &agentService{
		run: func(_ context.Context) error { return errors.New("registration: 401") },
		rep: rep,
	}

	statuses, svcSpecific, code := runService(t, s, nil)

	if !svcSpecific || code != 1 {
		t.Errorf("Execute() = (%v, %d), want (true, 1) for a startup failure", svcSpecific, code)
	}
	if !hasState(statuses, svc.StopPending) {
		t.Errorf("statuses = %v, want a StopPending among them", statuses)
	}
	_, _, errCount := rep.counts()
	if errCount != 1 {
		t.Fatalf("reported %d errors, want 1", errCount)
	}
	if !strings.Contains(rep.errs[0], "registration: 401") {
		t.Errorf("event text = %q, want the run's error in it", rep.errs[0])
	}
}

// The agent can also end with a nil error and no stop request: the health
// listener shuts the daemon down that way. It is still not a clean stop.
func TestAgentService_RunExitReportsFailure(t *testing.T) {
	rep := &fakeEventReporter{}
	s := &agentService{
		run: func(_ context.Context) error { return nil },
		rep: rep,
	}

	_, svcSpecific, code := runService(t, s, nil)

	if !svcSpecific || code != 1 {
		t.Errorf("Execute() = (%v, %d), want (true, 1) for an unrequested exit", svcSpecific, code)
	}
	_, warn, _ := rep.counts()
	if warn != 1 {
		t.Errorf("reported %d warnings, want 1", warn)
	}
}

func TestAgentService_Interrogate(t *testing.T) {
	rep := &fakeEventReporter{}
	s := &agentService{
		run: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		rep: rep,
	}

	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses, _, _ := runService(t, s, []svc.ChangeRequest{
		{Cmd: svc.Interrogate, CurrentStatus: current},
		{Cmd: svc.Stop},
	})

	var echoed bool
	for _, st := range statuses {
		if st.State == current.State && st.Accepts == current.Accepts {
			echoed = true
		}
	}
	if !echoed {
		t.Errorf("statuses = %v, want the interrogated status echoed back", statuses)
	}
}

// --- eventLogHandler ---

func newRecord(level slog.Level, msg string, attrs ...slog.Attr) slog.Record {
	rec := slog.NewRecord(time.Now(), level, msg, 0)
	rec.AddAttrs(attrs...)
	return rec
}

func TestEventLogHandler_LevelsRoute(t *testing.T) {
	rep := &fakeEventReporter{}
	h := newEventLogHandler(rep, slog.LevelInfo)
	ctx := context.Background()

	for _, rec := range []slog.Record{
		newRecord(slog.LevelError, "boom"),
		newRecord(slog.LevelWarn, "careful"),
		newRecord(slog.LevelInfo, "starting plexd"),
	} {
		if !h.Enabled(ctx, rec.Level) {
			t.Fatalf("Enabled(%v) = false, want true at minimum level info", rec.Level)
		}
		if err := h.Handle(ctx, rec); err != nil {
			t.Fatalf("Handle(%v) = %v", rec.Level, err)
		}
	}

	if h.Enabled(ctx, slog.LevelDebug) {
		t.Error("Enabled(debug) = true at minimum level info, want false")
	}

	info, warn, errCount := rep.counts()
	if info != 1 || warn != 1 || errCount != 1 {
		t.Errorf("reported info=%d warn=%d error=%d, want 1 of each", info, warn, errCount)
	}
}

func TestEventLogHandler_DropsTime(t *testing.T) {
	rep := &fakeEventReporter{}
	h := newEventLogHandler(rep, slog.LevelInfo)

	rec := newRecord(slog.LevelInfo, "starting plexd", slog.String("version", "0.2.0"))
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatalf("Handle() = %v", err)
	}

	if len(rep.infos) != 1 {
		t.Fatalf("reported %d info events, want 1", len(rep.infos))
	}
	got := rep.infos[0]
	if !strings.Contains(got, `msg="starting plexd"`) {
		t.Errorf("event text = %q, want the message in it", got)
	}
	if !strings.Contains(got, "version=0.2.0") {
		t.Errorf("event text = %q, want the attributes in it", got)
	}
	// The Event Log stamps every event, so a second timestamp is noise.
	if strings.Contains(got, "time=") {
		t.Errorf("event text = %q, want no time= field", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Errorf("event text = %q, want the trailing newline trimmed", got)
	}
}

func TestEventLogHandler_ReporterError(t *testing.T) {
	reportErr := errors.New("event log unavailable")
	rep := &fakeEventReporter{err: reportErr}
	h := newEventLogHandler(rep, slog.LevelInfo)

	err := h.Handle(context.Background(), newRecord(slog.LevelInfo, "starting plexd"))
	if !errors.Is(err, reportErr) {
		t.Errorf("Handle() = %v, want the reporter's error", err)
	}
}
