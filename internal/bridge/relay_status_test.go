package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The composition root hands the reporter the control-plane client; this
// assertion keeps the seam satisfiable by it.
var _ RelayStatusClient = (*api.ControlPlane)(nil)

const testRelayNodeID = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0c1"

var testAcceptedAt = time.Date(2026, 10, 30, 10, 15, 30, 123000000, time.UTC)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// errBlockUntilDone in a fakeRelayStatusClient's errs makes that call wait
// for its ctx to end and return ctx.Err().
var errBlockUntilDone = errors.New("block until ctx is done")

// fakeRelayStatusClient records every report it is handed, with its ctx's
// error and the time the call began, and answers the n-th with errs[n] when
// that is set, and with a receipt at testAcceptedAt otherwise.
type fakeRelayStatusClient struct {
	mu       sync.Mutex
	nodeIDs  []string
	requests []api.RelayStatusRequest
	ctxErrs  []error
	at       []time.Time
	errs     []error

	// onCall, when set, runs inside the n-th call before it answers, so a
	// test can act while a send is in flight.
	onCall func(n int)
}

func (c *fakeRelayStatusClient) ReportRelayStatus(ctx context.Context, nodeID string, req api.RelayStatusRequest) (*api.RelayStatusResponse, error) {
	c.mu.Lock()
	idx := len(c.requests)
	// The reporter builds a fresh body for every send, but a copy keeps the
	// recorded seconds independent of the caller's either way.
	if req.BoundSeconds != nil {
		secs := *req.BoundSeconds
		req.BoundSeconds = &secs
	}
	c.nodeIDs = append(c.nodeIDs, nodeID)
	c.requests = append(c.requests, req)
	c.ctxErrs = append(c.ctxErrs, ctx.Err())
	c.at = append(c.at, time.Now())
	var err error
	if idx < len(c.errs) {
		err = c.errs[idx]
	}
	onCall := c.onCall
	c.mu.Unlock()

	if onCall != nil {
		onCall(idx)
	}
	switch {
	case errors.Is(err, errBlockUntilDone):
		<-ctx.Done()
		return nil, ctx.Err()
	case err != nil:
		return nil, err
	}
	return &api.RelayStatusResponse{AcceptedAt: testAcceptedAt}, nil
}

func (c *fakeRelayStatusClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *fakeRelayStatusClient) recorded() (reqs []api.RelayStatusRequest, ctxErrs []error, at []time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests), slices.Clone(c.ctxErrs), slices.Clone(c.at)
}

// waitCalls waits up to 2 s for the client to have been called n times.
func (c *fakeRelayStatusClient) waitCalls(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for c.calls() < n {
		if time.Now().After(deadline) {
			t.Fatalf("reports = %d after 2s, want %d", c.calls(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// relayLogLine returns the line of logs carrying msg as its message, failing
// the test unless exactly one line does.
func relayLogLine(t *testing.T, logs *relayLog, msg string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("log lines with msg %q = %d, want 1; logs:\n%s", msg, len(found), logs.String())
	}
	return found[0]
}

// relayLogLines returns how many lines of logs carry msg as their message.
func relayLogLines(logs *relayLog, msg string) int {
	return logs.count(`msg="` + msg + `"`)
}

// relayRecords is a slog.Handler that keeps every record, so a test can read
// an attribute's value and not only its text.
type relayRecords struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *relayRecords) Enabled(context.Context, slog.Level) bool { return true }
func (h *relayRecords) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *relayRecords) WithGroup(string) slog.Handler            { return h }

func (h *relayRecords) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

// errorOf returns the error attribute of the one record at level carrying msg.
func (h *relayRecords) errorOf(t *testing.T, level slog.Level, msg string) error {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	var found []slog.Record
	for _, r := range h.records {
		if r.Message == msg && r.Level == level {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s records with msg %q = %d, want 1", level, msg, len(found))
	}
	var err error
	found[0].Attrs(func(a slog.Attr) bool {
		if a.Key == "error" {
			err, _ = a.Value.Any().(error)
			return false
		}
		return true
	})
	return err
}

// wantRelayStatus fails the test unless status holds want.
func wantRelayStatus(t *testing.T, status *RelayStatusTracker, want RelayStatus) {
	t.Helper()
	got, ok := status.Get()
	if !ok || !got.equal(want) {
		t.Errorf("status = %+v (known %v), want %+v", got, ok, want)
	}
}

// takeSignal consumes a pending Changed signal and reports whether there was
// one.
func takeSignal(status *RelayStatusTracker) bool {
	select {
	case <-status.Changed():
		return true
	default:
		return false
	}
}

func runningAt(port int, at time.Time) RelayStatus {
	return RelayStatus{State: api.RelayStateRunning, ListenPort: port, BoundAt: at}
}

// newTestRelayStatusReporter builds a reporter for testRelayNodeID whose clock
// reads 30 s after relayStart, for tests that drive reportOnce directly.
func newTestRelayStatusReporter(client RelayStatusClient, status *RelayStatusTracker, logger *slog.Logger) *RelayStatusReporter {
	r := NewRelayStatusReporter(time.Hour, testRelayNodeID, client, status, logger)
	r.now = func() time.Time { return relayStart.Add(30 * time.Second) }
	return r
}

// startRelayStatusReporter runs r.Run in a goroutine and returns a stop
// function that cancels it and waits for Run to return nil. The stop is also
// registered as a cleanup, so a failed assertion does not leave the goroutine
// to goleak.
func startRelayStatusReporter(t *testing.T, r *RelayStatusReporter) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run() = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Run did not return within 5s of the context being cancelled")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %+v: %v", v, err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// RelayStatusTracker
// ---------------------------------------------------------------------------

func TestRelayStatusTracker_SignalsEachChange(t *testing.T) {
	status := NewRelayStatusTracker()
	if s, ok := status.Get(); ok {
		t.Fatalf("Get before any Set = (%+v, true), want ok false", s)
	}
	if takeSignal(status) {
		t.Fatal("Changed signalled before any Set")
	}

	status.Set(runningAt(51821, relayStart))
	if !takeSignal(status) {
		t.Fatal("the first Set did not signal")
	}

	status.Set(runningAt(51821, relayStart.In(time.FixedZone("CET", 60*60))))
	if takeSignal(status) {
		t.Error("an equal status, BoundAt in another Location, signalled")
	}

	steps := []struct {
		name string
		s    RelayStatus
	}{
		{"port", runningAt(51822, relayStart)},
		{"BoundAt", runningAt(51822, relayStart.Add(time.Second))},
		{"state", RelayStatus{State: api.RelayStateBindFailed, ListenPort: 51822, BoundAt: relayStart.Add(time.Second)}},
	}
	for _, step := range steps {
		status.Set(step.s)
		if !takeSignal(status) {
			t.Errorf("a Set that changes the %s did not signal", step.name)
		}
		wantRelayStatus(t, status, step.s)
	}
}

func TestRelayStatusTracker_CollapsesSignals(t *testing.T) {
	status := NewRelayStatusTracker()
	third := RelayStatus{State: api.RelayStateBindFailed, ListenPort: 51823}
	status.Set(runningAt(51821, relayStart))
	status.Set(RelayStatus{State: api.RelayStateStopped})
	status.Set(third)

	if !takeSignal(status) {
		t.Fatal("three Set calls left no signal")
	}
	if takeSignal(status) {
		t.Error("three Set calls left more than one signal")
	}
	wantRelayStatus(t, status, third)
}

// ---------------------------------------------------------------------------
// buildRelayStatusRequest
// ---------------------------------------------------------------------------

func TestBuildRelayStatusRequest(t *testing.T) {
	now := relayStart.Add(time.Hour)
	tests := []struct {
		name string
		s    RelayStatus
		want string
	}{
		{
			name: "running bound at now",
			s:    runningAt(51821, now),
			want: `{"state":"running","listen_port":51821,"bound_seconds":0}`,
		},
		{
			name: "running bound 30.9 s before is floored",
			s:    runningAt(51821, now.Add(-30900*time.Millisecond)),
			want: `{"state":"running","listen_port":51821,"bound_seconds":30}`,
		},
		{
			name: "running bound after now is clamped to 0",
			s:    runningAt(51821, now.Add(time.Second)),
			want: `{"state":"running","listen_port":51821,"bound_seconds":0}`,
		},
		{
			name: "running bound 11 years before is clamped to the ceiling",
			s:    runningAt(51821, now.AddDate(-11, 0, 0)),
			want: `{"state":"running","listen_port":51821,"bound_seconds":315360000}`,
		},
		{
			// BoundAt is set to prove the builder drops it.
			name: "bind_failed carries only listen_port",
			s:    RelayStatus{State: api.RelayStateBindFailed, ListenPort: 51821, BoundAt: now},
			want: `{"state":"bind_failed","listen_port":51821}`,
		},
		{
			name: "stopped carries neither member",
			s:    RelayStatus{State: api.RelayStateStopped, ListenPort: 51821, BoundAt: now},
			want: `{"state":"stopped"}`,
		},
		{
			name: "not_consented carries neither member",
			s:    RelayStatus{State: api.RelayStateNotConsented, ListenPort: 51821, BoundAt: now},
			want: `{"state":"not_consented"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildRelayStatusRequest(tt.s, now)
			if got := mustJSON(t, req); got != tt.want {
				t.Errorf("body = %s, want %s", got, tt.want)
			}
			if tt.s.State == api.RelayStateRunning && req.BoundSeconds == nil {
				t.Error("BoundSeconds = nil for running, want a value")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Construction and Run
// ---------------------------------------------------------------------------

func TestNewRelayStatusReporter_NonPositiveIntervalRunsAtDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			client := &fakeRelayStatusClient{}
			logger, logs := newRelayLogger()

			r := NewRelayStatusReporter(interval, testRelayNodeID, client, NewRelayStatusTracker(), logger)
			if r.interval != 30*time.Second {
				t.Errorf("interval = %v, want 30s", r.interval)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := r.Run(ctx); err != nil {
				t.Fatalf("Run() = %v, want nil", err)
			}

			line := relayLogLine(t, logs, "relay status: reporter started")
			for _, want := range []string{"level=INFO", "component=bridge", "interval=30s"} {
				if !strings.Contains(line, want) {
					t.Errorf("started log = %q, want it to contain %q", line, want)
				}
			}
			if got := client.calls(); got != 0 {
				t.Errorf("reports = %d, want 0", got)
			}
		})
	}
}

func TestRelayStatusReporter_SendsNothingWithoutAStatus(t *testing.T) {
	client := &fakeRelayStatusClient{}
	logger, logs := newRelayLogger()
	r := NewRelayStatusReporter(10*time.Millisecond, testRelayNodeID, client, NewRelayStatusTracker(), logger)

	stop := startRelayStatusReporter(t, r)
	time.Sleep(60 * time.Millisecond) // five ticks and a little more
	stop()

	if got := client.calls(); got != 0 {
		t.Errorf("reports = %d with no status known, want 0 (no tick send, no shutdown send)", got)
	}
	for _, msg := range []string{"relay status: reported stopped at shutdown", "relay status: shutdown report failed"} {
		if n := relayLogLines(logs, msg); n != 0 {
			t.Errorf("%q logged %d times with no status known, want 0", msg, n)
		}
	}
}

func TestRelayStatusReporter_SendsAStatusSetBeforeRunAtOnce(t *testing.T) {
	client := &fakeRelayStatusClient{}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	r := newTestRelayStatusReporter(client, status, discardLogger())

	start := time.Now()
	startRelayStatusReporter(t, r)
	client.waitCalls(t, 1)

	reqs, _, at := client.recorded()
	if d := at[0].Sub(start); d > 150*time.Millisecond {
		t.Errorf("first report %v after the start, want within 150ms and no wait for a tick", d)
	}
	if got, want := mustJSON(t, reqs[0]), `{"state":"running","listen_port":51821,"bound_seconds":30}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestRelayStatusReporter_ChangeRestartsTheInterval(t *testing.T) {
	const interval = 300 * time.Millisecond
	client := &fakeRelayStatusClient{}
	status := NewRelayStatusTracker()
	logger, logs := newRelayLogger()
	r := NewRelayStatusReporter(interval, testRelayNodeID, client, status, logger)
	r.now = func() time.Time { return relayStart.Add(30 * time.Second) }

	startRelayStatusReporter(t, r)
	logs.waitFor(t, `msg="relay status: reporter started"`, 1)
	// Halfway to the first tick: without the restart after the on-change send,
	// that tick would follow the change about 150 ms later.
	time.Sleep(interval / 2)
	set := time.Now()
	status.Set(runningAt(51821, relayStart))
	client.waitCalls(t, 1)
	_, _, at := client.recorded()
	if d := at[0].Sub(set); d > 150*time.Millisecond {
		t.Errorf("report %v after the change, want within 150ms", d)
	}

	client.waitCalls(t, 2)
	_, _, at = client.recorded()
	if gap := at[1].Sub(at[0]); gap < 250*time.Millisecond || gap > 2*time.Second {
		t.Errorf("next report %v after the on-change one, want no earlier than 250ms and within 2s", gap)
	}
}

func TestRelayStatusReporter_ResendsAnUnchangedStatusEveryTick(t *testing.T) {
	client := &fakeRelayStatusClient{}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	clock := &relayClock{now: relayStart.Add(30 * time.Second)}
	r := NewRelayStatusReporter(20*time.Millisecond, testRelayNodeID, client, status, discardLogger())
	r.now = clock.Now

	stop := startRelayStatusReporter(t, r)
	client.waitCalls(t, 2)
	// Both bodies were built before the clock moves.
	clock.Add(time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for {
		reqs, _, _ := client.recorded()
		last := reqs[len(reqs)-1]
		if last.BoundSeconds != nil && *last.BoundSeconds == 31 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no report with bound_seconds 31 within 2s of the clock advancing; last = %s", mustJSON(t, last))
		}
		time.Sleep(time.Millisecond)
	}
	reqs, _, _ := client.recorded()
	stop()

	for k, req := range reqs {
		want := `{"state":"running","listen_port":51821,"bound_seconds":30}`
		if k >= 2 && req.BoundSeconds != nil && *req.BoundSeconds == 31 {
			want = `{"state":"running","listen_port":51821,"bound_seconds":31}`
		}
		if got := mustJSON(t, req); got != want {
			t.Errorf("report %d = %s, want %s", k, got, want)
		}
		if k > 0 && *req.BoundSeconds < *reqs[k-1].BoundSeconds {
			t.Errorf("report %d bound_seconds %d after %d, want it never to go back", k, *req.BoundSeconds, *reqs[k-1].BoundSeconds)
		}
	}
}

// A tick and a change signal can both be ready when a send outlasts the
// interval and the status changes during it. The tick's send already carries
// the new status, so the pending signal must not make the next iteration send
// it again at once. select picks between ready cases at random, so the
// scenario runs 20 times: a reporter that leaves the signal pending sends the
// new status twice in about half of them.
func TestRelayStatusReporter_TickSpendsAPendingChange(t *testing.T) {
	const interval = time.Minute
	for i := range 20 {
		t.Run(fmt.Sprintf("run %d", i), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				status := NewRelayStatusTracker()
				status.Set(runningAt(51821, relayStart))
				client := &fakeRelayStatusClient{}
				// Call 0 is the on-change send at the start and call 1 the
				// first tick's. During call 1 the status changes and the
				// next tick fires, so both are ready when it returns.
				client.onCall = func(n int) {
					if n == 1 {
						status.Set(runningAt(51822, relayStart))
						time.Sleep(interval + time.Millisecond)
					}
				}
				r := NewRelayStatusReporter(interval, testRelayNodeID, client, status, discardLogger())
				r.now = func() time.Time { return relayStart.Add(30 * time.Second) }

				stop := startRelayStatusReporter(t, r)
				// Call 1 returns at 2m+1ms; the next regular tick is at 3m.
				time.Sleep(2*interval + interval/2)
				reqs, _, _ := client.recorded()
				stop()

				want := []string{
					`{"state":"running","listen_port":51821,"bound_seconds":30}`,
					`{"state":"running","listen_port":51821,"bound_seconds":30}`,
					`{"state":"running","listen_port":51822,"bound_seconds":30}`,
				}
				var got []string
				for _, req := range reqs {
					got = append(got, mustJSON(t, req))
				}
				if !slices.Equal(got, want) {
					t.Errorf("reports before the next tick = %v, want %v", got, want)
				}
			})
		})
	}
}

func TestRelayStatusReporter_FailedSendIsNotRetriedWithinItsTick(t *testing.T) {
	const interval = 200 * time.Millisecond
	client := &fakeRelayStatusClient{errs: []error{errors.New("boom")}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := NewRelayStatusReporter(interval, testRelayNodeID, client, status, logger)
	r.now = func() time.Time { return relayStart.Add(30 * time.Second) }

	startRelayStatusReporter(t, r)
	client.waitCalls(t, 2)

	reqs, _, at := client.recorded()
	if gap := at[1].Sub(at[0]); gap < interval-50*time.Millisecond {
		t.Errorf("second report %v after the failed one, want it at the next tick (%v)", gap, interval)
	}
	if got, want := mustJSON(t, reqs[1]), mustJSON(t, reqs[0]); got != want {
		t.Errorf("next tick sent %s, want %s", got, want)
	}
	line := relayLogLine(t, logs, "relay status: send failed")
	for _, want := range []string{"level=WARN", "error=boom"} {
		if !strings.Contains(line, want) {
			t.Errorf("send failed log = %q, want it to contain %q", line, want)
		}
	}
}

func TestRelayStatusReporter_ShutdownSendsStopped(t *testing.T) {
	client := &fakeRelayStatusClient{}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := NewRelayStatusReporter(time.Hour, testRelayNodeID, client, status, logger)

	stop := startRelayStatusReporter(t, r)
	client.waitCalls(t, 1)
	stop()

	reqs, ctxErrs, _ := client.recorded()
	if len(reqs) != 2 {
		t.Fatalf("reports = %d, want the running report and one stopped report at shutdown", len(reqs))
	}
	if got, want := mustJSON(t, reqs[1]), `{"state":"stopped"}`; got != want {
		t.Errorf("shutdown report = %s, want %s", got, want)
	}
	if ctxErrs[1] != nil {
		t.Errorf("shutdown report's ctx was done as it was sent (%v), want a ctx the cancellation does not reach", ctxErrs[1])
	}
	line := relayLogLine(t, logs, "relay status: reported stopped at shutdown")
	if !strings.Contains(line, "level=INFO") {
		t.Errorf("shutdown log = %q, want level=INFO", line)
	}
}

func TestRelayStatusReporter_NoShutdownSendWhileNotServed(t *testing.T) {
	client := &fakeRelayStatusClient{errs: []error{&api.APIError{StatusCode: 404}}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := NewRelayStatusReporter(time.Hour, testRelayNodeID, client, status, logger)

	stop := startRelayStatusReporter(t, r)
	logs.waitFor(t, "relay status: control plane does not accept relay status reports", 1)
	stop()

	if got := client.calls(); got != 1 {
		t.Errorf("reports = %d, want only the refused one and no shutdown report", got)
	}
	for _, msg := range []string{"relay status: reported stopped at shutdown", "relay status: shutdown report failed"} {
		if n := relayLogLines(logs, msg); n != 0 {
			t.Errorf("%q logged %d times while not served, want 0", msg, n)
		}
	}
}

func TestRelayStatusReporter_ShutdownReportIsBounded(t *testing.T) {
	client := &fakeRelayStatusClient{errs: []error{nil, errBlockUntilDone}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	records := &relayRecords{}
	r := NewRelayStatusReporter(time.Hour, testRelayNodeID, client, status, slog.New(records))
	r.shutdownTimeout = 50 * time.Millisecond

	stop := startRelayStatusReporter(t, r)
	client.waitCalls(t, 1)
	began := time.Now()
	stop()
	if d := time.Since(began); d > r.shutdownTimeout+time.Second {
		t.Errorf("Run returned %v after the cancel, want within %v", d, r.shutdownTimeout+time.Second)
	}

	if got := client.calls(); got != 2 {
		t.Errorf("reports = %d, want 2", got)
	}
	err := records.errorOf(t, slog.LevelWarn, "relay status: shutdown report failed")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("shutdown report failed with %v, want an error wrapping context.DeadlineExceeded", err)
	}
}

// ---------------------------------------------------------------------------
// reportOnce
// ---------------------------------------------------------------------------

func TestRelayStatusReporter_NotServedLoggedOnTransitions(t *testing.T) {
	const (
		notServedMsg = "relay status: control plane does not accept relay status reports, retrying every interval"
		recoveredMsg = "relay status: control plane accepts relay status reports"
	)
	tests := []struct {
		name     string
		err      *api.APIError
		wantAttr string
	}{
		{name: "404 without code", err: &api.APIError{StatusCode: 404}, wantAttr: `status=404 code=""`},
		{
			name:     "501 relay_status_not_provisioned",
			err:      &api.APIError{StatusCode: 501, Code: "relay_status_not_provisioned"},
			wantAttr: "status=501 code=relay_status_not_provisioned",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeRelayStatusClient{errs: []error{tt.err, tt.err, tt.err}}
			status := NewRelayStatusTracker()
			status.Set(runningAt(51821, relayStart))
			logger, logs := newRelayLogger()
			r := newTestRelayStatusReporter(client, status, logger)
			ctx := context.Background()

			for range 3 {
				r.reportOnce(ctx)
			}
			if n := client.calls(); n != 3 {
				t.Errorf("reports = %d after three refused sends, want 3", n)
			}
			line := relayLogLine(t, logs, notServedMsg)
			for _, want := range []string{"level=INFO", tt.wantAttr} {
				if !strings.Contains(line, want) {
					t.Errorf("not-served log = %q, want it to contain %q", line, want)
				}
			}
			if n := relayLogLines(logs, recoveredMsg); n != 0 {
				t.Errorf("recovery logged %d times before any report was accepted, want 0", n)
			}
			if strings.Contains(logs.String(), "send failed") {
				t.Errorf("a not-served answer was logged as a send failure:\n%s", logs.String())
			}
			if !r.notServed {
				t.Error("notServed not set by a not-served answer")
			}

			r.reportOnce(ctx)
			r.reportOnce(ctx)
			if n := relayLogLines(logs, notServedMsg); n != 1 {
				t.Errorf("not-served logged %d times, want 1", n)
			}
			line = relayLogLine(t, logs, recoveredMsg)
			if !strings.Contains(line, "level=INFO") {
				t.Errorf("recovery log = %q, want level=INFO", line)
			}
			if r.notServed {
				t.Error("notServed still set after an accepted report")
			}
		})
	}
}

func TestRelayStatusReporter_NodeGoneWarnsOnEverySend(t *testing.T) {
	const msg = "relay status: rejected, this node was removed"
	gone := &api.APIError{StatusCode: 404, Code: "relay_status_node_gone"}
	client := &fakeRelayStatusClient{errs: []error{gone, gone, gone}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := newTestRelayStatusReporter(client, status, logger)

	for range 3 {
		r.reportOnce(context.Background())
	}

	if n := relayLogLines(logs, msg); n != 3 {
		t.Errorf("%q logged %d times over three sends, want 3:\n%s", msg, n, logs.String())
	}
	if n := logs.count(`level=WARN msg="` + msg + `" component=bridge code=relay_status_node_gone`); n != 3 {
		t.Errorf("node gone lines at Warn with the code = %d, want 3:\n%s", n, logs.String())
	}
	if r.notServed {
		t.Error("relay_status_node_gone entered the not-served state")
	}
	if strings.Contains(logs.String(), "does not accept relay status reports") {
		t.Errorf("relay_status_node_gone was logged as not served:\n%s", logs.String())
	}
}

func TestRelayStatusReporter_SendFailuresWarn(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "400 malformed_relay_status", err: &api.APIError{StatusCode: 400, Code: "malformed_relay_status"}},
		{name: "400 invalid_relay_status", err: &api.APIError{StatusCode: 400, Code: "invalid_relay_status"}},
		{name: "500", err: &api.APIError{StatusCode: 500, Code: "internal"}},
		{name: "501 for another surface", err: &api.APIError{StatusCode: 501, Code: "handshakes_not_provisioned"}},
		{name: "transport error", err: errors.New("dial tcp: connection refused")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeRelayStatusClient{errs: []error{tt.err}}
			status := NewRelayStatusTracker()
			status.Set(runningAt(51821, relayStart))
			logger, logs := newRelayLogger()
			r := newTestRelayStatusReporter(client, status, logger)

			r.reportOnce(context.Background())

			if n := client.calls(); n != 1 {
				t.Errorf("reports = %d within one send, want 1 (no retry)", n)
			}
			line := relayLogLine(t, logs, "relay status: send failed")
			for _, want := range []string{"level=WARN", "error="} {
				if !strings.Contains(line, want) {
					t.Errorf("send failed log = %q, want it to contain %q", line, want)
				}
			}
			if r.notServed {
				t.Error("notServed set by a failure that is not a not-served answer")
			}
		})
	}
}

// While the heartbeat has parked the agent, every send fails locally with
// api.ErrCredentialRefused. The heartbeat names the cause once, so the
// reporter logs the failure at Debug instead of a Warn per send.
func TestRelayStatusReporter_RefusedCredentialLoggedAtDebug(t *testing.T) {
	client := &fakeRelayStatusClient{errs: []error{fmt.Errorf("x: %w", api.ErrCredentialRefused)}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := newTestRelayStatusReporter(client, status, logger)

	r.reportOnce(context.Background())

	line := relayLogLine(t, logs, "relay status: send failed")
	for _, want := range []string{"level=DEBUG", "error="} {
		if !strings.Contains(line, want) {
			t.Errorf("send failed log = %q, want it to contain %q", line, want)
		}
	}
	if got := logs.String(); strings.Contains(got, "level=INFO") || strings.Contains(got, "level=WARN") || strings.Contains(got, "level=ERROR") {
		t.Errorf("logs = %s, want nothing above Debug for a refused credential", got)
	}
}

func TestRelayStatusReporter_CancelledSendIsNotLogged(t *testing.T) {
	client := &fakeRelayStatusClient{errs: []error{context.Canceled}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := newTestRelayStatusReporter(client, status, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.reportOnce(ctx)

	if n := client.calls(); n != 1 {
		t.Errorf("reports = %d, want 1", n)
	}
	if got := logs.String(); got != "" {
		t.Errorf("logs = %q, want nothing for a send cut short by shutdown", got)
	}
}

func TestRelayStatusReporter_ReportedOnChangeAcceptedOnEverySend(t *testing.T) {
	const (
		reportedMsg = "relay status: reported"
		acceptedMsg = "relay status: accepted"
	)
	client := &fakeRelayStatusClient{}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := newTestRelayStatusReporter(client, status, logger)
	ctx := context.Background()

	for range 3 {
		r.reportOnce(ctx)
	}
	line := relayLogLine(t, logs, reportedMsg)
	for _, want := range []string{"level=INFO", "state=running", "listen_port=51821", "bound_seconds=30"} {
		if !strings.Contains(line, want) {
			t.Errorf("reported log = %q, want it to contain %q", line, want)
		}
	}

	status.Set(RelayStatus{State: api.RelayStateBindFailed, ListenPort: 51822})
	r.reportOnce(ctx)
	if n := relayLogLines(logs, reportedMsg); n != 2 {
		t.Fatalf("reported logged %d times, want 2: the first running and the bind_failed\n%s", n, logs.String())
	}
	var bindFailed string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, `msg="`+reportedMsg+`"`) && strings.Contains(l, "state=bind_failed") {
			bindFailed = l
		}
	}
	if !strings.Contains(bindFailed, "listen_port=51822") || strings.Contains(bindFailed, "bound_seconds") {
		t.Errorf("bind_failed reported log = %q, want listen_port=51822 and no bound_seconds", bindFailed)
	}

	if n := logs.count(`level=DEBUG msg="` + acceptedMsg + `"`); n != 4 {
		t.Errorf("accepted logged at Debug %d times over four accepted sends, want 4:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "accepted_at=2026-10-30T10:15:30.123Z") {
		t.Errorf("accepted log lacks the receipt's accepted_at:\n%s", logs.String())
	}
}

// The reported line counts against the last status the control plane
// accepted, so a status whose first send failed is still reported once, by
// the send that is accepted.
func TestRelayStatusReporter_ReportedOnlyAfterAnAcceptedSend(t *testing.T) {
	const reportedMsg = "relay status: reported"
	client := &fakeRelayStatusClient{errs: []error{errors.New("boom")}}
	status := NewRelayStatusTracker()
	status.Set(runningAt(51821, relayStart))
	logger, logs := newRelayLogger()
	r := newTestRelayStatusReporter(client, status, logger)
	ctx := context.Background()

	r.reportOnce(ctx)
	if n := relayLogLines(logs, reportedMsg); n != 0 {
		t.Fatalf("reported logged %d times after a failed send, want 0:\n%s", n, logs.String())
	}
	if r.reported {
		t.Error("reported set by a failed send")
	}

	r.reportOnce(ctx)
	line := relayLogLine(t, logs, reportedMsg)
	for _, want := range []string{"level=INFO", "state=running", "listen_port=51821"} {
		if !strings.Contains(line, want) {
			t.Errorf("reported log = %q, want it to contain %q", line, want)
		}
	}
}

func TestRelayStatusReporter_ReportsThroughTheGivenNodeID(t *testing.T) {
	client := &fakeRelayStatusClient{}
	status := NewRelayStatusTracker()
	status.Set(RelayStatus{State: api.RelayStateStopped})
	r := newTestRelayStatusReporter(client, status, discardLogger())

	r.reportOnce(context.Background())

	client.mu.Lock()
	defer client.mu.Unlock()
	if !slices.Equal(client.nodeIDs, []string{testRelayNodeID}) {
		t.Errorf("node IDs = %v, want [%s]", client.nodeIDs, testRelayNodeID)
	}
}
