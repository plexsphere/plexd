package tunnel

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The lines an activity report logs above Debug.
const (
	activityStoppedMsg = "session no longer live server-side; stopping its activity reports"
	activityRefusedMsg = "control plane refused the session_active row; it revokes the tunnel one idle timeout after it started"
	activityRetryMsg   = "session activity report failed; retrying at the end of the interval"
)

// activitySessionID is the session every report in these tests posts for.
const activitySessionID = "sess-active"

// activityCall is one ReportSessionActive call, stamped when it started.
type activityCall struct {
	sessionID string
	at        time.Time
}

// activityRecorder is a TCPActivityReporter that sends every call on calls as
// it starts and answers it with answer, or with nil when answer is unset. call
// counts from 1.
type activityRecorder struct {
	calls  chan activityCall
	n      atomic.Int32
	answer func(ctx context.Context, call int) error
}

func newActivityRecorder(answer func(ctx context.Context, call int) error) *activityRecorder {
	return &activityRecorder{calls: make(chan activityCall, 16), answer: answer}
}

func (r *activityRecorder) ReportSessionActive(ctx context.Context, sessionID string) error {
	call := int(r.n.Add(1))
	// A report the test no longer drains must still end with its session.
	select {
	case r.calls <- activityCall{sessionID: sessionID, at: time.Now()}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if r.answer == nil {
		return nil
	}
	return r.answer(ctx, call)
}

// next waits up to within for the recorder's next call and requires it to be
// for wantID.
func (r *activityRecorder) next(t *testing.T, wantID string, within time.Duration) activityCall {
	t.Helper()
	select {
	case c := <-r.calls:
		if c.sessionID != wantID {
			t.Errorf("ReportSessionActive session id = %q, want %q", c.sessionID, wantID)
		}
		return c
	case <-time.After(within):
		t.Fatalf("no ReportSessionActive call within %v", within)
		return activityCall{}
	}
}

// none requires the recorder to see no call for d.
func (r *activityRecorder) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case c := <-r.calls:
		t.Fatalf("unexpected ReportSessionActive call for %q", c.sessionID)
	case <-time.After(d):
	}
}

// startActivityReport runs a report for activitySessionID on its own
// goroutine. done is closed once run returned; cancel ends the report's
// context, which the test's cleanup also does before it waits for run, so no
// report outlives its test.
func startActivityReport(t *testing.T, rec *activityRecorder, interval time.Duration, logger *slog.Logger) (a *activityReport, done <-chan struct{}, cancel context.CancelFunc) {
	t.Helper()
	a = newActivityReport(rec, activitySessionID, interval)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		a.run(ctx, logger)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("run did not return within 2s of its context ending")
		}
	})
	return a, finished, cancel
}

// waitRunDone requires run to return within d.
func waitRunDone(t *testing.T, done <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("run did not return within %v", d)
	}
}

func TestActivityReportInterval(t *testing.T) {
	tests := []struct {
		idleTimeoutSeconds int
		want               time.Duration
	}{
		// An entry without an idle window still reports, at the longest interval.
		{0, 60 * time.Second},
		{240, 60 * time.Second},
		{900, 60 * time.Second},
		{200, 50 * time.Second},
		// The Duration is divided, not the seconds.
		{10, 2500 * time.Millisecond},
		{1, 250 * time.Millisecond},
	}

	for _, tt := range tests {
		if got := activityReportInterval(tt.idleTimeoutSeconds); got != tt.want {
			t.Errorf("activityReportInterval(%d) = %v, want %v", tt.idleTimeoutSeconds, got, tt.want)
		}
	}
}

// At an hour's interval only the immediate path can post, so the call proves
// the first byte after a quiet spell does not wait for an interval's end.
func TestActivityReport_FirstByteReportsAtOnce(t *testing.T) {
	rec := newActivityRecorder(nil)
	a, _, _ := startActivityReport(t, rec, time.Hour, slog.New(newCountingHandler()))

	a.observe()
	rec.next(t, activitySessionID, time.Second)
	rec.none(t, 500*time.Millisecond)
}

func TestActivityReport_NoBytesNoRow(t *testing.T) {
	rec := newActivityRecorder(nil)
	startActivityReport(t, rec, 100*time.Millisecond, slog.New(newCountingHandler()))

	rec.none(t, time.Second)
}

// Bytes that cross after a row are reported at the end of its interval, and a
// whole interval without a byte ends the rows.
func TestActivityReport_BytesAfterARowReportAtTheIntervalEnd(t *testing.T) {
	rec := newActivityRecorder(nil)
	a, _, _ := startActivityReport(t, rec, 200*time.Millisecond, slog.New(newCountingHandler()))

	a.observe()
	first := rec.next(t, activitySessionID, time.Second)
	time.Sleep(time.Until(first.at.Add(50 * time.Millisecond)))
	a.observe()

	second := rec.next(t, activitySessionID, time.Second)
	if gap := second.at.Sub(first.at); gap < 150*time.Millisecond {
		t.Errorf("second row %v after the first, want it at the end of the 200ms interval", gap)
	}
	rec.none(t, 600*time.Millisecond)
}

// A report that went quiet posts the next byte at once, not at the end of an
// interval.
func TestActivityReport_ByteAfterAQuietIntervalReportsAtOnce(t *testing.T) {
	rec := newActivityRecorder(nil)
	a, _, _ := startActivityReport(t, rec, time.Second, slog.New(newCountingHandler()))

	a.observe()
	first := rec.next(t, activitySessionID, time.Second)
	// The interval after the row passes without a byte, so the report is
	// quiet by 2.5s after the row.
	rec.none(t, time.Until(first.at.Add(2500*time.Millisecond)))

	a.observe()
	rec.next(t, activitySessionID, 200*time.Millisecond)
}

// The interval is measured from the post's start, so bytes that cross while a
// post is in flight are left to the row at the end of that interval.
func TestActivityReport_BytesDuringAPostReportAtTheIntervalEnd(t *testing.T) {
	release := make(chan struct{})
	rec := newActivityRecorder(func(ctx context.Context, call int) error {
		if call == 1 {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	a, _, _ := startActivityReport(t, rec, 200*time.Millisecond, slog.New(newCountingHandler()))

	a.observe()
	first := rec.next(t, activitySessionID, time.Second)
	a.observe()
	time.Sleep(50 * time.Millisecond)
	close(release)

	second := rec.next(t, activitySessionID, time.Second)
	if gap := second.at.Sub(first.at); gap < 150*time.Millisecond {
		t.Errorf("second row %v after the first started, want it at the end of the 200ms interval", gap)
	}
	rec.none(t, 600*time.Millisecond)
}

// A post that outlasts the interval is followed at once by the row its bytes
// are due: the interval ran from the post's start, not from its answer.
func TestActivityReport_IntervalRunsFromThePostsStart(t *testing.T) {
	release := make(chan struct{})
	rec := newActivityRecorder(func(ctx context.Context, call int) error {
		if call == 1 {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	a, _, _ := startActivityReport(t, rec, time.Second, slog.New(newCountingHandler()))

	a.observe()
	first := rec.next(t, activitySessionID, time.Second)
	a.observe()
	time.Sleep(time.Until(first.at.Add(1500 * time.Millisecond)))
	released := time.Now()
	close(release)

	second := rec.next(t, activitySessionID, time.Second)
	if lag := second.at.Sub(released); lag > 500*time.Millisecond {
		t.Errorf("second row %v after the 1.5s post returned, want it at once: the 1s interval ended during the post", lag)
	}
}

// Every post carries the 15s bound, so a stalled control plane holds the report
// no longer than that.
func TestActivityReport_PostIsBounded(t *testing.T) {
	remaining := make(chan time.Duration, 1)
	rec := newActivityRecorder(func(ctx context.Context, _ int) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			remaining <- 0
			return nil
		}
		remaining <- time.Until(deadline)
		return nil
	})
	a, _, _ := startActivityReport(t, rec, time.Hour, slog.New(newCountingHandler()))

	a.observe()
	rec.next(t, activitySessionID, time.Second)
	if got := <-remaining; got <= sessionActiveReportTimeout-time.Second || got > sessionActiveReportTimeout {
		t.Errorf("post deadline %v away, want within a second below %v", got, sessionActiveReportTimeout)
	}
}

// observe runs on the forwarding path, so it never blocks, not even with no run
// reading its kicks.
func TestActivityReport_ObserveNeverBlocks(t *testing.T) {
	a := newActivityReport(newActivityRecorder(nil), activitySessionID, time.Hour)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			a.observe()
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observe blocked")
	}
}

// A kick left over from an earlier quiet spell carries no bytes, so it posts no
// row.
func TestActivityReport_StaleKickPostsNothing(t *testing.T) {
	rec := newActivityRecorder(nil)
	a, _, _ := startActivityReport(t, rec, 100*time.Millisecond, slog.New(newCountingHandler()))

	a.kick <- struct{}{}
	rec.none(t, 300*time.Millisecond)
}

// A kick still buffered when a post returns is not read before the interval
// ends, so the bytes that crossed during the post wait for that end.
func TestActivityReport_StaleKickAfterAPostWaitsForTheInterval(t *testing.T) {
	release := make(chan struct{})
	rec := newActivityRecorder(func(ctx context.Context, call int) error {
		if call == 1 {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	a, _, _ := startActivityReport(t, rec, 200*time.Millisecond, slog.New(newCountingHandler()))

	a.observe()
	first := rec.next(t, activitySessionID, time.Second)
	// The kick a second chunk sends when it still saw the report quiet.
	a.kick <- struct{}{}
	a.observe()
	close(release)

	second := rec.next(t, activitySessionID, time.Second)
	if gap := second.at.Sub(first.at); gap < 150*time.Millisecond {
		t.Errorf("second row %v after the first, want it at the end of the 200ms interval", gap)
	}
}

// A session the control plane no longer holds as live gets no more rows.
func TestActivityReport_NoLongerLiveStopsTheReports(t *testing.T) {
	for _, code := range []string{"session_already_revoked", "session_expired"} {
		t.Run(code, func(t *testing.T) {
			rec := newActivityRecorder(func(context.Context, int) error {
				return &api.APIError{StatusCode: http.StatusConflict, Message: "conflict", Code: code}
			})
			logs := newCountingHandler()
			a, done, _ := startActivityReport(t, rec, 200*time.Millisecond, slog.New(logs))

			a.observe()
			rec.next(t, activitySessionID, time.Second)
			waitRunDone(t, done, time.Second)

			a.observe()
			rec.none(t, 400*time.Millisecond)

			if n := logs.count(activityStoppedMsg); n != 1 {
				t.Fatalf("%q logged %d times, want 1", activityStoppedMsg, n)
			}
			if lvl := logs.level(activityStoppedMsg); lvl != slog.LevelInfo {
				t.Errorf("%q logged at %v, want INFO", activityStoppedMsg, lvl)
			}
		})
	}
}

// A post that was not recorded is retried at the end of the interval, though no
// byte crossed since.
func TestActivityReport_FailedPostRetriedAtTheIntervalEnd(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"503", &api.APIError{StatusCode: http.StatusServiceUnavailable, Message: "service unavailable"}},
		{"401 nsk_invalid", &api.APIError{StatusCode: http.StatusUnauthorized, Message: "unauthorized", Code: "nsk_invalid"}},
		{"404 session_not_found", &api.APIError{StatusCode: http.StatusNotFound, Message: "not found", Code: "session_not_found"}},
		{"deadline exceeded", context.DeadlineExceeded},
		{"credential refused", api.ErrCredentialRefused},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newActivityRecorder(func(_ context.Context, call int) error {
				if call == 1 {
					return tt.err
				}
				return nil
			})
			logs := newCountingHandler()
			a, _, _ := startActivityReport(t, rec, 200*time.Millisecond, slog.New(logs))

			a.observe()
			first := rec.next(t, activitySessionID, time.Second)
			second := rec.next(t, activitySessionID, time.Second)
			if gap := second.at.Sub(first.at); gap < 150*time.Millisecond {
				t.Errorf("retry %v after the failed post, want it at the end of the 200ms interval", gap)
			}
			rec.none(t, 400*time.Millisecond)

			if n := logs.count(activityRetryMsg); n != 1 {
				t.Fatalf("%q logged %d times, want 1", activityRetryMsg, n)
			}
			if lvl := logs.level(activityRetryMsg); lvl != slog.LevelWarn {
				t.Errorf("%q logged at %v, want WARN", activityRetryMsg, lvl)
			}
		})
	}
}

// A 400 is not retried, since the row's bytes would draw it again, and warned
// about once; later bytes still post, for a control plane rolled forward
// mid-session.
func TestActivityReport_BadRequestWarnsOnceAndIsNotRetried(t *testing.T) {
	rec := newActivityRecorder(func(context.Context, int) error {
		return &api.APIError{StatusCode: http.StatusBadRequest, Message: "bad request", Code: "invalid_session_activity"}
	})
	logs := newCountingHandler()
	a, _, _ := startActivityReport(t, rec, 200*time.Millisecond, slog.New(logs))

	a.observe()
	rec.next(t, activitySessionID, time.Second)
	rec.none(t, 600*time.Millisecond)

	a.observe()
	rec.next(t, activitySessionID, time.Second)
	rec.none(t, 600*time.Millisecond)

	if n := logs.count(activityRefusedMsg); n != 1 {
		t.Fatalf("%q logged %d times after two 400s, want 1", activityRefusedMsg, n)
	}
	if lvl := logs.level(activityRefusedMsg); lvl != slog.LevelWarn {
		t.Errorf("%q logged at %v, want WARN", activityRefusedMsg, lvl)
	}
	if n := logs.count(activityRetryMsg); n != 0 {
		t.Errorf("%q logged %d times, want 0: a 400 is not retried", activityRetryMsg, n)
	}
}

// A post the session's close cuts short says nothing about the row, so run
// returns without a warning.
func TestActivityReport_CloseDuringAPostEndsQuietly(t *testing.T) {
	rec := newActivityRecorder(func(ctx context.Context, _ int) error {
		<-ctx.Done()
		return ctx.Err()
	})
	logs := newCountingHandler()
	a, done, cancel := startActivityReport(t, rec, 200*time.Millisecond, slog.New(logs))

	a.observe()
	rec.next(t, activitySessionID, time.Second)
	cancel()
	waitRunDone(t, done, time.Second)

	logs.mu.Lock()
	defer logs.mu.Unlock()
	for msg, lvl := range logs.levels {
		if lvl >= slog.LevelWarn {
			t.Errorf("%q logged at %v while the session closed mid-post, want no warning", msg, lvl)
		}
	}
}
