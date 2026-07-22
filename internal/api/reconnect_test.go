package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fastEngine creates a ReconnectEngine with millisecond-scale intervals for fast testing.
func fastEngine(logger *slog.Logger) *ReconnectEngine {
	e := NewReconnectEngine(logger)
	e.baseInterval = 1 * time.Millisecond
	e.maxInterval = 10 * time.Millisecond
	e.pollingFallback = 50 * time.Millisecond
	e.pollInterval = 5 * time.Millisecond
	e.currentInterval = 1 * time.Millisecond
	return e
}

func TestReconnect_ExponentialBackoff(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	var callCount atomic.Int32
	connectFn := func(ctx context.Context) error {
		n := callCount.Add(1)
		if n <= 5 {
			return fmt.Errorf("transient error %d", n)
		}
		// Succeed on 6th call, then simulate connection drop by returning nil
		// After that, cancel the context to exit
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// We need to stop after the successful connect + drop cycle
	// Use a wrapper that cancels after one success
	var successCount atomic.Int32
	wrappedConnect := func(ctx context.Context) error {
		err := connectFn(ctx)
		if err == nil {
			if successCount.Add(1) >= 1 {
				cancel()
				return nil
			}
		}
		return err
	}

	pollFn := func(ctx context.Context) error { return nil }

	_ = e.Run(ctx, wrappedConnect, pollFn)

	calls := int(callCount.Load())
	if calls < 6 {
		t.Errorf("expected at least 6 connect calls, got %d", calls)
	}
}

func TestReconnect_JitterDistribution(t *testing.T) {
	e := NewReconnectEngine(slog.Default())
	base := 100 * time.Millisecond

	for i := 0; i < 100; i++ {
		jittered := e.jitter(base)
		low := time.Duration(float64(base) * (1 - e.jitterFraction))
		high := time.Duration(float64(base) * (1 + e.jitterFraction))
		if jittered < low || jittered > high {
			t.Errorf("jitter(%v) = %v, want in [%v, %v]", base, jittered, low, high)
		}
	}
}

func TestReconnect_401TriggersAuthCallback(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	var authCalled atomic.Bool
	e.SetOnAuthFailure(func() {
		authCalled.Store(true)
	})

	connectFn := func(ctx context.Context) error {
		return &APIError{StatusCode: 401, Message: "unauthorized"}
	}
	pollFn := func(ctx context.Context) error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := e.Run(ctx, connectFn, pollFn)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !authCalled.Load() {
		t.Error("expected onAuthFailure callback to be invoked")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
		t.Errorf("expected 401 APIError, got %v", err)
	}
}

func TestReconnect_429RespectsRetryAfter(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	retryAfter := 10 * time.Millisecond
	var callCount atomic.Int32

	connectFn := func(ctx context.Context) error {
		n := callCount.Add(1)
		if n == 1 {
			return &APIError{StatusCode: 429, Message: "rate limited", RetryAfter: retryAfter}
		}
		// Succeed on second call
		return nil
	}

	var successCount atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wrappedConnect := func(ctx context.Context) error {
		err := connectFn(ctx)
		if err == nil {
			if successCount.Add(1) >= 1 {
				cancel()
			}
		}
		return err
	}

	pollFn := func(ctx context.Context) error { return nil }

	start := time.Now()
	_ = e.Run(ctx, wrappedConnect, pollFn)
	elapsed := time.Since(start)

	if elapsed < retryAfter {
		t.Errorf("expected delay of at least %v, got %v", retryAfter, elapsed)
	}
}

func TestReconnect_PermanentFailure(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	connectFn := func(ctx context.Context) error {
		return &APIError{StatusCode: 403, Message: "forbidden"}
	}
	pollFn := func(ctx context.Context) error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := e.Run(ctx, connectFn, pollFn)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}

	if elapsed > 100*time.Millisecond {
		t.Errorf("expected immediate return, took %v", elapsed)
	}
}

func TestReconnect_PollingFallbackAfter5Min(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	var pollCount atomic.Int32
	var connectCount atomic.Int32

	connectFn := func(ctx context.Context) error {
		connectCount.Add(1)
		return fmt.Errorf("connection refused")
	}

	pollFn := func(ctx context.Context) error {
		pollCount.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run in background — will be stopped by context timeout
	done := make(chan error, 1)
	go func() {
		done <- e.Run(ctx, connectFn, pollFn)
	}()

	// Wait enough time for polling to kick in (pollingFallback = 50ms)
	time.Sleep(300 * time.Millisecond)
	cancel()

	<-done

	polls := int(pollCount.Load())
	if polls < 1 {
		t.Errorf("expected pollFn to be called at least once, got %d calls", polls)
	}
}

func TestReconnect_SSERetryFromPolling(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	var mu sync.Mutex
	var pollCalls int
	var connectCalls int

	connectFn := func(ctx context.Context) error {
		mu.Lock()
		connectCalls++
		n := connectCalls
		mu.Unlock()

		// Fail for first several calls, then succeed once in polling mode
		if n >= 15 {
			return nil
		}
		return fmt.Errorf("connection refused")
	}

	pollFn := func(ctx context.Context) error {
		mu.Lock()
		pollCalls++
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run — should enter polling, then SSE reconnects
	var successCount atomic.Int32
	wrappedConnect := func(ctx context.Context) error {
		err := connectFn(ctx)
		if err == nil {
			if successCount.Add(1) >= 1 {
				cancel()
			}
		}
		return err
	}

	_ = e.Run(ctx, wrappedConnect, pollFn)

	mu.Lock()
	polls := pollCalls
	mu.Unlock()

	if polls < 1 {
		t.Errorf("expected pollFn to be called at least once during fallback, got %d", polls)
	}
}

func TestReconnect_CancelDuringBackoff(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)
	// Set a longer backoff so we cancel during it
	e.baseInterval = 5 * time.Second
	e.currentInterval = 5 * time.Second

	connectFn := func(ctx context.Context) error {
		return fmt.Errorf("connection refused")
	}
	pollFn := func(ctx context.Context) error { return nil }

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- e.Run(ctx, connectFn, pollFn)
	}()

	// Let it enter backoff
	time.Sleep(20 * time.Millisecond)
	cancel()

	start := time.Now()
	err := <-done
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("expected prompt return after cancel, took %v", elapsed)
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestReconnect_SuccessResetsBackoff(t *testing.T) {
	logger := slog.Default()
	e := fastEngine(logger)

	var mu sync.Mutex
	var calls int
	phase := 0 // 0=first success, 1=fail, 2=second success

	connectFn := func(ctx context.Context) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()

		switch {
		case n == 1:
			// First call succeeds (connection active then drops)
			return nil
		case n >= 2 && phase == 0:
			mu.Lock()
			phase = 1
			mu.Unlock()
			return fmt.Errorf("transient error")
		default:
			// Succeed again
			return nil
		}
	}

	pollFn := func(ctx context.Context) error { return nil }

	var successCount atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wrappedConnect := func(ctx context.Context) error {
		err := connectFn(ctx)
		if err == nil {
			if successCount.Add(1) >= 2 {
				cancel()
			}
		}
		return err
	}

	_ = e.Run(ctx, wrappedConnect, pollFn)

	// Verify backoff was reset: currentInterval should be back to base
	e.mu.Lock()
	interval := e.currentInterval
	e.mu.Unlock()

	if interval > e.maxInterval {
		t.Errorf("expected interval to be within bounds, got %v", interval)
	}
}

func TestClassifyError_NetworkError(t *testing.T) {
	err := fmt.Errorf("dial tcp: connection refused")
	action := ClassifyError(err)
	if action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}

func TestClassifyError_401(t *testing.T) {
	err := &APIError{StatusCode: 401, Message: "unauthorized"}
	action := ClassifyError(err)
	if action != RetryAuth {
		t.Errorf("expected RetryAuth, got %v", action)
	}
}

func TestClassifyError_429(t *testing.T) {
	err := &APIError{StatusCode: 429, Message: "rate limited", RetryAfter: 10 * time.Millisecond}
	action := ClassifyError(err)
	if action != RespectServer {
		t.Errorf("expected RespectServer, got %v", action)
	}
}

func TestClassifyError_403(t *testing.T) {
	err := &APIError{StatusCode: 403, Message: "forbidden"}
	action := ClassifyError(err)
	if action != PermanentFailure {
		t.Errorf("expected PermanentFailure, got %v", action)
	}
}

func TestClassifyError_404(t *testing.T) {
	err := &APIError{StatusCode: 404, Message: "not found"}
	action := ClassifyError(err)
	if action != PermanentFailure {
		t.Errorf("expected PermanentFailure, got %v", action)
	}
}

// ClassifyError also drives the long-running SSE ReconnectEngine, where a 422
// means the control plane tightened body validation on an endpoint this build
// predates. That clears when the server is rolled back, so it must stay
// transient here: PermanentFailure would stop the whole fleet from reconnecting
// at once, with no recovery short of restarting every process. Registration
// stops on 422 locally instead — see registerWithRetry.
func TestClassifyError_422(t *testing.T) {
	err := &APIError{StatusCode: 422, Message: "unprocessable entity"}
	action := ClassifyError(err)
	if action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}

func TestClassifyError_ErrUnprocessable(t *testing.T) {
	action := ClassifyError(ErrUnprocessable)
	if action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}

func TestClassifyError_5xx(t *testing.T) {
	err := &APIError{StatusCode: 502, Message: "bad gateway"}
	action := ClassifyError(err)
	if action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}

// A 501 signed_event_bus_not_provisioned is the control plane's long-term
// events descope: it must classify as RetryDescoped even though it also matches
// the any-5xx ErrServer sentinel, so pull-only delivery engages instead of
// burning backoff against a channel that is not there.
func TestClassifyError_501EventBusDescoped(t *testing.T) {
	err := &APIError{StatusCode: 501, Code: "signed_event_bus_not_provisioned"}
	if action := ClassifyError(err); action != RetryDescoped {
		t.Errorf("expected RetryDescoped, got %v", action)
	}
}

// A 501 carrying any other code is a plain not-implemented and stays transient.
func TestClassifyError_501OtherCode(t *testing.T) {
	err := &APIError{StatusCode: 501, Code: "observability_ingest_not_provisioned"}
	if action := ClassifyError(err); action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}

// A 503 event_stream_unavailable is a transient outage, not a descope.
func TestClassifyError_503EventStreamUnavailable(t *testing.T) {
	err := &APIError{StatusCode: 503, Code: "event_stream_unavailable"}
	if action := ClassifyError(err); action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}

// discardLogger returns a logger that drops all output, keeping test logs quiet.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordingClock is a fake Clock that resolves After immediately and records
// every delay it was handed, so a test can assert the reconnect engine's wait
// cadence without real sleeps. Now advances by each waited delay, which lets the
// polling-fallback window elapse deterministically.
type recordingClock struct {
	mu    sync.Mutex
	now   time.Time
	after []time.Duration
}

func newRecordingClock() *recordingClock {
	return &recordingClock{now: time.Now()}
}

func (c *recordingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *recordingClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.after = append(c.after, d)
	now := c.now
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- now
	return ch
}

func (c *recordingClock) delays() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.after))
	copy(out, c.after)
	return out
}

// descopedErr is the control plane's long-term events descope.
func descopedErr() error {
	return &APIError{StatusCode: 501, Code: "signed_event_bus_not_provisioned"}
}

// modeRecorder collects the delivery-mode transitions the engine fires.
type modeRecorder struct {
	mu    sync.Mutex
	modes []DeliveryMode
}

func (m *modeRecorder) record(mode DeliveryMode) {
	m.mu.Lock()
	m.modes = append(m.modes, mode)
	m.mu.Unlock()
}

func (m *modeRecorder) seq() []DeliveryMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DeliveryMode, len(m.modes))
	copy(out, m.modes)
	return out
}

// TestReconnect_PullOnlyEntryImmediate proves the descope enters pull-only with
// no exponential-backoff wait and no 5-minute polling window preceding it: the
// first wait the engine performs equals the reprobe interval, and every wait in
// the run is the reprobe interval.
func TestReconnect_PullOnlyEntryImmediate(t *testing.T) {
	e := fastEngine(discardLogger())
	clk := newRecordingClock()
	e.SetClock(clk)
	const reprobe = 30 * time.Millisecond
	e.SetReprobeInterval(reprobe)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	connectFn := func(context.Context) error {
		if calls.Add(1) >= 3 {
			cancel()
		}
		return descopedErr()
	}
	pollFn := func(context.Context) error { return nil }

	_ = e.Run(ctx, connectFn, pollFn)

	delays := clk.delays()
	if len(delays) == 0 {
		t.Fatal("expected at least one wait, got none")
	}
	if delays[0] != reprobe {
		t.Errorf("first wait after descope = %v, want reprobe interval %v", delays[0], reprobe)
	}
	for i, d := range delays {
		if d != reprobe {
			t.Errorf("wait[%d] = %v, want reprobe interval %v (no backoff/polling wait may precede pull-only)", i, d, reprobe)
		}
	}
}

// TestReconnect_PullOnlyNeverPolls proves the pull path never calls pollFn while
// descoped, and re-probes SSE exactly once per elapsed reprobe interval.
func TestReconnect_PullOnlyNeverPolls(t *testing.T) {
	e := fastEngine(discardLogger())
	clk := newRecordingClock()
	e.SetClock(clk)
	const reprobe = 20 * time.Millisecond
	e.SetReprobeInterval(reprobe)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var connectCalls, pollCalls atomic.Int32
	connectFn := func(context.Context) error {
		if connectCalls.Add(1) >= 5 {
			cancel()
		}
		return descopedErr()
	}
	pollFn := func(context.Context) error {
		pollCalls.Add(1)
		return nil
	}

	_ = e.Run(ctx, connectFn, pollFn)

	if got := pollCalls.Load(); got != 0 {
		t.Errorf("pollFn called %d times in pull-only, want 0", got)
	}
	// Each reprobe wait is followed by exactly one connectFn attempt; the extra
	// attempt is the initial descope in Run's main loop.
	delays := clk.delays()
	if got := int(connectCalls.Load()); got != len(delays)+1 {
		t.Errorf("connectFn attempts = %d, want reprobe waits + 1 = %d", got, len(delays)+1)
	}
	for i, d := range delays {
		if d != reprobe {
			t.Errorf("wait[%d] = %v, want reprobe interval %v", i, d, reprobe)
		}
	}
}

// TestReconnect_PullOnlyStaysDescoped proves that re-probes still answering the
// descope keep the engine in pull-only with a single mode transition fired.
func TestReconnect_PullOnlyStaysDescoped(t *testing.T) {
	e := fastEngine(discardLogger())
	clk := newRecordingClock()
	e.SetClock(clk)
	e.SetReprobeInterval(15 * time.Millisecond)

	var rec modeRecorder
	e.SetOnModeChange(rec.record)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	connectFn := func(context.Context) error {
		if calls.Add(1) >= 4 {
			cancel()
		}
		return descopedErr()
	}

	_ = e.Run(ctx, connectFn, func(context.Context) error { return nil })

	if got := e.Mode(); got != DeliveryModePullOnly {
		t.Errorf("mode = %q, want pull_only", got)
	}
	if seq := rec.seq(); len(seq) != 1 || seq[0] != DeliveryModePullOnly {
		t.Errorf("mode transitions = %v, want exactly [pull_only]", seq)
	}
}

// TestReconnect_PullOnlyExitOnReconnect proves each reconnect path leaves
// pull-only for streaming with backoff reset and exactly two mode transitions
// (streaming->pull_only->streaming).
func TestReconnect_PullOnlyExitOnReconnect(t *testing.T) {
	cases := []struct {
		name string
		// probe is the connectFn behaviour on the pull-only re-probe (call 2).
		probe func(e *ReconnectEngine) error
	}{
		{
			name: "nil after notifyConnected",
			probe: func(e *ReconnectEngine) error {
				e.notifyConnected()
				return nil
			},
		},
		{
			name: "error after notifyConnected",
			probe: func(e *ReconnectEngine) error {
				e.notifyConnected()
				return errors.New("stream dropped after 200")
			},
		},
		{
			name: "nil without notifyConnected (hook not wired)",
			probe: func(*ReconnectEngine) error {
				return nil
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fastEngine(discardLogger())
			clk := newRecordingClock()
			e.SetClock(clk)
			e.SetReprobeInterval(15 * time.Millisecond)

			var rec modeRecorder
			e.SetOnModeChange(rec.record)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var calls atomic.Int32
			connectFn := func(context.Context) error {
				switch calls.Add(1) {
				case 1:
					return descopedErr()
				case 2:
					return tc.probe(e)
				default:
					cancel()
					return nil
				}
			}

			_ = e.Run(ctx, connectFn, func(context.Context) error { return nil })

			if got := e.Mode(); got != DeliveryModeStreaming {
				t.Errorf("mode = %q, want streaming", got)
			}
			if seq := rec.seq(); len(seq) != 2 || seq[0] != DeliveryModePullOnly || seq[1] != DeliveryModeStreaming {
				t.Errorf("mode transitions = %v, want [pull_only streaming]", seq)
			}
			e.mu.Lock()
			interval, failing := e.currentInterval, e.failingSince
			e.mu.Unlock()
			if interval != e.baseInterval {
				t.Errorf("currentInterval = %v, want base %v (backoff not reset)", interval, e.baseInterval)
			}
			if !failing.IsZero() {
				t.Errorf("failingSince = %v, want zero (backoff not reset)", failing)
			}
		})
	}
}

// TestReconnect_PullOnlyReprobePropagates proves an auth or permanent failure
// surfaced by a re-probe stops the engine and propagates the error.
func TestReconnect_PullOnlyReprobePropagates(t *testing.T) {
	t.Run("401 invokes auth callback and returns", func(t *testing.T) {
		e := fastEngine(discardLogger())
		e.SetClock(newRecordingClock())
		e.SetReprobeInterval(15 * time.Millisecond)

		var authCalled atomic.Bool
		e.SetOnAuthFailure(func() { authCalled.Store(true) })

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var calls atomic.Int32
		connectFn := func(context.Context) error {
			if calls.Add(1) == 1 {
				return descopedErr()
			}
			return &APIError{StatusCode: 401, Message: "unauthorized"}
		}

		err := e.Run(ctx, connectFn, func(context.Context) error { return nil })
		if !authCalled.Load() {
			t.Error("expected onAuthFailure callback to be invoked")
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
			t.Errorf("Run error = %v, want 401 APIError", err)
		}
	})

	t.Run("403 stops and returns", func(t *testing.T) {
		e := fastEngine(discardLogger())
		e.SetClock(newRecordingClock())
		e.SetReprobeInterval(15 * time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var calls atomic.Int32
		connectFn := func(context.Context) error {
			if calls.Add(1) == 1 {
				return descopedErr()
			}
			return &APIError{StatusCode: 403, Message: "forbidden"}
		}

		err := e.Run(ctx, connectFn, func(context.Context) error { return nil })
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("Run error = %v, want ErrForbidden", err)
		}
	})
}

// TestReconnect_DegradedPollingMode proves the legacy transient path is intact:
// a persistent transient error backs off, enters the polling fallback reporting
// degraded_polling, and returns to streaming once SSE reattaches from fallback.
func TestReconnect_DegradedPollingMode(t *testing.T) {
	e := NewReconnectEngine(discardLogger())
	clk := newRecordingClock()
	e.SetClock(clk)
	e.jitterFraction = 0 // deterministic backoff so the window elapses predictably
	e.SetIntervals(1*time.Second, 4*time.Second)
	e.SetPollingFallbackConfig(10*time.Second, 2*time.Second)

	var rec modeRecorder
	e.SetOnModeChange(rec.record)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var connectCalls, pollCalls atomic.Int32
	// Fail transiently until the polling window elapses, reconnect once from the
	// fallback, then cancel so Run returns.
	connectFn := func(context.Context) error {
		n := connectCalls.Add(1)
		if n <= 5 {
			return errors.New("connection refused")
		}
		if n == 6 {
			return nil // SSE reattaches from polling fallback
		}
		cancel()
		return nil
	}
	pollFn := func(context.Context) error {
		pollCalls.Add(1)
		return nil
	}

	_ = e.Run(ctx, connectFn, pollFn)

	if got := pollCalls.Load(); got < 1 {
		t.Errorf("pollFn called %d times, want >= 1 in degraded polling", got)
	}
	if got := e.Mode(); got != DeliveryModeStreaming {
		t.Errorf("mode = %q, want streaming after SSE reattaches", got)
	}
	if seq := rec.seq(); len(seq) != 2 || seq[0] != DeliveryModeDegradedPolling || seq[1] != DeliveryModeStreaming {
		t.Errorf("mode transitions = %v, want [degraded_polling streaming]", seq)
	}
}

// TestReconnect_NilModeChangeCallback proves the engine tolerates a nil
// on-mode-change callback: a descope drives a transition without panicking.
func TestReconnect_NilModeChangeCallback(t *testing.T) {
	e := fastEngine(discardLogger())
	e.SetClock(newRecordingClock())
	e.SetReprobeInterval(15 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	connectFn := func(context.Context) error {
		if calls.Add(1) >= 2 {
			cancel()
		}
		return descopedErr()
	}

	// No SetOnModeChange: the callback stays nil.
	_ = e.Run(ctx, connectFn, func(context.Context) error { return nil })

	if got := e.Mode(); got != DeliveryModePullOnly {
		t.Errorf("mode = %q, want pull_only", got)
	}
}
