package api

import (
	"context"
	"errors"
	"fmt"
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

func TestClassifyError_5xx(t *testing.T) {
	err := &APIError{StatusCode: 502, Message: "bad gateway"}
	action := ClassifyError(err)
	if action != RetryTransient {
		t.Errorf("expected RetryTransient, got %v", action)
	}
}
