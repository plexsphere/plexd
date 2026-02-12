package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// mockFetcher is a test double for StateFetcher.
type mockFetcher struct {
	mu          sync.Mutex
	fetchCount  int
	fetchFunc   func(ctx context.Context, nodeID string) (*api.StateResponse, error)
	driftCount  int
	driftFunc   func(ctx context.Context, nodeID string, req api.DriftReport) error
	lastDrift   *api.DriftReport
}

func (m *mockFetcher) FetchState(ctx context.Context, nodeID string) (*api.StateResponse, error) {
	m.mu.Lock()
	m.fetchCount++
	fn := m.fetchFunc
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx, nodeID)
	}
	return &api.StateResponse{}, nil
}

func (m *mockFetcher) ReportDrift(ctx context.Context, nodeID string, req api.DriftReport) error {
	m.mu.Lock()
	m.driftCount++
	m.lastDrift = &req
	fn := m.driftFunc
	m.mu.Unlock()
	if fn != nil {
		return fn(ctx, nodeID, req)
	}
	return nil
}

func (m *mockFetcher) getFetchCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fetchCount
}

func (m *mockFetcher) getDriftCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.driftCount
}

func (m *mockFetcher) getLastDrift() *api.DriftReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastDrift
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestReconciler_FirstReconcileImmediate(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{
				Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
			}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 10 * time.Second}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// First fetch should happen within 100ms, not after 10s interval.
	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-done
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if fetcher.getFetchCount() < 1 {
		t.Errorf("FetchState called %d times, want >= 1", fetcher.getFetchCount())
	}
}

func TestReconciler_PeriodicFetch(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Wait enough time for ~3-5 cycles (initial + 2-4 periodic).
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	count := fetcher.getFetchCount()
	if count < 3 {
		t.Errorf("FetchState called %d times, want >= 3 (immediate + periodic)", count)
	}
}

func TestReconciler_HandlerInvokedOnDrift(t *testing.T) {
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
	}
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return desired, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())

	var handlerCalled atomic.Int64
	var gotDiff StateDiff
	var gotDesired *api.StateResponse
	var mu sync.Mutex

	r.RegisterHandler(func(_ context.Context, d *api.StateResponse, diff StateDiff) error {
		mu.Lock()
		gotDesired = d
		gotDiff = diff
		mu.Unlock()
		handlerCalled.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if handlerCalled.Load() < 1 {
		t.Fatalf("handler called %d times, want >= 1", handlerCalled.Load())
	}

	mu.Lock()
	defer mu.Unlock()

	if len(gotDiff.PeersToAdd) != 1 {
		t.Errorf("PeersToAdd = %d, want 1", len(gotDiff.PeersToAdd))
	}
	if gotDesired == nil || len(gotDesired.Peers) != 1 {
		t.Error("handler did not receive the correct desired state")
	}
}

func TestReconciler_MultipleHandlers(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{
				Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
			}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())

	var called1, called2 atomic.Int64

	// First handler returns error — should not prevent second handler.
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		called1.Add(1)
		return errors.New("handler1 error")
	})
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		called2.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if called1.Load() < 1 {
		t.Errorf("handler1 called %d times, want >= 1", called1.Load())
	}
	if called2.Load() < 1 {
		t.Errorf("handler2 called %d times, want >= 1 (should not be blocked by handler1 error)", called2.Load())
	}
}

func TestReconciler_HandlerPanicRecovered(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{
				Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
			}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())

	var panicHandlerCalls, safeHandlerCalls atomic.Int64

	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		panicHandlerCalls.Add(1)
		panic("test panic")
	})
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		safeHandlerCalls.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Run long enough for 2+ cycles to prove the loop continues after panic.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if panicHandlerCalls.Load() < 2 {
		t.Errorf("panicking handler called %d times, want >= 2 (loop should continue)", panicHandlerCalls.Load())
	}
	if safeHandlerCalls.Load() < 2 {
		t.Errorf("safe handler called %d times, want >= 2 (panic should not block other handlers)", safeHandlerCalls.Load())
	}
}

func TestReconciler_DriftReported(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{
				Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
			}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if fetcher.getDriftCount() < 1 {
		t.Fatalf("ReportDrift called %d times, want >= 1", fetcher.getDriftCount())
	}

	report := fetcher.getLastDrift()
	if report == nil {
		t.Fatal("no drift report received")
	}

	found := false
	for _, c := range report.Corrections {
		if c.Type == "peer_added" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected peer_added correction, got %v", report.Corrections)
	}
}

func TestReconciler_NoDriftNoReport(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// After first cycle (which adds everything from empty snapshot), subsequent
	// cycles with same state should produce empty diff → no drift report.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// First cycle reports drift (empty snapshot → full desired).
	// But since desired is also empty, no drift at all.
	if fetcher.getDriftCount() != 0 {
		t.Errorf("ReportDrift called %d times, want 0 (no drift)", fetcher.getDriftCount())
	}
}

func TestReconciler_DriftReportFailureIgnored(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{
				Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
			}, nil
		},
		driftFunc: func(_ context.Context, _ string, _ api.DriftReport) error {
			return errors.New("drift report failed")
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Run enough cycles to verify the loop continues despite ReportDrift errors.
	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-done
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if fetcher.getFetchCount() < 2 {
		t.Errorf("FetchState called %d times, want >= 2 (loop should continue despite drift error)", fetcher.getFetchCount())
	}
}

func TestReconciler_TriggerReconcile(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 10 * time.Second}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Wait for the initial immediate cycle.
	time.Sleep(50 * time.Millisecond)
	initialCount := fetcher.getFetchCount()

	// Trigger should cause an additional fetch without waiting for the 10s interval.
	r.TriggerReconcile()
	time.Sleep(50 * time.Millisecond)

	afterTrigger := fetcher.getFetchCount()
	cancel()
	<-done

	if afterTrigger <= initialCount {
		t.Errorf("FetchState after trigger = %d, before = %d; want increase", afterTrigger, initialCount)
	}
}

func TestReconciler_TriggerCoalesced(t *testing.T) {
	var fetchCh = make(chan struct{}, 10)
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			fetchCh <- struct{}{}
			return &api.StateResponse{}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 10 * time.Second}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Wait for the initial fetch.
	<-fetchCh

	// Send multiple triggers rapidly — they should be coalesced.
	for i := 0; i < 10; i++ {
		r.TriggerReconcile()
	}

	// Wait for triggered fetch(es).
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Should have: 1 initial + 1 coalesced trigger = 2, maybe 3 at most.
	count := fetcher.getFetchCount()
	if count > 4 {
		t.Errorf("FetchState called %d times after 10 rapid triggers, want <= 4 (coalescing)", count)
	}
}

func TestReconciler_SnapshotUpdatedOnSuccess(t *testing.T) {
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
	}
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return desired, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())

	var handlerCalls atomic.Int64
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, diff StateDiff) error {
		handlerCalls.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Let multiple cycles run.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// The handler should only be called once (first cycle when snapshot is empty).
	// On subsequent cycles, snapshot matches desired → empty diff → handler not called.
	calls := handlerCalls.Load()
	if calls != 1 {
		t.Errorf("handler called %d times, want 1 (snapshot should be updated after first cycle)", calls)
	}
}

func TestReconciler_SnapshotNotUpdatedOnHandlerError(t *testing.T) {
	desired := &api.StateResponse{
		Peers: []api.Peer{{ID: "p1", MeshIP: "10.0.0.1"}},
	}
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return desired, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())

	var handlerCalls atomic.Int64
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		handlerCalls.Add(1)
		return errors.New("handler error")
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Because the handler always errors, snapshot is never updated,
	// so every cycle detects the same drift and calls the handler again.
	calls := handlerCalls.Load()
	if calls < 3 {
		t.Errorf("handler called %d times, want >= 3 (drift should persist across cycles)", calls)
	}
}

func TestReconciler_ContextCancellation(t *testing.T) {
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	// Let the initial cycle complete, then cancel during interval wait.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after cancellation")
	}
}

func TestReconciler_ContextCancelDuringFetch(t *testing.T) {
	// Block FetchState until context is cancelled.
	fetcher := &mockFetcher{
		fetchFunc: func(ctx context.Context, _ string) (*api.StateResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	r := NewReconciler(fetcher, Config{Interval: time.Hour}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s after cancellation during FetchState")
	}
}

func TestReconciler_FetchStateErrorSkipsTick(t *testing.T) {
	var fetchCalls atomic.Int64
	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			fetchCalls.Add(1)
			return nil, errors.New("fetch error")
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())

	var handlerCalled atomic.Int64
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		handlerCalled.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	err := <-done
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned unexpected error (should not crash): %v", err)
	}

	// FetchState should have been called multiple times (retried each tick).
	if fetchCalls.Load() < 2 {
		t.Errorf("FetchState called %d times, want >= 2 (loop should continue)", fetchCalls.Load())
	}

	// Handler should never be called since FetchState always errors.
	if handlerCalled.Load() != 0 {
		t.Errorf("handler called %d times, want 0 (no drift to process on fetch error)", handlerCalled.Load())
	}
}

func TestReconciler_NoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	fetcher := &mockFetcher{
		fetchFunc: func(_ context.Context, _ string) (*api.StateResponse, error) {
			return &api.StateResponse{}, nil
		},
	}

	r := NewReconciler(fetcher, Config{Interval: 20 * time.Millisecond}, discardLogger())
	r.RegisterHandler(func(_ context.Context, _ *api.StateResponse, _ StateDiff) error {
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, "node-1")
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
}

func TestReconciler_RunRejectsEmptyNodeID(t *testing.T) {
	r := NewReconciler(&mockFetcher{}, Config{Interval: time.Second}, discardLogger())
	err := r.Run(context.Background(), "")
	if err == nil {
		t.Fatal("Run() = nil, want error for empty nodeID")
	}
}

func TestReconciler_RunRejectsNilClient(t *testing.T) {
	r := NewReconciler(nil, Config{Interval: time.Second}, discardLogger())
	err := r.Run(context.Background(), "node-1")
	if err == nil {
		t.Fatal("Run() = nil, want error for nil client")
	}
}
