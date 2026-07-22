package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeEnvelopeSSE builds an SSE text block from the given event type and ID.
func makeEnvelopeSSE(eventType, eventID string) string {
	env := Envelope{
		Type:      eventType,
		ID:        eventID,
		IssuedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Payload:   json.RawMessage(`{}`),
		Signature: "sig",
	}
	data, _ := json.Marshal(env)
	return fmt.Sprintf("event: %s\ndata: %s\nid: %s\n\n", eventType, data, eventID)
}

// ---------------------------------------------------------------------------
// TestManager_StartAndDispatch — SSE stream starts and events reach handlers
// ---------------------------------------------------------------------------

func TestManager_StartAndDispatch(t *testing.T) {
	sseData := makeEnvelopeSSE("node_state_updated", "evt-1") + makeEnvelopeSSE("peer_removed", "evt-2")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, sseData)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{BaseURL: srv.URL}
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")

	mgr := NewSSEManager(client, nil, logger)

	var added atomic.Int64
	var removed atomic.Int64

	mgr.RegisterHandler("node_state_updated", func(_ context.Context, env Envelope) error {
		added.Add(1)
		return nil
	})
	mgr.RegisterHandler("peer_removed", func(_ context.Context, env Envelope) error {
		removed.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Start(ctx, "node-1")
	}()

	// The SSE stream will end when the server finishes sending events.
	// The reconnect engine will try to reconnect but we'll cancel to stop.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s")
	}

	if added.Load() < 1 {
		t.Errorf("node_state_updated handler called %d times, want >= 1", added.Load())
	}
	if removed.Load() < 1 {
		t.Errorf("peer_removed handler called %d times, want >= 1", removed.Load())
	}
}

// ---------------------------------------------------------------------------
// TestManager_ReconnectWithLastEventID — reconnection sends Last-Event-ID
// ---------------------------------------------------------------------------

func TestManager_ReconnectWithLastEventID(t *testing.T) {
	var mu sync.Mutex
	var requestCount int
	var lastEventIDs []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		n := requestCount
		lastEventIDs = append(lastEventIDs, r.Header.Get("Last-Event-ID"))
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)

		if n == 1 {
			// First connection: send event then close
			fmt.Fprint(w, makeEnvelopeSSE("node_state_updated", "evt-100"))
		} else if n == 2 {
			// Second connection: send one more event then close
			fmt.Fprint(w, makeEnvelopeSSE("node_state_updated", "evt-101"))
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{BaseURL: srv.URL}
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")

	mgr := NewSSEManager(client, nil, logger)

	// Use fast reconnect intervals
	mgr.SetReconnectIntervals(1*time.Millisecond, 10*time.Millisecond)

	var dispatched atomic.Int64
	mgr.RegisterHandler("node_state_updated", func(_ context.Context, env Envelope) error {
		dispatched.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Start(ctx, "node-1")
	}()

	// Wait for at least 2 connections to happen
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := requestCount
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for 2 connections")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()

	if len(lastEventIDs) < 2 {
		t.Fatalf("expected at least 2 requests, got %d", len(lastEventIDs))
	}

	// First request should have no Last-Event-ID
	if lastEventIDs[0] != "" {
		t.Errorf("first request Last-Event-ID = %q, want empty", lastEventIDs[0])
	}

	// Second request should have "evt-100" from the first connection
	if lastEventIDs[1] != "evt-100" {
		t.Errorf("second request Last-Event-ID = %q, want %q", lastEventIDs[1], "evt-100")
	}
}

// ---------------------------------------------------------------------------
// TestManager_PollingFallback — enters polling after prolonged SSE failure
// ---------------------------------------------------------------------------

func TestManager_PollingFallback(t *testing.T) {
	// Server always returns 500 for SSE connections
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"internal server error"}`)
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{BaseURL: srv.URL}
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")

	mgr := NewSSEManager(client, nil, logger)

	// Use very fast intervals so polling kicks in quickly
	mgr.SetReconnectIntervals(1*time.Millisecond, 10*time.Millisecond)
	mgr.SetPollingFallback(20*time.Millisecond, 5*time.Millisecond)

	var pollCount atomic.Int64
	mgr.SetPollFunc(func(ctx context.Context) error {
		pollCount.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Start(ctx, "node-1")
	}()

	// Wait for polling to kick in
	deadline := time.After(5 * time.Second)
	for {
		if pollCount.Load() >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for polling fallback")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	<-done

	if pollCount.Load() < 1 {
		t.Errorf("pollFn called %d times, want >= 1", pollCount.Load())
	}
}

// ---------------------------------------------------------------------------
// TestManager_Shutdown — graceful shutdown stops the manager
// ---------------------------------------------------------------------------

func TestManager_Shutdown(t *testing.T) {
	// Server holds connection open
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{BaseURL: srv.URL}
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")

	mgr := NewSSEManager(client, nil, logger)

	ctx := context.Background()
	done := make(chan error, 1)
	go func() {
		done <- mgr.Start(ctx, "node-1")
	}()

	// Let connection establish
	time.Sleep(100 * time.Millisecond)

	// Shutdown should cause Start to return
	mgr.Shutdown()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s after Shutdown")
	}
}

// ---------------------------------------------------------------------------
// TestManager_RegisterHandlerBeforeStart — handlers registered before Start
// ---------------------------------------------------------------------------

func TestManager_RegisterHandlerBeforeStart(t *testing.T) {
	sseData := makeEnvelopeSSE("policy_updated", "evt-50")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, sseData)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{BaseURL: srv.URL}
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")

	mgr := NewSSEManager(client, nil, logger)

	var called atomic.Int64
	// Register BEFORE Start
	mgr.RegisterHandler("policy_updated", func(_ context.Context, env Envelope) error {
		if env.ID != "evt-50" {
			t.Errorf("EventID = %q, want %q", env.ID, "evt-50")
		}
		called.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- mgr.Start(ctx, "node-1")
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	if called.Load() < 1 {
		t.Errorf("handler called %d times, want >= 1", called.Load())
	}
}

// ---------------------------------------------------------------------------
// TestManager_ModeDelegation — Mode and SetOnModeChange delegate to the engine
// ---------------------------------------------------------------------------

func TestManager_ModeDelegation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{BaseURL: "http://127.0.0.1:1"}
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}

	mgr := NewSSEManager(client, nil, logger)

	if got := mgr.Mode(); got != DeliveryModeStreaming {
		t.Errorf("fresh manager Mode() = %q, want streaming", got)
	}

	var got atomic.Value // DeliveryMode
	mgr.SetOnModeChange(func(m DeliveryMode) { got.Store(m) })

	// Drive a transition through the underlying engine to prove the callback the
	// manager registered is the one the engine fires.
	mgr.reconnect.setMode(DeliveryModePullOnly)

	if now := mgr.Mode(); now != DeliveryModePullOnly {
		t.Errorf("Mode() after transition = %q, want pull_only", now)
	}
	if v, ok := got.Load().(DeliveryMode); !ok || v != DeliveryModePullOnly {
		t.Errorf("SetOnModeChange callback got %v, want pull_only", got.Load())
	}
}

// ---------------------------------------------------------------------------
// Reconcile trigger, idle timeout, and on-connected hook wiring
// ---------------------------------------------------------------------------

// fakeReconcileTrigger counts TriggerReconcile calls.
type fakeReconcileTrigger struct {
	count atomic.Int64
}

func (f *fakeReconcileTrigger) TriggerReconcile() { f.count.Add(1) }

func newManagerTestClient(t *testing.T, baseURL string) *ControlPlane {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := NewControlPlane(Config{BaseURL: baseURL}, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")
	return client
}

// TestManager_ReconcilePullTrigger proves exactly one reconcile pull fires per
// successful connect: two connects yield exactly two TriggerReconcile calls.
func TestManager_ReconcilePullTrigger(t *testing.T) {
	var mu sync.Mutex
	var requestCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		n := requestCount
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, makeEnvelopeSSE("node_state_updated", "evt-1"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if n >= 2 {
			// Hold the second connection open so no third connect starts.
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewSSEManager(newManagerTestClient(t, srv.URL), nil, logger)
	mgr.SetReconnectIntervals(1*time.Millisecond, 10*time.Millisecond)

	trigger := &fakeReconcileTrigger{}
	mgr.SetReconcileTrigger(trigger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx, "node-1") }()

	// Wait for exactly two successful connects (two trigger calls).
	deadline := time.After(5 * time.Second)
	for trigger.count.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for 2 reconcile triggers")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done

	if got := trigger.count.Load(); got != 2 {
		t.Errorf("TriggerReconcile called %d times, want 2", got)
	}
}

// TestManager_NilReconcileTrigger proves Start tolerates an unset trigger: the
// on-connected hook fires without panicking.
func TestManager_NilReconcileTrigger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, makeEnvelopeSSE("node_state_updated", "evt-1"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewSSEManager(newManagerTestClient(t, srv.URL), nil, logger)
	mgr.SetReconnectIntervals(1*time.Millisecond, 10*time.Millisecond)
	// No SetReconcileTrigger — the trigger stays nil.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx, "node-1") }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s")
	}
}

// TestManager_SetIdleTimeoutPropagates proves the configured idle timeout
// reaches the stream (issue #27 item 1): a server that sends headers then falls
// silent triggers a reconnect within a short deadline, which the hardcoded 90s
// could never do.
func TestManager_SetIdleTimeoutPropagates(t *testing.T) {
	var mu sync.Mutex
	var requestCount int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Headers then silence — the client's idle timeout must fire.
		<-r.Context().Done()
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewSSEManager(newManagerTestClient(t, srv.URL), nil, logger)
	mgr.SetReconnectIntervals(1*time.Millisecond, 10*time.Millisecond)
	mgr.SetIdleTimeout(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx, "node-1") }()

	// A 50ms idle timeout must drive a second connect well under the old
	// hardcoded 90s.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := requestCount
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no second connect within 3s — idle timeout not propagated")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestManager_IdleTimeoutZeroFallsBackToDefault proves an unset idle timeout is
// a zero that Start substitutes with DefaultSSEIdleTimeout.
func TestManager_IdleTimeoutZeroFallsBackToDefault(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewSSEManager(newManagerTestClient(t, "http://127.0.0.1:1"), nil, logger)

	if mgr.idleTimeout != 0 {
		t.Errorf("fresh manager idleTimeout = %v, want 0 (Start substitutes the default)", mgr.idleTimeout)
	}
	if DefaultSSEIdleTimeout != 90*time.Second {
		t.Errorf("DefaultSSEIdleTimeout = %v, want 90s", DefaultSSEIdleTimeout)
	}
}

// TestManager_ConnectHookFlipsModeToStreaming proves the wired on-connected hook
// calls notifyConnected: an engine parked in pull-only flips back to streaming
// on the first real HTTP 200.
func TestManager_ConnectHookFlipsModeToStreaming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, makeEnvelopeSSE("node_state_updated", "evt-1"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewSSEManager(newManagerTestClient(t, srv.URL), nil, logger)
	mgr.SetReconnectIntervals(1*time.Millisecond, 10*time.Millisecond)

	// Park the engine in pull-only; the on-connected hook must flip it back.
	mgr.reconnect.setMode(DeliveryModePullOnly)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx, "node-1") }()

	deadline := time.After(3 * time.Second)
	for mgr.Mode() != DeliveryModeStreaming {
		select {
		case <-deadline:
			t.Fatal("Mode did not flip to streaming after a successful connect")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}
