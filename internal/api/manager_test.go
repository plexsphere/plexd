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
	env := SignedEnvelope{
		EventType: eventType,
		EventID:   eventID,
		IssuedAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Nonce:     "n",
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
	sseData := makeEnvelopeSSE("peer_added", "evt-1") + makeEnvelopeSSE("peer_removed", "evt-2")

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

	mgr.RegisterHandler("peer_added", func(_ context.Context, env SignedEnvelope) error {
		added.Add(1)
		return nil
	})
	mgr.RegisterHandler("peer_removed", func(_ context.Context, env SignedEnvelope) error {
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
		t.Errorf("peer_added handler called %d times, want >= 1", added.Load())
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
			fmt.Fprint(w, makeEnvelopeSSE("peer_added", "evt-100"))
		} else if n == 2 {
			// Second connection: send one more event then close
			fmt.Fprint(w, makeEnvelopeSSE("peer_added", "evt-101"))
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
	mgr.RegisterHandler("peer_added", func(_ context.Context, env SignedEnvelope) error {
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
	mgr.RegisterHandler("policy_updated", func(_ context.Context, env SignedEnvelope) error {
		if env.EventID != "evt-50" {
			t.Errorf("EventID = %q, want %q", env.EventID, "evt-50")
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
