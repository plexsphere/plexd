package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDispatcher_RoutesToHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	d := NewEventDispatcher(logger)

	var called bool
	var received SignedEnvelope

	d.Register("peer_added", func(_ context.Context, env SignedEnvelope) error {
		called = true
		received = env
		return nil
	})

	envelope := SignedEnvelope{
		EventType: "peer_added",
		EventID:   "evt_001",
	}

	d.Dispatch(context.Background(), envelope)

	if !called {
		t.Fatal("handler was not called")
	}
	if received.EventType != "peer_added" {
		t.Fatalf("expected event_type %q, got %q", "peer_added", received.EventType)
	}
	if received.EventID != "evt_001" {
		t.Fatalf("expected event_id %q, got %q", "evt_001", received.EventID)
	}
}

func TestDispatcher_MultipleHandlers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	d := NewEventDispatcher(logger)

	var order []int

	d.Register("policy_updated", func(_ context.Context, _ SignedEnvelope) error {
		order = append(order, 1)
		return errors.New("handler 1 failed")
	})
	d.Register("policy_updated", func(_ context.Context, _ SignedEnvelope) error {
		order = append(order, 2)
		return nil
	})

	envelope := SignedEnvelope{
		EventType: "policy_updated",
		EventID:   "evt_002",
	}

	d.Dispatch(context.Background(), envelope)

	if len(order) != 2 {
		t.Fatalf("expected 2 handlers called, got %d", len(order))
	}
	if order[0] != 1 || order[1] != 2 {
		t.Fatalf("expected call order [1, 2], got %v", order)
	}
}

func TestDispatcher_UnhandledEventLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := NewEventDispatcher(logger)

	envelope := SignedEnvelope{
		EventType: "unknown_event",
		EventID:   "evt_003",
	}

	d.Dispatch(context.Background(), envelope)

	output := buf.String()
	if output == "" {
		t.Fatal("expected debug log output for unhandled event, got empty")
	}
	if !bytes.Contains([]byte(output), []byte("no handler registered for event type")) {
		t.Fatalf("expected log message about no handler, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("unknown_event")) {
		t.Fatalf("expected event type in log, got: %s", output)
	}
}

func TestDispatcher_ErrorIsolation(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := NewEventDispatcher(logger)

	var firstCalled, secondCalled bool

	d.Register("peer_removed", func(_ context.Context, _ SignedEnvelope) error {
		firstCalled = true
		return errors.New("first handler error")
	})
	d.Register("peer_removed", func(_ context.Context, _ SignedEnvelope) error {
		secondCalled = true
		return nil
	})

	envelope := SignedEnvelope{
		EventType: "peer_removed",
		EventID:   "evt_004",
	}

	d.Dispatch(context.Background(), envelope)

	if !firstCalled {
		t.Fatal("first handler was not called")
	}
	if !secondCalled {
		t.Fatal("second handler was not called despite first handler error")
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("event handler failed")) {
		t.Fatalf("expected error log for failed handler, got: %s", output)
	}
}

func TestDispatcher_ConcurrentRegisterAndDispatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	d := NewEventDispatcher(logger)

	var wg sync.WaitGroup
	var callCount atomic.Int64

	// Pre-register a handler so dispatches have something to call.
	d.Register("concurrent_event", func(_ context.Context, _ SignedEnvelope) error {
		callCount.Add(1)
		return nil
	})

	envelope := SignedEnvelope{
		EventType: "concurrent_event",
		EventID:   "evt_005",
	}

	// Concurrently register new handlers and dispatch events.
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.Register("concurrent_event", func(_ context.Context, _ SignedEnvelope) error {
				callCount.Add(1)
				return nil
			})
		}()
		go func() {
			defer wg.Done()
			d.Dispatch(context.Background(), envelope)
		}()
	}

	wg.Wait()

	if callCount.Load() == 0 {
		t.Fatal("expected at least some handlers to be called")
	}
}
