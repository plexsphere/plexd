package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockHeartbeatClient struct {
	mu        sync.Mutex
	calls     int
	requests  []api.HeartbeatRequest
	responses []*api.HeartbeatResponse
	errors    []error
}

func (m *mockHeartbeatClient) Heartbeat(_ context.Context, _ string, req api.HeartbeatRequest) (*api.HeartbeatResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := m.calls
	m.calls++
	m.requests = append(m.requests, req)

	var err error
	if idx < len(m.errors) && m.errors[idx] != nil {
		err = m.errors[idx]
	}
	if err != nil {
		return nil, err
	}

	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return &api.HeartbeatResponse{}, nil
}

func (m *mockHeartbeatClient) getRequests() []api.HeartbeatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.HeartbeatRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *mockHeartbeatClient) getCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type mockReconcileTrigger struct {
	mu    sync.Mutex
	calls int
}

func (m *mockReconcileTrigger) TriggerReconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
}

func (m *mockReconcileTrigger) getCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// ---------------------------------------------------------------------------
// Config tests
// ---------------------------------------------------------------------------

func TestHeartbeatConfig_ApplyDefaults(t *testing.T) {
	cfg := HeartbeatConfig{NodeID: "node-1"}
	cfg.ApplyDefaults()

	if cfg.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, 30*time.Second)
	}

	// Existing value is preserved.
	cfg2 := HeartbeatConfig{NodeID: "node-1", Interval: 5 * time.Second}
	cfg2.ApplyDefaults()
	if cfg2.Interval != 5*time.Second {
		t.Errorf("Interval = %v, want %v", cfg2.Interval, 5*time.Second)
	}
}

func TestHeartbeatConfig_Validate(t *testing.T) {
	cfg := HeartbeatConfig{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty NodeID")
	}
	if err.Error() != "agent: heartbeat config: NodeID is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "agent: heartbeat config: NodeID is required")
	}

	cfg.NodeID = "node-1"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Service tests
// ---------------------------------------------------------------------------

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHeartbeatService_SendsAtInterval(t *testing.T) {
	client := &mockHeartbeatClient{}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: 50 * time.Millisecond}
	svc := NewHeartbeatService(cfg, client, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	calls := client.getCalls()
	// Expect immediate heartbeat + at least 2 ticker heartbeats.
	if calls < 3 {
		t.Errorf("heartbeat calls = %d, want >= 3", calls)
	}
}

func TestHeartbeatService_ReconcileTrigger(t *testing.T) {
	client := &mockHeartbeatClient{
		responses: []*api.HeartbeatResponse{
			{Reconcile: true},
		},
	}

	rt := &mockReconcileTrigger{}
	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetReconcileTrigger(rt)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if got := rt.getCalls(); got != 1 {
		t.Errorf("TriggerReconcile calls = %d, want 1", got)
	}
}

func TestHeartbeatService_RotateKeys(t *testing.T) {
	client := &mockHeartbeatClient{
		responses: []*api.HeartbeatResponse{
			{RotateKeys: true},
		},
	}

	var mu sync.Mutex
	rotated := 0

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetOnRotateKeys(func() {
		mu.Lock()
		rotated++
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	mu.Lock()
	got := rotated
	mu.Unlock()

	if got != 1 {
		t.Errorf("onRotateKeys calls = %d, want 1", got)
	}
}

func TestHeartbeatService_AuthFailure(t *testing.T) {
	client := &mockHeartbeatClient{
		errors: []error{
			&api.APIError{StatusCode: 401, Message: "token expired"},
		},
	}

	var mu sync.Mutex
	authFails := 0

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetOnAuthFailure(func() {
		mu.Lock()
		authFails++
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	mu.Lock()
	got := authFails
	mu.Unlock()

	if got != 1 {
		t.Errorf("onAuthFailure calls = %d, want 1", got)
	}
}

func TestHeartbeatService_TransientError(t *testing.T) {
	client := &mockHeartbeatClient{
		errors: []error{
			&api.APIError{StatusCode: 500, Message: "internal server error"},
			nil,
			nil,
		},
	}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: 50 * time.Millisecond}
	svc := NewHeartbeatService(cfg, client, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	calls := client.getCalls()
	// Heartbeats must continue past the first error.
	if calls < 3 {
		t.Errorf("heartbeat calls = %d, want >= 3 (should survive transient error)", calls)
	}
}

func TestHeartbeatService_ContextCancellation(t *testing.T) {
	client := &mockHeartbeatClient{}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := svc.Run(ctx); err != nil {
			t.Errorf("Run() = %v, want nil", err)
		}
	}()

	// Give the immediate heartbeat time to fire.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK: Run exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	if calls := client.getCalls(); calls != 1 {
		t.Errorf("heartbeat calls = %d, want 1", calls)
	}
}

func TestHeartbeatService_BuildRequest(t *testing.T) {
	client := &mockHeartbeatClient{}

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, testLogger())
	svc.SetBuildRequest(func() api.HeartbeatRequest {
		return api.HeartbeatRequest{
			BinaryChecksum: "abc123",
			BinaryVersion:  "1.2.3",
			NATSummary:     map[string]any{},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	reqs := client.getRequests()
	if len(reqs) == 0 {
		t.Fatal("expected at least one heartbeat request")
	}
	if reqs[0].BinaryChecksum != "abc123" {
		t.Errorf("request BinaryChecksum = %q, want %q", reqs[0].BinaryChecksum, "abc123")
	}
	if reqs[0].BinaryVersion != "1.2.3" {
		t.Errorf("request BinaryVersion = %q, want %q", reqs[0].BinaryVersion, "1.2.3")
	}
}

// TestHeartbeatService_ClockSkew verifies that a clock_skew rejection logs an
// operator-facing error naming clock synchronization and does not trigger an
// immediate retry — the next attempt is the next interval tick.
func TestHeartbeatService_ClockSkew(t *testing.T) {
	client := &mockHeartbeatClient{
		errors: []error{
			&api.APIError{StatusCode: 400, Code: "clock_skew", Message: "client_now outside tolerance"},
		},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := HeartbeatConfig{NodeID: "node-1", Interval: time.Hour}
	svc := NewHeartbeatService(cfg, client, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	// Exactly one send within the window — no immediate retry on skew.
	if calls := client.getCalls(); calls != 1 {
		t.Errorf("heartbeat calls = %d, want 1 (no immediate retry on clock skew)", calls)
	}

	logged := buf.String()
	if !strings.Contains(logged, "level=ERROR") {
		t.Errorf("expected ERROR-level log, got: %s", logged)
	}
	if !strings.Contains(logged, "clock skew") || !strings.Contains(logged, "synchronize") {
		t.Errorf("expected log naming clock skew and synchronization, got: %s", logged)
	}
}
