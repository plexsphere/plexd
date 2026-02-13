package actions

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

type handlerMockReporter struct {
	mu      sync.Mutex
	acks    []api.ExecutionAck
	results []api.ExecutionResult
}

func (m *handlerMockReporter) AckExecution(_ context.Context, _, _ string, ack api.ExecutionAck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acks = append(m.acks, ack)
	return nil
}

func (m *handlerMockReporter) ReportResult(_ context.Context, _, _ string, result api.ExecutionResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, result)
	return nil
}

type handlerMockVerifier struct {
	ok  bool
	err error
}

func (m *handlerMockVerifier) VerifyHook(_ context.Context, _, _, _ string) (bool, error) {
	return m.ok, m.err
}

func makeEnvelope(t *testing.T, req api.ActionRequest) api.SignedEnvelope {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return api.SignedEnvelope{
		EventType: api.EventActionRequest,
		EventID:   "evt-" + req.ExecutionID,
		Payload:   data,
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func handlerWaitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("handlerWaitFor: timed out")
}

func TestHandleActionRequest_BuiltinAction(t *testing.T) {
	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: true, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())
	exec.RegisterBuiltin("test_action", "test", nil, func(ctx context.Context, params map[string]string) (string, string, int, error) {
		return "ok", "", 0, nil
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-001", Action: "test_action", Timeout: "5m"}
	env := makeEnvelope(t, req)

	err := handler(context.Background(), env)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Wait for async execution to complete.
	handlerWaitFor(t, 5*time.Second, func() bool {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return len(reporter.results) > 0
	})

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	// Verify accepted ack.
	if len(reporter.acks) == 0 {
		t.Fatal("no acks received")
	}
	if reporter.acks[0].Status != "accepted" {
		t.Errorf("ack status = %q, want accepted", reporter.acks[0].Status)
	}
	// Verify result.
	if reporter.results[0].Status != "success" {
		t.Errorf("result status = %q, want success", reporter.results[0].Status)
	}
}

func TestHandleActionRequest_UnknownAction(t *testing.T) {
	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: true, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-002", Action: "nonexistent_action", Timeout: "5m"}
	env := makeEnvelope(t, req)

	err := handler(context.Background(), env)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Wait for ack with rejected status.
	handlerWaitFor(t, 5*time.Second, func() bool {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return len(reporter.acks) > 0
	})

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.acks[0].Status != "rejected" {
		t.Errorf("ack status = %q, want rejected", reporter.acks[0].Status)
	}
	if reporter.acks[0].Reason != "unknown_action" {
		t.Errorf("ack reason = %q, want unknown_action", reporter.acks[0].Reason)
	}
}

func TestHandleActionRequest_MalformedPayload(t *testing.T) {
	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: true, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	env := api.SignedEnvelope{
		EventType: api.EventActionRequest,
		EventID:   "evt-bad",
		Payload:   json.RawMessage(`{invalid json`),
	}

	err := handler(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}
}

func TestHandleActionRequest_HookAction(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "my-hook")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hook-output\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: true, HooksDir: dir, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "my-hook", Source: "local", Checksum: "abc123"},
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-003", Action: "my-hook", Timeout: "5m", Checksum: "abc123"}
	env := makeEnvelope(t, req)

	err := handler(context.Background(), env)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Wait for result.
	handlerWaitFor(t, 5*time.Second, func() bool {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return len(reporter.results) > 0
	})

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.acks) == 0 {
		t.Fatal("no acks received")
	}
	if reporter.acks[0].Status != "accepted" {
		t.Errorf("ack status = %q, want accepted", reporter.acks[0].Status)
	}
	if reporter.results[0].Status != "success" {
		t.Errorf("result status = %q, want success", reporter.results[0].Status)
	}
}

func TestHandleActionRequest_HookIntegrityFailure(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "my-hook")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hook-output\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: true, HooksDir: dir, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: false}, discardLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "my-hook", Source: "local", Checksum: "abc123"},
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-004", Action: "my-hook", Timeout: "5m", Checksum: "abc123"}
	env := makeEnvelope(t, req)

	err := handler(context.Background(), env)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// The executor accepts the hook (it's in the hooks list), then integrity
	// verification fails during runHook, producing an error result.
	handlerWaitFor(t, 5*time.Second, func() bool {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return len(reporter.results) > 0
	})

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.acks) == 0 {
		t.Fatal("no acks received")
	}
	if reporter.acks[0].Status != "accepted" {
		t.Errorf("ack status = %q, want accepted", reporter.acks[0].Status)
	}
	if reporter.results[0].Status != "error" {
		t.Errorf("result status = %q, want error", reporter.results[0].Status)
	}
}

func TestHandleActionRequest_HookNotFound(t *testing.T) {
	dir := t.TempDir()
	// Do NOT create the script on disk.

	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: true, HooksDir: dir, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "missing-hook", Source: "local", Checksum: "abc123"},
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-005", Action: "missing-hook", Timeout: "5m", Checksum: "abc123"}
	env := makeEnvelope(t, req)

	err := handler(context.Background(), env)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// The executor accepts the hook (it's in the hooks list), then runHook
	// fails because the file doesn't exist on disk, producing an error result.
	handlerWaitFor(t, 5*time.Second, func() bool {
		reporter.mu.Lock()
		defer reporter.mu.Unlock()
		return len(reporter.results) > 0
	})

	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.acks) == 0 {
		t.Fatal("no acks received")
	}
	if reporter.acks[0].Status != "accepted" {
		t.Errorf("ack status = %q, want accepted", reporter.acks[0].Status)
	}
	if reporter.results[0].Status != "error" {
		t.Errorf("result status = %q, want error", reporter.results[0].Status)
	}
}

func TestHandleActionRequest_Disabled(t *testing.T) {
	reporter := &handlerMockReporter{}
	cfg := Config{Enabled: false, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-006", Action: "test_action", Timeout: "5m"}
	env := makeEnvelope(t, req)

	err := handler(context.Background(), env)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Ack should be immediate (synchronous in handler).
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.acks) == 0 {
		t.Fatal("no acks received")
	}
	if reporter.acks[0].Status != "rejected" {
		t.Errorf("ack status = %q, want rejected", reporter.acks[0].Status)
	}
	if reporter.acks[0].Reason != "actions_disabled" {
		t.Errorf("ack reason = %q, want actions_disabled", reporter.acks[0].Reason)
	}
}
