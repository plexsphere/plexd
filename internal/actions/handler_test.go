package actions

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

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
	reporter := &mockReporter{}
	cfg := Config{Enabled: true, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())
	exec.RegisterBuiltin("test_action", "test", nil, func(ctx context.Context, params map[string]string) (string, string, int, error) {
		return "ok", "", 0, nil
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-001", Action: "test_action", Timeout: "5m"}
	env := makeEnvelope(t, req)

	if err := handler(context.Background(), env); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Wait for async execution to complete.
	handlerWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

func TestHandleActionRequest_UnknownAction(t *testing.T) {
	reporter := &mockReporter{}
	cfg := Config{Enabled: true, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-002", Action: "nonexistent_action", Timeout: "5m"}
	env := makeEnvelope(t, req)

	if err := handler(context.Background(), env); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	handlerWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{api.ExecutionStatusAck, api.ExecutionStatusFailed})
	if cbs[1].Error != "unknown_action" {
		t.Errorf("failed error = %q, want unknown_action", cbs[1].Error)
	}
}

func TestHandleActionRequest_MalformedPayload(t *testing.T) {
	reporter := &mockReporter{}
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

	reporter := &mockReporter{}
	cfg := Config{Enabled: true, HooksDir: dir, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "my-hook", Source: "local", Checksum: "abc123"},
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-003", Action: "my-hook", Timeout: "5m", Checksum: "abc123"}
	env := makeEnvelope(t, req)

	if err := handler(context.Background(), env); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	handlerWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

func TestHandleActionRequest_HookIntegrityFailure(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "my-hook")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hook-output\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	cfg := Config{Enabled: true, HooksDir: dir, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: false}, discardLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "my-hook", Source: "local", Checksum: "abc123"},
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-004", Action: "my-hook", Timeout: "5m", Checksum: "abc123"}
	env := makeEnvelope(t, req)

	if err := handler(context.Background(), env); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// The executor acks and starts the hook, then integrity verification fails
	// during runHook, producing a failed terminal callback.
	handlerWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
}

func TestHandleActionRequest_HookNotFound(t *testing.T) {
	dir := t.TempDir()
	// Do NOT create the script on disk.

	reporter := &mockReporter{}
	cfg := Config{Enabled: true, HooksDir: dir, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "missing-hook", Source: "local", Checksum: "abc123"},
	})

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-005", Action: "missing-hook", Timeout: "5m", Checksum: "abc123"}
	env := makeEnvelope(t, req)

	if err := handler(context.Background(), env); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// The executor acks and starts the hook, then runHook fails because the file
	// does not exist on disk, producing a failed terminal callback.
	handlerWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
}

func TestHandleActionRequest_Disabled(t *testing.T) {
	reporter := &mockReporter{}
	cfg := Config{Enabled: false, MaxConcurrent: 5, MaxActionTimeout: 10 * time.Minute, MaxOutputBytes: 1 << 20}
	exec := NewExecutor(cfg, reporter, &handlerMockVerifier{ok: true}, discardLogger())

	handler := HandleActionRequest(exec, "node-1", discardLogger())
	req := api.ActionRequest{ExecutionID: "exec-006", Action: "test_action", Timeout: "5m"}
	env := makeEnvelope(t, req)

	if err := handler(context.Background(), env); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// The disabled rejection is synchronous: ack + failed(actions_disabled).
	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{api.ExecutionStatusAck, api.ExecutionStatusFailed})
	if cbs[1].Error != "actions_disabled" {
		t.Errorf("failed error = %q, want actions_disabled", cbs[1].Error)
	}
}
