package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

type mockReporter struct {
	mu      sync.Mutex
	acks    []api.ExecutionAck
	results []api.ExecutionResult
	ackErr  error
	resErr  error
}

func (m *mockReporter) AckExecution(_ context.Context, _, _ string, ack api.ExecutionAck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acks = append(m.acks, ack)
	return m.ackErr
}

func (m *mockReporter) ReportResult(_ context.Context, _, _ string, result api.ExecutionResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, result)
	return m.resErr
}

func (m *mockReporter) getAcks() []api.ExecutionAck {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]api.ExecutionAck, len(m.acks))
	copy(cp, m.acks)
	return cp
}

func (m *mockReporter) getResults() []api.ExecutionResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]api.ExecutionResult, len(m.results))
	copy(cp, m.results)
	return cp
}

type mockVerifier struct {
	mu    sync.Mutex
	ok    bool
	err   error
	calls int
}

func (m *mockVerifier) VerifyHook(_ context.Context, _, _, _ string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.ok, m.err
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("waitFor: timed out")
}

func newTestExecutor(cfg Config, reporter *mockReporter, verifier *mockVerifier) *Executor {
	cfg.ApplyDefaults()
	return NewExecutor(cfg, reporter, verifier, testLogger())
}

func TestExecutor_RunBuiltin_Success(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, params map[string]string) (string, string, int, error) {
		return "hello from builtin", "", 0, nil
	})

	req := api.ActionRequest{
		ExecutionID: "exec-001",
		Action:      "test.echo",
		Timeout:     "10s",
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	acks := reporter.getAcks()
	if len(acks) != 1 {
		t.Fatalf("expected 1 ack, got %d", len(acks))
	}
	if acks[0].Status != "accepted" {
		t.Errorf("ack status = %q, want %q", acks[0].Status, "accepted")
	}

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "success" {
		t.Errorf("result status = %q, want %q", results[0].Status, "success")
	}
	if results[0].Stdout != "hello from builtin" {
		t.Errorf("stdout = %q, want %q", results[0].Stdout, "hello from builtin")
	}
	if results[0].ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", results[0].ExitCode)
	}
}

func TestExecutor_RunHook_Success(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "greet")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hello from hook\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "greet", Checksum: "abc123"},
	})

	req := api.ActionRequest{
		ExecutionID: "exec-002",
		Action:      "greet",
		Timeout:     "10s",
		Checksum:    "abc123",
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	acks := reporter.getAcks()
	if len(acks) != 1 {
		t.Fatalf("expected 1 ack, got %d", len(acks))
	}
	if acks[0].Status != "accepted" {
		t.Errorf("ack status = %q, want %q", acks[0].Status, "accepted")
	}

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "success" {
		t.Errorf("result status = %q, want %q", results[0].Status, "success")
	}
	if got := strings.TrimSpace(results[0].Stdout); got != "hello from hook" {
		t.Errorf("stdout = %q, want %q", got, "hello from hook")
	}
	if results[0].ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", results[0].ExitCode)
	}
}

func TestExecutor_RunHook_Timeout(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "slow")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 999\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "slow", Checksum: "abc123"},
	})

	req := api.ActionRequest{
		ExecutionID: "exec-003",
		Action:      "slow",
		Timeout:     "100ms",
		Checksum:    "abc123",
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "timeout" {
		t.Errorf("result status = %q, want %q", results[0].Status, "timeout")
	}
}

func TestExecutor_RunHook_NonZeroExit(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fail")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "fail", Checksum: "abc123"},
	})

	req := api.ActionRequest{
		ExecutionID: "exec-004",
		Action:      "fail",
		Timeout:     "10s",
		Checksum:    "abc123",
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "failed" {
		t.Errorf("result status = %q, want %q", results[0].Status, "failed")
	}
	if results[0].ExitCode != 42 {
		t.Errorf("exit_code = %d, want 42", results[0].ExitCode)
	}
}

func TestExecutor_RunHook_OutputTruncation(t *testing.T) {
	dir := t.TempDir()
	// Script outputs 200 bytes
	script := filepath.Join(dir, "big-output")
	content := "#!/bin/sh\nprintf '%0.s_' $(seq 1 200)\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		HooksDir:       dir,
		MaxOutputBytes: 64,
		MaxConcurrent:  5,
		MaxActionTimeout: 10 * time.Minute,
	}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "big-output", Checksum: "abc123"},
	})

	req := api.ActionRequest{
		ExecutionID: "exec-005",
		Action:      "big-output",
		Timeout:     "10s",
		Checksum:    "abc123",
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// Output should be at most 64 bytes of data + truncation suffix.
	maxExpected := 64 + len("\n...[truncated]")
	if len(results[0].Stdout) > maxExpected {
		t.Errorf("stdout length = %d, want <= %d", len(results[0].Stdout), maxExpected)
	}
	if !strings.Contains(results[0].Stdout, "...[truncated]") {
		t.Error("truncated output should contain truncation indicator")
	}
}

func TestExecutor_ConcurrencyLimit(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:   1,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:  DefaultMaxOutputBytes,
	}, reporter, verifier)

	started := make(chan struct{})
	block := make(chan struct{})

	exec.RegisterBuiltin("slow", "Slow action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		close(started)
		select {
		case <-block:
		case <-ctx.Done():
		}
		return "done", "", 0, nil
	})

	// Start first action
	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-slow-1",
		Action:      "slow",
		Timeout:     "30s",
	})

	// Wait for it to start running
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first action did not start")
	}

	// Try second action — should be rejected
	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-slow-2",
		Action:      "slow",
		Timeout:     "30s",
	})

	// Wait for second ack
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getAcks()) >= 2
	})

	acks := reporter.getAcks()
	// First ack should be accepted
	if acks[0].Status != "accepted" {
		t.Errorf("ack[0] status = %q, want %q", acks[0].Status, "accepted")
	}
	// Second ack should be rejected
	if acks[1].Status != "rejected" {
		t.Errorf("ack[1] status = %q, want %q", acks[1].Status, "rejected")
	}
	if acks[1].Reason != "max_concurrent_reached" {
		t.Errorf("ack[1] reason = %q, want %q", acks[1].Reason, "max_concurrent_reached")
	}

	close(block)
}

func TestExecutor_DuplicateExecutionID(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:   5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:  DefaultMaxOutputBytes,
	}, reporter, verifier)

	started := make(chan struct{})
	block := make(chan struct{})

	exec.RegisterBuiltin("slow", "Slow action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		close(started)
		select {
		case <-block:
		case <-ctx.Done():
		}
		return "done", "", 0, nil
	})

	// Start first action
	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-dup",
		Action:      "slow",
		Timeout:     "30s",
	})

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first action did not start")
	}

	// Try same execution ID
	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-dup",
		Action:      "slow",
		Timeout:     "30s",
	})

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getAcks()) >= 2
	})

	acks := reporter.getAcks()
	if acks[0].Status != "accepted" {
		t.Errorf("ack[0] status = %q, want %q", acks[0].Status, "accepted")
	}
	if acks[1].Status != "rejected" {
		t.Errorf("ack[1] status = %q, want %q", acks[1].Status, "rejected")
	}
	if acks[1].Reason != "duplicate_execution_id" {
		t.Errorf("ack[1] reason = %q, want %q", acks[1].Reason, "duplicate_execution_id")
	}

	close(block)
}

func TestExecutor_Shutdown(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:   5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:  DefaultMaxOutputBytes,
	}, reporter, verifier)

	started := make(chan struct{})

	exec.RegisterBuiltin("blocking", "Blocking action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		close(started)
		<-ctx.Done()
		return "", "", 0, ctx.Err()
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-shutdown",
		Action:      "blocking",
		Timeout:     "1m",
	})

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("action did not start")
	}

	exec.Shutdown(context.Background())

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != "cancelled" {
		t.Errorf("result status = %q, want %q", results[0].Status, "cancelled")
	}
}

func TestExecutor_ShutdownRejectsNew(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	exec.Shutdown(context.Background())

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-after-shutdown",
		Action:      "test.echo",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getAcks()) > 0
	})

	acks := reporter.getAcks()
	if len(acks) != 1 {
		t.Fatalf("expected 1 ack, got %d", len(acks))
	}
	if acks[0].Status != "rejected" {
		t.Errorf("ack status = %q, want %q", acks[0].Status, "rejected")
	}
	if acks[0].Reason != "shutting_down" {
		t.Errorf("ack reason = %q, want %q", acks[0].Reason, "shutting_down")
	}
}

func TestExecutor_ParameterEnvVars(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "env-check")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"target=$PLEXD_PARAM_TARGET mode=$PLEXD_PARAM_MODE\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "env-check", Checksum: "abc123"},
	})

	req := api.ActionRequest{
		ExecutionID: "exec-env",
		Action:      "env-check",
		Timeout:     "10s",
		Checksum:    "abc123",
		Parameters: map[string]string{
			"target": "10.0.0.1",
			"mode":   "fast",
		},
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	stdout := strings.TrimSpace(results[0].Stdout)
	if !strings.Contains(stdout, "target=10.0.0.1") {
		t.Errorf("stdout %q does not contain target=10.0.0.1", stdout)
	}
	if !strings.Contains(stdout, "mode=fast") {
		t.Errorf("stdout %q does not contain mode=fast", stdout)
	}
}

func TestExecutor_ParameterSanitization(t *testing.T) {
	dir := t.TempDir()
	// Script that prints the env var with sanitized name
	script := filepath.Join(dir, "sanitize-check")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"val=$PLEXD_PARAM_MY_PARAM_NAME_\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "sanitize-check", Checksum: "abc123"},
	})

	req := api.ActionRequest{
		ExecutionID: "exec-sanitize",
		Action:      "sanitize-check",
		Timeout:     "10s",
		Checksum:    "abc123",
		Parameters: map[string]string{
			"my-param.name!": "sanitized-value",
		},
	}

	exec.Execute(context.Background(), "node-1", req)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getResults()) > 0
	})

	results := reporter.getResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	stdout := strings.TrimSpace(results[0].Stdout)
	if !strings.Contains(stdout, "val=sanitized-value") {
		t.Errorf("stdout %q does not contain val=sanitized-value", stdout)
	}
}
