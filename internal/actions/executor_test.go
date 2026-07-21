package actions

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// uploadRecord captures a single UploadExecutionOutput call.
type uploadRecord struct {
	url  string
	data []byte
}

// mockReporter records the ordered execution callbacks and output uploads it
// receives from the executor (which drives them from goroutines) and lets tests
// inject per-status callback errors, upload errors, and a declare response.
type mockReporter struct {
	mu        sync.Mutex
	callbacks []api.ExecutionCallbackRequest
	uploads   []uploadRecord

	// statusErrs returns a per-status error from ExecutionCallback, letting a
	// test fail only the ack, started, or terminal callback.
	statusErrs map[string]error
	// statusErrBudget caps how many times statusErrs fires for a status, so a
	// test can make a callback fail transiently and then succeed. A status
	// absent from the map fails on every call.
	statusErrBudget map[string]int
	// uploadErr is returned from UploadExecutionOutput when set.
	uploadErr error
	// declareResp overrides the response returned for an output-declaring
	// callback (one carrying DeclaredOutputBytes > 0). When nil, a default
	// response with a derivable OutputUploadURL is returned.
	declareResp *api.ExecutionCallbackResponse
}

func (m *mockReporter) ExecutionCallback(_ context.Context, _, executionID string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, req)

	if err := m.statusErrs[req.Status]; err != nil {
		budget, limited := m.statusErrBudget[req.Status]
		if !limited || budget > 0 {
			if limited {
				m.statusErrBudget[req.Status] = budget - 1
			}
			return nil, err
		}
	}

	if req.DeclaredOutputBytes > 0 {
		if m.declareResp != nil {
			return m.declareResp, nil
		}
		return &api.ExecutionCallbackResponse{
			Status:          req.Status,
			OutputUploadURL: "http://mock/exec-output/" + executionID,
		}, nil
	}

	return &api.ExecutionCallbackResponse{Status: req.Status}, nil
}

func (m *mockReporter) UploadExecutionOutput(_ context.Context, uploadURL string, output []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.uploadErr != nil {
		return m.uploadErr
	}
	data := make([]byte, len(output))
	copy(data, output)
	m.uploads = append(m.uploads, uploadRecord{url: uploadURL, data: data})
	return nil
}

func (m *mockReporter) getCallbacks() []api.ExecutionCallbackRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]api.ExecutionCallbackRequest, len(m.callbacks))
	copy(cp, m.callbacks)
	return cp
}

func (m *mockReporter) getUploads() []uploadRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]uploadRecord, len(m.uploads))
	copy(cp, m.uploads)
	return cp
}

// assertStatuses fails the test unless the recorded callback statuses match want
// exactly and in order.
func assertStatuses(t *testing.T, cbs []api.ExecutionCallbackRequest, want []string) {
	t.Helper()
	got := make([]string, len(cbs))
	for i, cb := range cbs {
		got[i] = cb.Status
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("callback statuses = %v, want %v", got, want)
	}
}

// decodeInline returns the base64-decoded inline output, failing if it is absent.
func decodeInline(t *testing.T, out *api.ExecutionOutput) string {
	t.Helper()
	if out == nil {
		t.Fatal("expected inline output, got nil")
	}
	data, err := base64.StdEncoding.DecodeString(out.Inline)
	if err != nil {
		t.Fatalf("decode inline output: %v", err)
	}
	return string(data)
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
		return len(reporter.getCallbacks()) >= 3
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})

	terminal := cbs[len(cbs)-1]
	if terminal.ExitCode == nil || *terminal.ExitCode != 0 {
		t.Errorf("terminal exit_code = %v, want pointer to 0", terminal.ExitCode)
	}
	if got := decodeInline(t, terminal.Output); got != "hello from builtin" {
		t.Errorf("inline output = %q, want %q", got, "hello from builtin")
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
		return len(reporter.getCallbacks()) >= 3
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})

	terminal := cbs[len(cbs)-1]
	if terminal.ExitCode == nil || *terminal.ExitCode != 0 {
		t.Errorf("terminal exit_code = %v, want pointer to 0", terminal.ExitCode)
	}
	if got := strings.TrimSpace(decodeInline(t, terminal.Output)); got != "hello from hook" {
		t.Errorf("inline output = %q, want %q", got, "hello from hook")
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
		return len(reporter.getCallbacks()) >= 3
	})

	terminal := reporter.getCallbacks()[2]
	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if terminal.Error != "action timed out" {
		t.Errorf("terminal error = %q, want %q", terminal.Error, "action timed out")
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
		return len(reporter.getCallbacks()) >= 3
	})

	terminal := reporter.getCallbacks()[2]
	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if terminal.ExitCode == nil || *terminal.ExitCode != 42 {
		t.Errorf("terminal exit_code = %v, want pointer to 42", terminal.ExitCode)
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
		HooksDir:         dir,
		MaxOutputBytes:   64,
		MaxConcurrent:    5,
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
		return len(reporter.getCallbacks()) >= 3
	})

	out := decodeInline(t, reporter.getCallbacks()[2].Output)
	// Output should be at most 64 bytes of data + truncation suffix.
	maxExpected := 64 + len(truncationSuffix)
	if len(out) > maxExpected {
		t.Errorf("output length = %d, want <= %d", len(out), maxExpected)
	}
	if !strings.Contains(out, "...[truncated]") {
		t.Error("truncated output should contain truncation indicator")
	}
}

func TestExecutor_ConcurrencyLimit(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:    1,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
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

	// The running action sent ack+started; the rejected one adds ack+failed.
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 4
	})

	cbs := reporter.getCallbacks()
	rejectAck := cbs[len(cbs)-2]
	rejectFailed := cbs[len(cbs)-1]
	if rejectAck.Status != api.ExecutionStatusAck {
		t.Errorf("reject ack status = %q, want %q", rejectAck.Status, api.ExecutionStatusAck)
	}
	if rejectFailed.Status != api.ExecutionStatusFailed {
		t.Errorf("reject terminal status = %q, want %q", rejectFailed.Status, api.ExecutionStatusFailed)
	}
	if rejectFailed.Error != "max_concurrent_reached" {
		t.Errorf("reject error = %q, want %q", rejectFailed.Error, "max_concurrent_reached")
	}
	// Only the running action may emit a started callback.
	if got := countStatus(cbs, api.ExecutionStatusStarted); got != 1 {
		t.Errorf("started callbacks = %d, want 1", got)
	}

	close(block)
}

func TestExecutor_DuplicateExecutionID(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
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
		return len(reporter.getCallbacks()) >= 4
	})

	cbs := reporter.getCallbacks()
	rejectAck := cbs[len(cbs)-2]
	rejectFailed := cbs[len(cbs)-1]
	if rejectAck.Status != api.ExecutionStatusAck {
		t.Errorf("reject ack status = %q, want %q", rejectAck.Status, api.ExecutionStatusAck)
	}
	if rejectFailed.Status != api.ExecutionStatusFailed {
		t.Errorf("reject terminal status = %q, want %q", rejectFailed.Status, api.ExecutionStatusFailed)
	}
	if rejectFailed.Error != "duplicate_execution_id" {
		t.Errorf("reject error = %q, want %q", rejectFailed.Error, "duplicate_execution_id")
	}
	if got := countStatus(cbs, api.ExecutionStatusStarted); got != 1 {
		t.Errorf("started callbacks = %d, want 1", got)
	}

	close(block)
}

func TestExecutor_UnknownAction(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-unknown",
		Action:      "does.not.exist",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusFailed,
	})
	if cbs[1].Error != "unknown_action" {
		t.Errorf("failed error = %q, want %q", cbs[1].Error, "unknown_action")
	}
}

func TestExecutor_Shutdown(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
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
		cbs := reporter.getCallbacks()
		return len(cbs) > 0 && cbs[len(cbs)-1].Status == api.ExecutionStatusCancelled
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
}

// ctxAwareShutdownReporter models a control plane whose HTTP client aborts a
// request whose context is already cancelled: such a callback returns the
// context error and is not recorded. The shared mockReporter ignores its
// context, so it cannot show that the terminal callback survives shutdown.
type ctxAwareShutdownReporter struct {
	mu        sync.Mutex
	delivered []api.ExecutionCallbackRequest
}

func (r *ctxAwareShutdownReporter) ExecutionCallback(ctx context.Context, _, _ string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delivered = append(r.delivered, req)
	return &api.ExecutionCallbackResponse{Status: req.Status}, nil
}

func (r *ctxAwareShutdownReporter) UploadExecutionOutput(context.Context, string, []byte) error {
	return nil
}

func (r *ctxAwareShutdownReporter) deliveredCallbacks() []api.ExecutionCallbackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]api.ExecutionCallbackRequest, len(r.delivered))
	copy(cp, r.delivered)
	return cp
}

// TestExecutor_TerminalDeliveredAfterShutdownCancel verifies that the terminal
// callback for an action cancelled by shutdown is sent on a context detached
// from the cancelled action context. Without that detachment the terminal rides
// the already-cancelled actionCtx, the control plane aborts it, and the
// execution stays pinned at started forever.
func TestExecutor_TerminalDeliveredAfterShutdownCancel(t *testing.T) {
	reporter := &ctxAwareShutdownReporter{}
	verifier := &mockVerifier{ok: true}
	cfg := Config{
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
	}
	cfg.ApplyDefaults()
	exec := NewExecutor(cfg, reporter, verifier, testLogger())

	started := make(chan struct{})
	exec.RegisterBuiltin("blocking", "Blocking action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		close(started)
		<-ctx.Done()
		return "", "", 0, ctx.Err()
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-shutdown-detached",
		Action:      "blocking",
		Timeout:     "1m",
	})

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("action did not start")
	}

	// Shutdown cancels the action context and blocks until the goroutine drains,
	// so the terminal report has been attempted by the time it returns.
	exec.Shutdown(context.Background())

	assertStatuses(t, reporter.deliveredCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusCancelled,
	})
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
		return len(reporter.getCallbacks()) >= 2
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusFailed,
	})
	if cbs[1].Error != "shutting_down" {
		t.Errorf("failed error = %q, want %q", cbs[1].Error, "shutting_down")
	}
}

func TestExecutor_OverCeilingOutput(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	output := strings.Repeat("a", inlineOutputCeiling+1000)
	exec.RegisterBuiltin("big", "Big output", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return output, "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-over",
		Action:      "big",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 4
	})

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})

	if declared := cbs[2].DeclaredOutputBytes; declared != int64(len(output)) {
		t.Errorf("declared_output_bytes = %d, want %d", declared, len(output))
	}

	uploads := reporter.getUploads()
	if len(uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(uploads))
	}
	if string(uploads[0].data) != output {
		t.Errorf("uploaded %d bytes, want the %d-byte combined output", len(uploads[0].data), len(output))
	}

	terminal := cbs[3]
	if terminal.Output == nil {
		t.Fatal("terminal output is nil")
	}
	if terminal.Output.Inline != "" {
		t.Errorf("terminal inline = %q, want empty", terminal.Output.Inline)
	}
	if terminal.Output.ObjectKey != "exec-output/exec-over" {
		t.Errorf("object_key = %q, want %q", terminal.Output.ObjectKey, "exec-output/exec-over")
	}
	sum := sha256.Sum256([]byte(output))
	if want := hex.EncodeToString(sum[:]); terminal.Output.SHA256 != want {
		t.Errorf("sha256 = %q, want %q", terminal.Output.SHA256, want)
	}
}

func TestExecutor_OverCeilingUploadFailure(t *testing.T) {
	reporter := &mockReporter{uploadErr: errors.New("upload boom")}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	output := strings.Repeat("b", inlineOutputCeiling+1000)
	exec.RegisterBuiltin("big", "Big output", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return output, "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-over-fail",
		Action:      "big",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 4
	})

	cbs := reporter.getCallbacks()
	terminal := cbs[len(cbs)-1]
	if terminal.Status != api.ExecutionStatusSucceeded {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusSucceeded)
	}
	if terminal.Output == nil {
		t.Fatal("terminal output is nil")
	}
	if terminal.Output.ObjectKey != "" {
		t.Errorf("object_key = %q, want empty on fallback", terminal.Output.ObjectKey)
	}

	wantInline := output[:inlineOutputCeiling-len(truncationSuffix)] + truncationSuffix
	if got := decodeInline(t, terminal.Output); got != wantInline {
		t.Errorf("fallback inline (len %d) != truncated output (len %d)", len(got), len(wantInline))
	}
	if len(reporter.getUploads()) != 0 {
		t.Errorf("uploads = %d, want 0 after upload failure", len(reporter.getUploads()))
	}
}

func TestExecutor_AckRefused(t *testing.T) {
	tests := []struct {
		name   string
		apiErr *api.APIError
	}{
		{name: "forbidden", apiErr: &api.APIError{StatusCode: 403, Code: "nsk_node_mismatch"}},
		{name: "conflict", apiErr: &api.APIError{StatusCode: 409, Code: "invalid_state_transition"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &mockReporter{statusErrs: map[string]error{api.ExecutionStatusAck: tc.apiErr}}
			verifier := &mockVerifier{ok: true}
			exec := newTestExecutor(Config{}, reporter, verifier)

			ran := make(chan struct{}, 1)
			exec.RegisterBuiltin("noop", "Noop action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
				ran <- struct{}{}
				return "ran", "", 0, nil
			})

			exec.Execute(context.Background(), "node-1", api.ActionRequest{
				ExecutionID: "exec-ack-refused",
				Action:      "noop",
				Timeout:     "10s",
			})

			// The refused ack aborts synchronously: the action never runs.
			select {
			case <-ran:
				t.Fatal("action ran despite refused ack")
			case <-time.After(100 * time.Millisecond):
			}

			cbs := reporter.getCallbacks()
			assertStatuses(t, cbs, []string{api.ExecutionStatusAck})
			if got := exec.ActiveCount(); got != 0 {
				t.Errorf("active count = %d, want 0", got)
			}
		})
	}
}

func TestExecutor_StartedRefused(t *testing.T) {
	reporter := &mockReporter{statusErrs: map[string]error{
		api.ExecutionStatusStarted: &api.APIError{StatusCode: 409, Code: "invalid_state_transition"},
	}}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	ran := make(chan struct{}, 1)
	exec.RegisterBuiltin("noop", "Noop action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		ran <- struct{}{}
		return "ran", "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-started-refused",
		Action:      "noop",
		Timeout:     "10s",
	})

	// Wait for the ack + refused started callbacks.
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})

	select {
	case <-ran:
		t.Fatal("action ran despite refused started callback")
	case <-time.After(100 * time.Millisecond):
	}

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
	})
	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})
}

func TestExecutor_TerminalCallbackError(t *testing.T) {
	reporter := &mockReporter{statusErrs: map[string]error{
		api.ExecutionStatusSucceeded: errors.New("terminal boom"),
	}}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-terminal-error",
		Action:      "test.echo",
		Timeout:     "10s",
	})

	// A terminal callback that keeps failing is retried up to the bounded
	// attempt count and then logged; the run still completes.
	waitFor(t, 10*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})
	want := []string{api.ExecutionStatusAck, api.ExecutionStatusStarted}
	for range terminalCallbackAttempts {
		want = append(want, api.ExecutionStatusSucceeded)
	}
	assertStatuses(t, reporter.getCallbacks(), want)
}

func TestExecutor_TerminalCallbackRetriedAfterTransientError(t *testing.T) {
	// The terminal callback is the only transition out of started, so a
	// transient control-plane failure must not orphan the invocation there.
	reporter := &mockReporter{
		statusErrs:      map[string]error{api.ExecutionStatusSucceeded: errors.New("502 bad gateway")},
		statusErrBudget: map[string]int{api.ExecutionStatusSucceeded: 1},
	}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-terminal-retry",
		Action:      "test.echo",
		Timeout:     "10s",
	})

	waitFor(t, 10*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
		api.ExecutionStatusSucceeded,
	})
}

func TestExecutor_TerminalCallbackRefusalNotRetried(t *testing.T) {
	// A refusal is deliberate and permanent, so retrying it would only
	// double-report.
	reporter := &mockReporter{statusErrs: map[string]error{
		api.ExecutionStatusSucceeded: &api.APIError{
			StatusCode: 409,
			Code:       api.CodeExecutionAlreadyTerminal,
		},
	}}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-terminal-refused",
		Action:      "test.echo",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

func TestExecutor_AckTransportError(t *testing.T) {
	// A non-APIError ack failure keeps the lenient posture: the action runs.
	reporter := &mockReporter{statusErrs: map[string]error{
		api.ExecutionStatusAck: errors.New("connection reset"),
	}}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-ack-transport",
		Action:      "test.echo",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		cbs := reporter.getCallbacks()
		return len(cbs) > 0 && cbs[len(cbs)-1].Status == api.ExecutionStatusSucceeded
	})
	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

func TestExecutor_AckUncodedStatusErrorIsNotRefusal(t *testing.T) {
	// A 403 from a proxy or WAF and a 409 raised for an unrelated reason carry
	// no refusal code. Treating them as deliberate refusals would drop the
	// action: it would never run and never be reported.
	tests := []struct {
		name   string
		apiErr *api.APIError
	}{
		{name: "uncoded forbidden", apiErr: &api.APIError{StatusCode: 403, Message: "blocked by proxy"}},
		{name: "uncoded conflict", apiErr: &api.APIError{StatusCode: 409, Message: "conflict"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &mockReporter{statusErrs: map[string]error{api.ExecutionStatusAck: tc.apiErr}}
			verifier := &mockVerifier{ok: true}
			exec := newTestExecutor(Config{}, reporter, verifier)

			exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
				return "hello", "", 0, nil
			})

			exec.Execute(context.Background(), "node-1", api.ActionRequest{
				ExecutionID: "exec-ack-uncoded",
				Action:      "test.echo",
				Timeout:     "10s",
			})

			waitFor(t, 5*time.Second, func() bool {
				cbs := reporter.getCallbacks()
				return len(cbs) > 0 && cbs[len(cbs)-1].Status == api.ExecutionStatusSucceeded
			})
			assertStatuses(t, reporter.getCallbacks(), []string{
				api.ExecutionStatusAck,
				api.ExecutionStatusStarted,
				api.ExecutionStatusSucceeded,
			})
		})
	}
}

func TestExecutor_CombinedOutputCappedAtMaxOutputBytes(t *testing.T) {
	// Each stream is captured under its own MaxOutputBytes limit, so a hook
	// saturating both must still not produce a body over the per-action cap.
	const maxOutput = 4096
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		Enabled:          true,
		MaxConcurrent:    1,
		MaxActionTimeout: time.Minute,
		MaxOutputBytes:   maxOutput,
	}, reporter, verifier)

	exec.RegisterBuiltin("test.loud", "Loud action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return strings.Repeat("o", maxOutput), strings.Repeat("e", maxOutput), 0, nil
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-combined-cap",
		Action:      "test.loud",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		cbs := reporter.getCallbacks()
		return len(cbs) > 0 && cbs[len(cbs)-1].Status == api.ExecutionStatusSucceeded
	})

	cbs := reporter.getCallbacks()
	got := decodeInline(t, cbs[len(cbs)-1].Output)
	if len(got) != maxOutput {
		t.Errorf("combined output len = %d, want %d", len(got), maxOutput)
	}
	if !strings.HasSuffix(got, truncationSuffix) {
		t.Errorf("combined output does not end with %q", truncationSuffix)
	}
}

func TestExecutor_PanicRecovery(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("boom", "Panicking action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		panic("kaboom")
	})

	exec.Execute(context.Background(), "node-1", api.ActionRequest{
		ExecutionID: "exec-panic",
		Action:      "boom",
		Timeout:     "10s",
	})

	waitFor(t, 5*time.Second, func() bool {
		cbs := reporter.getCallbacks()
		return len(cbs) > 0 && cbs[len(cbs)-1].Status == api.ExecutionStatusFailed
	})

	cbs := reporter.getCallbacks()
	terminal := cbs[len(cbs)-1]
	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if !strings.Contains(terminal.Error, "panic") {
		t.Errorf("terminal error = %q, want to contain %q", terminal.Error, "panic")
	}
	if terminal.ExitCode != nil {
		t.Errorf("terminal exit_code = %v, want nil", terminal.ExitCode)
	}
	if terminal.Output != nil {
		t.Errorf("terminal output = %v, want nil", terminal.Output)
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
		return len(reporter.getCallbacks()) >= 3
	})

	stdout := strings.TrimSpace(decodeInline(t, reporter.getCallbacks()[2].Output))
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
		return len(reporter.getCallbacks()) >= 3
	})

	stdout := strings.TrimSpace(decodeInline(t, reporter.getCallbacks()[2].Output))
	if !strings.Contains(stdout, "val=sanitized-value") {
		t.Errorf("stdout %q does not contain val=sanitized-value", stdout)
	}
}

// countStatus returns how many recorded callbacks carry the given status.
func countStatus(cbs []api.ExecutionCallbackRequest, status string) int {
	n := 0
	for _, cb := range cbs {
		if cb.Status == status {
			n++
		}
	}
	return n
}
