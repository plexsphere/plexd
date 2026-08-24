package actions

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	// legBudgets records, per callback and in the same order as callbacks, how
	// much of its deadline the call's context still carried when it landed. It
	// lets a test assert that a multi-leg sequence hands every leg a budget of
	// its own instead of splitting one across all of them.
	legBudgets []time.Duration

	// statusErrs returns a per-status error from ExecutionCallback, letting a
	// test fail only the ack, started, or terminal callback.
	statusErrs map[string]error
	// statusErrBudget caps how many times statusErrs fires for a status, so a
	// test can make a callback fail transiently and then succeed. A status
	// absent from the map fails on every call.
	statusErrBudget map[string]int
	// uploadErr is returned from UploadExecutionOutput when set.
	uploadErr error
	// callbackDelay is slept before every callback is recorded, letting a test
	// consume an execution's remaining deadline inside the claim handshake. It
	// is set at construction and never mutated, so it needs no lock.
	callbackDelay time.Duration
	// declareResp overrides the response returned for an output-declaring
	// callback (one carrying DeclaredOutputBytes > 0). When nil, a default
	// response with a derivable OutputUploadURL is returned.
	declareResp *api.ExecutionCallbackResponse
}

func (m *mockReporter) ExecutionCallback(ctx context.Context, _, executionID string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	// Read before the delay: what is asserted on is the budget the leg started
	// with, not what this mock left of it.
	var legBudget time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		legBudget = time.Until(deadline)
	}

	if m.callbackDelay > 0 {
		time.Sleep(m.callbackDelay)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, req)
	m.legBudgets = append(m.legBudgets, legBudget)

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

func (m *mockReporter) getLegBudgets() []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]time.Duration, len(m.legBudgets))
	copy(cp, m.legBudgets)
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
	// checksums records the expected checksum of every verification, so a test
	// can assert the hook was verified against the digest pinned at discovery.
	checksums []string
}

func (m *mockVerifier) VerifyHook(_ context.Context, _, _, expectedChecksum string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.checksums = append(m.checksums, expectedChecksum)
	return m.ok, m.err
}

func (m *mockVerifier) getChecksums() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(m.checksums))
	copy(cp, m.checksums)
	return cp
}

// pendingExec builds the pull entry for a builtin action that a test which is
// about neither status nor expiry wants: pending, with a deadline far beyond
// the test's own runtime.
func pendingExec(executionID, action string) api.NodeStateExecution {
	return api.NodeStateExecution{
		ExecutionID: executionID,
		Action:      action,
		Type:        api.ActionKindBuiltin,
		Status:      api.ExecutionStatusPending,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

// pendingHookExec is pendingExec for a hook-typed entry.
func pendingHookExec(executionID, action string) api.NodeStateExecution {
	entry := pendingExec(executionID, action)
	entry.Type = api.ActionKindHook
	return entry
}

// mustExecute dispatches an entry and fails the test if the executor deferred it.
func mustExecute(t *testing.T, e *Executor, nodeID string, entry api.NodeStateExecution) {
	t.Helper()
	if err := e.Execute(context.Background(), nodeID, entry); err != nil {
		t.Fatalf("Execute(%s): %v", entry.ExecutionID, err)
	}
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

	mustExecute(t, exec, "node-1", pendingExec("exec-001", "test.echo"))

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
	requireHookScripts(t)
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

	mustExecute(t, exec, "node-1", pendingHookExec("exec-002", "greet"))

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

	// The pull entry carries no checksum: trust re-anchors on the digest the
	// discovery snapshot recorded for the hook.
	if got := verifier.getChecksums(); !reflect.DeepEqual(got, []string{"abc123"}) {
		t.Errorf("verified checksums = %v, want [abc123]", got)
	}
}

func TestExecutor_RunHook_Timeout(t *testing.T) {
	requireHookScripts(t)
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

	// The entry's absolute deadline is what bounds the run.
	entry := pendingHookExec("exec-003", "slow")
	entry.ExpiresAt = time.Now().Add(100 * time.Millisecond)

	mustExecute(t, exec, "node-1", entry)

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
	requireHookScripts(t)
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

	mustExecute(t, exec, "node-1", pendingHookExec("exec-004", "fail"))

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
	requireHookScripts(t)
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

	mustExecute(t, exec, "node-1", pendingHookExec("exec-005", "big-output"))

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
	mustExecute(t, exec, "node-1", pendingExec("exec-slow-1", "slow"))

	// Wait for it to start running
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first action did not start")
	}

	// The running action sent ack+started; a saturated executor must add nothing
	// for the second entry, which the pull block redelivers.
	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})

	err := exec.Execute(context.Background(), "node-1", pendingExec("exec-slow-2", "slow"))
	if !errors.Is(err, ErrDispatchDeferred) {
		t.Fatalf("Execute over the concurrency limit = %v, want ErrDispatchDeferred", err)
	}

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
	})

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
	mustExecute(t, exec, "node-1", pendingExec("exec-dup", "slow"))

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first action did not start")
	}

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})

	// The same id is the block redelivering an entry whose run is still in
	// flight: it is deferred, never re-reported.
	err := exec.Execute(context.Background(), "node-1", pendingExec("exec-dup", "slow"))
	if !errors.Is(err, ErrDispatchDeferred) {
		t.Fatalf("Execute for an in-flight id = %v, want ErrDispatchDeferred", err)
	}

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
	})

	close(block)
}

// TestExecutor_UnknownAction covers every way an entry can fail to resolve: a
// name in neither registry, a name registered under the other kind, and a type
// outside the two-value set. All of them fail fast along the legal edges from
// the status the entry declared.
func TestExecutor_UnknownAction(t *testing.T) {
	requireHookScripts(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "greet")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		kind   string
		status string
		action string
		want   []string
	}{
		{
			name:   "unregistered name",
			kind:   api.ActionKindBuiltin,
			status: api.ExecutionStatusPending,
			action: "does.not.exist",
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
		{
			name:   "builtin type naming a hook",
			kind:   api.ActionKindBuiltin,
			status: api.ExecutionStatusPending,
			action: "greet",
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
		{
			name:   "hook type naming a builtin",
			kind:   api.ActionKindHook,
			status: api.ExecutionStatusPending,
			action: "test.echo",
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
		{
			// The control plane already holds the ack, so repeating it would be
			// a self-edge answered 409: the rejection starts at started.
			name:   "already acked",
			kind:   api.ActionKindBuiltin,
			status: api.ExecutionStatusAck,
			action: "does.not.exist",
			want:   []string{api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &mockReporter{}
			verifier := &mockVerifier{ok: true}
			exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)
			exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
				return "ran", "", 0, nil
			})
			exec.SetHooks([]api.HookInfo{{Name: "greet", Checksum: "abc123"}})

			entry := pendingExec("exec-unknown", tc.action)
			entry.Type = tc.kind
			entry.Status = tc.status
			mustExecute(t, exec, "node-1", entry)

			cbs := reporter.getCallbacks()
			assertStatuses(t, cbs, tc.want)
			if got := cbs[len(cbs)-1].Error; got != "unknown_action" {
				t.Errorf("failed error = %q, want %q", got, "unknown_action")
			}
		})
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

	mustExecute(t, exec, "node-1", pendingExec("exec-shutdown", "blocking"))

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

	mustExecute(t, exec, "node-1", pendingExec("exec-shutdown-detached", "blocking"))

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

// TestExecutor_ShutdownDefersNew checks that a dispatch arriving after shutdown
// is deferred rather than failed: the control plane keeps the entry in the
// executions block, so the next agent process picks it up.
func TestExecutor_ShutdownDefersNew(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	exec.Shutdown(context.Background())

	err := exec.Execute(context.Background(), "node-1", pendingExec("exec-after-shutdown", "test.echo"))
	if !errors.Is(err, ErrDispatchDeferred) {
		t.Fatalf("Execute after shutdown = %v, want ErrDispatchDeferred", err)
	}
	if cbs := reporter.getCallbacks(); len(cbs) != 0 {
		t.Errorf("callbacks = %v, want none for a deferral", cbs)
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

	mustExecute(t, exec, "node-1", pendingExec("exec-over", "big"))

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

	mustExecute(t, exec, "node-1", pendingExec("exec-over-fail", "big"))

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

			mustExecute(t, exec, "node-1", pendingExec("exec-ack-refused", "noop"))

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
	tests := []struct {
		name   string
		status string
		want   []string
	}{
		{
			name:   "from pending",
			status: api.ExecutionStatusPending,
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted},
		},
		{
			// The ack is skipped for an already-acked entry, so the refused
			// started is the only callback the execution ever produces.
			name:   "from ack",
			status: api.ExecutionStatusAck,
			want:   []string{api.ExecutionStatusStarted},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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

			entry := pendingExec("exec-started-refused", "noop")
			entry.Status = tc.status
			mustExecute(t, exec, "node-1", entry)

			// Wait for the refused started callback.
			waitFor(t, 5*time.Second, func() bool {
				return len(reporter.getCallbacks()) >= len(tc.want)
			})

			select {
			case <-ran:
				t.Fatal("action ran despite refused started callback")
			case <-time.After(100 * time.Millisecond):
			}

			assertStatuses(t, reporter.getCallbacks(), tc.want)
			waitFor(t, 5*time.Second, func() bool {
				return exec.ActiveCount() == 0
			})
		})
	}
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

	mustExecute(t, exec, "node-1", pendingExec("exec-terminal-error", "test.echo"))

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

	mustExecute(t, exec, "node-1", pendingExec("exec-terminal-retry", "test.echo"))

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

	mustExecute(t, exec, "node-1", pendingExec("exec-terminal-refused", "test.echo"))

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
	// A transient ack failure defers the dispatch instead of running anyway.
	// Running would leave the control plane at pending with the action already
	// executed, and the next pull would redeliver it for a second run.
	reporter := &mockReporter{statusErrs: map[string]error{
		api.ExecutionStatusAck: errors.New("connection reset"),
	}}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	ran := make(chan struct{}, 1)
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		ran <- struct{}{}
		return "hello", "", 0, nil
	})

	err := exec.Execute(context.Background(), "node-1", pendingExec("exec-ack-transport", "test.echo"))
	if !errors.Is(err, ErrDispatchDeferred) {
		t.Fatalf("Execute() = %v, want ErrDispatchDeferred", err)
	}

	select {
	case <-ran:
		t.Fatal("action ran without a recorded ack")
	case <-time.After(100 * time.Millisecond):
	}

	assertStatuses(t, reporter.getCallbacks(), []string{api.ExecutionStatusAck})
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count = %d, want 0", got)
	}
}

// TestExecutor_StartedTransportErrorDefersRun checks that started is a hard
// precondition for running. If the run went ahead on a transient started
// failure, the control plane would still hold the execution at ack — and a
// restart before the terminal callback (which service.upgrade causes by design)
// would have the next pull redeliver it and run a non-idempotent action twice.
func TestExecutor_StartedTransportErrorDefersRun(t *testing.T) {
	reporter := &mockReporter{statusErrs: map[string]error{
		api.ExecutionStatusStarted: errors.New("connection reset"),
	}}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	ran := make(chan struct{}, 1)
	exec.RegisterBuiltin("service.upgrade", "Upgrade action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		ran <- struct{}{}
		return "upgraded", "", 0, nil
	})

	err := exec.Execute(context.Background(), "node-1", pendingExec("exec-started-transport", "service.upgrade"))
	if !errors.Is(err, ErrDispatchDeferred) {
		t.Fatalf("Execute() = %v, want ErrDispatchDeferred", err)
	}

	select {
	case <-ran:
		t.Fatal("action ran without a recorded started")
	case <-time.After(100 * time.Millisecond):
	}

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
	})
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count = %d, want 0", got)
	}
}

// TestExecutor_DeadlineLapsedDuringClaim checks the floor on the derived run
// budget: the claim handshake is synchronous, so a slow control plane can
// consume the entry's whole remaining deadline. An already-lapsed context would
// kill a hook at Start and let a context-ignoring builtin report succeeded past
// its deadline, so the execution is settled without running instead.
func TestExecutor_DeadlineLapsedDuringClaim(t *testing.T) {
	reporter := &mockReporter{callbackDelay: 60 * time.Millisecond}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	ran := make(chan struct{}, 1)
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		ran <- struct{}{}
		return "hello", "", 0, nil
	})

	entry := pendingExec("exec-lapsed", "test.echo")
	entry.ExpiresAt = time.Now().Add(50 * time.Millisecond)

	mustExecute(t, exec, "node-1", entry)

	waitFor(t, 5*time.Second, func() bool {
		return exec.ActiveCount() == 0
	})

	select {
	case <-ran:
		t.Fatal("action ran past its deadline")
	case <-time.After(100 * time.Millisecond):
	}

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
	if got := cbs[len(cbs)-1].Error; got != deadlineLapsedError {
		t.Errorf("terminal error = %q, want %q", got, deadlineLapsedError)
	}
}

// TestExecutor_CallbackLegsGetIndependentBudgets checks that every leg of a
// pre-run callback sequence is issued with a callback budget of its own. One
// deadline spanning the whole sequence starves its later legs against a control
// plane that is slow rather than unreachable: the ack consumes it and the
// started call inherits a sliver, so a transition the control plane commits but
// cannot answer in time cuts the sequence short. The next pull then reports the
// entry at started, which the dispatcher settles as an execution lost to an
// agent restart — on a node that never restarted, and without ever running the
// requested action.
func TestExecutor_CallbackLegsGetIndependentBudgets(t *testing.T) {
	// Every leg burns a measurable slice of the budget, so under one shared
	// deadline each leg after the first starts that much short of a full one.
	const legDelay = 200 * time.Millisecond
	const wantAtLeast = dispatchCallbackTimeout - legDelay/2

	for _, tc := range []struct {
		name   string
		action string
		want   []string
	}{
		{
			name:   "claim handshake",
			action: "test.block",
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted},
		},
		{
			name:   "rejection walk",
			action: "test.unregistered",
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &mockReporter{callbackDelay: legDelay}
			exec := newTestExecutor(Config{}, reporter, &mockVerifier{ok: true})

			// The run is held open so the terminal callback — which has a budget
			// of its own — cannot land among the legs under assertion.
			block := make(chan struct{})
			exec.RegisterBuiltin("test.block", "Blocking action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
				<-block
				return "", "", 0, nil
			})

			mustExecute(t, exec, "node-1", pendingExec("exec-legs", tc.action))

			waitFor(t, 5*time.Second, func() bool {
				return len(reporter.getCallbacks()) >= len(tc.want)
			})
			assertStatuses(t, reporter.getCallbacks()[:len(tc.want)], tc.want)

			for i, budget := range reporter.getLegBudgets()[:len(tc.want)] {
				if budget < wantAtLeast {
					t.Errorf("leg %d (%s) started with %v of its callback budget, want at least %v",
						i, tc.want[i], budget, wantAtLeast)
				}
			}

			close(block)
			waitFor(t, 5*time.Second, func() bool {
				return exec.ActiveCount() == 0
			})
		})
	}
}

// TestExecutor_UnsupportedActionType checks that a type outside the roster is
// reported as such. Reporting unknown_action would send the operator auditing
// the action registry, where the action may well be registered.
func TestExecutor_UnsupportedActionType(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	ran := make(chan struct{}, 1)
	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		ran <- struct{}{}
		return "hello", "", 0, nil
	})

	entry := pendingExec("exec-bad-type", "test.echo")
	entry.Type = "container"
	mustExecute(t, exec, "node-1", entry)

	select {
	case <-ran:
		t.Fatal("action ran for an unsupported type")
	case <-time.After(100 * time.Millisecond):
	}

	cbs := reporter.getCallbacks()
	assertStatuses(t, cbs, []string{
		api.ExecutionStatusAck,
		api.ExecutionStatusStarted,
		api.ExecutionStatusFailed,
	})
	if got := cbs[len(cbs)-1].Error; got != "unsupported_action_type" {
		t.Errorf("terminal error = %q, want %q", got, "unsupported_action_type")
	}
}

// TestExecutor_HookIntegrityAnchorIsPinned checks that the digest a hook is
// verified against is the one recorded at first discovery, not the one the
// watcher last recomputed. HookWatcher re-hashes on every write, so verifying
// against the refreshed digest would compare the file with a hash of itself and
// admit whatever an attacker with write access to the hooks directory put there.
func TestExecutor_HookIntegrityAnchorIsPinned(t *testing.T) {
	requireHookScripts(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "deploy")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho deployed\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{{Name: "deploy", Checksum: "digest-at-discovery"}})
	// The watcher observes a write and pushes the rehashed digest.
	exec.SetHooks([]api.HookInfo{{Name: "deploy", Checksum: "digest-after-tampering"}})

	mustExecute(t, exec, "node-1", pendingHookExec("exec-pinned", "deploy"))

	waitFor(t, 5*time.Second, func() bool {
		return len(verifier.getChecksums()) >= 1
	})
	if got := verifier.getChecksums(); got[0] != "digest-at-discovery" {
		t.Errorf("verified against %q, want the digest pinned at discovery", got[0])
	}
}

func TestExecutor_AckUncodedStatusErrorIsNotRefusal(t *testing.T) {
	// A 403 from a proxy or WAF and a 409 raised for an unrelated reason carry
	// no refusal code. Treating them as deliberate refusals would settle the
	// execution: it would never run and never be reported. They are transient,
	// so the dispatch is deferred and the next pull retries it.
	tests := []struct {
		name   string
		apiErr *api.APIError
	}{
		{name: "uncoded forbidden", apiErr: &api.APIError{StatusCode: 403, Message: "blocked by proxy"}},
		{name: "uncoded conflict", apiErr: &api.APIError{StatusCode: 409, Message: "conflict"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &mockReporter{
				statusErrs:      map[string]error{api.ExecutionStatusAck: tc.apiErr},
				statusErrBudget: map[string]int{api.ExecutionStatusAck: 1},
			}
			verifier := &mockVerifier{ok: true}
			exec := newTestExecutor(Config{}, reporter, verifier)

			exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
				return "hello", "", 0, nil
			})

			entry := pendingExec("exec-ack-uncoded", "test.echo")
			if err := exec.Execute(context.Background(), "node-1", entry); !errors.Is(err, ErrDispatchDeferred) {
				t.Fatalf("Execute() = %v, want ErrDispatchDeferred", err)
			}

			// The redelivered entry runs, which a refusal would have prevented.
			mustExecute(t, exec, "node-1", entry)

			waitFor(t, 5*time.Second, func() bool {
				cbs := reporter.getCallbacks()
				return len(cbs) > 0 && cbs[len(cbs)-1].Status == api.ExecutionStatusSucceeded
			})
			assertStatuses(t, reporter.getCallbacks(), []string{
				api.ExecutionStatusAck,
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
		Enabled:          boolPtr(true),
		MaxConcurrent:    1,
		MaxActionTimeout: time.Minute,
		MaxOutputBytes:   maxOutput,
	}, reporter, verifier)

	exec.RegisterBuiltin("test.loud", "Loud action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return strings.Repeat("o", maxOutput), strings.Repeat("e", maxOutput), 0, nil
	})

	mustExecute(t, exec, "node-1", pendingExec("exec-combined-cap", "test.loud"))

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

	mustExecute(t, exec, "node-1", pendingExec("exec-panic", "boom"))

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
	requireHookScripts(t)
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

	entry := pendingHookExec("exec-env", "env-check")
	entry.Parameters = map[string]json.RawMessage{
		"target": json.RawMessage(`"10.0.0.1"`),
		"mode":   json.RawMessage(`"fast"`),
	}

	mustExecute(t, exec, "node-1", entry)

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

// TestExecutor_NonStringParameterEnvVars checks that the flattening of a
// structured parameter object survives all the way into the hook environment.
func TestExecutor_NonStringParameterEnvVars(t *testing.T) {
	requireHookScripts(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "json-check")
	content := "#!/bin/sh\necho \"count=$PLEXD_PARAM_COUNT flag=$PLEXD_PARAM_FLAG tags=$PLEXD_PARAM_TAGS since_ns=$PLEXD_PARAM_SINCE_NS\"\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

	exec.SetHooks([]api.HookInfo{
		{Name: "json-check", Checksum: "abc123"},
	})

	entry := pendingHookExec("exec-json-params", "json-check")
	entry.Parameters = map[string]json.RawMessage{
		"count": json.RawMessage(`3`),
		"flag":  json.RawMessage(`true`),
		"tags":  json.RawMessage(`["a","b"]`),
		// An integer past 2^53: routed through an any it would reach the hook as
		// 1769500800123456800.
		"since_ns": json.RawMessage(`1769500800123456789`),
	}

	mustExecute(t, exec, "node-1", entry)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	stdout := strings.TrimSpace(decodeInline(t, reporter.getCallbacks()[2].Output))
	for _, want := range []string{"count=3", "flag=true", `tags=["a","b"]`, "since_ns=1769500800123456789"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout %q does not contain %q", stdout, want)
		}
	}
}

func TestExecutor_ParameterSanitization(t *testing.T) {
	requireHookScripts(t)
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

	entry := pendingHookExec("exec-sanitize", "sanitize-check")
	entry.Parameters = map[string]json.RawMessage{
		"my-param.name!": json.RawMessage(`"sanitized-value"`),
	}

	mustExecute(t, exec, "node-1", entry)

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

// TestExecutor_AckSkippedForAckedEntry verifies that an entry the pull already
// reports at ack is not acked again: the control plane holds that state, and a
// repeat would be a non-terminal self-edge answered 409.
func TestExecutor_AckSkippedForAckedEntry(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{}, reporter, verifier)

	exec.RegisterBuiltin("test.echo", "Echo action", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return "hello", "", 0, nil
	})

	entry := pendingExec("exec-already-acked", "test.echo")
	entry.Status = api.ExecutionStatusAck
	mustExecute(t, exec, "node-1", entry)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 2
	})

	assertStatuses(t, reporter.getCallbacks(), []string{
		api.ExecutionStatusStarted,
		api.ExecutionStatusSucceeded,
	})
}

// TestExecutor_ExpiresAtBoundsRun verifies that the entry's absolute deadline
// wins over the configured maximum when it is nearer, and that a run outliving
// it reports the timeout.
func TestExecutor_ExpiresAtBoundsRun(t *testing.T) {
	reporter := &mockReporter{}
	verifier := &mockVerifier{ok: true}
	exec := newTestExecutor(Config{
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   DefaultMaxOutputBytes,
	}, reporter, verifier)

	exec.RegisterBuiltin("slow", "Slow action", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		<-ctx.Done()
		return "", "", 0, ctx.Err()
	})

	entry := pendingExec("exec-deadline", "slow")
	entry.ExpiresAt = time.Now().Add(200 * time.Millisecond)
	mustExecute(t, exec, "node-1", entry)

	waitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	cbs := reporter.getCallbacks()
	terminal := cbs[len(cbs)-1]
	if terminal.Status != api.ExecutionStatusFailed {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
	}
	if terminal.Error != "action timed out" {
		t.Errorf("terminal error = %q, want %q", terminal.Error, "action timed out")
	}
}

// TestExecutor_RunHook_MissingFromSnapshot covers the two ways a hook can fail
// to resolve: absent from the discovery snapshot when the entry is dispatched,
// and dropped from it between dispatch and run.
func TestExecutor_RunHook_MissingFromSnapshot(t *testing.T) {
	requireHookScripts(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "greet")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("undiscovered at dispatch", func(t *testing.T) {
		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{HooksDir: dir}, reporter, verifier)

		mustExecute(t, exec, "node-1", pendingHookExec("exec-hook-undiscovered", "greet"))

		cbs := reporter.getCallbacks()
		assertStatuses(t, cbs, []string{
			api.ExecutionStatusAck,
			api.ExecutionStatusStarted,
			api.ExecutionStatusFailed,
		})
		if got := cbs[len(cbs)-1].Error; got != "unknown_action" {
			t.Errorf("failed error = %q, want %q", got, "unknown_action")
		}
		if got := verifier.getChecksums(); len(got) != 0 {
			t.Errorf("verifications = %v, want none", got)
		}
	})

	t.Run("dropped before run", func(t *testing.T) {
		reporter := newBlockingReporter()
		verifier := &mockVerifier{ok: true}
		cfg := Config{HooksDir: dir}
		cfg.ApplyDefaults()
		exec := NewExecutor(cfg, reporter, verifier, testLogger())
		exec.SetHooks([]api.HookInfo{{Name: "greet", Checksum: "abc123"}})

		// The dispatch is parked in its ack callback, which the claim handshake
		// sends before the run goroutine exists.
		dispatched := make(chan error, 1)
		go func() {
			dispatched <- exec.Execute(context.Background(), "node-1", pendingHookExec("exec-hook-dropped", "greet"))
		}()

		// runHook re-reads the snapshot, so a hook the watcher removed between
		// dispatch and run is refused instead of executed against a checksum
		// nobody vouches for any more.
		reporter.waitForAck(t)
		exec.SetHooks(nil)
		close(reporter.release)

		if err := <-dispatched; err != nil {
			t.Fatalf("Execute(exec-hook-dropped): %v", err)
		}

		waitFor(t, 5*time.Second, func() bool {
			return exec.ActiveCount() == 0
		})
		terminal := reporter.last(t)
		if terminal.Status != api.ExecutionStatusFailed {
			t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusFailed)
		}
		if !strings.Contains(terminal.Error, "hook not discovered") {
			t.Errorf("terminal error = %q, want to mention %q", terminal.Error, "hook not discovered")
		}
		if got := verifier.getChecksums(); len(got) != 0 {
			t.Errorf("verifications = %v, want none", got)
		}
	})
}

// blockingReporter records callbacks and holds Execute at its ack callback
// until the test releases it, so the test can mutate executor state after the
// dispatch is accepted and before the run goroutine starts.
type blockingReporter struct {
	mu        sync.Mutex
	callbacks []api.ExecutionCallbackRequest
	blocked   bool
	acked     chan struct{}
	release   chan struct{}
}

func newBlockingReporter() *blockingReporter {
	return &blockingReporter{
		acked:   make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *blockingReporter) ExecutionCallback(_ context.Context, _, _ string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	r.mu.Lock()
	r.callbacks = append(r.callbacks, req)
	block := req.Status == api.ExecutionStatusAck && !r.blocked
	r.blocked = r.blocked || block
	r.mu.Unlock()

	if block {
		close(r.acked)
		<-r.release
	}
	return &api.ExecutionCallbackResponse{Status: req.Status}, nil
}

func (r *blockingReporter) UploadExecutionOutput(context.Context, string, []byte) error { return nil }

func (r *blockingReporter) waitForAck(t *testing.T) {
	t.Helper()
	select {
	case <-r.acked:
	case <-time.After(5 * time.Second):
		t.Fatal("ack callback never arrived")
	}
}

func (r *blockingReporter) last(t *testing.T) api.ExecutionCallbackRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.callbacks) == 0 {
		t.Fatal("no callbacks recorded")
	}
	return r.callbacks[len(r.callbacks)-1]
}

func TestFlattenParams(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]json.RawMessage
		want   map[string]string
	}{
		{
			name:   "nil object flattens to an empty map",
			params: nil,
			want:   map[string]string{},
		},
		{
			name: "string passes through unquoted",
			params: map[string]json.RawMessage{
				"target": json.RawMessage(`"10.0.0.1"`),
				"quoted": json.RawMessage(`"a \"b\" c"`),
			},
			want: map[string]string{"target": "10.0.0.1", "quoted": `a "b" c`},
		},
		{
			name: "scalars travel as their json text",
			params: map[string]json.RawMessage{
				"count":  json.RawMessage(`3`),
				"ratio":  json.RawMessage(`1.5`),
				"flag":   json.RawMessage(`false`),
				"absent": json.RawMessage(`null`),
			},
			want: map[string]string{"count": "3", "ratio": "1.5", "flag": "false", "absent": "null"},
		},
		{
			name: "containers travel as their json text",
			params: map[string]json.RawMessage{
				"tags": json.RawMessage(`["a",1]`),
				"meta": json.RawMessage(`{"k":"v"}`),
			},
			want: map[string]string{"tags": `["a",1]`, "meta": `{"k":"v"}`},
		},
		{
			// An integer past 2^53 survives only because the value is never
			// decoded into an any: float64 would round it to ...800.
			name:   "a large integer keeps every digit",
			params: map[string]json.RawMessage{"since_ns": json.RawMessage(`1769500800123456789`)},
			want:   map[string]string{"since_ns": "1769500800123456789"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := flattenParams(tc.params)
			if got == nil {
				t.Fatal("flattenParams returned a nil map")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("flattenParams() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestExecutor_FailOrphan(t *testing.T) {
	t.Run("reports the terminal once", func(t *testing.T) {
		reporter := &mockReporter{}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{}, reporter, verifier)

		if err := exec.FailOrphan(context.Background(), "node-1", "exec-orphan"); err != nil {
			t.Fatalf("FailOrphan() = %v, want nil for a delivered report", err)
		}

		cbs := reporter.getCallbacks()
		assertStatuses(t, cbs, []string{api.ExecutionStatusFailed})
		if cbs[0].Error != orphanedRunError {
			t.Errorf("terminal error = %q, want %q", cbs[0].Error, orphanedRunError)
		}
		if cbs[0].ExitCode != nil {
			t.Errorf("terminal exit_code = %v, want nil", cbs[0].ExitCode)
		}
	})

	// A refusal settles the execution: the control plane answers no later attempt
	// differently, so reporting it as undelivered would have the dispatcher
	// redeliver the entry on every pull for the life of the process.
	t.Run("a refusal is not retried and settles the execution", func(t *testing.T) {
		refusals := []*api.APIError{
			{StatusCode: 409, Code: api.CodeInvalidStateTransition},
			{StatusCode: 409, Code: api.CodeExecutionAlreadyTerminal},
			{StatusCode: 403, Code: api.CodeNSKNodeMismatch},
		}
		for _, refusal := range refusals {
			t.Run(refusal.Code, func(t *testing.T) {
				reporter := &mockReporter{statusErrs: map[string]error{
					api.ExecutionStatusFailed: refusal,
				}}
				verifier := &mockVerifier{ok: true}
				exec := newTestExecutor(Config{}, reporter, verifier)

				if err := exec.FailOrphan(context.Background(), "node-1", "exec-orphan-refused"); err != nil {
					t.Fatalf("FailOrphan() = %v, want nil for a refused report", err)
				}

				assertStatuses(t, reporter.getCallbacks(), []string{api.ExecutionStatusFailed})
			})
		}
	})

	t.Run("a transient failure is retried", func(t *testing.T) {
		reporter := &mockReporter{
			statusErrs:      map[string]error{api.ExecutionStatusFailed: errors.New("502 bad gateway")},
			statusErrBudget: map[string]int{api.ExecutionStatusFailed: 1},
		}
		verifier := &mockVerifier{ok: true}
		exec := newTestExecutor(Config{}, reporter, verifier)

		if err := exec.FailOrphan(context.Background(), "node-1", "exec-orphan-retry"); err != nil {
			t.Fatalf("FailOrphan() = %v, want nil once the retry lands", err)
		}

		assertStatuses(t, reporter.getCallbacks(), []string{
			api.ExecutionStatusFailed,
			api.ExecutionStatusFailed,
		})
	})
}

func TestRejectSequence(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   []string
	}{
		{
			name:   "pending walks the full roster",
			status: api.ExecutionStatusPending,
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
		{
			name:   "ack skips the recorded transition",
			status: api.ExecutionStatusAck,
			want:   []string{api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
		{
			name:   "started only needs the terminal",
			status: api.ExecutionStatusStarted,
			want:   []string{api.ExecutionStatusFailed},
		},
		{
			name:   "an unknown status is walked like pending",
			status: "queued",
			want:   []string{api.ExecutionStatusAck, api.ExecutionStatusStarted, api.ExecutionStatusFailed},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rejectSequence(tc.status); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rejectSequence(%q) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}

// TestExecutor_RejectStopsOnRefusal verifies that a refusal anywhere in the
// rejection sequence stops it: the control plane has settled the execution, so
// the remaining edges would only double-report.
func TestExecutor_RejectStopsOnRefusal(t *testing.T) {
	tests := []struct {
		name     string
		refuseAt string
		want     []string
	}{
		{
			name:     "refused ack",
			refuseAt: api.ExecutionStatusAck,
			want:     []string{api.ExecutionStatusAck},
		},
		{
			name:     "refused started",
			refuseAt: api.ExecutionStatusStarted,
			want:     []string{api.ExecutionStatusAck, api.ExecutionStatusStarted},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &mockReporter{statusErrs: map[string]error{
				tc.refuseAt: &api.APIError{StatusCode: 409, Code: api.CodeInvalidStateTransition},
			}}
			verifier := &mockVerifier{ok: true}
			exec := newTestExecutor(Config{}, reporter, verifier)

			mustExecute(t, exec, "node-1", pendingExec("exec-reject-refused", "does.not.exist"))

			assertStatuses(t, reporter.getCallbacks(), tc.want)
		})
	}
}
