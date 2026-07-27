package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/integrity"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// integrationReporter is a thread-safe mock reporter for integration tests. It
// records the ordered execution callbacks the executor drives from goroutines.
type integrationReporter struct {
	mu        sync.Mutex
	callbacks []api.ExecutionCallbackRequest
}

func (r *integrationReporter) ExecutionCallback(_ context.Context, _, _ string, req api.ExecutionCallbackRequest) (*api.ExecutionCallbackResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callbacks = append(r.callbacks, req)
	return &api.ExecutionCallbackResponse{Status: req.Status}, nil
}

func (r *integrationReporter) UploadExecutionOutput(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (r *integrationReporter) getCallbacks() []api.ExecutionCallbackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]api.ExecutionCallbackRequest, len(r.callbacks))
	copy(cp, r.callbacks)
	return cp
}

func (r *integrationReporter) statusCount(status string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, cb := range r.callbacks {
		if cb.Status == status {
			n++
		}
	}
	return n
}

func integrationWaitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("integrationWaitFor: timed out")
}

func integrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// newRealVerifier creates a real integrity.Verifier backed by a temp store and
// the given violation reporter.
func newRealVerifier(t *testing.T, violations integrity.ViolationReporter) *integrity.Verifier {
	t.Helper()
	dataDir := t.TempDir()
	store, err := integrity.NewStore(dataDir)
	if err != nil {
		t.Fatalf("new integrity store: %v", err)
	}
	return integrity.NewVerifier(integrity.Config{
		Enabled:        true,
		BinaryPath:     "/dev/null",
		VerifyInterval: time.Hour,
	}, store, violations, integrationLogger())
}

type noopViolationReporter struct{}

func (noopViolationReporter) ReportViolation(_ context.Context, _ string, _ api.IntegrityViolationReport) error {
	return nil
}

// recordingViolationReporter captures the integrity violations a refused hook
// files with the control plane.
type recordingViolationReporter struct {
	mu      sync.Mutex
	reports []api.IntegrityViolationReport
}

func (r *recordingViolationReporter) ReportViolation(_ context.Context, _ string, report api.IntegrityViolationReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, report)
	return nil
}

func (r *recordingViolationReporter) getReports() []api.IntegrityViolationReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]api.IntegrityViolationReport, len(r.reports))
	copy(cp, r.reports)
	return cp
}

// integrationConfig is the enabled, generously bounded config the integration
// scenarios share.
func integrationConfig(hooksDir string) Config {
	return Config{
		Enabled:          boolPtr(true),
		HooksDir:         hooksDir,
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1 << 20,
	}
}

// TestIntegration_FullActionLifecycle drives the full lifecycle through the
// dispatcher — pull entry → ack → started → terminal — for both the builtin and
// the hook path, with real integrity verification.
func TestIntegration_FullActionLifecycle(t *testing.T) {
	hooksDir := t.TempDir()
	hookContent := "#!/bin/sh\necho \"hook-lifecycle-output\"\n"
	hookPath := filepath.Join(hooksDir, "lifecycle-hook")
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		t.Fatal(err)
	}

	hookChecksum, err := integrity.HashFile(hookPath)
	if err != nil {
		t.Fatalf("hash hook: %v", err)
	}

	cfg := integrationConfig(hooksDir)
	verifier := newRealVerifier(t, noopViolationReporter{})

	newExecutor := func(reporter ActionReporter) *Executor {
		exec := NewExecutor(cfg, reporter, verifier, integrationLogger())
		exec.RegisterBuiltin("gather_info", "Gather info", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
			return `{"status":"ok"}`, "", 0, nil
		})
		exec.SetHooks([]api.HookInfo{
			{Name: "lifecycle-hook", Source: "local", Checksum: hookChecksum},
		})
		return exec
	}

	t.Run("builtin", func(t *testing.T) {
		reporter := &integrationReporter{}
		exec := newExecutor(reporter)
		dispatcher := NewDispatcher(exec, "node-integ", integrationLogger())

		dispatcher.Handle(context.Background(), snapshot(pendingExec("integ-builtin-001", "gather_info")))

		integrationWaitFor(t, 5*time.Second, func() bool {
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
			t.Errorf("builtin exit_code = %v, want pointer to 0", terminal.ExitCode)
		}
		if got := decodeInline(t, terminal.Output); !strings.Contains(got, "status") {
			t.Errorf("builtin output = %q, expected to contain 'status'", got)
		}
	})

	t.Run("hook", func(t *testing.T) {
		reporter := &integrationReporter{}
		exec := newExecutor(reporter)
		dispatcher := NewDispatcher(exec, "node-integ", integrationLogger())

		dispatcher.Handle(context.Background(), snapshot(pendingHookExec("integ-hook-001", "lifecycle-hook")))

		integrationWaitFor(t, 5*time.Second, func() bool {
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
			t.Errorf("hook exit_code = %v, want pointer to 0", terminal.ExitCode)
		}
		if got := decodeInline(t, terminal.Output); !strings.Contains(got, "hook-lifecycle-output") {
			t.Errorf("hook output = %q, want to contain 'hook-lifecycle-output'", got)
		}
	})
}

// TestIntegration_ConcurrencyBackpressure fires a full block at a saturated
// executor: the entries beyond the limit are deferred without a callback, and a
// later cycle delivers every one of them.
func TestIntegration_ConcurrencyBackpressure(t *testing.T) {
	hooksDir := t.TempDir()
	hookContent := "#!/bin/sh\nsleep 0.1\necho done\n"
	hookPath := filepath.Join(hooksDir, "concurrent-hook")
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		t.Fatal(err)
	}

	hookChecksum, err := integrity.HashFile(hookPath)
	if err != nil {
		t.Fatalf("hash hook: %v", err)
	}

	reporter := &integrationReporter{}
	verifier := newRealVerifier(t, noopViolationReporter{})

	const maxConcurrent = 3
	cfg := integrationConfig(hooksDir)
	cfg.MaxConcurrent = maxConcurrent
	exec := NewExecutor(cfg, reporter, verifier, integrationLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "concurrent-hook", Source: "local", Checksum: hookChecksum},
	})
	dispatcher := NewDispatcher(exec, "node-concurrent", integrationLogger())

	const totalEntries = 6
	block := make([]api.NodeStateExecution, 0, totalEntries)
	for i := range totalEntries {
		block = append(block, pendingHookExec(fmt.Sprintf("integ-concurrent-%03d", i), "concurrent-hook"))
	}

	dispatcher.Handle(context.Background(), snapshot(block...))

	// A saturated executor defers: no entry beyond the limit is failed, so the
	// first cycle can never produce more than maxConcurrent acks.
	if got := reporter.statusCount(api.ExecutionStatusAck); got > maxConcurrent {
		t.Errorf("acks after the first cycle = %d, want at most %d", got, maxConcurrent)
	}
	if got := reporter.statusCount(api.ExecutionStatusFailed); got != 0 {
		t.Errorf("failed callbacks = %d, want 0 for deferred entries", got)
	}

	// Later cycles redeliver the block until every entry has run.
	integrationWaitFor(t, 30*time.Second, func() bool {
		dispatcher.Handle(context.Background(), snapshot(block...))
		return reporter.statusCount(api.ExecutionStatusSucceeded) >= totalEntries
	})

	if got := reporter.statusCount(api.ExecutionStatusAck); got != totalEntries {
		t.Errorf("acks = %d, want %d", got, totalEntries)
	}
	if got := reporter.statusCount(api.ExecutionStatusFailed); got != 0 {
		t.Errorf("failed callbacks = %d, want 0", got)
	}
}

// TestIntegration_HookIntegrityAndExecution covers hook discovery, real
// integrity verification against the discovery digest, parameter passing as env
// vars, and the violation filed when the hook's bytes drift after discovery.
func TestIntegration_HookIntegrityAndExecution(t *testing.T) {
	hooksDir := t.TempDir()

	// Create a hook that echoes its PLEXD_PARAM_ env vars.
	hookContent := "#!/bin/sh\necho \"target=$PLEXD_PARAM_TARGET region=$PLEXD_PARAM_REGION\"\n"
	hookPath := filepath.Join(hooksDir, "deploy")
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		t.Fatal(err)
	}

	// Discover hooks (real discovery with real integrity.HashFile).
	hooks, err := DiscoverHooks(hooksDir, integrationLogger())
	if err != nil {
		t.Fatalf("discover hooks: %v", err)
	}
	if len(hooks) != 1 {
		t.Fatalf("discovered %d hooks, want 1", len(hooks))
	}
	if hooks[0].Name != "deploy" {
		t.Fatalf("hook name = %q, want deploy", hooks[0].Name)
	}

	cfg := integrationConfig(hooksDir)

	t.Run("valid_integrity", func(t *testing.T) {
		reporter := &integrationReporter{}
		exec := NewExecutor(cfg, reporter, newRealVerifier(t, noopViolationReporter{}), integrationLogger())
		exec.SetHooks(hooks)
		dispatcher := NewDispatcher(exec, "node-integrity", integrationLogger())

		entry := pendingHookExec("integ-integrity-001", "deploy")
		entry.Parameters = map[string]json.RawMessage{
			"target": json.RawMessage(`"10.0.0.1"`),
			"region": json.RawMessage(`"us-east-1"`),
		}
		dispatcher.Handle(context.Background(), snapshot(entry))

		integrationWaitFor(t, 5*time.Second, func() bool {
			return len(reporter.getCallbacks()) >= 3
		})

		cbs := reporter.getCallbacks()
		assertStatuses(t, cbs, []string{
			api.ExecutionStatusAck,
			api.ExecutionStatusStarted,
			api.ExecutionStatusSucceeded,
		})
		stdout := strings.TrimSpace(decodeInline(t, cbs[len(cbs)-1].Output))
		if !strings.Contains(stdout, "target=10.0.0.1") {
			t.Errorf("stdout %q missing target=10.0.0.1", stdout)
		}
		if !strings.Contains(stdout, "region=us-east-1") {
			t.Errorf("stdout %q missing region=us-east-1", stdout)
		}
	})

	// The pull entry carries no checksum, so a hook rewritten after discovery is
	// caught only because verification re-anchors on the discovery digest.
	t.Run("drift_after_discovery", func(t *testing.T) {
		driftDir := t.TempDir()
		driftPath := filepath.Join(driftDir, "deploy")
		if err := os.WriteFile(driftPath, []byte(hookContent), 0o755); err != nil {
			t.Fatal(err)
		}
		discovered, err := DiscoverHooks(driftDir, integrationLogger())
		if err != nil {
			t.Fatalf("discover hooks: %v", err)
		}

		violations := &recordingViolationReporter{}
		reporter := &integrationReporter{}
		exec := NewExecutor(integrationConfig(driftDir), reporter, newRealVerifier(t, violations), integrationLogger())
		exec.SetHooks(discovered)
		dispatcher := NewDispatcher(exec, "node-integrity", integrationLogger())

		// Rewrite the hook's bytes behind the recorded digest.
		if err := os.WriteFile(driftPath, []byte("#!/bin/sh\necho tampered\n"), 0o755); err != nil {
			t.Fatal(err)
		}

		dispatcher.Handle(context.Background(), snapshot(pendingHookExec("integ-integrity-002", "deploy")))

		integrationWaitFor(t, 5*time.Second, func() bool {
			return len(reporter.getCallbacks()) >= 3
		})

		assertStatuses(t, reporter.getCallbacks(), []string{
			api.ExecutionStatusAck,
			api.ExecutionStatusStarted,
			api.ExecutionStatusFailed,
		})

		reports := violations.getReports()
		if len(reports) == 0 {
			t.Fatal("drifted hook filed no integrity violation")
		}
	})
}

// TestIntegration_ShutdownCancelsExecutions verifies that shutdown cancels
// running executions, reports cancelled terminal callbacks, and defers every
// later dispatch. Goroutine leak detection is handled by goleak via TestMain.
func TestIntegration_ShutdownCancelsExecutions(t *testing.T) {
	hooksDir := t.TempDir()
	// Create a hook that blocks until cancelled.
	hookContent := "#!/bin/sh\nsleep 999\n"
	hookPath := filepath.Join(hooksDir, "blocking-hook")
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		t.Fatal(err)
	}

	hookChecksum, err := integrity.HashFile(hookPath)
	if err != nil {
		t.Fatalf("hash hook: %v", err)
	}

	reporter := &integrationReporter{}
	verifier := newRealVerifier(t, noopViolationReporter{})

	exec := NewExecutor(integrationConfig(hooksDir), reporter, verifier, integrationLogger())

	// Register a blocking builtin.
	builtinStarted := make(chan struct{})
	exec.RegisterBuiltin("block", "Blocking builtin", nil, func(ctx context.Context, _ map[string]string) (string, string, int, error) {
		close(builtinStarted)
		<-ctx.Done()
		return "", "", 0, ctx.Err()
	})

	exec.SetHooks([]api.HookInfo{
		{Name: "blocking-hook", Source: "local", Checksum: hookChecksum},
	})

	dispatcher := NewDispatcher(exec, "node-shutdown", integrationLogger())

	dispatcher.Handle(context.Background(), snapshot(
		pendingExec("integ-shutdown-001", "block"),
		pendingHookExec("integ-shutdown-002", "blocking-hook"),
	))

	// Wait for the builtin to start.
	select {
	case <-builtinStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("builtin did not start")
	}

	integrationWaitFor(t, 5*time.Second, func() bool {
		return reporter.statusCount(api.ExecutionStatusAck) >= 2
	})

	if exec.ActiveCount() < 1 {
		t.Fatal("expected at least 1 active execution before shutdown")
	}

	// Shutdown cancels all active executions.
	exec.Shutdown(context.Background())

	integrationWaitFor(t, 10*time.Second, func() bool {
		return reporter.statusCount(api.ExecutionStatusCancelled) >= 1
	})

	// After shutdown a dispatch is deferred, not failed: the entry stays in the
	// block for the next agent process.
	before := len(reporter.getCallbacks())
	shutdownDispatcher := NewDispatcher(exec, "node-shutdown", integrationLogger())
	shutdownDispatcher.Handle(context.Background(), snapshot(pendingExec("integ-shutdown-003", "block")))

	if got := len(reporter.getCallbacks()); got != before {
		t.Errorf("callbacks after a post-shutdown dispatch = %d, want %d", got, before)
	}
	if _, settled := shutdownDispatcher.handled["integ-shutdown-003"]; settled {
		t.Error("deferred entry was marked handled")
	}

	// Verify no active executions remain.
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count after shutdown = %d, want 0", got)
	}
}

// TestIntegration_WatcherFeedsExecutor verifies that HookWatcher dynamically
// updates the Executor's hooks list via the onChange → SetHooks integration, and
// that a hook it discovers is dispatchable from the pull block.
func TestIntegration_WatcherFeedsExecutor(t *testing.T) {
	hooksDir := t.TempDir()

	reporter := &integrationReporter{}
	verifier := newRealVerifier(t, noopViolationReporter{})

	exec := NewExecutor(integrationConfig(hooksDir), reporter, verifier, integrationLogger())

	// Wire HookWatcher onChange to executor.SetHooks — this is the integration point.
	watcher := NewHookWatcher(hooksDir, exec.SetHooks, nil, integrationLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watchDone := make(chan error, 1)
	go func() { watchDone <- watcher.Watch(ctx) }()

	// Wait for initial scan (empty directory).
	time.Sleep(200 * time.Millisecond)

	// Executor should have no hooks.
	_, hooks := exec.Capabilities()
	if len(hooks) != 0 {
		t.Fatalf("initial hooks = %d, want 0", len(hooks))
	}

	// --- Add a hook file ---
	hookContent := "#!/bin/sh\necho watcher-integration\n"
	hookPath := filepath.Join(hooksDir, "watcher-hook")
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		t.Fatal(err)
	}

	hookChecksum, err := integrity.HashFile(hookPath)
	if err != nil {
		t.Fatalf("hash hook: %v", err)
	}

	// Wait for watcher debounce + processing.
	time.Sleep(500 * time.Millisecond)

	// Executor should now have the hook.
	_, hooks = exec.Capabilities()
	if len(hooks) != 1 {
		t.Fatalf("hooks after add = %d, want 1", len(hooks))
	}
	if hooks[0].Name != "watcher-hook" {
		t.Errorf("hook name = %q, want %q", hooks[0].Name, "watcher-hook")
	}
	if hooks[0].Checksum != hookChecksum {
		t.Errorf("hook checksum = %q, want %q", hooks[0].Checksum, hookChecksum)
	}

	// --- Dispatch the hook from the pull block ---
	dispatcher := NewDispatcher(exec, "node-watcher", integrationLogger())
	dispatcher.Handle(context.Background(), snapshot(pendingHookExec("integ-watcher-001", "watcher-hook")))

	integrationWaitFor(t, 5*time.Second, func() bool {
		return len(reporter.getCallbacks()) >= 3
	})

	cbs := reporter.getCallbacks()
	terminal := cbs[len(cbs)-1]
	if terminal.Status != api.ExecutionStatusSucceeded {
		t.Errorf("terminal status = %q, want %q", terminal.Status, api.ExecutionStatusSucceeded)
	}
	if got := decodeInline(t, terminal.Output); !strings.Contains(got, "watcher-integration") {
		t.Errorf("output = %q, want to contain 'watcher-integration'", got)
	}

	// --- Remove the hook file ---
	if err := os.Remove(hookPath); err != nil {
		t.Fatal(err)
	}

	// Wait for watcher debounce + processing.
	time.Sleep(500 * time.Millisecond)

	// Executor should have no hooks again.
	_, hooks = exec.Capabilities()
	if len(hooks) != 0 {
		t.Fatalf("hooks after remove = %d, want 0", len(hooks))
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not exit")
	}
}
