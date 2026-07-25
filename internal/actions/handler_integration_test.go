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

// newRealVerifier creates a real integrity.Verifier backed by a temp store.
func newRealVerifier(t *testing.T) *integrity.Verifier {
	t.Helper()
	dataDir := t.TempDir()
	store, err := integrity.NewStore(dataDir)
	if err != nil {
		t.Fatalf("new integrity store: %v", err)
	}
	// Use a no-op violation reporter since we only care about the bool return.
	return integrity.NewVerifier(integrity.Config{
		Enabled:        true,
		BinaryPath:     "/dev/null",
		VerifyInterval: time.Hour,
	}, store, &noopViolationReporter{}, integrationLogger())
}

type noopViolationReporter struct{}

func (noopViolationReporter) ReportViolation(_ context.Context, _ string, _ api.IntegrityViolationReport) error {
	return nil
}

func integrationEnvelope(t *testing.T, req api.ActionRequest) api.Envelope {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return api.Envelope{
		Type:    api.EventActionRequest,
		ID:      "evt-" + req.ExecutionID,
		Payload: data,
	}
}

// TestIntegration_FullActionLifecycle tests the full lifecycle:
// action_request → ack → started → terminal callback.
// Tests both built-in and hook paths with real integrity verification.
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

	reporter := &integrationReporter{}
	verifier := newRealVerifier(t)

	cfg := Config{
		Enabled:          boolPtr(true),
		HooksDir:         hooksDir,
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1 << 20,
	}
	exec := NewExecutor(cfg, reporter, verifier, integrationLogger())

	exec.RegisterBuiltin("gather_info", "Gather info", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
		return `{"status":"ok"}`, "", 0, nil
	})
	exec.SetHooks([]api.HookInfo{
		{Name: "lifecycle-hook", Source: "local", Checksum: hookChecksum},
	})

	handler := HandleActionRequest(exec, "node-integ", integrationLogger())

	// --- Builtin path ---
	t.Run("builtin", func(t *testing.T) {
		req := api.ActionRequest{
			ExecutionID: "integ-builtin-001",
			Action:      "gather_info",
			Timeout:     "30s",
		}
		if err := handler(context.Background(), integrationEnvelope(t, req)); err != nil {
			t.Fatalf("handler error: %v", err)
		}

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

	// --- Hook path ---
	t.Run("hook", func(t *testing.T) {
		reporter2 := &integrationReporter{}
		exec2 := NewExecutor(cfg, reporter2, verifier, integrationLogger())
		exec2.RegisterBuiltin("gather_info", "Gather info", nil, func(_ context.Context, _ map[string]string) (string, string, int, error) {
			return `{"status":"ok"}`, "", 0, nil
		})
		exec2.SetHooks([]api.HookInfo{
			{Name: "lifecycle-hook", Source: "local", Checksum: hookChecksum},
		})
		handler2 := HandleActionRequest(exec2, "node-integ", integrationLogger())

		req := api.ActionRequest{
			ExecutionID: "integ-hook-001",
			Action:      "lifecycle-hook",
			Timeout:     "30s",
			Checksum:    hookChecksum,
		}
		if err := handler2(context.Background(), integrationEnvelope(t, req)); err != nil {
			t.Fatalf("handler error: %v", err)
		}

		integrationWaitFor(t, 5*time.Second, func() bool {
			return len(reporter2.getCallbacks()) >= 3
		})

		cbs := reporter2.getCallbacks()
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

// TestIntegration_ConcurrentExecutions fires multiple action requests concurrently,
// verifies concurrency limit enforcement, and passes under -race.
func TestIntegration_ConcurrentExecutions(t *testing.T) {
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
	verifier := newRealVerifier(t)

	maxConcurrent := 3
	cfg := Config{
		Enabled:          boolPtr(true),
		HooksDir:         hooksDir,
		MaxConcurrent:    maxConcurrent,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1 << 20,
	}
	exec := NewExecutor(cfg, reporter, verifier, integrationLogger())
	exec.SetHooks([]api.HookInfo{
		{Name: "concurrent-hook", Source: "local", Checksum: hookChecksum},
	})

	handler := HandleActionRequest(exec, "node-concurrent", integrationLogger())

	totalRequests := 6
	var wg sync.WaitGroup
	wg.Add(totalRequests)

	for i := 0; i < totalRequests; i++ {
		go func(idx int) {
			defer wg.Done()
			req := api.ActionRequest{
				ExecutionID: fmt.Sprintf("integ-concurrent-%03d", idx),
				Action:      "concurrent-hook",
				Timeout:     "30s",
				Checksum:    hookChecksum,
			}
			_ = handler(context.Background(), integrationEnvelope(t, req))
		}(i)
	}

	wg.Wait()

	// Every execution acks; accepted ones then start, rejected ones fail.
	integrationWaitFor(t, 10*time.Second, func() bool {
		return reporter.statusCount(api.ExecutionStatusAck) >= totalRequests
	})
	integrationWaitFor(t, 10*time.Second, func() bool {
		terminal := reporter.statusCount(api.ExecutionStatusSucceeded) + reporter.statusCount(api.ExecutionStatusFailed)
		return terminal >= totalRequests
	})

	cbs := reporter.getCallbacks()
	var acks, started, succeeded, rejected int
	for _, cb := range cbs {
		switch cb.Status {
		case api.ExecutionStatusAck:
			acks++
		case api.ExecutionStatusStarted:
			started++
		case api.ExecutionStatusSucceeded:
			succeeded++
		case api.ExecutionStatusFailed:
			rejected++
			if cb.Error != "max_concurrent_reached" {
				t.Errorf("failed error = %q, want max_concurrent_reached", cb.Error)
			}
		default:
			t.Errorf("unexpected callback status = %q", cb.Status)
		}
	}

	if acks != totalRequests {
		t.Errorf("acks = %d, want %d", acks, totalRequests)
	}
	// Accepted executions start and succeed; rejected ones only fail.
	if started != succeeded {
		t.Errorf("started = %d, succeeded = %d, want equal", started, succeeded)
	}
	if started+rejected != totalRequests {
		t.Errorf("started+rejected = %d, want %d", started+rejected, totalRequests)
	}
	if started > maxConcurrent+1 {
		// Some concurrency overlap is possible since hooks complete quickly (0.1s).
		// But we should never exceed the limit by a lot.
		t.Errorf("started = %d, maxConcurrent = %d (should not wildly exceed)", started, maxConcurrent)
	}
}

// TestIntegration_HookIntegrityAndExecution tests hook discovery, real integrity
// verification, parameter passing as env vars, and terminal callback reporting.
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

	reporter := &integrationReporter{}
	verifier := newRealVerifier(t)

	cfg := Config{
		Enabled:          boolPtr(true),
		HooksDir:         hooksDir,
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1 << 20,
	}
	exec := NewExecutor(cfg, reporter, verifier, integrationLogger())
	exec.SetHooks(hooks)

	handler := HandleActionRequest(exec, "node-integrity", integrationLogger())

	// --- Valid integrity: checksum matches ---
	t.Run("valid_integrity", func(t *testing.T) {
		rep := &integrationReporter{}
		e := NewExecutor(cfg, rep, verifier, integrationLogger())
		e.SetHooks(hooks)
		h := HandleActionRequest(e, "node-integrity", integrationLogger())

		req := api.ActionRequest{
			ExecutionID: "integ-integrity-001",
			Action:      "deploy",
			Timeout:     "30s",
			Checksum:    hooks[0].Checksum,
			Parameters: map[string]string{
				"target": "10.0.0.1",
				"region": "us-east-1",
			},
		}
		if err := h(context.Background(), integrationEnvelope(t, req)); err != nil {
			t.Fatalf("handler error: %v", err)
		}

		integrationWaitFor(t, 5*time.Second, func() bool {
			return len(rep.getCallbacks()) >= 3
		})

		cbs := rep.getCallbacks()
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

	// --- Invalid integrity: wrong checksum ---
	t.Run("invalid_integrity", func(t *testing.T) {
		req := api.ActionRequest{
			ExecutionID: "integ-integrity-002",
			Action:      "deploy",
			Timeout:     "30s",
			Checksum:    "0000000000000000000000000000000000000000000000000000000000000000",
		}
		if err := handler(context.Background(), integrationEnvelope(t, req)); err != nil {
			t.Fatalf("handler error: %v", err)
		}

		// The executor acks and starts, but runHook fails the integrity check.
		integrationWaitFor(t, 5*time.Second, func() bool {
			return len(reporter.getCallbacks()) >= 3
		})

		cbs := reporter.getCallbacks()
		assertStatuses(t, cbs, []string{
			api.ExecutionStatusAck,
			api.ExecutionStatusStarted,
			api.ExecutionStatusFailed,
		})
	})
}

// TestIntegration_ShutdownCancelsExecutions verifies that shutdown cancels
// running executions, reports cancelled terminal callbacks, and leaves no
// goroutine leaks. Goroutine leak detection is handled by goleak via TestMain.
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
	verifier := newRealVerifier(t)

	cfg := Config{
		Enabled:          boolPtr(true),
		HooksDir:         hooksDir,
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1 << 20,
	}
	exec := NewExecutor(cfg, reporter, verifier, integrationLogger())

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

	handler := HandleActionRequest(exec, "node-shutdown", integrationLogger())

	// Start a blocking builtin execution.
	req1 := api.ActionRequest{
		ExecutionID: "integ-shutdown-001",
		Action:      "block",
		Timeout:     "5m",
	}
	if err := handler(context.Background(), integrationEnvelope(t, req1)); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Wait for builtin to start.
	select {
	case <-builtinStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("builtin did not start")
	}

	// Start a blocking hook execution.
	req2 := api.ActionRequest{
		ExecutionID: "integ-shutdown-002",
		Action:      "blocking-hook",
		Timeout:     "5m",
		Checksum:    hookChecksum,
	}
	if err := handler(context.Background(), integrationEnvelope(t, req2)); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	// Wait for both to ack.
	integrationWaitFor(t, 5*time.Second, func() bool {
		return reporter.statusCount(api.ExecutionStatusAck) >= 2
	})

	if exec.ActiveCount() < 1 {
		t.Fatal("expected at least 1 active execution before shutdown")
	}

	// Shutdown cancels all active executions.
	exec.Shutdown(context.Background())

	// Wait for at least one cancelled terminal callback.
	integrationWaitFor(t, 10*time.Second, func() bool {
		return reporter.statusCount(api.ExecutionStatusCancelled) >= 1
	})

	// After shutdown, new requests should be rejected.
	req3 := api.ActionRequest{
		ExecutionID: "integ-shutdown-003",
		Action:      "block",
		Timeout:     "30s",
	}
	if err := handler(context.Background(), integrationEnvelope(t, req3)); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	integrationWaitFor(t, 5*time.Second, func() bool {
		for _, cb := range reporter.getCallbacks() {
			if cb.Status == api.ExecutionStatusFailed && cb.Error == "shutting_down" {
				return true
			}
		}
		return false
	})

	// Verify no active executions remain.
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count after shutdown = %d, want 0", got)
	}
}

// TestIntegration_WatcherFeedsExecutor verifies that HookWatcher dynamically
// updates the Executor's hooks list via the onChange → SetHooks integration.
func TestIntegration_WatcherFeedsExecutor(t *testing.T) {
	hooksDir := t.TempDir()

	reporter := &integrationReporter{}
	verifier := newRealVerifier(t)

	cfg := Config{
		Enabled:          boolPtr(true),
		HooksDir:         hooksDir,
		MaxConcurrent:    5,
		MaxActionTimeout: 10 * time.Minute,
		MaxOutputBytes:   1 << 20,
	}
	exec := NewExecutor(cfg, reporter, verifier, integrationLogger())

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

	// --- Execute the hook through the handler ---
	handler := HandleActionRequest(exec, "node-watcher", integrationLogger())
	req := api.ActionRequest{
		ExecutionID: "integ-watcher-001",
		Action:      "watcher-hook",
		Timeout:     "30s",
		Checksum:    hookChecksum,
	}
	if err := handler(context.Background(), integrationEnvelope(t, req)); err != nil {
		t.Fatalf("handler error: %v", err)
	}

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
