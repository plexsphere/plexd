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

// integrationReporter is a thread-safe mock reporter for integration tests.
type integrationReporter struct {
	mu      sync.Mutex
	acks    []api.ExecutionAck
	results []api.ExecutionResult
}

func (r *integrationReporter) AckExecution(_ context.Context, _, _ string, ack api.ExecutionAck) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acks = append(r.acks, ack)
	return nil
}

func (r *integrationReporter) ReportResult(_ context.Context, _, _ string, result api.ExecutionResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, result)
	return nil
}

func (r *integrationReporter) getAcks() []api.ExecutionAck {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]api.ExecutionAck, len(r.acks))
	copy(cp, r.acks)
	return cp
}

func (r *integrationReporter) getResults() []api.ExecutionResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]api.ExecutionResult, len(r.results))
	copy(cp, r.results)
	return cp
}

func (r *integrationReporter) ackCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.acks)
}

func (r *integrationReporter) resultCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.results)
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

func integrationEnvelope(t *testing.T, req api.ActionRequest) api.SignedEnvelope {
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

// TestIntegration_FullActionLifecycle tests the full lifecycle:
// action_request → ack → execute → result reported.
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
		Enabled:          true,
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
			return reporter.resultCount() > 0
		})

		acks := reporter.getAcks()
		results := reporter.getResults()

		if len(acks) < 1 {
			t.Fatal("no acks received for builtin")
		}
		if acks[0].Status != "accepted" {
			t.Errorf("builtin ack status = %q, want accepted", acks[0].Status)
		}
		if acks[0].ExecutionID != "integ-builtin-001" {
			t.Errorf("builtin ack execution_id = %q, want integ-builtin-001", acks[0].ExecutionID)
		}

		if len(results) < 1 {
			t.Fatal("no results received for builtin")
		}
		if results[0].Status != "success" {
			t.Errorf("builtin result status = %q, want success", results[0].Status)
		}
		if results[0].ExitCode != 0 {
			t.Errorf("builtin exit_code = %d, want 0", results[0].ExitCode)
		}
		if !strings.Contains(results[0].Stdout, "status") {
			t.Errorf("builtin stdout = %q, expected to contain 'status'", results[0].Stdout)
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
			return reporter2.resultCount() > 0
		})

		acks := reporter2.getAcks()
		results := reporter2.getResults()

		if len(acks) < 1 {
			t.Fatal("no acks received for hook")
		}
		if acks[0].Status != "accepted" {
			t.Errorf("hook ack status = %q, want accepted", acks[0].Status)
		}

		if len(results) < 1 {
			t.Fatal("no results received for hook")
		}
		if results[0].Status != "success" {
			t.Errorf("hook result status = %q, want success", results[0].Status)
		}
		if results[0].ExitCode != 0 {
			t.Errorf("hook exit_code = %d, want 0", results[0].ExitCode)
		}
		if !strings.Contains(results[0].Stdout, "hook-lifecycle-output") {
			t.Errorf("hook stdout = %q, want to contain 'hook-lifecycle-output'", results[0].Stdout)
		}
		if results[0].Duration == "" {
			t.Error("hook result duration is empty")
		}
		if results[0].FinishedAt.IsZero() {
			t.Error("hook result finished_at is zero")
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
		Enabled:          true,
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

	// Wait for all acks and results to arrive.
	integrationWaitFor(t, 10*time.Second, func() bool {
		return reporter.ackCount() >= totalRequests
	})

	// Wait for all results (accepted ones complete, rejected ones don't produce results).
	acks := reporter.getAcks()
	acceptedCount := 0
	rejectedCount := 0
	for _, ack := range acks {
		switch ack.Status {
		case "accepted":
			acceptedCount++
		case "rejected":
			rejectedCount++
			if ack.Reason != "max_concurrent_reached" {
				t.Errorf("rejected reason = %q, want max_concurrent_reached", ack.Reason)
			}
		default:
			t.Errorf("unexpected ack status = %q", ack.Status)
		}
	}

	if acceptedCount+rejectedCount != totalRequests {
		t.Errorf("total acks = %d, want %d", acceptedCount+rejectedCount, totalRequests)
	}
	if acceptedCount > maxConcurrent+1 {
		// Some concurrency overlap is possible since hooks complete quickly (0.1s).
		// But we should never exceed the limit by a lot.
		t.Errorf("accepted = %d, maxConcurrent = %d (should not wildly exceed)", acceptedCount, maxConcurrent)
	}

	// Wait for all accepted executions to produce results.
	integrationWaitFor(t, 10*time.Second, func() bool {
		return reporter.resultCount() >= acceptedCount
	})

	results := reporter.getResults()
	for _, r := range results {
		if r.Status != "success" {
			t.Errorf("result %q status = %q, want success", r.ExecutionID, r.Status)
		}
	}
}

// TestIntegration_HookIntegrityAndExecution tests hook discovery, real integrity
// verification, parameter passing as env vars, and result reporting.
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
		Enabled:          true,
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
			return rep.resultCount() > 0
		})

		acks := rep.getAcks()
		results := rep.getResults()

		if len(acks) < 1 || acks[0].Status != "accepted" {
			t.Fatalf("expected accepted ack, got %v", acks)
		}
		if len(results) < 1 {
			t.Fatal("no results")
		}
		if results[0].Status != "success" {
			t.Errorf("result status = %q, want success", results[0].Status)
		}
		stdout := strings.TrimSpace(results[0].Stdout)
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

		// The executor accepts (hook is in list), but runHook fails integrity check.
		integrationWaitFor(t, 5*time.Second, func() bool {
			return reporter.resultCount() > 0
		})

		results := reporter.getResults()
		if len(results) < 1 {
			t.Fatal("no results")
		}
		if results[0].Status != "error" {
			t.Errorf("result status = %q, want error", results[0].Status)
		}
	})
}

// TestIntegration_ShutdownCancelsExecutions verifies that shutdown cancels
// running executions, reports cancelled results, and leaves no goroutine leaks.
// Goroutine leak detection is handled by goleak via TestMain.
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
		Enabled:          true,
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

	// Wait for both to be accepted.
	integrationWaitFor(t, 5*time.Second, func() bool {
		return reporter.ackCount() >= 2
	})

	acks := reporter.getAcks()
	for _, ack := range acks {
		if ack.Status != "accepted" {
			t.Errorf("ack %q status = %q, want accepted", ack.ExecutionID, ack.Status)
		}
	}

	if exec.ActiveCount() < 1 {
		t.Fatal("expected at least 1 active execution before shutdown")
	}

	// Shutdown cancels all active executions.
	exec.Shutdown(context.Background())

	// Wait for results from both cancelled executions.
	integrationWaitFor(t, 10*time.Second, func() bool {
		return reporter.resultCount() >= 2
	})

	results := reporter.getResults()
	cancelledCount := 0
	for _, r := range results {
		if r.Status == "cancelled" {
			cancelledCount++
		}
	}
	if cancelledCount < 1 {
		t.Errorf("expected at least 1 cancelled result, got %d out of %v", cancelledCount, results)
	}

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
		acks := reporter.getAcks()
		for _, a := range acks {
			if a.ExecutionID == "integ-shutdown-003" && a.Status == "rejected" {
				return true
			}
		}
		return false
	})

	acks = reporter.getAcks()
	var postShutdownAck *api.ExecutionAck
	for i := range acks {
		if acks[i].ExecutionID == "integ-shutdown-003" {
			postShutdownAck = &acks[i]
			break
		}
	}
	if postShutdownAck == nil {
		t.Fatal("no ack for post-shutdown request")
	}
	if postShutdownAck.Status != "rejected" {
		t.Errorf("post-shutdown ack status = %q, want rejected", postShutdownAck.Status)
	}
	if postShutdownAck.Reason != "shutting_down" {
		t.Errorf("post-shutdown ack reason = %q, want shutting_down", postShutdownAck.Reason)
	}

	// Verify no active executions remain.
	if got := exec.ActiveCount(); got != 0 {
		t.Errorf("active count after shutdown = %d, want 0", got)
	}
}

