package integrity

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter records violations reported by the Verifier.
type mockReporter struct {
	mu         sync.Mutex
	violations []api.IntegrityViolationReport
}

func (m *mockReporter) ReportViolation(_ context.Context, _ string, report api.IntegrityViolationReport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.violations = append(m.violations, report)
	return nil
}

func (m *mockReporter) get() []api.IntegrityViolationReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.IntegrityViolationReport, len(m.violations))
	copy(out, m.violations)
	return out
}

// writeTempFile creates a file in dir with the given content and returns its path.
func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

// sha256Hex is defined in checker_test.go.

func TestVerifier_StartupVerification_NoBaseline(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "binary-v1"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)
	expectedChecksum := sha256Hex(binaryContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if err := v.VerifyBinary(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	// Baseline should be stored.
	if got := store.Get(binaryPath); got != expectedChecksum {
		t.Errorf("stored baseline = %q, want %q", got, expectedChecksum)
	}

	// No violations should be reported.
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations: %v", viol)
	}

	// BinaryChecksum should be set.
	if got := v.BinaryChecksum(); got != expectedChecksum {
		t.Errorf("BinaryChecksum() = %q, want %q", got, expectedChecksum)
	}
}

func TestVerifier_StartupVerification_MatchingBaseline(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "binary-v1"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)
	expectedChecksum := sha256Hex(binaryContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(binaryPath, expectedChecksum); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if err := v.VerifyBinary(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	// No violations.
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations: %v", viol)
	}
}

func TestVerifier_StartupVerification_MismatchedBaseline(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "binary-v2-tampered"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	// Store a different baseline.
	oldChecksum := sha256Hex("binary-v1-original")
	if err := store.Set(binaryPath, oldChecksum); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if err := v.VerifyBinary(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	// A violation should be reported.
	viol := reporter.get()
	if len(viol) != 1 {
		t.Fatalf("got %d violations, want 1", len(viol))
	}
	if viol[0].Type != "binary" {
		t.Errorf("violation type = %q, want %q", viol[0].Type, "binary")
	}
	if viol[0].ExpectedChecksum != oldChecksum {
		t.Errorf("expected checksum = %q, want %q", viol[0].ExpectedChecksum, oldChecksum)
	}
	actualChecksum := sha256Hex(binaryContent)
	if viol[0].ActualChecksum != actualChecksum {
		t.Errorf("actual checksum = %q, want %q", viol[0].ActualChecksum, actualChecksum)
	}
}

func TestVerifier_VerifyHook_Matching(t *testing.T) {
	dir := t.TempDir()
	hookContent := "#!/bin/sh\necho hello"
	hookPath := writeTempFile(t, dir, "hook.sh", hookContent)
	expectedChecksum := sha256Hex(hookContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     filepath.Join(dir, "plexd"),
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	ok, err := v.VerifyHook(context.Background(), "node-1", hookPath, expectedChecksum)
	if err != nil {
		t.Fatalf("verify hook: %v", err)
	}
	if !ok {
		t.Error("expected hook verification to pass")
	}
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations: %v", viol)
	}
}

func TestVerifier_VerifyHook_Mismatched(t *testing.T) {
	dir := t.TempDir()
	hookContent := "#!/bin/sh\necho tampered"
	hookPath := writeTempFile(t, dir, "hook.sh", hookContent)
	wrongChecksum := sha256Hex("#!/bin/sh\necho original")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     filepath.Join(dir, "plexd"),
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	ok, err := v.VerifyHook(context.Background(), "node-1", hookPath, wrongChecksum)
	if err != nil {
		t.Fatalf("verify hook: %v", err)
	}
	if ok {
		t.Error("expected hook verification to fail")
	}

	viol := reporter.get()
	if len(viol) != 1 {
		t.Fatalf("got %d violations, want 1", len(viol))
	}
	if viol[0].Type != "hook" {
		t.Errorf("violation type = %q, want %q", viol[0].Type, "hook")
	}
}

func TestVerifier_VerifyHook_EmptyChecksum(t *testing.T) {
	dir := t.TempDir()
	hookPath := writeTempFile(t, dir, "hook.sh", "#!/bin/sh")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     filepath.Join(dir, "plexd"),
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	_, err = v.VerifyHook(context.Background(), "node-1", hookPath, "")
	if err == nil {
		t.Fatal("expected error for empty expected checksum")
	}
}

func TestVerifier_BinaryChecksum(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "binary-checksum-test"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)
	expectedChecksum := sha256Hex(binaryContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	// Run startup verification.
	if err := v.VerifyBinary(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	if got := v.BinaryChecksum(); got != expectedChecksum {
		t.Errorf("BinaryChecksum() = %q, want %q", got, expectedChecksum)
	}
}

func TestVerifier_BinaryChecksum_BeforeVerification(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     filepath.Join(dir, "plexd"),
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if got := v.BinaryChecksum(); got != "" {
		t.Errorf("BinaryChecksum() before verification = %q, want empty", got)
	}
}

func TestVerifier_Disabled(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled: false,
	}, store, reporter, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run should return immediately when disabled.
	if err := v.Run(ctx, "node-1"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// No violations, no checksum computed.
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations: %v", viol)
	}
	if got := v.BinaryChecksum(); got != "" {
		t.Errorf("BinaryChecksum() = %q, want empty when disabled", got)
	}
}

func TestVerifier_PeriodicRun_DetectsTampering(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "binary-original"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: 50 * time.Millisecond, // short for test
	}, store, reporter, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run startup verification first to establish baseline.
	if err := v.VerifyBinary(ctx, "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	// Tamper with the binary.
	if err := os.WriteFile(binaryPath, []byte("binary-tampered"), 0o644); err != nil {
		t.Fatalf("tamper binary: %v", err)
	}

	// Start periodic loop in a goroutine.
	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-1")
	}()

	// Wait for at least one periodic check to detect the tampering.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for violation to be detected")
		default:
		}
		if viol := reporter.get(); len(viol) > 0 {
			if viol[0].Type != "binary" {
				t.Errorf("violation type = %q, want %q", viol[0].Type, "binary")
			}
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestVerifier_WatchHooksDir_DetectsChange(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	binaryPath := writeTempFile(t, dir, "plexd", "binary-content")

	// Create an initial hook file.
	hookContent := "#!/bin/sh\necho original"
	writeTempFile(t, hooksDir, "test-hook.sh", hookContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// Store the original baseline for the hook.
	hookPath := filepath.Join(hooksDir, "test-hook.sh")
	originalChecksum := sha256Hex(hookContent)
	if err := store.Set(hookPath, originalChecksum); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		HooksDir:       hooksDir,
		VerifyInterval: 1 * time.Hour, // long interval; we rely on the watcher
		WatchEnabled:   true,
	}, store, reporter, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the verifier (which starts the watcher goroutine).
	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-1")
	}()

	// Give watcher time to initialize.
	time.Sleep(200 * time.Millisecond)

	// Modify the hook file.
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho tampered"), 0o644); err != nil {
		t.Fatalf("write tampered hook: %v", err)
	}

	// Wait for the watcher to detect the change and report a violation.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for hook violation from watcher")
		default:
		}
		if viol := reporter.get(); len(viol) > 0 {
			found := false
			for _, v := range viol {
				if v.Type == "hook" && v.Path == hookPath {
					found = true
					break
				}
			}
			if found {
				cancel()
				<-done
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestVerifier_VerifyHooksDir_NoViolation(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	binaryPath := writeTempFile(t, dir, "plexd", "binary-content")
	hookContent := "#!/bin/sh\necho hello"
	writeTempFile(t, hooksDir, "hook.sh", hookContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// Store matching baseline.
	hookPath := filepath.Join(hooksDir, "hook.sh")
	if err := store.Set(hookPath, sha256Hex(hookContent)); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	v.VerifyHooksDir(context.Background(), "node-1")

	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations: %v", viol)
	}
}

func TestVerifier_VerifyHooksDir_DetectsViolation(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	binaryPath := writeTempFile(t, dir, "plexd", "binary-content")
	writeTempFile(t, hooksDir, "hook.sh", "#!/bin/sh\necho tampered")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	// Store a different baseline.
	hookPath := filepath.Join(hooksDir, "hook.sh")
	if err := store.Set(hookPath, sha256Hex("#!/bin/sh\necho original")); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	v.VerifyHooksDir(context.Background(), "node-1")

	viol := reporter.get()
	if len(viol) != 1 {
		t.Fatalf("got %d violations, want 1", len(viol))
	}
	if viol[0].Type != "hook" {
		t.Errorf("violation type = %q, want %q", viol[0].Type, "hook")
	}
	if viol[0].Path != hookPath {
		t.Errorf("violation path = %q, want %q", viol[0].Path, hookPath)
	}
}

func TestVerifier_PeriodicRun_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "binary-cancel-test"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: 1 * time.Hour, // long interval; we cancel quickly
	}, store, reporter, slog.Default())

	// Run startup verification.
	if err := v.VerifyBinary(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-1")
	}()

	// Cancel after a short delay.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after context cancellation")
	}
}
