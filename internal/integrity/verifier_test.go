package integrity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter records the violations and the batches the Verifier reports.
type mockReporter struct {
	mu         sync.Mutex
	violations []api.IntegrityViolationReport
	batches    [][]api.IntegrityViolationReport
}

func (m *mockReporter) ReportViolations(_ context.Context, _ string, reports []api.IntegrityViolationReport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(reports) == 0 {
		return api.ErrIntegrityViolationsEmpty
	}
	m.violations = append(m.violations, reports...)
	m.batches = append(m.batches, slices.Clone(reports))
	return nil
}

func (m *mockReporter) get() []api.IntegrityViolationReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.IntegrityViolationReport, len(m.violations))
	copy(out, m.violations)
	return out
}

// getBatches returns one entry per request the reporter received, so a test can
// tell one batch of three violations from three batches of one.
func (m *mockReporter) getBatches() [][]api.IntegrityViolationReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]api.IntegrityViolationReport, len(m.batches))
	copy(out, m.batches)
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

// wireDigest converts a hex digest into the base64 form the contract's checksum
// fields carry, so an assertion can be written against the hex the test already
// computed.
func wireDigest(t *testing.T, hexDigest string) string {
	t.Helper()
	wire, err := WireChecksum(hexDigest)
	if err != nil {
		t.Fatalf("WireChecksum(%q): %v", hexDigest, err)
	}
	return wire
}

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
	if viol[0].Kind != api.IntegrityKindBinaryChecksum {
		t.Errorf("violation kind = %q, want %q", viol[0].Kind, api.IntegrityKindBinaryChecksum)
	}
	if want := wireDigest(t, oldChecksum); viol[0].ExpectedChecksum != want {
		t.Errorf("expected checksum = %q, want %q", viol[0].ExpectedChecksum, want)
	}
	if want := wireDigest(t, sha256Hex(binaryContent)); viol[0].ObservedChecksum != want {
		t.Errorf("observed checksum = %q, want %q", viol[0].ObservedChecksum, want)
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
	if viol[0].Kind != api.IntegrityKindHookChecksum {
		t.Errorf("violation kind = %q, want %q", viol[0].Kind, api.IntegrityKindHookChecksum)
	}
	if viol[0].DetectedBy != api.IntegrityDetectorPreDispatch {
		t.Errorf("detected_by = %q, want %q", viol[0].DetectedBy, api.IntegrityDetectorPreDispatch)
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
			if viol[0].Kind != api.IntegrityKindBinaryChecksum {
				t.Errorf("violation kind = %q, want %q", viol[0].Kind, api.IntegrityKindBinaryChecksum)
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
			for _, v := range viol {
				if v.Kind != api.IntegrityKindHookChecksum || v.ArtifactID != hookPath {
					continue
				}
				// The ticker is an hour out, so only the watcher can have
				// produced this — and the watcher's detector is inotify.
				if v.DetectedBy != api.IntegrityDetectorInotify {
					t.Errorf("detected_by = %q, want %q", v.DetectedBy, api.IntegrityDetectorInotify)
				}
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
	if viol[0].Kind != api.IntegrityKindHookChecksum {
		t.Errorf("violation kind = %q, want %q", viol[0].Kind, api.IntegrityKindHookChecksum)
	}
	if viol[0].ArtifactID != hookPath {
		t.Errorf("violation artifact_id = %q, want %q", viol[0].ArtifactID, hookPath)
	}
	// The exported sweep is the scanning detector; the watcher enters the same
	// sweep as inotify.
	if viol[0].DetectedBy != api.IntegrityDetectorStartupScan {
		t.Errorf("detected_by = %q, want %q", viol[0].DetectedBy, api.IntegrityDetectorStartupScan)
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

// ---------------------------------------------------------------------------
// Wire form
// ---------------------------------------------------------------------------

// TestVerifier_VerifyHooksDir_PinsWireBody drives two real tampered hooks
// through the reporter and compares the marshalled batch against the body the
// contract accepts, byte for byte. Every earlier test asserts a field; this one
// asserts the document, so a renamed key, a hex digest, or a resurrected
// timestamp fails here rather than at a control plane nobody is watching.
func TestVerifier_VerifyHooksDir_PinsWireBody(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Two hooks, both tampered, so the sweep has a batch to build.
	for _, name := range []string{"alpha.sh", "beta.sh"} {
		writeTempFile(t, hooksDir, name, "#!/bin/sh\necho tampered")
	}

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	for _, name := range []string{"alpha.sh", "beta.sh"} {
		if err := store.Set(filepath.Join(hooksDir, name), sha256Hex("#!/bin/sh\necho original")); err != nil {
			t.Fatalf("store set: %v", err)
		}
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	v.VerifyHooksDir(context.Background(), "node-1")

	batches := reporter.getBatches()
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1: the sweep must deliver its findings together", len(batches))
	}

	body, err := json.Marshal(api.IntegrityViolationsRequest{Violations: batches[0]})
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}

	observed := wireDigest(t, sha256Hex("#!/bin/sh\necho tampered"))
	expected := wireDigest(t, sha256Hex("#!/bin/sh\necho original"))
	// The artifact id is a filesystem path. On Windows it contains backslashes,
	// which JSON escapes, so the expectation has to encode it the way the wire
	// body does instead of pasting it into the literal.
	artifactID := func(name string) string {
		encoded, err := json.Marshal(filepath.Join(hooksDir, name))
		if err != nil {
			t.Fatalf("marshal artifact id for %q: %v", name, err)
		}
		return string(encoded)
	}
	want := `{"violations":[` +
		`{"kind":"hook_checksum","detected_by":"startup_scan","artifact_id":` +
		artifactID("alpha.sh") + `,"observed_checksum":"` + observed +
		`","expected_checksum":"` + expected + `"},` +
		`{"kind":"hook_checksum","detected_by":"startup_scan","artifact_id":` +
		artifactID("beta.sh") + `,"observed_checksum":"` + observed +
		`","expected_checksum":"` + expected + `"}]}`
	if string(body) != want {
		t.Errorf("wire body =\n  %s\nwant\n  %s", body, want)
	}
}

// TestVerifier_VerifyHooksDir_DropsEntryWithUnconvertibleDigest pins the rule
// declaredHooks already uses for the capability manifest: a digest that will not
// re-encode costs its own entry, not the batch it travels in.
func TestVerifier_VerifyHooksDir_DropsEntryWithUnconvertibleDigest(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTempFile(t, hooksDir, "good.sh", "#!/bin/sh\necho tampered")
	writeTempFile(t, hooksDir, "bad.sh", "#!/bin/sh\necho tampered")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	goodPath := filepath.Join(hooksDir, "good.sh")
	if err := store.Set(goodPath, sha256Hex("#!/bin/sh\necho original")); err != nil {
		t.Fatalf("store set: %v", err)
	}
	// A baseline that is not a SHA-256 hex digest, as a store written by an
	// older agent or a hand-edited checksums.json could hold.
	if err := store.Set(filepath.Join(hooksDir, "bad.sh"), "not-a-digest"); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	v.VerifyHooksDir(context.Background(), "node-1")

	viol := reporter.get()
	if len(viol) != 1 {
		t.Fatalf("got %d violations, want 1: the unconvertible entry drops, the batch survives", len(viol))
	}
	if viol[0].ArtifactID != goodPath {
		t.Errorf("surviving violation = %q, want %q", viol[0].ArtifactID, goodPath)
	}
}

// ---------------------------------------------------------------------------
// SSH host key
// ---------------------------------------------------------------------------

// writeHostKey generates an Ed25519 host key, writes it to dir in the OpenSSH
// PEM form LoadOrGenerateHostKey persists, and returns its path and canonical
// fingerprint.
func writeHostKey(t *testing.T, dir, name string) (path, fingerprint string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal host key: %v", err)
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return path, ssh.FingerprintSHA256(sshPub)
}

func TestVerifier_VerifyHostKey_EstablishesBaseline(t *testing.T) {
	dir := t.TempDir()
	keyPath, fingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
		HostKeyPath:    keyPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if err := v.VerifyHostKey(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify host key: %v", err)
	}
	if got := store.Get(keyPath); got != fingerprint {
		t.Errorf("baseline = %q, want %q", got, fingerprint)
	}
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations on first run: %v", viol)
	}

	// A second pass over the unchanged key verifies and reports nothing.
	if err := v.VerifyHostKey(context.Background(), "node-1"); err != nil {
		t.Fatalf("re-verify host key: %v", err)
	}
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations for an unchanged key: %v", viol)
	}
}

func TestVerifier_VerifyHostKey_DetectsRotation(t *testing.T) {
	dir := t.TempDir()
	keyPath, oldFingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(keyPath, oldFingerprint); err != nil {
		t.Fatalf("store set: %v", err)
	}

	// Replace the key under the running agent.
	_, newFingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")
	if newFingerprint == oldFingerprint {
		t.Fatal("regenerated host key kept its fingerprint")
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
		HostKeyPath:    keyPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if err := v.VerifyHostKey(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify host key: %v", err)
	}

	viol := reporter.get()
	if len(viol) != 1 {
		t.Fatalf("got %d violations, want 1", len(viol))
	}
	want := api.IntegrityViolationReport{
		Kind:                api.IntegrityKindSSHHostKey,
		DetectedBy:          api.IntegrityDetectorStartupScan,
		ArtifactID:          keyPath,
		ObservedFingerprint: newFingerprint,
		ExpectedFingerprint: oldFingerprint,
	}
	if viol[0] != want {
		t.Errorf("violation = %+v, want %+v", viol[0], want)
	}
}

func TestVerifier_VerifyHostKey_NoKeyIsNoOp(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}

	tests := []struct {
		name string
		path string
	}{
		{"unconfigured", ""},
		{"absent file", filepath.Join(dir, "ssh_host_ed25519_key")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(Config{
				Enabled:        true,
				BinaryPath:     filepath.Join(dir, "plexd"),
				HostKeyPath:    tt.path,
				VerifyInterval: DefaultVerifyInterval,
			}, store, reporter, slog.Default())

			if err := v.VerifyHostKey(context.Background(), "node-1"); err != nil {
				t.Fatalf("verify host key: %v", err)
			}
			if viol := reporter.get(); len(viol) != 0 {
				t.Errorf("unexpected violations: %v", viol)
			}
		})
	}
}
