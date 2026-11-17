package integrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/fsutil"
)

// mockReporter records the violations and the batches the Verifier reports.
// violations and batches hold what it accepted; attempts holds every batch it
// was sent, refused ones included.
type mockReporter struct {
	mu         sync.Mutex
	violations []api.IntegrityViolationReport
	batches    [][]api.IntegrityViolationReport
	attempts   [][]api.IntegrityViolationReport

	// errs is consumed one entry per call: a non-nil entry is returned and
	// the batch is recorded as an attempt only. Calls past its end succeed.
	errs []error

	// hold, when set, runs at the start of every call, outside mu, so a test
	// can keep a call open inside ReportViolations.
	hold func()
}

func (m *mockReporter) ReportViolations(_ context.Context, _ string, reports []api.IntegrityViolationReport) error {
	if m.hold != nil {
		m.hold()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(reports) == 0 {
		return api.ErrIntegrityViolationsEmpty
	}
	m.attempts = append(m.attempts, slices.Clone(reports))
	if len(m.errs) > 0 {
		err := m.errs[0]
		m.errs = m.errs[1:]
		if err != nil {
			return err
		}
	}
	m.violations = append(m.violations, reports...)
	m.batches = append(m.batches, slices.Clone(reports))
	return nil
}

// getAttempts returns one entry per call, accepted or refused.
func (m *mockReporter) getAttempts() [][]api.IntegrityViolationReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]api.IntegrityViolationReport, len(m.attempts))
	copy(out, m.attempts)
	return out
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
	// The expected value is the executor's pin, not a stored baseline, so an
	// accepted report adopts nothing.
	if got := store.Get(hookPath); got != "" {
		t.Errorf("store.Get(hookPath) = %q, want empty: VerifyHook must not write the store", got)
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
		BinaryPath:     filepath.Join(dir, "plexd"),
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	if got := v.BinaryChecksum(); got != "" {
		t.Errorf("BinaryChecksum() before verification = %q, want empty", got)
	}
}

func TestVerifier_Disabled(t *testing.T) {
	dir := t.TempDir()
	binaryPath := writeTempFile(t, dir, "plexd", "binary-content")
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		Enabled:        boolPtr(false),
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run should return immediately when disabled.
	if err := v.Run(ctx, "node-1"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// No violations, no checksum computed, no baseline stored.
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations: %v", viol)
	}
	if got := v.BinaryChecksum(); got != "" {
		t.Errorf("BinaryChecksum() = %q, want empty when disabled", got)
	}
	if got := store.Get(binaryPath); got != "" {
		t.Errorf("binary baseline = %q, want none when disabled", got)
	}
}

// startRun runs v.Run in a goroutine and returns a stop func that cancels it
// and waits for Run to return. The stop func is also a cleanup, so a test that
// fails before calling it leaves no goroutine behind for goleak.
func startRun(t *testing.T, v *Verifier) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-1")
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Run did not return after cancel")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// waitFor polls cond until it holds, failing the test when timeout passes
// first.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// replaceAtomically swaps the content of path in one rename, so a pass that
// runs at the same moment reads the old file or the new one, never a torn one.
func replaceAtomically(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := fsutil.WriteFileAtomic(filepath.Dir(path), filepath.Base(path), data, 0o600); err != nil {
		t.Fatalf("replace %s: %v", path, err)
	}
}

// logRecords decodes the lines a slog.JSONHandler wrote into logs and returns
// those whose message is msg. Decoding, rather than searching the text, keeps
// a Windows path inside a quoted error value comparable.
func logRecords(t *testing.T, logs *syncBuffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// jsonLogger returns a logger that writes JSON lines into logs.
func jsonLogger(logs *syncBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(logs, nil))
}

// TestVerifier_PeriodicRun_DetectsTampering changes the binary only after the
// startup pass has stored its baseline, so the violation can come from a tick
// alone.
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
		Enabled:        boolPtr(true),
		BinaryPath:     binaryPath,
		VerifyInterval: 50 * time.Millisecond, // short for test
	}, store, reporter, slog.Default())

	stop := startRun(t, v)

	// The startup pass establishes the baseline from an empty store.
	waitFor(t, 2*time.Second, "the binary baseline", func() bool {
		return store.Get(binaryPath) == sha256Hex(binaryContent)
	})

	// Tamper with the binary.
	replaceAtomically(t, binaryPath, []byte("binary-tampered"))

	// Wait for a periodic check to detect the tampering.
	waitFor(t, 2*time.Second, "the binary violation", func() bool {
		return len(reporter.get()) > 0
	})
	stop()

	viol := reporter.get()
	want := api.IntegrityViolationReport{
		Kind:             api.IntegrityKindBinaryChecksum,
		DetectedBy:       api.IntegrityDetectorStartupScan,
		ArtifactID:       binaryPath,
		ObservedChecksum: wireDigest(t, sha256Hex("binary-tampered")),
		ExpectedChecksum: wireDigest(t, sha256Hex(binaryContent)),
	}
	if viol[0] != want {
		t.Errorf("violation = %+v, want %+v", viol[0], want)
	}
}

// TestVerifier_PeriodicRun_DetectsHostKeyChange replaces the host key after the
// startup pass stored its fingerprint, and expects a tick to report the old and
// the new fingerprint.
func TestVerifier_PeriodicRun_DetectsHostKeyChange(t *testing.T) {
	dir := t.TempDir()
	keyPath, oldFingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
		HostKeyPath:    keyPath,
		VerifyInterval: 50 * time.Millisecond,
	}, store, reporter, slog.Default())

	stop := startRun(t, v)

	waitFor(t, 2*time.Second, "the host key baseline", func() bool {
		return store.Get(keyPath) == oldFingerprint
	})

	// Generate the replacement elsewhere and swap it in with one rename.
	newPath, newFingerprint := writeHostKey(t, t.TempDir(), "ssh_host_ed25519_key")
	if newFingerprint == oldFingerprint {
		t.Fatal("regenerated host key kept its fingerprint")
	}
	newKey, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("read new host key: %v", err)
	}
	replaceAtomically(t, keyPath, newKey)

	waitFor(t, 2*time.Second, "the host key violation", func() bool {
		return len(reporter.get()) > 0
	})
	stop()

	want := api.IntegrityViolationReport{
		Kind:                api.IntegrityKindSSHHostKey,
		DetectedBy:          api.IntegrityDetectorStartupScan,
		ArtifactID:          keyPath,
		ObservedFingerprint: newFingerprint,
		ExpectedFingerprint: oldFingerprint,
	}
	if got := reporter.get()[0]; got != want {
		t.Errorf("violation = %+v, want %+v", got, want)
	}
}

// TestVerifier_Run_VerifiesAtStartup gives Run an interval no test waits for,
// so both violations can only come from the pass Run makes at start.
func TestVerifier_Run_VerifiesAtStartup(t *testing.T) {
	dir := t.TempDir()
	binaryPath := writeTempFile(t, dir, "plexd", "binary-v2")
	keyPath, fingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")
	_, oldFingerprint := writeHostKey(t, t.TempDir(), "ssh_host_ed25519_key")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(binaryPath, sha256Hex("binary-v1")); err != nil {
		t.Fatalf("store set: %v", err)
	}
	if err := store.Set(keyPath, oldFingerprint); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	v := NewVerifier(Config{
		BinaryPath:     binaryPath,
		HostKeyPath:    keyPath,
		VerifyInterval: time.Hour,
	}, store, reporter, slog.Default())

	stop := startRun(t, v)
	waitFor(t, 3*time.Second, "both startup violations", func() bool {
		return len(reporter.get()) >= 2
	})
	stop()

	want := []api.IntegrityViolationReport{
		{
			Kind:             api.IntegrityKindBinaryChecksum,
			DetectedBy:       api.IntegrityDetectorStartupScan,
			ArtifactID:       binaryPath,
			ObservedChecksum: wireDigest(t, sha256Hex("binary-v2")),
			ExpectedChecksum: wireDigest(t, sha256Hex("binary-v1")),
		},
		{
			Kind:                api.IntegrityKindSSHHostKey,
			DetectedBy:          api.IntegrityDetectorStartupScan,
			ArtifactID:          keyPath,
			ObservedFingerprint: fingerprint,
			ExpectedFingerprint: oldFingerprint,
		},
	}
	if got := reporter.get(); !slices.Equal(got, want) {
		t.Errorf("violations = %+v, want %+v", got, want)
	}
}

// TestVerifier_Run_EstablishesBaselinesSilently starts Run on an empty store:
// the startup pass stores what it finds and has nothing to report.
func TestVerifier_Run_EstablishesBaselinesSilently(t *testing.T) {
	dir := t.TempDir()
	binaryPath := writeTempFile(t, dir, "plexd", "binary-content")
	keyPath, fingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	v := NewVerifier(Config{
		BinaryPath:     binaryPath,
		HostKeyPath:    keyPath,
		VerifyInterval: time.Hour,
	}, store, reporter, slog.Default())

	stop := startRun(t, v)
	waitFor(t, 3*time.Second, "both baselines", func() bool {
		return store.Get(binaryPath) != "" && store.Get(keyPath) != ""
	})
	stop()

	if got, want := store.Get(binaryPath), sha256Hex("binary-content"); got != want {
		t.Errorf("binary baseline = %q, want %q", got, want)
	}
	if got := store.Get(keyPath); got != fingerprint {
		t.Errorf("host key baseline = %q, want %q", got, fingerprint)
	}
	if got, want := v.BinaryChecksum(), sha256Hex("binary-content"); got != want {
		t.Errorf("BinaryChecksum() = %q, want %q", got, want)
	}
	if batches := reporter.getBatches(); len(batches) != 0 {
		t.Errorf("reporter received %d batches, want none: %v", len(batches), batches)
	}
}

// TestVerifier_Run_StartsNoWatcherWithoutHooksDirOrWatch pins the opt-in: the
// watcher needs both a hooks directory and the watch switch. The last case is
// the control that shows the counting seam is reached when both are given.
func TestVerifier_Run_StartsNoWatcherWithoutHooksDirOrWatch(t *testing.T) {
	tests := []struct {
		name      string
		hooksDir  bool
		watch     *bool
		wantCalls int32
	}{
		{"no hooks dir", false, nil, 0},
		{"watch disabled", true, boolPtr(false), 0},
		{"hooks dir and watch", true, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			binaryPath := writeTempFile(t, dir, "plexd", "binary-content")
			cfg := Config{
				BinaryPath:     binaryPath,
				VerifyInterval: time.Hour,
				WatchEnabled:   tt.watch,
			}
			if tt.hooksDir {
				cfg.HooksDir = filepath.Join(dir, "hooks")
			}
			store, err := NewStore(dir)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			v := NewVerifier(cfg, store, &mockReporter{}, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))
			var calls atomic.Int32
			v.watchDir = func(context.Context, string, func(error)) (*fsnotify.Watcher, error) {
				calls.Add(1)
				return nil, errors.New("counting seam: no watch")
			}

			stop := startRun(t, v)
			waitFor(t, 3*time.Second, "the startup pass", func() bool {
				return store.Get(binaryPath) != ""
			})
			// Run returns only after its watcher, so the count is final.
			stop()

			if got := calls.Load(); got != tt.wantCalls {
				t.Errorf("watchDir calls = %d, want %d", got, tt.wantCalls)
			}
		})
	}
}

// TestVerifier_Run_ContinuesPastAnUnreadableBinary starts Run against a binary
// path that names no file: the failure is logged, and the host key in the same
// pass is still checked and reported.
func TestVerifier_Run_ContinuesPastAnUnreadableBinary(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "plexd")
	keyPath, fingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")
	_, oldFingerprint := writeHostKey(t, t.TempDir(), "ssh_host_ed25519_key")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(keyPath, oldFingerprint); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{}
	logs := &syncBuffer{}
	v := NewVerifier(Config{
		BinaryPath:     missing,
		HostKeyPath:    keyPath,
		VerifyInterval: time.Hour,
	}, store, reporter, jsonLogger(logs))

	stop := startRun(t, v)
	waitFor(t, 3*time.Second, "the host key violation", func() bool {
		return len(reporter.get()) > 0
	})
	stop()

	want := api.IntegrityViolationReport{
		Kind:                api.IntegrityKindSSHHostKey,
		DetectedBy:          api.IntegrityDetectorStartupScan,
		ArtifactID:          keyPath,
		ObservedFingerprint: fingerprint,
		ExpectedFingerprint: oldFingerprint,
	}
	if got := reporter.get(); len(got) != 1 || got[0] != want {
		t.Errorf("violations = %+v, want [%+v]", got, want)
	}

	// The platform's own text for a missing file, so the test reads the same
	// on every OS.
	_, openErr := os.Open(missing)
	var pathErr *fs.PathError
	if !errors.As(openErr, &pathErr) {
		t.Fatalf("os.Open(%q) = %v, want a *fs.PathError", missing, openErr)
	}
	recs := logRecords(t, logs, "binary verification failed")
	if len(recs) != 1 {
		t.Fatalf("binary verification failed logged %d times, want 1 (log %s)", len(recs), logs.String())
	}
	if level := recs[0]["level"]; level != "ERROR" {
		t.Errorf("level = %v, want ERROR", level)
	}
	errText, _ := recs[0]["error"].(string)
	if !strings.Contains(errText, "integrity: open "+missing) || !strings.Contains(errText, pathErr.Err.Error()) {
		t.Errorf("error = %q, want it to contain %q and %q", errText, "integrity: open "+missing, pathErr.Err.Error())
	}
}

// TestVerifier_Run_ContinuesPastAnUnparsableHostKey gives Run a host key file
// that holds no private key: each pass logs the failure, and the loop keeps
// ticking.
func TestVerifier_Run_ContinuesPastAnUnparsableHostKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTempFile(t, dir, "ssh_host_ed25519_key", "not a private key")
	binaryPath := writeTempFile(t, dir, "plexd", "binary-content")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	logs := &syncBuffer{}
	v := NewVerifier(Config{
		BinaryPath:     binaryPath,
		HostKeyPath:    keyPath,
		VerifyInterval: 50 * time.Millisecond,
	}, store, &mockReporter{}, jsonLogger(logs))

	stop := startRun(t, v)
	// The startup pass logs the first failure; a second one can only come
	// from a tick.
	waitFor(t, 3*time.Second, "two failed host key checks", func() bool {
		return len(logRecords(t, logs, "host key verification failed")) >= 2
	})
	stop()

	rec := logRecords(t, logs, "host key verification failed")[0]
	if level := rec["level"]; level != "ERROR" {
		t.Errorf("level = %v, want ERROR", level)
	}
	errText, _ := rec["error"].(string)
	if want := "integrity: parse host key " + keyPath; !strings.Contains(errText, want) {
		t.Errorf("error = %q, want it to contain %q", errText, want)
	}
	if got := store.Get(keyPath); got != "" {
		t.Errorf("host key baseline = %q, want none for an unparsable key", got)
	}
	if got := store.Get(binaryPath); got == "" {
		t.Error("binary baseline missing: the pass must not stop at the host key")
	}
}

// TestVerifier_Run_WaitsForTheWatcher holds the watcher's setup open past the
// cancellation: Run must not return before it has.
func TestVerifier_Run_WaitsForTheWatcher(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	v := NewVerifier(Config{
		BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
		HooksDir:       filepath.Join(dir, "hooks"),
		VerifyInterval: time.Hour,
	}, store, &mockReporter{}, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))

	entered := make(chan struct{})
	var returned atomic.Bool
	v.watchDir = func(ctx context.Context, _ string, _ func(error)) (*fsnotify.Watcher, error) {
		close(entered)
		<-ctx.Done()
		time.Sleep(200 * time.Millisecond)
		returned.Store(true)
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-1")
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("Run did not start the watcher")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if !returned.Load() {
		t.Error("Run returned before the watcher did")
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
		Enabled:        boolPtr(true),
		BinaryPath:     binaryPath,
		HooksDir:       hooksDir,
		VerifyInterval: 1 * time.Hour, // long interval; we rely on the watcher
		WatchEnabled:   boolPtr(true),
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
	logs := &syncBuffer{}
	v := NewVerifier(Config{
		Enabled:        boolPtr(true),
		BinaryPath:     binaryPath,
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, jsonLogger(logs))

	v.VerifyHooksDir(context.Background(), "node-1")

	if attempts := reporter.getAttempts(); len(attempts) != 0 {
		t.Errorf("unexpected reports: %v", attempts)
	}
	assertNoWarnOrError(t, logs)
}

// TestVerifier_VerifyHooksDir_EmptyOrMissingDir sweeps a hooks directory with
// nothing in it and one that does not exist: neither is a finding.
func TestVerifier_VerifyHooksDir_EmptyOrMissingDir(t *testing.T) {
	tests := []struct {
		name   string
		create bool
	}{
		{"empty directory", true},
		{"missing directory", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			hooksDir := filepath.Join(dir, "hooks")
			if tt.create {
				if err := os.MkdirAll(hooksDir, 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			}
			store, err := NewStore(dir)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			reporter := &mockReporter{}
			logs := &syncBuffer{}
			v := NewVerifier(Config{
				BinaryPath:     writeTempFile(t, dir, "plexd", "binary-content"),
				HooksDir:       hooksDir,
				VerifyInterval: DefaultVerifyInterval,
			}, store, reporter, jsonLogger(logs))

			v.VerifyHooksDir(context.Background(), "node-1")

			if attempts := reporter.getAttempts(); len(attempts) != 0 {
				t.Errorf("unexpected reports: %v", attempts)
			}
			assertNoWarnOrError(t, logs)
		})
	}
}

// assertNoWarnOrError fails the test for any record above Info in logs.
func assertNoWarnOrError(t *testing.T, logs *syncBuffer) {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if level := rec["level"]; level == "WARN" || level == "ERROR" {
			t.Errorf("unexpected %v record: %s", level, line)
		}
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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

	// No later pass could report the dropped entry either, so its observed
	// digest becomes the baseline without a report.
	observed := sha256Hex("#!/bin/sh\necho tampered")
	if got := store.Get(filepath.Join(hooksDir, "bad.sh")); got != observed {
		t.Errorf("bad.sh baseline = %q, want the observed digest %q", got, observed)
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
		Enabled:        boolPtr(true),
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
		Enabled:        boolPtr(true),
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
				Enabled:        boolPtr(true),
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

// syncBuffer is a bytes.Buffer that is safe to write from the verifier's
// goroutines while a test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newWatchTestVerifier returns a Verifier that watches hooksDir and logs into
// logs, with a baseline stored for every file already in hooksDir.
func newWatchTestVerifier(t *testing.T, hooksDir string, reporter *mockReporter, logs *syncBuffer) *Verifier {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		t.Fatalf("read hooks dir: %v", err)
	}
	for _, e := range entries {
		path := filepath.Join(hooksDir, e.Name())
		sum, err := HashFile(path)
		if err != nil {
			t.Fatalf("hash %s: %v", path, err)
		}
		if err := store.Set(path, sum); err != nil {
			t.Fatalf("store set: %v", err)
		}
	}
	return NewVerifier(Config{
		Enabled:        boolPtr(true),
		HooksDir:       hooksDir,
		VerifyInterval: time.Hour,
		WatchEnabled:   boolPtr(true),
	}, store, reporter, slog.New(slog.NewTextHandler(logs, nil)))
}

func TestVerifier_WatchHooksDir_RetriesWhenAHookVanishes(t *testing.T) {
	hooksDir := t.TempDir()
	hookPath := writeTempFile(t, hooksDir, "test-hook.sh", "#!/bin/sh\necho original")

	reporter := &mockReporter{}
	logs := &syncBuffer{}
	v := newWatchTestVerifier(t, hooksDir, reporter, logs)

	ready := make(chan struct{})
	v.watchDir = func(ctx context.Context, dir string, onRetry func(error)) (*fsnotify.Watcher, error) {
		vanished := filepath.Join(dir, "vanished")
		onRetry(fmt.Errorf("%q: %w", vanished, &fs.PathError{Op: "lstat", Path: vanished, Err: fs.ErrNotExist}))
		fsw, err := fsutil.WatchDir(ctx, dir, onRetry)
		close(ready)
		return fsw, err
	}

	// The timeout ends a watchHooksDir that never calls v.watchDir.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		v.watchHooksDir(ctx, "node-1")
	}()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("watchHooksDir did not set up its watch through v.watchDir")
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho tampered"), 0o644); err != nil {
		t.Fatalf("write tampered hook: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !slices.ContainsFunc(reporter.get(), func(r api.IntegrityViolationReport) bool {
		return r.ArtifactID == hookPath && r.DetectedBy == api.IntegrityDetectorInotify
	}) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the watcher to report the tampered hook after a retried setup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	want := `level=WARN msg="integrity: a hook vanished while the watch was set up; retrying" component=integrity path=` + hooksDir
	if got := logs.String(); !strings.Contains(got, want) {
		t.Errorf("log = %q, want it to contain %q", got, want)
	}
}

// TestVerifier_WatchHooksDir_WaitsForADebouncedSweep holds a sweep the watcher
// started inside ReportViolations and cancels the watch: watchHooksDir must
// not return before that sweep has.
func TestVerifier_WatchHooksDir_WaitsForADebouncedSweep(t *testing.T) {
	hooksDir := t.TempDir()
	hookPath := writeTempFile(t, hooksDir, "test-hook.sh", "#!/bin/sh\necho original")

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSweep := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseSweep()

	reporter := &mockReporter{hold: func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}}
	v := newWatchTestVerifier(t, hooksDir, reporter, &syncBuffer{})

	ready := make(chan struct{})
	v.watchDir = func(ctx context.Context, dir string, onRetry func(error)) (*fsnotify.Watcher, error) {
		fsw, err := fsutil.WatchDir(ctx, dir, onRetry)
		close(ready)
		return fsw, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		v.watchHooksDir(ctx, "node-1")
	}()
	// However the test ends, release the sweep first and then wait for the
	// watcher, so goleak finds neither.
	defer func() {
		releaseSweep()
		cancel()
		<-done
	}()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("watchHooksDir did not set up its watch through v.watchDir")
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho tampered"), 0o644); err != nil {
		t.Fatalf("write tampered hook: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the debounced sweep did not reach the reporter")
	}

	cancel()
	select {
	case <-done:
		t.Fatal("watchHooksDir returned while its sweep was still inside ReportViolations")
	case <-time.After(200 * time.Millisecond):
	}

	releaseSweep()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchHooksDir did not return after its sweep finished")
	}
}

func TestVerifier_WatchHooksDir_SetupErrorIsLogged(t *testing.T) {
	hooksDir := t.TempDir()
	reporter := &mockReporter{}
	logs := &syncBuffer{}
	v := newWatchTestVerifier(t, hooksDir, reporter, logs)
	v.watchDir = func(context.Context, string, func(error)) (*fsnotify.Watcher, error) {
		return nil, fmt.Errorf("%q: %w", hooksDir, &fs.PathError{Op: "open", Path: hooksDir, Err: fs.ErrPermission})
	}

	// The timeout ends a watchHooksDir that never calls v.watchDir.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v.watchHooksDir(ctx, "node-1")

	want := `level=WARN msg="integrity: failed to watch hooks dir" component=integrity path=` + hooksDir
	if got := logs.String(); !strings.Contains(got, want) || !strings.Contains(got, "permission denied") {
		t.Errorf("log = %q, want it to contain %q and the error", got, want)
	}
	if got := reporter.get(); len(got) != 0 {
		t.Errorf("violations = %v, want none", got)
	}
}

func TestVerifier_WatchHooksDir_CancelDuringSetupLogsNoFailure(t *testing.T) {
	hooksDir := t.TempDir()
	logs := &syncBuffer{}
	v := newWatchTestVerifier(t, hooksDir, &mockReporter{}, logs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	called := false
	v.watchDir = func(ctx context.Context, _ string, _ func(error)) (*fsnotify.Watcher, error) {
		called = true
		cancel()
		return nil, ctx.Err()
	}

	v.watchHooksDir(ctx, "node-1")

	if !called {
		t.Fatal("watchHooksDir did not set up its watch through v.watchDir")
	}
	if got := logs.String(); strings.Contains(got, "failed to watch hooks dir") {
		t.Errorf("log = %q, want no setup failure after cancellation", got)
	}
}

// ---------------------------------------------------------------------------
// Report once, then adopt
// ---------------------------------------------------------------------------

// TestVerifier_AdoptsBaselineAfterAcceptedReport runs each baseline check
// against a mismatch with a reporter that accepts: the divergence is reported
// once, the observed value becomes the baseline, and the next run of the check
// has nothing to report.
func TestVerifier_AdoptsBaselineAfterAcceptedReport(t *testing.T) {
	tests := []struct {
		name string
		// setup seeds a mismatching baseline under the returned key and
		// returns the Config for it and the value the check will observe.
		setup func(t *testing.T, dir string, store *Store) (cfg Config, key, observed string)
		check func(ctx context.Context, v *Verifier) error
	}{
		{
			name: "binary",
			setup: func(t *testing.T, dir string, store *Store) (Config, string, string) {
				binaryPath := writeTempFile(t, dir, "plexd", "binary-v2")
				if err := store.Set(binaryPath, sha256Hex("binary-v1")); err != nil {
					t.Fatalf("store set: %v", err)
				}
				return Config{BinaryPath: binaryPath}, binaryPath, sha256Hex("binary-v2")
			},
			check: func(ctx context.Context, v *Verifier) error {
				return v.VerifyBinary(ctx, "node-1")
			},
		},
		{
			name: "hook in HooksDir",
			setup: func(t *testing.T, dir string, store *Store) (Config, string, string) {
				hooksDir := filepath.Join(dir, "hooks")
				if err := os.MkdirAll(hooksDir, 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				hookPath := writeTempFile(t, hooksDir, "hook.sh", "#!/bin/sh\necho tampered")
				if err := store.Set(hookPath, sha256Hex("#!/bin/sh\necho original")); err != nil {
					t.Fatalf("store set: %v", err)
				}
				return Config{HooksDir: hooksDir}, hookPath, sha256Hex("#!/bin/sh\necho tampered")
			},
			check: func(ctx context.Context, v *Verifier) error {
				v.VerifyHooksDir(ctx, "node-1")
				return nil
			},
		},
		{
			name: "host key",
			setup: func(t *testing.T, dir string, store *Store) (Config, string, string) {
				keyPath, fingerprint := writeHostKey(t, dir, "ssh_host_ed25519_key")
				_, oldFingerprint := writeHostKey(t, t.TempDir(), "ssh_host_ed25519_key")
				if err := store.Set(keyPath, oldFingerprint); err != nil {
					t.Fatalf("store set: %v", err)
				}
				return Config{HostKeyPath: keyPath}, keyPath, fingerprint
			},
			check: func(ctx context.Context, v *Verifier) error {
				return v.VerifyHostKey(ctx, "node-1")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewStore(dir)
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			cfg, key, observed := tt.setup(t, dir, store)
			cfg.VerifyInterval = DefaultVerifyInterval

			reporter := &mockReporter{}
			logs := &syncBuffer{}
			v := NewVerifier(cfg, store, reporter, jsonLogger(logs))

			if err := tt.check(context.Background(), v); err != nil {
				t.Fatalf("check: %v", err)
			}
			batches := reporter.getBatches()
			if len(batches) != 1 || len(batches[0]) != 1 || batches[0][0].ArtifactID != key {
				t.Fatalf("batches = %+v, want one report for %s", batches, key)
			}
			if got := store.Get(key); got != observed {
				t.Errorf("baseline = %q, want the observed %q", got, observed)
			}
			recs := logRecords(t, logs, "integrity baseline updated")
			if len(recs) != 1 || recs[0]["path"] != key || recs[0]["level"] != "INFO" {
				t.Errorf("baseline updated records = %v, want one at INFO with path %s", recs, key)
			}

			// The adopted baseline matches, so a second run reports nothing.
			if err := tt.check(context.Background(), v); err != nil {
				t.Fatalf("second check: %v", err)
			}
			if attempts := reporter.getAttempts(); len(attempts) != 1 {
				t.Errorf("reports after the second run = %d, want still 1", len(attempts))
			}
		})
	}
}

// TestVerifier_KeepsBaselineWhenReportFails makes the first report fail: the
// baseline stays, so the next pass reports the same divergence again, and only
// the accepted report moves the baseline.
func TestVerifier_KeepsBaselineWhenReportFails(t *testing.T) {
	dir := t.TempDir()
	binaryPath := writeTempFile(t, dir, "plexd", "binary-v2")
	oldChecksum := sha256Hex("binary-v1")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(binaryPath, oldChecksum); err != nil {
		t.Fatalf("store set: %v", err)
	}

	reporter := &mockReporter{errs: []error{context.DeadlineExceeded}}
	logs := &syncBuffer{}
	v := NewVerifier(Config{
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, jsonLogger(logs))
	ctx := context.Background()

	// Pass 1: the report fails.
	v.verifyAll(ctx, "node-1")
	if got := len(reporter.getAttempts()); got != 1 {
		t.Fatalf("attempts after pass 1 = %d, want 1", got)
	}
	recs := logRecords(t, logs, "failed to report integrity violations")
	if len(recs) != 1 || recs[0]["level"] != "WARN" || recs[0]["error"] != context.DeadlineExceeded.Error() {
		t.Errorf("failed report records = %v, want one WARN with error %q", recs, context.DeadlineExceeded)
	}
	if got := store.Get(binaryPath); got != oldChecksum {
		t.Errorf("baseline after a failed report = %q, want the old %q", got, oldChecksum)
	}

	// Pass 2: the same divergence is reported again, and accepted.
	v.verifyAll(ctx, "node-1")
	attempts := reporter.getAttempts()
	if len(attempts) != 2 {
		t.Fatalf("attempts after pass 2 = %d, want 2", len(attempts))
	}
	if !slices.Equal(attempts[1], attempts[0]) {
		t.Errorf("second report = %+v, want the first one again %+v", attempts[1], attempts[0])
	}
	if got, want := store.Get(binaryPath), sha256Hex("binary-v2"); got != want {
		t.Errorf("baseline after an accepted report = %q, want %q", got, want)
	}

	// Pass 3: nothing left to report.
	v.verifyAll(ctx, "node-1")
	if got := len(reporter.getAttempts()); got != 2 {
		t.Errorf("attempts after pass 3 = %d, want still 2", got)
	}
}

// TestVerifier_AdoptLogsAStoreFailure removes the store's directory before a
// pass that finds a mismatch: the report still goes out, and the failed write
// of the new baseline is logged.
func TestVerifier_AdoptLogsAStoreFailure(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	binaryPath := writeTempFile(t, t.TempDir(), "plexd", "binary-v2")

	store, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(binaryPath, sha256Hex("binary-v1")); err != nil {
		t.Fatalf("store set: %v", err)
	}
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatalf("remove data dir: %v", err)
	}
	// The platform's own text for creating a file in a missing directory.
	_, probeErr := os.CreateTemp(dataDir, "probe-")
	var pathErr *fs.PathError
	if !errors.As(probeErr, &pathErr) {
		t.Fatalf("os.CreateTemp in a removed dir = %v, want a *fs.PathError", probeErr)
	}

	reporter := &mockReporter{}
	logs := &syncBuffer{}
	v := NewVerifier(Config{
		BinaryPath:     binaryPath,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, jsonLogger(logs))

	if err := v.VerifyBinary(context.Background(), "node-1"); err != nil {
		t.Fatalf("verify binary: %v", err)
	}

	if got := len(reporter.getBatches()); got != 1 {
		t.Errorf("batches = %d, want 1: the report goes out before the store write", got)
	}
	recs := logRecords(t, logs, "failed to store integrity baseline")
	if len(recs) != 1 {
		t.Fatalf("failed store records = %d, want 1 (log %s)", len(recs), logs.String())
	}
	if recs[0]["level"] != "WARN" || recs[0]["path"] != binaryPath {
		t.Errorf("record = %v, want WARN with path %s", recs[0], binaryPath)
	}
	errText, _ := recs[0]["error"].(string)
	tmpPrefix := filepath.Join(dataDir, ".tmp-"+checksumFileName+"-")
	if !strings.Contains(errText, tmpPrefix) || !strings.Contains(errText, pathErr.Err.Error()) {
		t.Errorf("error = %q, want the CreateTemp error for %s* (%q)", errText, tmpPrefix, pathErr.Err.Error())
	}
}

// TestVerifier_AdoptsPerDeliveredBatch sweeps more diverged hooks than one
// request may carry, and lets the first request through and fails the second:
// only the baselines of the delivered batch move.
func TestVerifier_AdoptsPerDeliveredBatch(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const total = api.MaxIntegrityViolationsPerBatch + 2
	original := sha256Hex("#!/bin/sh\necho original")
	tampered := sha256Hex("#!/bin/sh\necho tampered")

	// Seed the store file directly rather than through one fsynced Set per
	// hook. ReadDir sorts by name, so the zero-padded names are sweep order.
	paths := make([]string, total)
	seed := make(map[string]string, total)
	for i := range paths {
		paths[i] = writeTempFile(t, hooksDir, fmt.Sprintf("hook-%03d.sh", i), "#!/bin/sh\necho tampered")
		seed[paths[i]] = original
	}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, checksumFileName), data, 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	reporter := &mockReporter{errs: []error{nil, context.DeadlineExceeded}}
	v := NewVerifier(Config{
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))

	v.VerifyHooksDir(context.Background(), "node-1")

	attempts := reporter.getAttempts()
	if len(attempts) != 2 || len(attempts[0]) != api.MaxIntegrityViolationsPerBatch || len(attempts[1]) != 2 {
		sizes := make([]int, len(attempts))
		for i, a := range attempts {
			sizes[i] = len(a)
		}
		t.Fatalf("batch sizes = %v, want [%d 2]", sizes, api.MaxIntegrityViolationsPerBatch)
	}
	for i, p := range paths {
		want := tampered
		if i >= api.MaxIntegrityViolationsPerBatch {
			want = original
		}
		if got := store.Get(p); got != want {
			t.Errorf("baseline of %s = %q, want %q", filepath.Base(p), got, want)
		}
	}
}

// TestVerifier_ConcurrentSweepsReportAChangeOnce holds one sweep inside
// ReportViolations while a second sweep of the same changed hook starts, as a
// tick and the watcher's debounced sweep can: the second must see the adopted
// baseline, not the old one, so the change is reported once.
func TestVerifier_ConcurrentSweepsReportAChangeOnce(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	hookPath := writeTempFile(t, hooksDir, "hook.sh", "#!/bin/sh\necho tampered")

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := store.Set(hookPath, sha256Hex("#!/bin/sh\necho original")); err != nil {
		t.Fatalf("store set: %v", err)
	}

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseSweeps := func() { releaseOnce.Do(func() { close(release) }) }
	reporter := &mockReporter{hold: func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}}
	v := NewVerifier(Config{
		HooksDir:       hooksDir,
		VerifyInterval: DefaultVerifyInterval,
	}, store, reporter, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)))

	ctx := context.Background()
	var sweeps sync.WaitGroup
	defer func() {
		releaseSweeps()
		sweeps.Wait()
	}()

	sweeps.Add(1)
	go func() {
		defer sweeps.Done()
		v.VerifyHooksDir(ctx, "node-1")
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first sweep did not reach the reporter")
	}

	sweeps.Add(1)
	go func() {
		defer sweeps.Done()
		v.verifyHooksDir(ctx, "node-1", api.IntegrityDetectorInotify)
	}()
	// Give the second sweep the time to read the baseline and report, which
	// it must not do while the first is still inside ReportViolations.
	select {
	case <-entered:
		t.Error("a second sweep reached the reporter while the first was still inside it")
	case <-time.After(300 * time.Millisecond):
	}

	releaseSweeps()
	sweeps.Wait()

	if batches := reporter.getBatches(); len(batches) != 1 {
		t.Errorf("batches = %d, want 1: one change is reported once (%+v)", len(batches), batches)
	}
	if got, want := store.Get(hookPath), sha256Hex("#!/bin/sh\necho tampered"); got != want {
		t.Errorf("baseline = %q, want %q", got, want)
	}
}
