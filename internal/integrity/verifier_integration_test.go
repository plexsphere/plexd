package integrity

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/plexsphere/plexd/internal/api"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestIntegration_FullLifecycle wires real files, a real Store, and a mock reporter.
// Lifecycle: startup pass establishes the baseline → binary tampered → a tick
// reports it once and adopts it → five more ticks report nothing → hook
// verified → hook tampered → violation reported.
func TestIntegration_FullLifecycle(t *testing.T) {
	dir := t.TempDir()
	binaryContent := "plexd-binary-v1"
	binaryPath := writeTempFile(t, dir, "plexd", binaryContent)
	binaryChecksum := sha256Hex(binaryContent)

	hookContent := "#!/bin/sh\necho hook-v1"
	hookPath := writeTempFile(t, dir, "deploy.sh", hookContent)
	hookChecksum := sha256Hex(hookContent)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	reporter := &mockReporter{}
	logs := &syncBuffer{}
	v := NewVerifier(Config{
		Enabled:        boolPtr(true),
		BinaryPath:     binaryPath,
		VerifyInterval: 50 * time.Millisecond,
	}, store, reporter, jsonLogger(logs))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-integ")
	}()
	// A failed wait below must not leave Run behind for goleak.
	stopped := false
	defer func() {
		if !stopped {
			cancel()
			<-done
		}
	}()

	// 1. The startup pass establishes the baseline from an empty store.
	waitFor(t, 3*time.Second, "the startup baseline", func() bool {
		return store.Get(binaryPath) == binaryChecksum
	})
	if got := v.BinaryChecksum(); got != binaryChecksum {
		t.Fatalf("BinaryChecksum() = %q, want %q", got, binaryChecksum)
	}
	if viol := reporter.get(); len(viol) != 0 {
		t.Fatalf("unexpected violations after startup: %v", viol)
	}

	// 2. Tamper the binary under the running loop, in one rename so no tick
	// reads a torn file.
	tamperedContent := "plexd-binary-TAMPERED"
	replaceAtomically(t, binaryPath, []byte(tamperedContent))

	// Wait for a tick to detect the tampering.
	waitFor(t, 3*time.Second, "the binary violation", func() bool {
		return len(reporter.get()) > 0
	})
	viol := reporter.get()
	if viol[0].Kind != api.IntegrityKindBinaryChecksum {
		t.Errorf("violation[0].Kind = %q, want %q", viol[0].Kind, api.IntegrityKindBinaryChecksum)
	}
	if want := wireDigest(t, binaryChecksum); viol[0].ExpectedChecksum != want {
		t.Errorf("violation[0].ExpectedChecksum = %q, want %q", viol[0].ExpectedChecksum, want)
	}

	// Let at least five more ticks pass over the changed binary. Each one
	// logs either a match or a violation, so counting both counts ticks
	// whatever they find.
	binaryPasses := func() int {
		return len(logRecords(t, logs, "binary verified")) +
			len(logRecords(t, logs, "binary integrity violation"))
	}
	passes := binaryPasses()
	waitFor(t, 3*time.Second, "five ticks after the violation", func() bool {
		return binaryPasses() >= passes+5
	})
	if got, want := store.Get(binaryPath), sha256Hex(tamperedContent); got != want {
		t.Errorf("store baseline = %q, want the adopted %q", got, want)
	}

	// 3. Verify a valid hook.
	ok, err := v.VerifyHook(ctx, "node-integ", hookPath, hookChecksum)
	if err != nil {
		t.Fatalf("verify valid hook: %v", err)
	}
	if !ok {
		t.Error("expected valid hook to pass")
	}

	// 4. Tamper the hook and re-verify.
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho TAMPERED"), 0o644); err != nil {
		t.Fatalf("tamper hook: %v", err)
	}

	ok, err = v.VerifyHook(ctx, "node-integ", hookPath, hookChecksum)
	if err != nil {
		t.Fatalf("verify tampered hook: %v", err)
	}
	if ok {
		t.Error("expected tampered hook to fail verification")
	}

	// Exactly 2 violations: the binary change, reported once across every
	// tick that saw it, and the hook.
	viol = reporter.get()
	binaryViolations := 0
	hookViolations := 0
	for _, v := range viol {
		switch v.Kind {
		case api.IntegrityKindBinaryChecksum:
			binaryViolations++
		case api.IntegrityKindHookChecksum:
			hookViolations++
		}
	}
	if binaryViolations != 1 {
		t.Errorf("expected exactly 1 binary violation, got %d", binaryViolations)
	}
	if hookViolations != 1 {
		t.Errorf("expected 1 hook violation, got %d", hookViolations)
	}

	// Clean shutdown.
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("Run error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

// TestIntegration_ConcurrentVerification runs concurrent VerifyBinary and VerifyHook
// calls to verify thread safety under the race detector.
func TestIntegration_ConcurrentVerification(t *testing.T) {
	dir := t.TempDir()
	binaryPath := writeTempFile(t, dir, "plexd", "binary-concurrent")

	// Create a few hook files.
	hooks := make([]string, 5)
	checksums := make([]string, 5)
	for i := range hooks {
		content := filepath.Join("hook-script-", string(rune('a'+i)))
		hooks[i] = writeTempFile(t, dir, filepath.Base(content)+".sh", content)
		checksums[i] = sha256Hex(content)
	}

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

	// Establish binary baseline first.
	if err := v.VerifyBinary(context.Background(), "node-concurrent"); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < iterations; i++ {
				// Alternate between binary and hook verification.
				if i%2 == 0 {
					_ = v.VerifyBinary(ctx, "node-concurrent")
				} else {
					idx := i % len(hooks)
					_, _ = v.VerifyHook(ctx, "node-concurrent", hooks[idx], checksums[idx])
				}
				_ = v.BinaryChecksum()
			}
		}(g)
	}

	wg.Wait()

	// No violations expected (nothing was tampered).
	if viol := reporter.get(); len(viol) != 0 {
		t.Errorf("unexpected violations during concurrent test: %d", len(viol))
	}
}
