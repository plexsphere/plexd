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
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestIntegration_FullLifecycle wires real files, a real Store, and a mock reporter.
// Lifecycle: startup verification → periodic check → binary tampered → violation reported
// → hook verified → hook tampered → violation reported.
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
	v := NewVerifier(Config{
		Enabled:        true,
		BinaryPath:     binaryPath,
		VerifyInterval: 50 * time.Millisecond,
	}, store, reporter, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Startup verification — no baseline yet.
	if err := v.VerifyBinary(ctx, "node-integ"); err != nil {
		t.Fatalf("startup verify: %v", err)
	}
	if got := v.BinaryChecksum(); got != binaryChecksum {
		t.Fatalf("BinaryChecksum() = %q, want %q", got, binaryChecksum)
	}
	if got := store.Get(binaryPath); got != binaryChecksum {
		t.Fatalf("store baseline = %q, want %q", got, binaryChecksum)
	}
	if viol := reporter.get(); len(viol) != 0 {
		t.Fatalf("unexpected violations after startup: %v", viol)
	}

	// 2. Tamper the binary and start periodic loop.
	tamperedContent := "plexd-binary-TAMPERED"
	if err := os.WriteFile(binaryPath, []byte(tamperedContent), 0o644); err != nil {
		t.Fatalf("tamper binary: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- v.Run(ctx, "node-integ")
	}()

	// Wait for the periodic check to detect tampering.
	deadline := time.After(3 * time.Second)
	for {
		if viol := reporter.get(); len(viol) > 0 {
			if viol[0].Type != "binary" {
				t.Errorf("violation[0].Type = %q, want %q", viol[0].Type, "binary")
			}
			if viol[0].ExpectedChecksum != binaryChecksum {
				t.Errorf("violation[0].Expected = %q, want %q", viol[0].ExpectedChecksum, binaryChecksum)
			}
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for binary tampering detection")
		default:
		}
		time.Sleep(10 * time.Millisecond)
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

	// Should have at least 2 violations: 1 binary + 1 hook.
	viol := reporter.get()
	binaryViolations := 0
	hookViolations := 0
	for _, v := range viol {
		switch v.Type {
		case "binary":
			binaryViolations++
		case "hook":
			hookViolations++
		}
	}
	if binaryViolations < 1 {
		t.Errorf("expected at least 1 binary violation, got %d", binaryViolations)
	}
	if hookViolations != 1 {
		t.Errorf("expected 1 hook violation, got %d", hookViolations)
	}

	// Clean shutdown.
	cancel()
	select {
	case err := <-done:
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
		Enabled:        true,
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
