//go:build unix

package actions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBuiltinServiceReloadConfig(t *testing.T) {
	// Ignore SIGHUP so the test process isn't killed.
	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)

	fn := ServiceReloadConfig()
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if _, ok := result["status"]; !ok {
		t.Error("missing key 'status' in JSON output")
	}
	if result["status"] != "reload_signal_sent" {
		t.Errorf("expected status='reload_signal_sent', got %q", result["status"])
	}
	if _, ok := result["pid"]; !ok {
		t.Error("missing key 'pid' in JSON output")
	}
}

func TestDiskTotalBytes_EmptyPath(t *testing.T) {
	// unix.Statfs("") fails with ENOENT, which diskTotalBytes reports as 0.
	if got := diskTotalBytes(""); got != 0 {
		t.Errorf("diskTotalBytes(%q) = %d, want 0", "", got)
	}
}

// TestReplaceExecutable pins the Unix swap: a single rename over the running
// executable, which Unix allows, leaving no copy behind.
func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plexd")
	tmp := filepath.Join(dir, ".plexd-upgrade-1")

	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(target) = %v", err)
	}
	if err := os.WriteFile(tmp, []byte("new binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(tmp) = %v", err)
	}

	if err := replaceExecutable(tmp, target); err != nil {
		t.Fatalf("replaceExecutable() = %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) = %v", err)
	}
	if string(got) != "new binary" {
		t.Errorf("target = %q, want %q", got, "new binary")
	}
	if _, err := os.Stat(target + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(%q.old) = %v, want os.ErrNotExist: Unix keeps no copy", target, err)
	}
}
