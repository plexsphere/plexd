//go:build windows

package actions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinServiceReloadConfig_Unsupported(t *testing.T) {
	fn := ServiceReloadConfig()
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if !errors.Is(err, errReloadSignalUnsupported) {
		t.Fatalf("expected errReloadSignalUnsupported, got %v", err)
	}
	if want := "actions: reload config: reload signal not supported on windows; restart the service instead"; err.Error() != want {
		t.Errorf("error text = %q, want %q", err.Error(), want)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout, got %q", stdout)
	}
	if stderr != "" {
		t.Errorf("expected empty stderr, got %q", stderr)
	}
}

// TestReplaceExecutable pins the Windows swap. Windows refuses to rename over a
// running image, so the running executable is moved aside first and the copy
// stays until the next upgrade removes it.
func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plexd.exe")
	old := target + ".old"

	writeTmp := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatalf("WriteFile(%q) = %v", p, err)
		}
		return p
	}

	if err := os.WriteFile(target, []byte("v1 binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(target) = %v", err)
	}

	if err := replaceExecutable(writeTmp(".plexd-upgrade-1", "v2 binary"), target); err != nil {
		t.Fatalf("replaceExecutable() = %v", err)
	}
	if got := readFile(t, target); got != "v2 binary" {
		t.Errorf("target = %q, want %q", got, "v2 binary")
	}
	if got := readFile(t, old); got != "v1 binary" {
		t.Errorf("%q = %q, want the previous binary %q", old, got, "v1 binary")
	}

	// A second upgrade replaces the stale .old rather than failing on it.
	if err := replaceExecutable(writeTmp(".plexd-upgrade-2", "v3 binary"), target); err != nil {
		t.Fatalf("second replaceExecutable() = %v", err)
	}
	if got := readFile(t, target); got != "v3 binary" {
		t.Errorf("target = %q, want %q", got, "v3 binary")
	}
	if got := readFile(t, old); got != "v2 binary" {
		t.Errorf("%q = %q, want the previous binary %q", old, got, "v2 binary")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", path, err)
	}
	return string(data)
}
