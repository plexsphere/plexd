//go:build darwin

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useDaemonLogPath points daemonLogPath at path for the duration of the test,
// so no case depends on whether this Mac has ever run plexd install.
func useDaemonLogPath(t *testing.T, path string) {
	t.Helper()
	old := daemonLogPath
	daemonLogPath = path
	t.Cleanup(func() { daemonLogPath = old })
}

// writeDaemonLog creates a log file and points daemonLogPath at it.
func writeDaemonLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plexd.log")
	line := "time=2026-09-06T10:00:00.000+02:00 level=INFO msg=\"reconciliation completed\"\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatalf("write daemon log: %v", err)
	}
	useDaemonLogPath(t, path)
	return path
}

func TestLogsCommand_Tail(t *testing.T) {
	path := writeDaemonLog(t)

	name, args, err := logsCommand(false)
	if err != nil {
		t.Fatalf("logsCommand: %v", err)
	}
	if filepath.Base(name) != "tail" {
		t.Errorf("command = %q, want tail", name)
	}
	want := "-n 100 " + path
	if got := strings.Join(args, " "); got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// TestLogsCommand_TailFollow pins where -f sits: before the path, because tail
// reads the operand after its flags.
func TestLogsCommand_TailFollow(t *testing.T) {
	path := writeDaemonLog(t)

	_, args, err := logsCommand(true)
	if err != nil {
		t.Fatalf("logsCommand: %v", err)
	}
	want := "-n 100 -f " + path
	if got := strings.Join(args, " "); got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// TestLogsCommand_NoDaemonLog covers the ordinary case on a Mac where nobody
// ran plexd install: the file launchd would write does not exist.
func TestLogsCommand_NoDaemonLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.log")
	useDaemonLogPath(t, path)

	_, _, err := logsCommand(false)

	var unavailable logsUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v, want logsUnavailableError", err)
	}
	if !strings.Contains(unavailable.reason, path) {
		t.Errorf("reason = %q, want it to name %q", unavailable.reason, path)
	}
	if !strings.Contains(unavailable.reason, "console plexd up") {
		t.Errorf("reason = %q, want it to explain where a console run writes", unavailable.reason)
	}
}

// TestLogsCommand_StatFails proves a stat failure that is not "absent" reaches
// the operator as an error rather than as an unavailable notice, so the
// command exits non-zero on it.
func TestLogsCommand_StatFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a directory whose mode denies everyone")
	}

	dir := t.TempDir()
	denied := filepath.Join(dir, "denied")
	if err := os.Mkdir(denied, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Restore the mode before TempDir's own cleanup runs. Cleanups run in
	// reverse registration order and TempDir registered its removal first, so
	// this one goes first; without it RemoveAll cannot traverse the directory
	// and fails the test after it has already passed.
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	useDaemonLogPath(t, filepath.Join(denied, "plexd.log"))

	_, _, err := logsCommand(false)
	if err == nil {
		t.Fatal("expected an error for a path that cannot be stat'ed")
	}

	var unavailable logsUnavailableError
	if errors.As(err, &unavailable) {
		t.Fatalf("a stat failure must fail the command, got an unavailable notice: %q", unavailable.reason)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v, want it to carry the stat failure", err)
	}
}

func TestLogsCommand_TailMissing(t *testing.T) {
	writeDaemonLog(t)
	t.Setenv("PATH", t.TempDir())

	_, _, err := logsCommand(false)

	var unavailable logsUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v, want logsUnavailableError", err)
	}
	if !strings.Contains(unavailable.reason, "tail not found") {
		t.Errorf("reason = %q, want it to name tail", unavailable.reason)
	}
}
