//go:build unix && !darwin

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeJournalctl puts an executable named journalctl in a directory that
// becomes the whole PATH, so exec.LookPath resolves it on a runner with no
// journald. It returns the path LookPath reports.
func fakeJournalctl(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake journalctl: %v", err)
	}
	t.Setenv("PATH", dir)
	return path
}

func TestLogsCommand_Journalctl(t *testing.T) {
	want := fakeJournalctl(t)

	name, args, err := logsCommand(false)
	if err != nil {
		t.Fatalf("logsCommand: %v", err)
	}
	if name != want {
		t.Errorf("command = %q, want %q", name, want)
	}
	const wantArgs = "-u plexd --no-pager"
	if got := strings.Join(args, " "); got != wantArgs {
		t.Errorf("args = %q, want %q", got, wantArgs)
	}
}

func TestLogsCommand_JournalctlFollow(t *testing.T) {
	fakeJournalctl(t)

	_, args, err := logsCommand(true)
	if err != nil {
		t.Fatalf("logsCommand: %v", err)
	}
	const wantArgs = "-u plexd --no-pager -f"
	if got := strings.Join(args, " "); got != wantArgs {
		t.Errorf("args = %q, want %q", got, wantArgs)
	}
}

// TestLogsCommand_JournalctlMissing pins the message a host without journalctl
// gets. It is an unavailable notice rather than an error, so plexd logs keeps
// exiting 0 there, which is what it did before the command read three
// platforms.
func TestLogsCommand_JournalctlMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, _, err := logsCommand(false)

	var unavailable logsUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v, want logsUnavailableError", err)
	}
	if !strings.Contains(unavailable.reason, "journalctl not found") {
		t.Errorf("reason = %q, want it to name journalctl", unavailable.reason)
	}
}
