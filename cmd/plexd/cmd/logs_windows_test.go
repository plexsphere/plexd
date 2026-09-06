//go:build windows

package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestLogsCommand_EventLog(t *testing.T) {
	name, args, err := logsCommand(false)
	if err != nil {
		t.Fatalf("logsCommand: %v", err)
	}
	if !strings.HasSuffix(strings.ToLower(name), "powershell.exe") {
		t.Errorf("command = %q, want powershell.exe", name)
	}
	if len(args) == 0 {
		t.Fatal("no arguments")
	}
	if got := strings.Join(args[:len(args)-1], " "); got != "-NoProfile -NonInteractive -Command" {
		t.Errorf("flags = %q, want %q", got, "-NoProfile -NonInteractive -Command")
	}

	script := args[len(args)-1]
	for _, want := range []string{
		"LogName='Application'",
		"ProviderName='plexd'",
		"-MaxEvents 100",
		"-ErrorAction SilentlyContinue",
		"Sort-Object TimeCreated",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q\nscript: %s", want, script)
		}
	}
}

// TestLogsCommand_FollowUnsupported pins that --follow fails the command.
// Printing a snapshot to somebody who asked to keep watching would be worse
// than refusing, so this must not be an unavailable notice, which exits 0.
func TestLogsCommand_FollowUnsupported(t *testing.T) {
	_, _, err := logsCommand(true)
	if err == nil {
		t.Fatal("expected --follow to be refused")
	}

	var unavailable logsUnavailableError
	if errors.As(err, &unavailable) {
		t.Fatalf("--follow must fail the command, got an unavailable notice: %q", unavailable.reason)
	}
	if !strings.Contains(err.Error(), "--follow is not supported on windows") {
		t.Errorf("error = %v, want it to name the unsupported flag", err)
	}
}

func TestLogsCommand_PowerShellMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, _, err := logsCommand(false)

	var unavailable logsUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v, want logsUnavailableError", err)
	}
	if !strings.Contains(unavailable.reason, "powershell.exe not found") {
		t.Errorf("reason = %q, want it to name powershell.exe", unavailable.reason)
	}
}
