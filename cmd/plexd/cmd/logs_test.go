package cmd

import (
	"strings"
	"testing"
)

func TestLogsCommand_Help(t *testing.T) {
	output := executeHelp(t, "logs", "--help")
	if !strings.Contains(output, "logs") {
		t.Errorf("help should contain 'logs', got: %s", output)
	}
	if !strings.Contains(output, "--follow") {
		t.Errorf("help should mention '--follow' flag, got: %s", output)
	}
	// The command reads a different log on each platform, and the operator
	// running --help is the one who has to know which.
	for _, want := range []string{"journald", "/Library/Logs/plexd/plexd.log", "Event Log"} {
		if !strings.Contains(output, want) {
			t.Errorf("help should name %q, got: %s", want, output)
		}
	}
}

// TestLogsCommand_UnavailableExitsZero pins the contract every platform's
// logsCommand shares: a host with no reader gets a sentence naming where the
// log lives, and plexd logs still exits 0. An empty PATH removes the reader on
// all three — journalctl, tail, powershell.exe — and on macOS the log file the
// stat runs first is absent on any host that never ran plexd install, which
// reaches the same branch.
func TestLogsCommand_UnavailableExitsZero(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	out, err := executeCmd(t, "logs")
	if err != nil {
		t.Fatalf("plexd logs must exit 0 when no log can be read, got: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("plexd logs printed nothing; it must say where the log lives")
	}
}

func TestLogStatusCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd log-status", "log-status")
}
