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
}

func TestLogStatusCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd log-status", "log-status")
}
