package cmd

import (
	"strings"
	"testing"
)

func TestActionsCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd actions", "actions")
}

func TestActionsRunCommand_RequiresArgs(t *testing.T) {
	_, err := executeCmd(t, "actions", "run")
	if err == nil {
		t.Fatal("expected error for missing action name")
	}
}

func TestActionsRunCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd actions run", "actions", "run", "my-action")
}

func TestActionsCommand_Help(t *testing.T) {
	output := executeHelp(t, "actions", "--help")
	if !strings.Contains(output, "run") {
		t.Errorf("help should list 'run' subcommand, got: %s", output)
	}
}

func TestActionsRunCommand_ParamFlag(t *testing.T) {
	output := executeHelp(t, "actions", "run", "--help")
	if !strings.Contains(output, "--param") {
		t.Errorf("help should mention '--param' flag, got: %s", output)
	}
}
