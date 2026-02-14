package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestActionsCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"actions"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd actions") {
		t.Errorf("error should mention 'plexd actions', got: %v", err)
	}
}

func TestActionsRunCommand_RequiresArgs(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"actions", "run"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing action name")
	}
}

func TestActionsRunCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"actions", "run", "my-action"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd actions run") {
		t.Errorf("error should mention 'plexd actions run', got: %v", err)
	}
}

func TestActionsCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"actions", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "run") {
		t.Errorf("help should list 'run' subcommand, got: %s", output)
	}
}

func TestActionsRunCommand_ParamFlag(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"actions", "run", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "--param") {
		t.Errorf("help should mention '--param' flag, got: %s", output)
	}
}

func TestHooksCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hooks", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "list") {
		t.Errorf("help should list 'list' subcommand, got: %s", output)
	}
	if !strings.Contains(output, "verify") {
		t.Errorf("help should list 'verify' subcommand, got: %s", output)
	}
	if !strings.Contains(output, "reload") {
		t.Errorf("help should list 'reload' subcommand, got: %s", output)
	}
}

func TestHooksListCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hooks", "list"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd hooks list") {
		t.Errorf("error should mention 'plexd hooks list', got: %v", err)
	}
}

func TestHooksVerifyCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hooks", "verify"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd hooks verify") {
		t.Errorf("error should mention 'plexd hooks verify', got: %v", err)
	}
}

func TestHooksReloadCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"hooks", "reload"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd hooks reload") {
		t.Errorf("error should mention 'plexd hooks reload', got: %v", err)
	}
}
