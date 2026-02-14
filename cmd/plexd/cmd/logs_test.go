package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogsCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"logs", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "logs") {
		t.Errorf("help should contain 'logs', got: %s", output)
	}
	if !strings.Contains(output, "--follow") {
		t.Errorf("help should mention '--follow' flag, got: %s", output)
	}
}

func TestLogStatusCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"log-status"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd log-status") {
		t.Errorf("error should mention 'plexd log-status', got: %v", err)
	}
}

func TestAuditCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"audit"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd audit") {
		t.Errorf("error should mention 'plexd audit', got: %v", err)
	}
}

func TestAuditCommand_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"audit", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "audit") {
		t.Errorf("help should contain 'audit', got: %s", output)
	}
}
