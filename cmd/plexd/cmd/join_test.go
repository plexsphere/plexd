package cmd

import (
	"strings"
	"testing"
)

func TestJoinCommand_Help(t *testing.T) {
	output := executeHelp(t, "join", "--help")
	if !strings.Contains(output, "join") {
		t.Errorf("help should contain 'join', got: %s", output)
	}
	if !strings.Contains(output, "control plane") {
		t.Errorf("help should mention 'control plane', got: %s", output)
	}
	for _, flag := range []string{"--project-id", "--resource-handle", "--requested-resource-id"} {
		if !strings.Contains(output, flag) {
			t.Errorf("join help should contain global flag %q, got: %s", flag, output)
		}
	}
}

func TestJoinCommand_TokenFileFlag(t *testing.T) {
	f := joinCmd.Flags().Lookup("token-file")
	if f == nil {
		t.Fatal("expected --token-file flag to exist")
	}
	if f.DefValue != "" {
		t.Errorf("expected --token-file default to be empty, got %q", f.DefValue)
	}
	if !strings.Contains(f.Usage, "bootstrap token") {
		t.Errorf("--token-file usage should mention 'bootstrap token', got: %q", f.Usage)
	}
}

func TestJoinCommand_ConfigError(t *testing.T) {
	oldCfgFile := cfgFile
	t.Cleanup(func() { cfgFile = oldCfgFile })

	_, err := executeCmd(t, "join", "--config", "/nonexistent/path/config.yaml")

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)

	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
	if !strings.Contains(err.Error(), "plexd join") {
		t.Errorf("error should mention 'plexd join', got: %v", err)
	}
}

func TestJoinCommand_IsRegistered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "join" {
			found = true
			break
		}
	}
	if !found {
		t.Error("join should be registered as a subcommand of root")
	}
}

func TestJoinCommand_LongDescription(t *testing.T) {
	if joinCmd.Long == "" {
		t.Error("join command should have a long description")
	}
	if !strings.Contains(joinCmd.Long, "agent daemon") {
		t.Errorf("long description should mention 'agent daemon', got: %s", joinCmd.Long)
	}
}
