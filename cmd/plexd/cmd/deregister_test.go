package cmd

import (
	"strings"
	"testing"
)

func TestDeregisterCommand_Help(t *testing.T) {
	output := executeHelp(t, "deregister", "--help")
	if !strings.Contains(output, "deregister") {
		t.Errorf("help should contain 'deregister', got: %s", output)
	}
	if !strings.Contains(output, "control plane") {
		t.Errorf("help should mention 'control plane', got: %s", output)
	}
}

func TestDeregisterCommand_PurgeFlag(t *testing.T) {
	f := deregisterCmd.Flags().Lookup("purge")
	if f == nil {
		t.Fatal("expected --purge flag to exist")
	}
	if f.DefValue != "false" {
		t.Errorf("expected --purge default to be 'false', got %q", f.DefValue)
	}
	if !strings.Contains(f.Usage, "data_dir") {
		t.Errorf("--purge usage should mention 'data_dir', got: %q", f.Usage)
	}
}

func TestDeregisterCommand_ConfigError(t *testing.T) {
	oldCfgFile := cfgFile
	t.Cleanup(func() { cfgFile = oldCfgFile })

	_, err := executeCmd(t, "deregister", "--config", "/nonexistent/path/config.yaml")

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)

	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
	if !strings.Contains(err.Error(), "plexd deregister") {
		t.Errorf("error should mention 'plexd deregister', got: %v", err)
	}
}

func TestDeregisterCommand_IsRegistered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "deregister" {
			found = true
			break
		}
	}
	if !found {
		t.Error("deregister should be registered as a subcommand of root")
	}
}

func TestDeregisterCommand_LongDescription(t *testing.T) {
	if deregisterCmd.Long == "" {
		t.Error("deregister command should have a long description")
	}
	if !strings.Contains(deregisterCmd.Long, "--purge") {
		t.Errorf("long description should mention '--purge', got: %s", deregisterCmd.Long)
	}
}
