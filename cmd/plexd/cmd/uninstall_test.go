package cmd

import (
	"strings"
	"testing"
)

func TestUninstallCommand_Help(t *testing.T) {
	output := executeHelp(t, "uninstall", "--help")
	if !strings.Contains(output, "uninstall") {
		t.Errorf("help should contain 'uninstall', got: %s", output)
	}
	if !strings.Contains(output, "systemd") {
		t.Errorf("help should mention 'systemd', got: %s", output)
	}
}

func TestUninstallCommand_PurgeFlag(t *testing.T) {
	f := uninstallCmd.Flags().Lookup("purge")
	if f == nil {
		t.Fatal("expected --purge flag to exist")
	}
	if f.DefValue != "false" {
		t.Errorf("expected --purge default to be 'false', got %q", f.DefValue)
	}
	if !strings.Contains(f.Usage, "data and config") {
		t.Errorf("--purge usage should mention 'data and config', got: %q", f.Usage)
	}
}

func TestUninstallCommand_RequiresRoot(t *testing.T) {
	assertCmdError(t, "plexd uninstall", "uninstall")
}
