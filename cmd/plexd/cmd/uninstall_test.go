package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/packaging"
)

func TestUninstallCommand_Help(t *testing.T) {
	output := executeHelp(t, "uninstall", "--help")
	if !strings.Contains(output, "uninstall") {
		t.Errorf("help should contain 'uninstall', got: %s", output)
	}
	if !strings.Contains(output, "system service") {
		t.Errorf("help should mention 'system service', got: %s", output)
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

// TestUninstallCommand_RequiresPrivileges skips on a privileged host for the
// reason TestInstallCommand_RequiresPrivileges gives.
func TestUninstallCommand_RequiresPrivileges(t *testing.T) {
	if packaging.NewRootChecker().IsRoot() {
		t.Skip("running privileged; uninstall would touch a real service on this host")
	}
	assertCmdError(t, "plexd uninstall", "uninstall")
}
