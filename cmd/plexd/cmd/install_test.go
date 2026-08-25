package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/packaging"
)

func TestInstallCommand_Help(t *testing.T) {
	output := executeHelp(t, "install", "--help")
	if !strings.Contains(output, "install") {
		t.Errorf("help should contain 'install', got: %s", output)
	}
	if !strings.Contains(output, "system service") {
		t.Errorf("help should mention 'system service', got: %s", output)
	}
}

func TestInstallCommand_Flags(t *testing.T) {
	tests := []struct {
		flag string
		want string
	}{
		{"api-url", "control plane API URL"},
		{"token", "bootstrap token value"},
		{"token-file", "path to bootstrap token file"},
	}
	for _, tt := range tests {
		f := installCmd.Flags().Lookup(tt.flag)
		if f == nil {
			t.Errorf("expected flag %q to exist", tt.flag)
			continue
		}
		if !strings.Contains(f.Usage, tt.want) {
			t.Errorf("flag %q usage should contain %q, got: %q", tt.flag, tt.want, f.Usage)
		}
	}
}

// TestInstallCommand_RequiresPrivileges runs the real command, so it can only
// assert the refusal on a host that would actually be refused. The GitHub
// windows-latest runner is elevated, and without this skip the test would
// register a plexd service on the runner itself.
func TestInstallCommand_RequiresPrivileges(t *testing.T) {
	if packaging.NewRootChecker().IsRoot() {
		t.Skip("running privileged; install would register a real service on this host")
	}
	assertCmdError(t, "plexd install", "install")
}
