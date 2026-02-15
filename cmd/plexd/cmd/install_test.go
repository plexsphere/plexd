package cmd

import (
	"strings"
	"testing"
)

func TestInstallCommand_Help(t *testing.T) {
	output := executeHelp(t, "install", "--help")
	if !strings.Contains(output, "install") {
		t.Errorf("help should contain 'install', got: %s", output)
	}
	if !strings.Contains(output, "systemd") {
		t.Errorf("help should mention 'systemd', got: %s", output)
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

func TestInstallCommand_RequiresRoot(t *testing.T) {
	assertCmdError(t, "plexd install", "install")
}
