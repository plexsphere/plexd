package cmd

import (
	"os"
	"path/filepath"
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

// TestJoinCommand_AbsentConfigMissingBaseURL pins that an absent config file is
// no longer the failure: join continues with defaults, and it is the base URL
// missing from the merged config that aborts the command. The explicit empty
// --api keeps the test hermetic against an ambient PLEXD_API, which feeds the
// flag default at package init.
func TestJoinCommand_AbsentConfigMissingBaseURL(t *testing.T) {
	oldCfgFile := cfgFile
	oldAPIURL := apiURL
	t.Cleanup(func() {
		cfgFile = oldCfgFile
		apiURL = oldAPIURL
	})

	_, err := executeCmd(t, "join", "--config", "/nonexistent/path/config.yaml", "--api=")

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)

	if err == nil {
		t.Fatal("expected error for a merged config without a base URL")
	}
	want := "plexd join: api: config: BaseURL is required"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error should contain %q, got: %v", want, err)
	}
}

// TestJoinCommand_MalformedConfig pins that an unparsable config file stays a
// hard error at command level and names the offending path.
func TestJoinCommand_MalformedConfig(t *testing.T) {
	oldCfgFile := cfgFile
	oldAPIURL := apiURL
	t.Cleanup(func() {
		cfgFile = oldCfgFile
		apiURL = oldAPIURL
	})

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := executeCmd(t, "join", "--config", cfgPath, "--api=")

	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)

	if err == nil {
		t.Fatal("expected error for a malformed config")
	}
	for _, want := range []string{"plexd join:", "agent: config: parse", cfgPath} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q, got: %v", want, err)
		}
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
