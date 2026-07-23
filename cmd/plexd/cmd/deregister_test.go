package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDeregisterConfig writes a minimal agent config to a temp file and points
// cfgFile at it for the duration of the test. The config never needs a
// reachable control plane: deregister makes no HTTP request, so base_url is a
// dead address that is only present to satisfy config validation.
func writeDeregisterConfig(t *testing.T, dataDir, tokenFile string) {
	t.Helper()

	tokenLine := ""
	if tokenFile != "" {
		tokenLine = fmt.Sprintf("  token_file: %s\n", tokenFile)
	}
	body := fmt.Sprintf(
		"data_dir: %[1]s\n"+
			"api:\n  base_url: http://127.0.0.1:0\n"+
			"registration:\n  data_dir: %[1]s\n%[2]s"+
			"node_api:\n  data_dir: %[1]s\n"+
			"heartbeat:\n  node_id: deregister-test-node\n",
		dataDir, tokenLine)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	old := cfgFile
	cfgFile = cfgPath
	t.Cleanup(func() { cfgFile = old })
}

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
	if !strings.Contains(deregisterCmd.Long, "control plane") {
		t.Errorf("long description should mention 'control plane', got: %s", deregisterCmd.Long)
	}
}

func TestDeregisterCommand_RemovesIdentity(t *testing.T) {
	dataDir := t.TempDir()
	identityPath := filepath.Join(dataDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte(`{"node_id":"n1"}`), 0600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	writeDeregisterConfig(t, dataDir, "")

	output, err := executeCmd(t, "deregister")
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}
	if _, statErr := os.Stat(identityPath); !os.IsNotExist(statErr) {
		t.Errorf("identity.json should be removed, stat err = %v", statErr)
	}
	if !strings.Contains(output, "operator-driven") {
		t.Errorf("output should mention operator-driven platform removal, got: %s", output)
	}
}

func TestDeregisterCommand_MissingIdentityIsIdempotent(t *testing.T) {
	writeDeregisterConfig(t, t.TempDir(), "")

	output, err := executeCmd(t, "deregister")
	if err != nil {
		t.Fatalf("deregister with no identity should succeed, got: %v", err)
	}
	if !strings.Contains(output, "no local identity") {
		t.Errorf("output should say no local identity exists, got: %s", output)
	}
}

func TestDeregisterCommand_RemoveFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions, so os.Remove cannot fail here")
	}

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "identity.json"), []byte(`{"node_id":"n1"}`), 0600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	// A read-only data dir makes unlinking identity.json fail.
	if err := os.Chmod(dataDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0700) })

	writeDeregisterConfig(t, dataDir, "")

	_, err := executeCmd(t, "deregister")
	if err == nil {
		t.Fatal("expected error when identity removal fails")
	}
	if !strings.Contains(err.Error(), "plexd deregister: remove identity:") {
		t.Errorf("error should mention 'plexd deregister: remove identity:', got: %v", err)
	}
}

func TestDeregisterCommand_Purge(t *testing.T) {
	old := deregisterPurge
	t.Cleanup(func() { deregisterPurge = old })

	dataDir := t.TempDir()
	identityPath := filepath.Join(dataDir, "identity.json")
	if err := os.WriteFile(identityPath, []byte(`{"node_id":"n1"}`), 0600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	tokenFile := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(tokenFile, []byte("tok"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	writeDeregisterConfig(t, dataDir, tokenFile)

	output, err := executeCmd(t, "deregister", "--purge")
	if err != nil {
		t.Fatalf("deregister --purge: %v", err)
	}
	if _, statErr := os.Stat(identityPath); !os.IsNotExist(statErr) {
		t.Errorf("identity.json should be removed, stat err = %v", statErr)
	}
	if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
		t.Errorf("data_dir should be removed, stat err = %v", statErr)
	}
	if _, statErr := os.Stat(tokenFile); !os.IsNotExist(statErr) {
		t.Errorf("token file should be removed, stat err = %v", statErr)
	}
	if !strings.Contains(output, "local data purged") {
		t.Errorf("output should contain 'local data purged', got: %s", output)
	}
}
