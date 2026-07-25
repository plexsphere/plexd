package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/agent"
)

// useConfigFile points cfgFile at path and sets cobra's "changed" bookkeeping
// for the persistent --config flag, restoring both afterwards. deregister reads
// that flag to tell an explicit --config from the default one, and the flag is
// shared across every command execution in this package — a test that left it
// changed would make a later file-less test look as if the operator had passed
// the flag.
func useConfigFile(t *testing.T, path string, changed bool) {
	t.Helper()

	f := rootCmd.PersistentFlags().Lookup("config")
	oldPath, oldChanged := cfgFile, f.Changed
	cfgFile, f.Changed = path, changed
	t.Cleanup(func() { cfgFile, f.Changed = oldPath, oldChanged })
}

// writeDeregisterConfig writes a minimal agent config to a temp file and points
// cfgFile at it for the duration of the test. deregister is local-only, so the
// data dir and the registration token file are the only values it reads.
func writeDeregisterConfig(t *testing.T, dataDir, tokenFile string) {
	t.Helper()

	registrationSection := ""
	if tokenFile != "" {
		registrationSection = fmt.Sprintf("registration:\n  token_file: %s\n", tokenFile)
	}
	body := fmt.Sprintf("data_dir: %s\n%s", dataDir, registrationSection)

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	useConfigFile(t, cfgPath, true)
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

// TestDeregisterCommand_ExplicitConfigMissing pins the guard against a mistyped
// --config. Passing the flag asserts the file is there; when it is not,
// data_dir silently falls back to the built-in default, and both outcomes at
// that path report success — removing an unrelated identity, or vouching for a
// decommission while the node's real identity, and a node secret the control
// plane still accepts, stays on disk. The identity written here stands in for
// that real one: it lives under a data_dir only the unread config names, so it
// must survive untouched. The explicit empty --api keeps the test hermetic
// against an ambient PLEXD_API, which feeds the flag default at package init.
func TestDeregisterCommand_ExplicitConfigMissing(t *testing.T) {
	// The guard runs before the removal, so nothing under the default data dir
	// is touched — but a regression would unlink identity.json there. The
	// hazard is a writable directory, not uid 0, so skip whenever the path
	// exists at all.
	if _, err := os.Stat(agent.DefaultDataDir); err == nil {
		t.Skipf("%s exists on this host; a regression would touch real state there", agent.DefaultDataDir)
	}

	realDataDir := t.TempDir()
	realIdentity := filepath.Join(realDataDir, "identity.json")
	if err := os.WriteFile(realIdentity, []byte(`{"node_id":"n1"}`), 0600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	oldAPIURL := apiURL
	t.Cleanup(func() { apiURL = oldAPIURL })
	useConfigFile(t, "/nonexistent/path/config.yaml", true)

	output, err := executeCmd(t, "deregister", "--config", "/nonexistent/path/config.yaml", "--api=")
	if err == nil {
		t.Fatal("expected an error for an explicit --config that names no file")
	}
	for _, want := range []string{"plexd deregister: no config file at", agent.DefaultDataDir, "/nonexistent/path/config.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q, got: %v", want, err)
		}
	}
	for _, unwanted := range []string{"no local identity found", "local identity removed"} {
		if strings.Contains(output, unwanted) {
			t.Errorf("output must not contain %q, got: %s", unwanted, output)
		}
	}
	if _, statErr := os.Stat(realIdentity); statErr != nil {
		t.Errorf("the configured data_dir's identity must be untouched, stat err = %v", statErr)
	}
}

// TestDeregisterCommand_FilelessDefaultIsIdempotent pins the documented
// contract for the file-less deployment this branch blesses: there is no config
// file by construction, so a deregister that finds no identity is "nothing to
// do", not a failure. A retried Helm pre-delete hook or a re-run Ansible task
// must not record an error — and under `set -e` a failure here would abort
// every remaining cleanup step.
func TestDeregisterCommand_FilelessDefaultIsIdempotent(t *testing.T) {
	if _, err := os.Stat(agent.DefaultDataDir); err == nil {
		t.Skipf("%s exists on this host; the file-less default data_dir would touch real state", agent.DefaultDataDir)
	}

	// changed=false is the point: the operator never passed --config, so the
	// absent file is the deployment, not a typo.
	useConfigFile(t, "/nonexistent/path/config.yaml", false)

	output, err := executeCmd(t, "deregister")
	if err != nil {
		t.Fatalf("deregister without a config file should succeed, got: %v", err)
	}
	if !strings.Contains(output, "no local identity found") {
		t.Errorf("output should report nothing to do, got: %s", output)
	}
}

// TestDeregisterCommand_AbsentConfigRefusesPurge pins that the destructive path
// fails closed: without a config file, data_dir is the built-in default rather
// than the configured one, so purging it would wipe unrelated state and leave
// the node's real identity — and a node secret the control plane still accepts
// — untouched while reporting success.
func TestDeregisterCommand_AbsentConfigRefusesPurge(t *testing.T) {
	oldAPIURL := apiURL
	oldPurge := deregisterPurge
	t.Cleanup(func() {
		apiURL = oldAPIURL
		deregisterPurge = oldPurge
	})
	useConfigFile(t, "/nonexistent/path/config.yaml", true)

	output, err := executeCmd(t, "deregister", "--purge", "--config", "/nonexistent/path/config.yaml", "--api=")
	if err == nil {
		t.Fatal("expected error for --purge without a config file")
	}
	for _, want := range []string{"plexd deregister: --purge needs a config file", "/nonexistent/path/config.yaml", agent.DefaultDataDir} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should contain %q, got: %v", want, err)
		}
	}
	if strings.Contains(output, "purged") {
		t.Errorf("output must not claim a purge happened, got: %s", output)
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
