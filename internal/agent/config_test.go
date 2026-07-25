package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/health"
	"github.com/plexsphere/plexd/internal/upgrade"
)

func TestAgentConfig_ApplyDefaults(t *testing.T) {
	var cfg AgentConfig
	cfg.ApplyDefaults()

	if cfg.Mode != DefaultMode {
		t.Errorf("Mode = %q, want %q", cfg.Mode, DefaultMode)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
	if cfg.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, DefaultDataDir)
	}
	if cfg.Upgrade.ReleaseBaseURL != "https://github.com/plexsphere/plexd/releases/download" {
		t.Errorf("Upgrade.ReleaseBaseURL = %q, want %q", cfg.Upgrade.ReleaseBaseURL, "https://github.com/plexsphere/plexd/releases/download")
	}
	if cfg.Upgrade.SigningIdentityRegexp != upgrade.DefaultSigningIdentityRegexp {
		t.Errorf("Upgrade.SigningIdentityRegexp = %q, want %q", cfg.Upgrade.SigningIdentityRegexp, upgrade.DefaultSigningIdentityRegexp)
	}
	if cfg.Upgrade.SigningIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Upgrade.SigningIssuer = %q, want %q", cfg.Upgrade.SigningIssuer, "https://token.actions.githubusercontent.com")
	}
	if cfg.Upgrade.TrustedRootPath != "" {
		t.Errorf("Upgrade.TrustedRootPath = %q, want empty", cfg.Upgrade.TrustedRootPath)
	}
	if cfg.Health.Listen != health.DefaultListen {
		t.Errorf("Health.Listen = %q, want %q", cfg.Health.Listen, health.DefaultListen)
	}
	// A config file without a health block must still bring the listener up:
	// the shipped DaemonSet probes /healthz and /readyz unconditionally, so an
	// unbound probe target means a liveness failure and a restart loop.
	if !cfg.Health.IsEnabled() {
		t.Error("Health.IsEnabled() = false, want true for an omitted health block")
	}
	// Both are propagated from the top-level data_dir at runtime and never
	// appear in YAML, so defaulting them here is what lets an empty config
	// validate.
	if cfg.Registration.DataDir != DefaultDataDir {
		t.Errorf("Registration.DataDir = %q, want %q", cfg.Registration.DataDir, DefaultDataDir)
	}
	if cfg.NodeAPI.DataDir != DefaultDataDir {
		t.Errorf("NodeAPI.DataDir = %q, want %q", cfg.NodeAPI.DataDir, DefaultDataDir)
	}
	// A config that reaches ApplyDefaults through a file is an
	// operator-expressed configuration, so action execution stays on unless it
	// says otherwise. Only ParseConfig's absent-file path turns it off.
	if !cfg.Actions.IsEnabled() {
		t.Error("Actions.IsEnabled() = false, want true for an omitted actions block")
	}
}

// TestAgentConfig_ApplyDefaults_TopLevelDataDirWins pins the propagation
// contract with values that differ on both sides: the subsystem fields are
// overwritten from the top level, never merged or preserved.
func TestAgentConfig_ApplyDefaults_TopLevelDataDirWins(t *testing.T) {
	var cfg AgentConfig
	cfg.DataDir = "/tmp/plexd-top"
	cfg.Registration.DataDir = "/tmp/plexd-registration"
	cfg.NodeAPI.DataDir = "/tmp/plexd-nodeapi"
	cfg.ApplyDefaults()

	if cfg.Registration.DataDir != "/tmp/plexd-top" {
		t.Errorf("Registration.DataDir = %q, want %q", cfg.Registration.DataDir, "/tmp/plexd-top")
	}
	if cfg.NodeAPI.DataDir != "/tmp/plexd-top" {
		t.Errorf("NodeAPI.DataDir = %q, want %q", cfg.NodeAPI.DataDir, "/tmp/plexd-top")
	}
}

func TestAgentConfig_Validate_InvalidMode(t *testing.T) {
	cfg := validConfig()
	cfg.Mode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestParseConfig_ValidYAML(t *testing.T) {
	yaml := `
mode: bridge
log_level: debug
data_dir: /tmp/plexd
api:
  base_url: "https://example.com"
registration:
  data_dir: /tmp/plexd
  project_id: 11111111-2222-3333-4444-555555555555
  resource_handle: my-resource
  requested_resource_id: substrate-id-1
node_api:
  data_dir: /tmp/plexd
health:
  enabled: false
  listen: "127.0.0.1:19101"
heartbeat:
  node_id: "node-1"
`
	path := writeTemp(t, yaml)
	cfg, found, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !found {
		t.Error("found = false, want true for an existing file")
	}
	if cfg.Mode != "bridge" {
		t.Errorf("Mode = %q, want %q", cfg.Mode, "bridge")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.DataDir != "/tmp/plexd" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/tmp/plexd")
	}
	if cfg.API.BaseURL != "https://example.com" {
		t.Errorf("API.BaseURL = %q, want %q", cfg.API.BaseURL, "https://example.com")
	}
	if cfg.Registration.ProjectID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("Registration.ProjectID = %q, want %q", cfg.Registration.ProjectID, "11111111-2222-3333-4444-555555555555")
	}
	if cfg.Registration.ResourceHandle != "my-resource" {
		t.Errorf("Registration.ResourceHandle = %q, want %q", cfg.Registration.ResourceHandle, "my-resource")
	}
	if cfg.Registration.RequestedResourceID != "substrate-id-1" {
		t.Errorf("Registration.RequestedResourceID = %q, want %q", cfg.Registration.RequestedResourceID, "substrate-id-1")
	}
	// An explicit false must survive parsing: that opt-out is the only way to
	// turn the listener off now that an omitted block enables it.
	if cfg.Health.IsEnabled() {
		t.Error("Health.IsEnabled() = true, want false for an explicit enabled: false")
	}
	if cfg.Health.Listen != "127.0.0.1:19101" {
		t.Errorf("Health.Listen = %q, want %q", cfg.Health.Listen, "127.0.0.1:19101")
	}
}

func TestParseConfig_UpgradeSection(t *testing.T) {
	yaml := `
api:
  base_url: "https://example.com"
registration:
  data_dir: /tmp/plexd
node_api:
  data_dir: /tmp/plexd
heartbeat:
  node_id: "node-1"
upgrade:
  release_base_url: "https://mirror.example.com/releases"
  signing_issuer: "https://issuer.example.com"
`
	path := writeTemp(t, yaml)
	cfg, found, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !found {
		t.Error("found = false, want true for an existing file")
	}
	if cfg.Upgrade.ReleaseBaseURL != "https://mirror.example.com/releases" {
		t.Errorf("Upgrade.ReleaseBaseURL = %q, want %q", cfg.Upgrade.ReleaseBaseURL, "https://mirror.example.com/releases")
	}
	if cfg.Upgrade.SigningIssuer != "https://issuer.example.com" {
		t.Errorf("Upgrade.SigningIssuer = %q, want %q", cfg.Upgrade.SigningIssuer, "https://issuer.example.com")
	}
	// Unset fields still receive their defaults.
	if cfg.Upgrade.SigningIdentityRegexp != upgrade.DefaultSigningIdentityRegexp {
		t.Errorf("Upgrade.SigningIdentityRegexp = %q, want default", cfg.Upgrade.SigningIdentityRegexp)
	}
}

func TestParseConfig_UpgradeInvalidRegexp(t *testing.T) {
	yaml := `
api:
  base_url: "https://example.com"
registration:
  data_dir: /tmp/plexd
node_api:
  data_dir: /tmp/plexd
heartbeat:
  node_id: "node-1"
upgrade:
  signing_identity_regexp: "("
`
	path := writeTemp(t, yaml)
	cfg, found, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !found {
		t.Error("found = false, want true for an existing file")
	}
	// Parsing no longer validates; the bad pattern surfaces once the caller
	// validates the merged config.
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid signing_identity_regexp")
	}
	if !strings.Contains(err.Error(), "upgrade: config: compile signing_identity_regexp:") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "upgrade: config: compile signing_identity_regexp:")
	}
}

func TestParseConfig_MissingRequiredField(t *testing.T) {
	// api.BaseURL is required, but only once the caller validates: the file may
	// legitimately omit it and have --api or PLEXD_API supply it.
	yaml := `
mode: node
registration:
  data_dir: /tmp/plexd
node_api:
  data_dir: /tmp/plexd
heartbeat:
  node_id: "node-1"
`
	path := writeTemp(t, yaml)
	cfg, found, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !found {
		t.Error("found = false, want true for an existing file")
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing api.base_url")
	}
	if err.Error() != "api: config: BaseURL is required" {
		t.Errorf("Validate() error = %q, want %q", err.Error(), "api: config: BaseURL is required")
	}
}

func TestParseConfig_DefaultValues(t *testing.T) {
	// Minimal YAML with only required fields; verify defaults are applied.
	yaml := `
api:
  base_url: "https://example.com"
registration:
  data_dir: /tmp/plexd
node_api:
  data_dir: /tmp/plexd
heartbeat:
  node_id: "node-1"
`
	path := writeTemp(t, yaml)
	cfg, found, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !found {
		t.Error("found = false, want true for an existing file")
	}
	if cfg.Mode != DefaultMode {
		t.Errorf("Mode = %q, want %q", cfg.Mode, DefaultMode)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, DefaultLogLevel)
	}
	if cfg.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, DefaultDataDir)
	}
}

// TestParseConfig_ActionsDisabledByFile pins the kill switch against
// defaulting. The override is deliberately minimal — the shape an operator
// writes when the rest of the actions block is fine as-is — because that is
// the case where an omitted key and an explicit false are easiest to confuse:
// getting it wrong hands the control plane command execution on the node.
func TestParseConfig_ActionsDisabledByFile(t *testing.T) {
	path := writeTemp(t, "actions:\n  enabled: false\n")
	cfg, found, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !found {
		t.Error("found = false, want true for an existing file")
	}
	if cfg.Actions.IsEnabled() {
		t.Error("Actions.IsEnabled() = true, want false for an explicit enabled: false")
	}
}

func TestParseConfig_AbsentFile(t *testing.T) {
	// The DaemonSet mounts the config as optional, so a missing file must yield
	// a defaulted config that flags and environment overrides can complete.
	cfg, found, err := ParseConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if found {
		t.Error("found = true, want false for a non-existent file")
	}
	if cfg.Mode != DefaultMode {
		t.Errorf("Mode = %q, want %q", cfg.Mode, DefaultMode)
	}
	if cfg.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, DefaultDataDir)
	}
	if !cfg.Health.IsEnabled() {
		t.Error("Health.IsEnabled() = false, want true without a config file")
	}
	if cfg.Registration.DataDir != DefaultDataDir {
		t.Errorf("Registration.DataDir = %q, want %q", cfg.Registration.DataDir, DefaultDataDir)
	}
	if cfg.NodeAPI.DataDir != DefaultDataDir {
		t.Errorf("NodeAPI.DataDir = %q, want %q", cfg.NodeAPI.DataDir, DefaultDataDir)
	}
	// Actions.Enabled is the only kill switch on control-plane-driven
	// execution, and it defaults to on. Without a file there is no operator
	// policy to honour, so it must come up off: a deleted or unmounted config
	// must not silently undo actions.enabled: false.
	if cfg.Actions.IsEnabled() {
		t.Error("Actions.IsEnabled() = true, want false without a config file")
	}

	// An API base URL from --api or PLEXD_API is all the merged config needs.
	cfg.API.BaseURL = "https://example.com"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// TestParseConfig_EmptyFile guards the actions kill switch against the gap the
// absent-file path leaves open. yaml.Unmarshal accepts empty input without an
// error, so a zero-byte file would otherwise parse as an operator-supplied
// config and hand back Actions.Enabled unset — that is, action execution on —
// for a truncated write, a ConfigMap key that rendered to nothing, or a
// bootstrap that has not written the file yet.
func TestParseConfig_EmptyFile(t *testing.T) {
	for _, body := range []string{"", "\n", "  \n  \n"} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			path := writeTemp(t, body)
			cfg, found, err := ParseConfig(path)
			if err == nil {
				t.Fatalf("expected an error for an empty file, got cfg with Actions.IsEnabled() = %v", cfg.Actions.IsEnabled())
			}
			if found {
				t.Error("found = true, want false alongside the error")
			}
			if !strings.Contains(err.Error(), "is empty") {
				t.Errorf("err = %q, want it to contain %q", err.Error(), "is empty")
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("err = %q, want it to contain the path %q", err.Error(), path)
			}
		})
	}
}

func TestParseConfig_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions, so the read cannot fail")
	}
	path := writeTemp(t, "mode: node\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	// A file that exists but cannot be read stays fatal: silently falling back
	// to defaults would hide a misconfigured mount.
	_, _, err := ParseConfig(path)
	if err == nil {
		t.Fatal("expected error for an unreadable file")
	}
	if !strings.Contains(err.Error(), "agent: config: read") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "agent: config: read")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %q, want it to contain the path %q", err.Error(), path)
	}
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{invalid yaml")
	_, _, err := ParseConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "agent: config: parse") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "agent: config: parse")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %q, want it to contain the path %q", err.Error(), path)
	}
}

// validConfig returns an AgentConfig that passes Validate after ApplyDefaults.
// The API base URL is the only field defaults cannot supply.
func validConfig() AgentConfig {
	var cfg AgentConfig
	cfg.API.BaseURL = "https://example.com"
	cfg.ApplyDefaults()
	return cfg
}

// writeTemp writes content to a temporary YAML file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
