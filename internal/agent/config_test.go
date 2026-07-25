package agent

import (
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
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
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
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
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
	_, err := ParseConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid signing_identity_regexp")
	}
	if !strings.Contains(err.Error(), "upgrade: config: compile signing_identity_regexp:") {
		t.Errorf("err = %q, want it to contain %q", err.Error(), "upgrade: config: compile signing_identity_regexp:")
	}
}

func TestParseConfig_MissingRequiredField(t *testing.T) {
	// api.BaseURL is required; omitting it should fail validation.
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
	_, err := ParseConfig(path)
	if err == nil {
		t.Fatal("expected error for missing api.base_url")
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
	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
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

func TestParseConfig_FileNotFound(t *testing.T) {
	_, err := ParseConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{invalid yaml")
	_, err := ParseConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// validConfig returns an AgentConfig that passes Validate after ApplyDefaults.
func validConfig() AgentConfig {
	var cfg AgentConfig
	cfg.API.BaseURL = "https://example.com"
	cfg.Registration.DataDir = "/tmp/plexd"
	cfg.NodeAPI.DataDir = "/tmp/plexd"
	cfg.Heartbeat.NodeID = "node-1"
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
