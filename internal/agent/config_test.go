package agent

import (
	"os"
	"path/filepath"
	"testing"
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
  baseurl: "https://example.com"
registration:
  datadir: /tmp/plexd
node_api:
  datadir: /tmp/plexd
heartbeat:
  nodeid: "node-1"
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
}

func TestParseConfig_MissingRequiredField(t *testing.T) {
	// api.BaseURL is required; omitting it should fail validation.
	yaml := `
mode: node
registration:
  datadir: /tmp/plexd
node_api:
  datadir: /tmp/plexd
heartbeat:
  nodeid: "node-1"
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
  baseurl: "https://example.com"
registration:
  datadir: /tmp/plexd
node_api:
  datadir: /tmp/plexd
heartbeat:
  nodeid: "node-1"
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
