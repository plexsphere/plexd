package packaging

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/plexsphere/plexd/internal/paths"
)

func TestGenerateDefaultConfig_WithAPIURL(t *testing.T) {
	output := GenerateDefaultConfig("https://api.example.com")

	if !strings.Contains(output, "api:\n  base_url: https://api.example.com") {
		t.Errorf("output missing api.base_url, got:\n%s", output)
	}
	if !strings.Contains(output, "data_dir: "+DefaultDataDir) {
		t.Errorf("output missing data_dir %q, got:\n%s", DefaultDataDir, output)
	}
	if !strings.Contains(output, "log_level: info") {
		t.Error("output missing log_level")
	}
	if !strings.Contains(output, "registration:\n  token_file: "+paths.TokenFile()) {
		t.Errorf("output missing registration.token_file, got:\n%s", output)
	}
	if !strings.Contains(output, "# project_id: <project uuid>") {
		t.Errorf("output missing project_id placeholder, got:\n%s", output)
	}
	if !strings.Contains(output, "# resource_handle: <platform resource handle>") {
		t.Errorf("output missing resource_handle placeholder, got:\n%s", output)
	}
}

func TestGenerateDefaultConfig_WithoutAPIURL(t *testing.T) {
	output := GenerateDefaultConfig("")

	if !strings.Contains(output, "# api:") {
		t.Errorf("output missing commented api placeholder, got:\n%s", output)
	}
	if !strings.Contains(output, "#   base_url:") {
		t.Errorf("output missing commented base_url placeholder, got:\n%s", output)
	}
	// Should NOT contain an uncommented api: section
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "api:" {
			t.Errorf("output contains uncommented api: line: %q", line)
		}
	}
	if !strings.Contains(output, "data_dir: "+DefaultDataDir) {
		t.Errorf("output missing data_dir %q, got:\n%s", DefaultDataDir, output)
	}
	if !strings.Contains(output, "log_level: info") {
		t.Error("output missing log_level")
	}
}

// TestGenerateDefaultConfig_RoundTrip parses the generated file back. The two
// paths are written as plain YAML scalars, where a backslash is literal and a
// space needs no quoting — so this is what proves a Windows
// "C:\ProgramData\plexd\data" and a macOS "/Library/Application Support/plexd"
// survive the write intact rather than coming back escaped or truncated.
func TestGenerateDefaultConfig_RoundTrip(t *testing.T) {
	output := GenerateDefaultConfig("https://api.example.com")

	var parsed struct {
		DataDir      string `yaml:"data_dir"`
		Registration struct {
			TokenFile string `yaml:"token_file"`
		} `yaml:"registration"`
	}
	if err := yaml.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("yaml.Unmarshal: %v, got:\n%s", err, output)
	}

	if parsed.DataDir != DefaultDataDir {
		t.Errorf("data_dir = %q, want %q", parsed.DataDir, DefaultDataDir)
	}
	if parsed.Registration.TokenFile != paths.TokenFile() {
		t.Errorf("registration.token_file = %q, want %q", parsed.Registration.TokenFile, paths.TokenFile())
	}
}

func TestGenerateDefaultConfig_YAMLValidity(t *testing.T) {
	// Verify basic YAML structure: all non-comment, non-empty lines have key: value or key:\n format
	output := GenerateDefaultConfig("https://api.example.com")
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(trimmed, ":") {
			t.Errorf("non-comment line missing key format: %q", trimmed)
		}
	}
}
