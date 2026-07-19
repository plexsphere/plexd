package packaging

import (
	"strings"
	"testing"
)

func TestGenerateDefaultConfig_WithAPIURL(t *testing.T) {
	output := GenerateDefaultConfig("https://api.example.com")

	if !strings.Contains(output, "api:\n  base_url: https://api.example.com") {
		t.Errorf("output missing api.base_url, got:\n%s", output)
	}
	if !strings.Contains(output, "data_dir: /var/lib/plexd") {
		t.Error("output missing data_dir")
	}
	if !strings.Contains(output, "log_level: info") {
		t.Error("output missing log_level")
	}
	if !strings.Contains(output, "registration:\n  token_file: /etc/plexd/bootstrap-token") {
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
	if !strings.Contains(output, "data_dir: /var/lib/plexd") {
		t.Error("output missing data_dir")
	}
	if !strings.Contains(output, "log_level: info") {
		t.Error("output missing log_level")
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
