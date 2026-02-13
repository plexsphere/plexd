package packaging

import (
	"strings"
	"testing"
)

func TestGenerateDefaultConfig_WithAPIURL(t *testing.T) {
	output := GenerateDefaultConfig("https://api.example.com")

	if !strings.Contains(output, "api_url: https://api.example.com") {
		t.Errorf("output missing api_url, got:\n%s", output)
	}
	if !strings.Contains(output, "data_dir: /var/lib/plexd") {
		t.Error("output missing data_dir")
	}
	if !strings.Contains(output, "log_level: info") {
		t.Error("output missing log_level")
	}
	if !strings.Contains(output, "token_file: /etc/plexd/bootstrap-token") {
		t.Error("output missing token_file")
	}
}

func TestGenerateDefaultConfig_WithoutAPIURL(t *testing.T) {
	output := GenerateDefaultConfig("")

	if !strings.Contains(output, "# api_url:") {
		t.Errorf("output missing commented api_url placeholder, got:\n%s", output)
	}
	// Should NOT contain an uncommented api_url line
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "api_url:") {
			t.Errorf("output contains uncommented api_url line: %q", line)
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
	// Verify basic YAML structure: all non-comment, non-empty lines have key: value format
	output := GenerateDefaultConfig("https://api.example.com")
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(trimmed, ": ") {
			t.Errorf("non-comment line missing key-value format: %q", trimmed)
		}
	}
}
