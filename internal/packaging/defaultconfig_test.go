package packaging

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/plexsphere/plexd/internal/paths"
)

func TestGenerateDefaultConfig_WithAPIURL(t *testing.T) {
	output := GenerateDefaultConfig("https://api.example.com", "")

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
	output := GenerateDefaultConfig("", "")

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

// TestGenerateDefaultConfig_RoundTrip parses the generated file back. The
// paths are written as plain YAML scalars, where a backslash is literal and a
// space needs no quoting — so this is what proves a Windows
// "C:\ProgramData\plexd\data" and a macOS "/Library/Application Support/plexd"
// survive the write intact rather than coming back escaped or truncated. The
// CA path is the one Install writes on this platform.
func TestGenerateDefaultConfig_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		tlsCAFile string
	}{
		{"without CA file", ""},
		{"with CA file", filepath.Join(DefaultConfigDir, InstalledCAFileName)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := GenerateDefaultConfig("https://api.example.com", tt.tlsCAFile)

			var parsed struct {
				API struct {
					TLSCAFile string `yaml:"tls_ca_file"`
				} `yaml:"api"`
				DataDir      string `yaml:"data_dir"`
				Registration struct {
					TokenFile string `yaml:"token_file"`
				} `yaml:"registration"`
			}
			if err := yaml.Unmarshal([]byte(output), &parsed); err != nil {
				t.Fatalf("yaml.Unmarshal: %v, got:\n%s", err, output)
			}

			if parsed.API.TLSCAFile != tt.tlsCAFile {
				t.Errorf("api.tls_ca_file = %q, want %q", parsed.API.TLSCAFile, tt.tlsCAFile)
			}
			if parsed.DataDir != DefaultDataDir {
				t.Errorf("data_dir = %q, want %q", parsed.DataDir, DefaultDataDir)
			}
			if parsed.Registration.TokenFile != paths.TokenFile() {
				t.Errorf("registration.token_file = %q, want %q", parsed.Registration.TokenFile, paths.TokenFile())
			}
		})
	}
}

// defaultConfigHead and defaultConfigTail are the template text around the api
// section, spelled out here rather than taken from GenerateDefaultConfig so a
// change to the template shows up as a failing test.
const defaultConfigHead = "# plexd configuration\n" +
	"# See documentation for all available options.\n" +
	"\n"

func defaultConfigTail() string {
	return "\n" +
		"\n" +
		"data_dir: " + DefaultDataDir + "\n" +
		"log_level: info\n" +
		"\n" +
		"registration:\n" +
		"  token_file: " + paths.TokenFile() + "\n" +
		"  # project_id: <project uuid>\n" +
		"  # resource_handle: <platform resource handle>\n"
}

// TestGenerateDefaultConfig_WithoutCAFileUnchanged pins the whole file written
// without a CA bundle, so adding tls_ca_file cannot alter what an install
// without --ca-file has always written.
func TestGenerateDefaultConfig_WithoutCAFileUnchanged(t *testing.T) {
	tests := []struct {
		name       string
		apiBaseURL string
		apiSection string
	}{
		{
			name:       "with api url",
			apiBaseURL: "https://api.example.com",
			apiSection: "api:\n" +
				"  base_url: https://api.example.com",
		},
		{
			name:       "without api url",
			apiBaseURL: "",
			apiSection: "# api:\n" +
				"#   base_url: https://your-control-plane.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := defaultConfigHead + tt.apiSection + defaultConfigTail()
			if got := GenerateDefaultConfig(tt.apiBaseURL, ""); got != want {
				t.Errorf("GenerateDefaultConfig(%q, \"\") =\n%s\nwant:\n%s", tt.apiBaseURL, got, want)
			}
		})
	}
}

// TestGenerateDefaultConfig_WithCAFile checks the two api sections a CA bundle
// produces. Without an API URL the api key itself is live, since tls_ca_file
// would otherwise sit in a comment, and only base_url stays a placeholder.
func TestGenerateDefaultConfig_WithCAFile(t *testing.T) {
	const caFile = "/etc/plexd/control-plane-ca.pem"
	tests := []struct {
		name        string
		apiBaseURL  string
		apiSection  string
		wantBaseURL string
	}{
		{
			name:       "with api url",
			apiBaseURL: "https://api.example.com",
			apiSection: "api:\n" +
				"  base_url: https://api.example.com\n" +
				"  tls_ca_file: /etc/plexd/control-plane-ca.pem",
			wantBaseURL: "https://api.example.com",
		},
		{
			name:       "without api url",
			apiBaseURL: "",
			apiSection: "api:\n" +
				"  # base_url: https://your-control-plane.example.com\n" +
				"  tls_ca_file: /etc/plexd/control-plane-ca.pem",
			wantBaseURL: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := GenerateDefaultConfig(tt.apiBaseURL, caFile)

			want := defaultConfigHead + tt.apiSection + defaultConfigTail()
			if output != want {
				t.Errorf("GenerateDefaultConfig(%q, %q) =\n%s\nwant:\n%s", tt.apiBaseURL, caFile, output, want)
			}

			var parsed struct {
				API struct {
					BaseURL   string `yaml:"base_url"`
					TLSCAFile string `yaml:"tls_ca_file"`
				} `yaml:"api"`
			}
			if err := yaml.Unmarshal([]byte(output), &parsed); err != nil {
				t.Fatalf("yaml.Unmarshal: %v, got:\n%s", err, output)
			}
			if parsed.API.BaseURL != tt.wantBaseURL {
				t.Errorf("api.base_url = %q, want %q", parsed.API.BaseURL, tt.wantBaseURL)
			}
			if parsed.API.TLSCAFile != caFile {
				t.Errorf("api.tls_ca_file = %q, want %q", parsed.API.TLSCAFile, caFile)
			}
		})
	}
}

func TestGenerateDefaultConfig_YAMLValidity(t *testing.T) {
	// Verify basic YAML structure: all non-comment, non-empty lines have key: value or key:\n format
	output := GenerateDefaultConfig("https://api.example.com", "")
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
