package packaging

import (
	"fmt"

	"github.com/plexsphere/plexd/internal/paths"
)

// GenerateDefaultConfig produces a minimal default config.yaml for plexd.
// If apiBaseURL is empty, a placeholder comment is written instead. A
// non-empty tlsCAFile is written as api.tls_ca_file, and the api section is
// then live even without apiBaseURL, with only base_url left as a placeholder.
//
// data_dir, registration.token_file and api.tls_ca_file are written as plain
// YAML scalars, where a backslash is a literal character and a space needs no
// quoting. data_dir and registration.token_file are the platform defaults, so
// the file names the same directories the daemon would fall back to without
// it.
func GenerateDefaultConfig(apiBaseURL, tlsCAFile string) string {
	var apiSection string
	switch {
	case tlsCAFile != "" && apiBaseURL != "":
		apiSection = fmt.Sprintf("api:\n  base_url: %s\n  tls_ca_file: %s", apiBaseURL, tlsCAFile)
	case tlsCAFile != "":
		apiSection = fmt.Sprintf("api:\n  # base_url: https://your-control-plane.example.com\n  tls_ca_file: %s", tlsCAFile)
	case apiBaseURL != "":
		apiSection = fmt.Sprintf("api:\n  base_url: %s", apiBaseURL)
	default:
		apiSection = "# api:\n#   base_url: https://your-control-plane.example.com"
	}

	return fmt.Sprintf(`# plexd configuration
# See documentation for all available options.

%s

data_dir: %s
log_level: info

registration:
  token_file: %s
  # project_id: <project uuid>
  # resource_handle: <platform resource handle>
`, apiSection, DefaultDataDir, paths.TokenFile())
}
