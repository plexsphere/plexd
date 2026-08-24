package packaging

import (
	"fmt"

	"github.com/plexsphere/plexd/internal/paths"
)

// GenerateDefaultConfig produces a minimal default config.yaml for plexd.
// If apiBaseURL is empty, a placeholder comment is written instead.
//
// data_dir and registration.token_file are written as the platform defaults,
// so the file names the same directories the daemon would fall back to without
// it. Both are plain YAML scalars, where a backslash is a literal character
// and needs no escaping.
func GenerateDefaultConfig(apiBaseURL string) string {
	apiSection := "# api:\n#   base_url: https://your-control-plane.example.com"
	if apiBaseURL != "" {
		apiSection = fmt.Sprintf("api:\n  base_url: %s", apiBaseURL)
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
