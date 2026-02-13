package packaging

import "fmt"

// GenerateDefaultConfig produces a minimal default config.yaml for plexd.
// If apiBaseURL is empty, a placeholder comment is written instead.
func GenerateDefaultConfig(apiBaseURL string) string {
	apiLine := "# api_url: https://your-control-plane.example.com"
	if apiBaseURL != "" {
		apiLine = fmt.Sprintf("api_url: %s", apiBaseURL)
	}

	return fmt.Sprintf(`# plexd configuration
# See documentation for all available options.

%s
data_dir: /var/lib/plexd
log_level: info
token_file: /etc/plexd/bootstrap-token
`, apiLine)
}
