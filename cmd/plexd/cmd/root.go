// Package cmd implements the plexd CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// envOrDefault returns the value of the environment variable named by key,
// or defaultVal if the variable is not set or empty.
func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

var (
	cfgFile  string
	logLevel string
	apiURL   string
	mode     string

	projectID           string
	resourceHandle      string
	requestedResourceID string
)

// Build info set from main.
var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetVersionInfo sets the version info from build-time ldflags.
func SetVersionInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
	rootCmd.Version = buildVersion
	rootCmd.SetVersionTemplate(fmt.Sprintf("plexd version {{.Version}}\ncommit: %s\nbuilt: %s\n", buildCommit, buildDate))
}

var rootCmd = &cobra.Command{
	Use:   "plexd",
	Short: "plexd is the Plexsphere node agent",
	Long: "plexd is a node agent that runs on every node in a Plexsphere-managed environment.\n" +
		"It connects to the control plane, registers the node, establishes encrypted\n" +
		"WireGuard mesh tunnels, enforces network policies, and continuously reconciles local state.",
	// No Run function — prints help by default.
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", envOrDefault("PLEXD_CONFIG", "/etc/plexd/config.yaml"), "config file path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", envOrDefault("PLEXD_LOG_LEVEL", "info"), "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", os.Getenv("PLEXD_API"), "control plane API URL (overrides config)")
	rootCmd.PersistentFlags().StringVar(&mode, "mode", envOrDefault("PLEXD_MODE", ""), "operating mode: node or bridge (overrides config)")
	rootCmd.PersistentFlags().StringVar(&projectID, "project-id", envOrDefault("PLEXD_PROJECT_ID", ""), "platform project UUID for registration (overrides config)")
	rootCmd.PersistentFlags().StringVar(&resourceHandle, "resource-handle", envOrDefault("PLEXD_RESOURCE_HANDLE", ""), "platform resource handle for registration (overrides config)")
	rootCmd.PersistentFlags().StringVar(&requestedResourceID, "requested-resource-id", envOrDefault("PLEXD_REQUESTED_RESOURCE_ID", ""), "override resource id when substrate naming differs (overrides config)")

	rootCmd.Version = buildVersion
	rootCmd.SetVersionTemplate(fmt.Sprintf("plexd version {{.Version}}\ncommit: %s\nbuilt: %s\n", buildCommit, buildDate))
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
