// Package cmd implements the plexd CLI commands.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	logLevel string
	apiURL   string
	mode     string
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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "/etc/plexd/config.yaml", "config file path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "", "control plane API URL (overrides config)")
	rootCmd.PersistentFlags().StringVar(&mode, "mode", "", "operating mode: node or bridge (overrides config)")

	rootCmd.Version = buildVersion
	rootCmd.SetVersionTemplate(fmt.Sprintf("plexd version {{.Version}}\ncommit: %s\nbuilt: %s\n", buildCommit, buildDate))
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
