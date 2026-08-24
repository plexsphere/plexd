// Package cmd implements the plexd CLI commands.
package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/paths"
)

// warnIfConfigAbsent reports a missing config file once, at warn level, so a
// mistyped --config stays visible on the file-less path. The data dir is named
// alongside the path because it decides which identity the command reads and
// writes, and without a file it is the built-in default rather than a
// configured one.
//
// It writes through its own stderr handler instead of the command's logger:
// plexd up's logger is level-filtered, so --log-level error would drop this
// line — and that is the deployment where it matters most, since a pod that
// lost its ConfigMap emits no other signal before it registers as a new node.
// A missing config file is a startup fact, not routine chatter.
func warnIfConfigAbsent(found bool, path, dataDir string) {
	if found {
		return
	}
	slog.New(slog.NewTextHandler(os.Stderr, nil)).Warn(
		"config file not found, continuing with defaults and overrides",
		"path", path, "data_dir", dataDir)
}

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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", envOrDefault("PLEXD_CONFIG", paths.ConfigFile()), "config file path")
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
