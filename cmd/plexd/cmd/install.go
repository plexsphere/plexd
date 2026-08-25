package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/packaging"
)

var (
	installAPIURL    string
	installToken     string
	installTokenFile string
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install plexd as a system service (systemd, launchd or Windows service)",
	Long: "Registers plexd as a system service with the host's service manager: a\n" +
		"systemd unit on Linux, a launchd daemon on macOS, a Windows service on\n" +
		"Windows. The service is registered but not started.\n" +
		"\n" +
		"Start it with one of:\n" +
		"  systemctl enable --now plexd\n" +
		"  sudo launchctl bootstrap system /Library/LaunchDaemons/com.plexsphere.plexd.plist\n" +
		"  sc start plexd",
	RunE: runInstall,
}

func init() {
	installCmd.Flags().StringVar(&installAPIURL, "api-url", "", "control plane API URL")
	installCmd.Flags().StringVar(&installToken, "token", "", "bootstrap token value")
	installCmd.Flags().StringVar(&installTokenFile, "token-file", "", "path to bootstrap token file")
	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := packaging.InstallConfig{
		APIBaseURL: installAPIURL,
		TokenValue: installToken,
		TokenFile:  installTokenFile,
	}

	installer := packaging.NewInstaller(cfg, packaging.NewServiceManager(logger), packaging.NewRootChecker(), logger)

	if err := installer.Install(); err != nil {
		return fmt.Errorf("plexd install: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "plexd installed successfully")
	return nil
}
