package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/packaging"
)

var purge bool

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove plexd systemd service",
	RunE:  runUninstall,
}

func init() {
	uninstallCmd.Flags().BoolVar(&purge, "purge", false, "also remove data and config directories")
	rootCmd.AddCommand(uninstallCmd)
}

func runUninstall(cmd *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := packaging.InstallConfig{}
	installer := packaging.NewInstaller(cfg, packaging.NewSystemdController(), packaging.NewRootChecker(), logger)

	if err := installer.Uninstall(purge); err != nil {
		return fmt.Errorf("plexd uninstall: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "plexd uninstalled successfully")
	return nil
}
