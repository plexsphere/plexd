package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/agent"
)

var deregisterPurge bool

var deregisterCmd = &cobra.Command{
	Use:   "deregister",
	Short: "Remove this node's local identity",
	Long: "Remove this node's local identity (identity.json) from the data directory.\n\n" +
		"This is a local-only cleanup: it makes no request to the control plane. " +
		"Removing the node from the control plane is operator-driven and is done on " +
		"the platform. Running this command when no local identity exists is not an " +
		"error.\n\n" +
		"With --purge, also remove the data directory and the registration token file.",
	RunE: runDeregister,
}

func init() {
	deregisterCmd.Flags().BoolVar(&deregisterPurge, "purge", false, "also remove data_dir and the registration token file")
	rootCmd.AddCommand(deregisterCmd)
}

func runDeregister(cmd *cobra.Command, _ []string) error {
	cfg, err := agent.ParseConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("plexd deregister: %w", err)
	}

	identityPath := filepath.Join(cfg.DataDir, "identity.json")
	switch err := os.Remove(identityPath); {
	case err == nil:
		fmt.Fprintf(cmd.OutOrStdout(), "local identity removed (%s)\n", identityPath)
		fmt.Fprintln(cmd.OutOrStdout(), "node removal from the control plane is operator-driven on the platform")
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintln(cmd.OutOrStdout(), "no local identity found (nothing to do)")
	default:
		return fmt.Errorf("plexd deregister: remove identity: %w", err)
	}

	// Purge local data if requested.
	if deregisterPurge {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		if err := os.RemoveAll(cfg.DataDir); err != nil {
			logger.Warn("failed to remove data directory", "path", cfg.DataDir, "error", err)
		}
		tokenPath := cfg.Registration.TokenFile
		if tokenPath != "" {
			os.Remove(tokenPath)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "local data purged")
	}

	return nil
}
