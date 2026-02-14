package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/registration"
)

var deregisterPurge bool

var deregisterCmd = &cobra.Command{
	Use:   "deregister",
	Short: "Deregister this node from the control plane",
	Long:  "Deregister this node from the control plane.\nWith --purge, also removes local data and config.",
	RunE:  runDeregister,
}

func init() {
	deregisterCmd.Flags().BoolVar(&deregisterPurge, "purge", false, "remove data_dir, token file, and disable systemd unit")
	rootCmd.AddCommand(deregisterCmd)
}

func runDeregister(cmd *cobra.Command, _ []string) error {
	cfg, err := agent.ParseConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("plexd deregister: %w", err)
	}
	if apiURL != "" {
		cfg.API.BaseURL = apiURL
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Load identity from disk.
	identity, err := registration.LoadIdentity(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("plexd deregister: load identity: %w", err)
	}

	// Create client with auth token.
	client, err := api.NewControlPlane(cfg.API, buildVersion, logger)
	if err != nil {
		return fmt.Errorf("plexd deregister: create client: %w", err)
	}
	client.SetAuthToken(identity.NodeSecretKey)

	// Deregister from control plane.
	if err := client.Deregister(context.Background(), identity.NodeID); err != nil {
		return fmt.Errorf("plexd deregister: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "node %s deregistered\n", identity.NodeID)

	// Purge local data if requested.
	if deregisterPurge {
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
