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
		"An explicit --config naming a file that does not exist is an error: data_dir " +
		"would silently fall back to the built-in default, so the command would work " +
		"on a directory the operator did not name.\n\n" +
		"With --purge, also remove the data directory and the registration token file.",
	RunE: runDeregister,
}

func init() {
	deregisterCmd.Flags().BoolVar(&deregisterPurge, "purge", false, "also remove data_dir and the registration token file")
	rootCmd.AddCommand(deregisterCmd)
}

func runDeregister(cmd *cobra.Command, _ []string) error {
	cfg, cfgFound, err := agent.ParseConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("plexd deregister: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	warnIfConfigAbsent(cfgFound, cfgFile, cfg.DataDir)

	// The config is deliberately not validated: deregister is local-only, and
	// the two values it reads — data_dir and the registration token file —
	// always carry a default. Requiring api.base_url here would block cleanup
	// on a host that no longer knows its control plane.

	// --purge destroys the node's key material, so it must run against the data
	// dir the operator configured. Without a config file that dir is the
	// built-in default: purging it would wipe unrelated state while leaving the
	// real identity — and a node secret the control plane still accepts — in
	// place, and report success either way.
	if deregisterPurge && !cfgFound {
		return fmt.Errorf("plexd deregister: --purge needs a config file: none at %s, so data_dir would be the default %s rather than the configured one", cfgFile, agent.DefaultDataDir)
	}

	// An explicit --config that resolves to nothing is a typo, not a file-less
	// deployment: data_dir silently falls back to the built-in default, so the
	// command works on a directory the operator did not name. Both outcomes
	// there report success — deleting an unrelated identity, or vouching for a
	// decommission while the node's real identity, and a node secret the
	// control plane still accepts, stays on disk. This has to run before the
	// removal below, because the success branch is where the damage is done.
	//
	// Without the flag the default path is the deliberately file-less
	// deployment, which stays idempotent as documented.
	if !cfgFound && cmd.Flags().Changed("config") {
		return fmt.Errorf("plexd deregister: no config file at %s: data_dir would be the default %s rather than the configured one", cfgFile, agent.DefaultDataDir)
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
		if err := os.RemoveAll(cfg.DataDir); err != nil {
			logger.Warn("failed to remove data directory", "path", cfg.DataDir, "error", err)
		}
		tokenPath := cfg.Registration.TokenFile
		if tokenPath != "" {
			if err := os.Remove(tokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				logger.Warn("failed to remove registration token file", "path", tokenPath, "error", err)
			}
		}
		fmt.Fprintln(cmd.OutOrStdout(), "local data purged")
	}

	return nil
}
