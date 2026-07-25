package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
)

var joinTokenFile string

var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "Register this node with the control plane",
	Long:  "Register this node with the control plane and exit.\nDoes not start the agent daemon.",
	RunE:  runJoin,
}

func init() {
	joinCmd.Flags().StringVar(&joinTokenFile, "token-file", "", "path to bootstrap token file")
	rootCmd.AddCommand(joinCmd)
}

func runJoin(cmd *cobra.Command, _ []string) error {
	cfg, cfgFound, err := agent.ParseConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("plexd join: %w", err)
	}
	if apiURL != "" {
		cfg.API.BaseURL = apiURL
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	warnIfConfigAbsent(cfgFound, cfgFile, cfg.DataDir)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("plexd join: %w", err)
	}

	client, err := api.NewControlPlane(cfg.API, buildVersion, logger)
	if err != nil {
		return fmt.Errorf("plexd join: create client: %w", err)
	}

	regCfg := cfg.Registration
	if joinTokenFile != "" {
		regCfg.TokenFile = joinTokenFile
	}
	if projectID != "" {
		regCfg.ProjectID = projectID
	}
	if resourceHandle != "" {
		regCfg.ResourceHandle = resourceHandle
	}
	if requestedResourceID != "" {
		regCfg.RequestedResourceID = requestedResourceID
	}

	registrar := newRegistrar(client, regCfg, logger)

	identity, err := registrar.Register(context.Background())
	if err != nil {
		return fmt.Errorf("plexd join: registration: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "node_id: %s\nmesh_ip: %s\n", identity.NodeID, identity.MeshIP)
	return nil
}
