package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List mesh peers",
	Long:  "Connect to the local agent via Unix socket and list mesh peers.",
	RunE:  runPeers,
}

func init() {
	rootCmd.AddCommand(peersCmd)
}

func runPeers(cmd *cobra.Command, _ []string) error {
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd peers: %w", err)
	}
	// Peer listing will be wired to a dedicated endpoint in a future iteration.
	fmt.Fprintln(cmd.OutOrStdout(), "peer listing not yet available")
	return nil
}
