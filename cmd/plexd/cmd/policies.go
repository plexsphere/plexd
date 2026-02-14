package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "List network policies",
	Long:  "Connect to the local agent via Unix socket and list network policies.",
	RunE:  runPolicies,
}

func init() {
	rootCmd.AddCommand(policiesCmd)
}

func runPolicies(cmd *cobra.Command, _ []string) error {
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd policies: %w", err)
	}
	// Policy listing will be wired to a dedicated endpoint in a future iteration.
	fmt.Fprintln(cmd.OutOrStdout(), "policy listing not yet available")
	return nil
}
