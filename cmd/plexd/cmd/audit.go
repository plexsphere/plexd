package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show audit collection status",
	Long:  "Show the current audit log collection status from the local agent.",
	RunE:  runAudit,
}

func init() {
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, _ []string) error {
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd audit: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "audit collection status not yet available")
	return nil
}
