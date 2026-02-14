package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show node agent status",
	Long:  "Connect to the local agent via Unix socket and display node state.",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd status: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd status: read response: %w", err)
	}

	var summary nodeapi.StateSummary
	if err := json.Unmarshal(body, &summary); err != nil {
		return fmt.Errorf("plexd status: parse response: %w", err)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Metadata entries: %d\n", len(summary.Metadata))
	fmt.Fprintf(w, "Data keys:        %d\n", len(summary.DataKeys))
	fmt.Fprintf(w, "Secret keys:      %d\n", len(summary.SecretKeys))
	fmt.Fprintf(w, "Report keys:      %d\n", len(summary.ReportKeys))

	if len(summary.Metadata) > 0 {
		fmt.Fprintln(w, "\nMetadata:")
		for k, v := range summary.Metadata {
			fmt.Fprintf(w, "  %s: %s\n", k, v)
		}
	}

	return nil
}
