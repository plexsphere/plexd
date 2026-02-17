package cmd

import (
	"encoding/json"
	"fmt"
	"io"

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

type forwarderStatusResp struct {
	Enabled      bool   `json:"enabled"`
	BufferSize   int    `json:"buffer_size"`
	SourceCount  int    `json:"source_count"`
	ErrorCount   int    `json:"error_count"`
	LastReportAt string `json:"last_report_at,omitempty"`
}

func runAudit(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/audit/status")
	if err != nil {
		return fmt.Errorf("plexd audit: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd audit: read response: %w", err)
	}

	var status forwarderStatusResp
	if err := json.Unmarshal(body, &status); err != nil {
		return fmt.Errorf("plexd audit: parse response: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Audit Forwarding Status\n")
	fmt.Fprintf(out, "  Enabled:       %v\n", status.Enabled)
	fmt.Fprintf(out, "  Sources:       %d\n", status.SourceCount)
	fmt.Fprintf(out, "  Buffer size:   %d\n", status.BufferSize)
	fmt.Fprintf(out, "  Errors:        %d\n", status.ErrorCount)
	if status.LastReportAt != "" {
		fmt.Fprintf(out, "  Last report:   %s\n", status.LastReportAt)
	} else {
		fmt.Fprintf(out, "  Last report:   never\n")
	}
	return nil
}
