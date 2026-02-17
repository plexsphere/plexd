package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var logsFollow bool

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Stream agent logs",
	Long:  "Stream plexd agent logs from journald. Falls back to a helpful message if journald is unavailable.",
	RunE:  runLogs,
}

var logStatusCmd = &cobra.Command{
	Use:   "log-status",
	Short: "Show log forwarding status",
	Long:  "Show the current log forwarding configuration.",
	RunE:  runLogStatus,
}

func init() {
	logsCmd.Flags().BoolVarP(&logsFollow, "follow", "f", false, "follow log output")
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(logStatusCmd)
}

func runLogs(cmd *cobra.Command, _ []string) error {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		fmt.Fprintln(cmd.OutOrStdout(), "journalctl not found; logs may be available on stdout of the plexd process")
		return nil
	}

	args := []string{"-u", "plexd", "--no-pager"}
	if logsFollow {
		args = append(args, "-f")
	}

	c := exec.Command(journalctl, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		return fmt.Errorf("plexd logs: %w", err)
	}
	return nil
}

func runLogStatus(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/log-status")
	if err != nil {
		return fmt.Errorf("plexd log-status: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd log-status: read response: %w", err)
	}

	var status forwarderStatusResp
	if err := json.Unmarshal(body, &status); err != nil {
		return fmt.Errorf("plexd log-status: parse response: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Log Forwarding Status\n")
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
