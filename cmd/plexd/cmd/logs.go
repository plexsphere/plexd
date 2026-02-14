package cmd

import (
	"fmt"
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
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd log-status: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "log forwarding status not yet available")
	return nil
}
