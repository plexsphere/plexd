package cmd

import (
	"encoding/json"
	"errors"
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
	Long: "Stream the plexd agent's own log from wherever the host's service manager keeps it:\n" +
		"journald on Linux, /Library/Logs/plexd/plexd.log on macOS, and the Application\n" +
		"Event Log under source plexd on Windows.\n" +
		"\n" +
		"Prints where the log lives instead when this host has no reader for it.\n" +
		"--follow is refused on Windows, where the Event Log has no follow mode.",
	RunE: runLogs,
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

// logsUnavailableError reports that this host holds nothing for plexd logs to
// read: the reader the platform needs is not installed, or the file the
// service manager writes is not there yet. It carries the sentence the
// operator gets instead of output.
//
// It is a type rather than a sentinel error because the reason differs per
// platform and names a path, and because runLogs answers it differently from
// every other error: the command prints the reason and exits 0, which is what
// plexd logs has always done for a missing journalctl.
type logsUnavailableError struct{ reason string }

func (e logsUnavailableError) Error() string { return e.reason }

// runLogs runs the reader logsCommand picks for this platform, with the
// daemon's log going straight to the terminal rather than through cobra's
// buffer, because --follow streams until the operator stops it.
func runLogs(cmd *cobra.Command, _ []string) error {
	name, args, err := logsCommand(logsFollow)
	if err != nil {
		var unavailable logsUnavailableError
		if errors.As(err, &unavailable) {
			fmt.Fprintln(cmd.OutOrStdout(), unavailable.reason)
			return nil
		}
		return fmt.Errorf("plexd logs: %w", err)
	}

	c := exec.Command(name, args...)
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
