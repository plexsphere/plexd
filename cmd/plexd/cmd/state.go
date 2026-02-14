package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

var stateCmd = &cobra.Command{
	Use:   "state",
	Short: "Show state summary",
	Long:  "Connect to the local agent via Unix socket and show state summary.",
	RunE:  runState,
}

var stateGetCmd = &cobra.Command{
	Use:   "get <type> <key>",
	Short: "Get a specific state entry",
	Long:  "Fetch a specific state entry by type (metadata, data, report) and key.",
	Args:  cobra.ExactArgs(2),
	RunE:  runStateGet,
}

var stateReportData string

var stateReportCmd = &cobra.Command{
	Use:   "report <key>",
	Short: "Write a report entry",
	Long:  "Write a report entry via the local agent Unix socket.",
	Args:  cobra.ExactArgs(1),
	RunE:  runStateReport,
}

func init() {
	stateReportCmd.Flags().StringVar(&stateReportData, "data", "", "JSON data for the report payload")
	stateCmd.AddCommand(stateGetCmd)
	stateCmd.AddCommand(stateReportCmd)
	rootCmd.AddCommand(stateCmd)
}

func runState(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd state: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd state: read response: %w", err)
	}

	var raw json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("plexd state: parse response: %w", err)
	}

	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("plexd state: format response: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
	return nil
}

func runStateGet(cmd *cobra.Command, args []string) error {
	entryType := args[0]
	key := args[1]

	var path string
	switch entryType {
	case "metadata":
		path = "/v1/state/metadata/" + key
	case "data":
		path = "/v1/state/data/" + key
	case "report":
		path = "/v1/state/report/" + key
	default:
		return fmt.Errorf("plexd state get: unknown type %q (valid: metadata, data, report)", entryType)
	}

	resp, err := socketGet(defaultSocketPath(), path)
	if err != nil {
		return fmt.Errorf("plexd state get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd state get: read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("plexd state get: %s/%s not found", entryType, key)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plexd state get: unexpected status %d", resp.StatusCode)
	}

	var raw json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("plexd state get: parse response: %w", err)
	}

	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("plexd state get: format response: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
	return nil
}

func runStateReport(cmd *cobra.Command, args []string) error {
	key := args[0]

	if stateReportData == "" {
		return fmt.Errorf("plexd state report: --data is required")
	}

	if !json.Valid([]byte(stateReportData)) {
		return fmt.Errorf("plexd state report: --data must be valid JSON")
	}

	payload := map[string]json.RawMessage{
		"content_type": json.RawMessage(`"application/json"`),
		"payload":      json.RawMessage(stateReportData),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("plexd state report: marshal: %w", err)
	}

	client := newSocketClient(defaultSocketPath())
	req, err := http.NewRequest(http.MethodPut, socketURL("/v1/state/report/"+key), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("plexd state report: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("plexd state report: agent not running or socket unavailable: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd state report: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plexd state report: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "report %s written\n", key)
	return nil
}
