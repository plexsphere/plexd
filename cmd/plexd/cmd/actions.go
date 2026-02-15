package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/api"
)

var actionsCmd = &cobra.Command{
	Use:   "actions",
	Short: "List available actions",
	Long:  "Connect to the local agent via Unix socket and list available actions.",
	RunE:  runActions,
}

var actionsRunParam []string

var actionsRunCmd = &cobra.Command{
	Use:   "run <name>",
	Short: "Run an action",
	Long:  "Dispatch an action to the local agent via Unix socket.",
	Args:  cobra.ExactArgs(1),
	RunE:  runActionsRun,
}

func init() {
	actionsRunCmd.Flags().StringArrayVar(&actionsRunParam, "param", nil, "action parameter in key=value format")
	actionsCmd.AddCommand(actionsRunCmd)
	rootCmd.AddCommand(actionsCmd)
}

type actionsListResponse struct {
	BuiltinActions []api.ActionInfo `json:"builtin_actions"`
	Hooks          []api.HookInfo   `json:"hooks"`
}

func runActions(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/actions")
	if err != nil {
		return fmt.Errorf("plexd actions: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd actions: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plexd actions: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result actionsListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("plexd actions: parse response: %w", err)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "TYPE\tNAME\tDESCRIPTION\n")
	for _, a := range result.BuiltinActions {
		fmt.Fprintf(w, "builtin\t%s\t%s\n", a.Name, a.Description)
	}
	for _, h := range result.Hooks {
		fmt.Fprintf(w, "hook\t%s\t%s\n", h.Name, h.Description)
	}
	w.Flush()

	return nil
}

type runActionRequest struct {
	Action     string            `json:"action"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

type runActionResponseMsg struct {
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func runActionsRun(cmd *cobra.Command, args []string) error {
	name := args[0]

	params := make(map[string]string)
	for _, p := range actionsRunParam {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return fmt.Errorf("plexd actions run: invalid param format %q (expected key=value)", p)
		}
		params[k] = v
	}

	reqBody := runActionRequest{
		Action:     name,
		Parameters: params,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("plexd actions run: marshal request: %w", err)
	}

	resp, err := socketPost(defaultSocketPath(), "/v1/actions/run", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("plexd actions run: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd actions run: read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// success, continue to parse
	case http.StatusNotFound:
		return fmt.Errorf("plexd actions run: unknown action %q", name)
	default:
		return fmt.Errorf("plexd actions run: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result runActionResponseMsg
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("plexd actions run: parse response: %w", err)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Status:    %s\n", result.Status)
	fmt.Fprintf(w, "Exit code: %d\n", result.ExitCode)
	if result.Stdout != "" {
		fmt.Fprintf(w, "\n--- stdout ---\n%s\n", result.Stdout)
	}
	if result.Stderr != "" {
		fmt.Fprintf(w, "\n--- stderr ---\n%s\n", result.Stderr)
	}

	return nil
}
