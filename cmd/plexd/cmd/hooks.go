package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/api"
)

var hooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Manage action hooks",
	Long:  "List, verify, or reload action hooks via the local agent.",
}

var hooksListCmd = &cobra.Command{
	Use:   "list",
	Short: "List hooks",
	Long:  "List all registered action hooks.",
	RunE:  runHooksList,
}

var hooksVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify hook integrity",
	Long:  "Run integrity verification on all registered hooks.",
	RunE:  runHooksVerify,
}

var hooksReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload hooks",
	Long:  "Trigger a re-scan of action hooks.",
	RunE:  runHooksReload,
}

func init() {
	hooksCmd.AddCommand(hooksListCmd)
	hooksCmd.AddCommand(hooksVerifyCmd)
	hooksCmd.AddCommand(hooksReloadCmd)
	rootCmd.AddCommand(hooksCmd)
}

func runHooksList(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/hooks")
	if err != nil {
		return fmt.Errorf("plexd hooks list: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd hooks list: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plexd hooks list: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var hooks []api.HookInfo
	if err := json.Unmarshal(body, &hooks); err != nil {
		return fmt.Errorf("plexd hooks list: parse response: %w", err)
	}

	if len(hooks) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No hooks registered.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "NAME\tSOURCE\tCHECKSUM\tDESCRIPTION\n")
	for _, h := range hooks {
		checksum := h.Checksum
		if len(checksum) > 12 {
			checksum = checksum[:12] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", h.Name, h.Source, checksum, h.Description)
	}
	w.Flush()

	return nil
}

func runHooksVerify(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/hooks")
	if err != nil {
		return fmt.Errorf("plexd hooks verify: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd hooks verify: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plexd hooks verify: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var hooks []api.HookInfo
	if err := json.Unmarshal(body, &hooks); err != nil {
		return fmt.Errorf("plexd hooks verify: parse response: %w", err)
	}

	if len(hooks) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No hooks to verify.")
		return nil
	}

	w := cmd.OutOrStdout()
	allOK := true
	for _, h := range hooks {
		if h.Checksum == "" {
			fmt.Fprintf(w, "WARN  %s: no checksum\n", h.Name)
			allOK = false
		} else {
			fmt.Fprintf(w, "OK    %s: %s\n", h.Name, h.Checksum)
		}
	}

	if allOK {
		fmt.Fprintf(w, "\nAll %d hooks have checksums.\n", len(hooks))
	}

	return nil
}

type hooksReloadResponseMsg struct {
	Status string         `json:"status"`
	Hooks  []api.HookInfo `json:"hooks"`
}

func runHooksReload(cmd *cobra.Command, _ []string) error {
	resp, err := socketPost(defaultSocketPath(), "/v1/hooks/reload", "application/json", nil)
	if err != nil {
		return fmt.Errorf("plexd hooks reload: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd hooks reload: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plexd hooks reload: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result hooksReloadResponseMsg
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("plexd hooks reload: parse response: %w", err)
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Status: %s\n", result.Status)
	fmt.Fprintf(w, "Hooks:  %d\n", len(result.Hooks))

	return nil
}
