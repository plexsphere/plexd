package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd hooks list: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "hook listing not yet available")
	return nil
}

func runHooksVerify(cmd *cobra.Command, _ []string) error {
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd hooks verify: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "hook verification not yet available")
	return nil
}

func runHooksReload(cmd *cobra.Command, _ []string) error {
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd hooks reload: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "hook reload not yet available")
	return nil
}
