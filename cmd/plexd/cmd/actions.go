package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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

func runActions(cmd *cobra.Command, _ []string) error {
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd actions: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "action listing not yet available")
	return nil
}

func runActionsRun(cmd *cobra.Command, args []string) error {
	name := args[0]
	_, err := socketGet(defaultSocketPath(), "/v1/state")
	if err != nil {
		return fmt.Errorf("plexd actions run: %w", err)
	}
	// Action dispatch endpoint will be added in a future iteration.
	fmt.Fprintf(cmd.OutOrStdout(), "action dispatch for %q not yet available\n", name)
	return nil
}
