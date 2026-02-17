package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "List network policies",
	Long:  "Connect to the local agent via Unix socket and list network policies.",
	RunE:  runPolicies,
}

func init() {
	rootCmd.AddCommand(policiesCmd)
}

type policyInfo struct {
	ID    string       `json:"id"`
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
}

func runPolicies(cmd *cobra.Command, _ []string) error {
	resp, err := socketGet(defaultSocketPath(), "/v1/policies")
	if err != nil {
		return fmt.Errorf("plexd policies: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plexd policies: read response: %w", err)
	}

	var policies []policyInfo
	if err := json.Unmarshal(body, &policies); err != nil {
		return fmt.Errorf("plexd policies: parse response: %w", err)
	}

	if len(policies) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No policies active.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "POLICY\tSRC\tDST\tPORT\tPROTOCOL\tACTION")
	for _, pol := range policies {
		for _, r := range pol.Rules {
			port := "*"
			if r.Port > 0 {
				port = fmt.Sprintf("%d", r.Port)
			}
			proto := "*"
			if r.Protocol != "" {
				proto = r.Protocol
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", pol.ID, r.Src, r.Dst, port, proto, r.Action)
		}
	}
	w.Flush()
	return nil
}
