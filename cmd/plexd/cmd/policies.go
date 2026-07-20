package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/api"
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

	// GET /v1/policies serves the single merged policy as a PolicySnapshot
	// object ({} when none is active), not an array of policies.
	var policy api.PolicySnapshot
	if err := json.Unmarshal(body, &policy); err != nil {
		return fmt.Errorf("plexd policies: parse response: %w", err)
	}

	if len(policy.Rules) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No policies active.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "REVISION\tSRC\tDST\tPORT\tPROTOCOL\tACTION")
	for _, r := range policy.Rules {
		port := "*"
		if r.Ports != nil {
			if r.Ports.From == r.Ports.To {
				port = fmt.Sprintf("%d", r.Ports.From)
			} else {
				port = fmt.Sprintf("%d-%d", r.Ports.From, r.Ports.To)
			}
		}
		proto := "*"
		if r.Protocol != "" {
			proto = r.Protocol
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			policy.RevisionID, r.SourceCIDR, r.DestinationCIDR, port, proto, r.Action)
	}
	w.Flush()
	return nil
}
