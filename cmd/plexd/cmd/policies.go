package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nodeapi"
)

var policiesCmd = &cobra.Command{
	Use:   "policies",
	Short: "List network policies",
	Long: "Connect to the local agent via Unix socket and list the rules of the network policy " +
		"ruleset that is applied. When that ruleset differs from the one the node received last, " +
		"or policy enforcement is off, the command says so before the rules.",
	RunE: runPolicies,
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

	// GET /v1/policies serves one object: the applied block at the top level
	// beside its state. An older agent serves the pulled block alone, without
	// enforcement, and {} when none is active; both decode into the block
	// members and print as the table.
	var view nodeapi.PolicyView
	if err := json.Unmarshal(body, &view); err != nil {
		return fmt.Errorf("plexd policies: parse response: %w", err)
	}

	out := cmd.OutOrStdout()
	switch view.Enforcement {
	case api.PolicyEnforcementDisabled:
		fmt.Fprintln(out, "Policy enforcement is disabled (policy.enabled: false). No ruleset is applied.")
		printPolicyNotEnforced(out, view.Received)
		return nil
	case api.PolicyEnforcementUnavailable:
		fmt.Fprintln(out, "Policy enforcement is unavailable: this platform has no firewall backend. No ruleset is applied.")
		printPolicyNotEnforced(out, view.Received)
		return nil
	case api.PolicyEnforcementEnforcing:
		if !view.Applied {
			fmt.Fprintln(out, "No ruleset from the control plane is applied yet.")
			printPolicyRejection(out, view.Rejected)
			return nil
		}
		if !view.InSync {
			if view.Rejected != nil {
				printPolicyRejection(out, view.Rejected)
				fmt.Fprintln(out, "Showing the ruleset applied before it.")
			} else {
				fmt.Fprintln(out, "The ruleset below is not the one the node received last.")
			}
			fmt.Fprintln(out)
		}
	}

	printPolicyTable(out, view)
	return nil
}

// printPolicyNotEnforced prints the line that names the received block a node
// without enforcement leaves alone, and nothing for a nil received.
func printPolicyNotEnforced(out io.Writer, received *nodeapi.PolicyViewReceived) {
	if received == nil {
		return
	}
	fmt.Fprintf(out, "Received revision %s (fingerprint %s) is not enforced.\n",
		received.RevisionID, received.Fingerprint)
}

// printPolicyRejection prints the line that names the block the latest apply
// failed on, and nothing for a nil rejected.
func printPolicyRejection(out io.Writer, rejected *nodeapi.PolicyViewRejected) {
	if rejected == nil {
		return
	}
	fmt.Fprintf(out, "Received revision %s (fingerprint %s) is not applied: %s (tried %d times).\n",
		rejected.RevisionID, rejected.Fingerprint, rejected.Reason, rejected.Attempts)
}

// printPolicyTable prints one row per rule of the view's block, or "No
// policies active." for a block without rules.
func printPolicyTable(out io.Writer, view nodeapi.PolicyView) {
	if len(view.Rules) == 0 {
		fmt.Fprintln(out, "No policies active.")
		return
	}

	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "REVISION\tSRC\tDST\tPORT\tPROTOCOL\tLOG")
	for _, r := range view.Rules {
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
		logged := "no"
		if r.Log {
			logged = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			view.RevisionID, r.SourceCIDR, r.DestinationCIDR, port, proto, logged)
	}
	w.Flush()
}
