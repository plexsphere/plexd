package cmd

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestPoliciesCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd policies", "policies")
}

func TestPoliciesCommand_Help(t *testing.T) {
	output := executeHelp(t, "policies", "--help")
	if !strings.Contains(output, "policies") {
		t.Errorf("help should contain 'policies', got: %s", output)
	}
	if !strings.Contains(output, "Unix socket") {
		t.Errorf("help should mention 'Unix socket', got: %s", output)
	}
}

func TestPoliciesCommand_SuccessPath(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-1"},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "policies")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "No policies active") {
		t.Errorf("expected 'No policies active', got: %s", output)
	}
}

func TestPoliciesCommand_ListsRulesWithLogColumn(t *testing.T) {
	socketPath := startFakePolicyAgent(t, api.PolicySnapshot{
		RevisionID:  "rev-1",
		Fingerprint: "fp-1",
		Rules: []api.PolicyRule{
			{Protocol: "tcp", SourceCIDR: "10.99.0.2/32", DestinationCIDR: "10.99.0.1/32", Ports: &api.PortRange{From: 5432, To: 5432}, Log: true},
			{Protocol: "any", SourceCIDR: "fd00:99::/64", DestinationCIDR: "fd00:99::1/128"},
		},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "policies")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 {
		t.Fatalf("output has %d lines, want a header and two rules:\n%s", len(lines), output)
	}
	if got := strings.Fields(lines[0]); strings.Join(got, " ") != "REVISION SRC DST PORT PROTOCOL LOG" {
		t.Errorf("header = %q, want REVISION SRC DST PORT PROTOCOL LOG", lines[0])
	}
	for i, want := range [][]string{
		{"rev-1", "10.99.0.2/32", "10.99.0.1/32", "5432", "tcp", "yes"},
		{"rev-1", "fd00:99::/64", "fd00:99::1/128", "*", "any", "no"},
	} {
		if got := strings.Fields(lines[i+1]); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("row %d = %q, want %q", i, lines[i+1], strings.Join(want, " "))
		}
	}
}

// The output states of plexd policies, in the order the command checks them.

const (
	policiesDisabledLine    = "Policy enforcement is disabled (policy.enabled: false). No ruleset is applied."
	policiesUnavailableLine = "Policy enforcement is unavailable: this platform has no firewall backend. No ruleset is applied."
	policiesNoneAppliedLine = "No ruleset from the control plane is applied yet."
	policiesPreviousLine    = "Showing the ruleset applied before it."
	policiesNotLatestLine   = "The ruleset below is not the one the node received last."
	policiesNoRulesLine     = "No policies active."
	policiesRejectedReason  = `policy: invalid ruleset: rule 0: unsupported action "deny"`
	policiesRejectedLine    = "Received revision rev-c (fingerprint fp-c) is not applied: " + policiesRejectedReason + " (tried 3 times)."
)

// policiesAppliedTable is the table of appliedPolicyView's block.
var policiesAppliedTable = [][]string{
	{"REVISION", "SRC", "DST", "PORT", "PROTOCOL", "LOG"},
	{"rev-b", "10.99.0.2/32", "10.99.0.1/32", "5432", "tcp", "yes"},
	{"rev-b", "fd00:99::/64", "fd00:99::1/128", "*", "any", "no"},
}

// appliedPolicyView is the view of an enforcing node whose applied block,
// revision rev-b, is the block of the latest pull.
func appliedPolicyView() nodeapi.PolicyView {
	return nodeapi.PolicyView{
		RevisionID:  "rev-b",
		Fingerprint: "fp-b",
		Rules: []api.PolicyRule{
			{Protocol: "tcp", SourceCIDR: "10.99.0.2/32", DestinationCIDR: "10.99.0.1/32", Ports: &api.PortRange{From: 5432, To: 5432}, Log: true},
			{Protocol: "any", SourceCIDR: "fd00:99::/64", DestinationCIDR: "fd00:99::1/128"},
		},
		Revisions:   []api.PolicyRevisionRef{{PolicyID: "pol-1", RevisionID: "rev-b"}},
		Enforcement: api.PolicyEnforcementEnforcing,
		Applied:     true,
		InSync:      true,
		Received:    &nodeapi.PolicyViewReceived{RevisionID: "rev-b", Fingerprint: "fp-b"},
	}
}

// receivedRevisionC is the block of a latest pull that is not applied.
func receivedRevisionC() *nodeapi.PolicyViewReceived {
	return &nodeapi.PolicyViewReceived{
		RevisionID:  "rev-c",
		Fingerprint: "fp-c",
		Revisions:   []api.PolicyRevisionRef{{PolicyID: "pol-1", RevisionID: "rev-c"}},
	}
}

// rejectedRevisionC is the rejection of receivedRevisionC's block.
func rejectedRevisionC() *nodeapi.PolicyViewRejected {
	return &nodeapi.PolicyViewRejected{
		RevisionID:  "rev-c",
		Fingerprint: "fp-c",
		Reason:      policiesRejectedReason,
		Attempts:    3,
	}
}

// runPoliciesOn serves body on GET /v1/policies of a fake agent and runs
// plexd policies against it. The command exits 0 in every state, so an error
// fails the test.
func runPoliciesOn(t *testing.T, body any) string {
	t.Helper()
	overrideSocketPath(t, startFakePolicyAgent(t, body))
	output, err := executeCmd(t, "policies")
	if err != nil {
		t.Fatalf("plexd policies: %v, want exit status 0\n%s", err, output)
	}
	return output
}

// assertPoliciesOutput checks output: the lines of prose first, each exactly,
// then the rows of the table, each field by field because tabwriter pads the
// columns.
func assertPoliciesOutput(t *testing.T, output string, prose []string, table [][]string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != len(prose)+len(table) {
		t.Fatalf("output has %d lines, want %d:\n%s", len(lines), len(prose)+len(table), output)
	}
	for i, want := range prose {
		if lines[i] != want {
			t.Errorf("line %d = %q, want %q", i, lines[i], want)
		}
	}
	for i, want := range table {
		line := lines[len(prose)+i]
		if got := strings.Fields(line); !slices.Equal(got, want) {
			t.Errorf("table row %d = %q, want %q", i, line, strings.Join(want, " "))
		}
	}
}

func TestPoliciesCommand_EnforcementDisabled(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{Enforcement: api.PolicyEnforcementDisabled})
	assertPoliciesOutput(t, output, []string{policiesDisabledLine}, nil)
}

func TestPoliciesCommand_EnforcementDisabledWithReceived(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementDisabled,
		Received:    receivedRevisionC(),
	})
	assertPoliciesOutput(t, output, []string{
		policiesDisabledLine,
		"Received revision rev-c (fingerprint fp-c) is not enforced.",
	}, nil)
}

func TestPoliciesCommand_EnforcementUnavailable(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{Enforcement: api.PolicyEnforcementUnavailable})
	assertPoliciesOutput(t, output, []string{policiesUnavailableLine}, nil)
}

func TestPoliciesCommand_EnforcementUnavailableWithReceived(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementUnavailable,
		Received:    receivedRevisionC(),
	})
	assertPoliciesOutput(t, output, []string{
		policiesUnavailableLine,
		"Received revision rev-c (fingerprint fp-c) is not enforced.",
	}, nil)
}

func TestPoliciesCommand_NothingAppliedYet(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementEnforcing,
		Received:    receivedRevisionC(),
	})
	assertPoliciesOutput(t, output, []string{policiesNoneAppliedLine}, nil)
}

func TestPoliciesCommand_NothingAppliedYetWithRejection(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementEnforcing,
		Received:    receivedRevisionC(),
		Rejected:    rejectedRevisionC(),
	})
	assertPoliciesOutput(t, output, []string{policiesNoneAppliedLine, policiesRejectedLine}, nil)
}

func TestPoliciesCommand_RejectionShowsThePreviousRuleset(t *testing.T) {
	view := appliedPolicyView()
	view.InSync = false
	view.Received = receivedRevisionC()
	view.Rejected = rejectedRevisionC()

	output := runPoliciesOn(t, view)
	assertPoliciesOutput(t, output, []string{policiesRejectedLine, policiesPreviousLine, ""}, policiesAppliedTable)
}

func TestPoliciesCommand_RejectionOverAnAppliedNullPull(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementEnforcing,
		Applied:     true,
		Received:    receivedRevisionC(),
		Rejected:    rejectedRevisionC(),
	})
	assertPoliciesOutput(t, output, []string{policiesRejectedLine, policiesPreviousLine, "", policiesNoRulesLine}, nil)
}

func TestPoliciesCommand_AppliedIsNotTheLatestReceived(t *testing.T) {
	view := appliedPolicyView()
	view.InSync = false
	view.Received = nil

	output := runPoliciesOn(t, view)
	assertPoliciesOutput(t, output, []string{policiesNotLatestLine, ""}, policiesAppliedTable)
}

func TestPoliciesCommand_AppliedNullIsNotTheLatestReceived(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementEnforcing,
		Applied:     true,
		Received:    receivedRevisionC(),
	})
	assertPoliciesOutput(t, output, []string{policiesNotLatestLine, "", policiesNoRulesLine}, nil)
}

func TestPoliciesCommand_InSyncPrintsTheTable(t *testing.T) {
	output := runPoliciesOn(t, appliedPolicyView())
	assertPoliciesOutput(t, output, nil, policiesAppliedTable)
}

func TestPoliciesCommand_InSyncNullPull(t *testing.T) {
	output := runPoliciesOn(t, nodeapi.PolicyView{
		Enforcement: api.PolicyEnforcementEnforcing,
		Applied:     true,
		InSync:      true,
	})
	assertPoliciesOutput(t, output, []string{policiesNoRulesLine}, nil)
}

func TestPoliciesCommand_BeforeTheFirstPull(t *testing.T) {
	// The zero view carries an empty enforcement and prints like a body
	// without one.
	output := runPoliciesOn(t, nodeapi.PolicyView{})
	assertPoliciesOutput(t, output, []string{policiesNoRulesLine}, nil)
}

func TestPoliciesCommand_LegacyBodyPrintsTheTable(t *testing.T) {
	// The body of an agent before the policy view: the pulled block alone,
	// without enforcement.
	output := runPoliciesOn(t, json.RawMessage(`{"revision_id":"rev-b","fingerprint":"fp-b","rules":[`+
		`{"protocol":"tcp","source_cidr":"10.99.0.2/32","destination_cidr":"10.99.0.1/32","ports":{"from":5432,"to":5432},"log":true},`+
		`{"protocol":"any","source_cidr":"fd00:99::/64","destination_cidr":"fd00:99::1/128"}]}`))
	assertPoliciesOutput(t, output, nil, policiesAppliedTable)
}

func TestPoliciesCommand_EmptyBody(t *testing.T) {
	output := runPoliciesOn(t, json.RawMessage(`{}`))
	assertPoliciesOutput(t, output, []string{policiesNoRulesLine}, nil)
}
