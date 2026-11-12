package cmd

import (
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
