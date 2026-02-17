package cmd

import (
	"strings"
	"testing"

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
