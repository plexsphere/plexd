package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestAuditCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd audit", "audit")
}

func TestAuditCommand_SuccessPath(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-1"},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "audit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "Audit Forwarding Status") {
		t.Errorf("expected 'Audit Forwarding Status', got: %s", output)
	}
	if !strings.Contains(output, "Enabled") {
		t.Errorf("expected 'Enabled', got: %s", output)
	}
}

func TestAuditCommand_Help(t *testing.T) {
	output := executeHelp(t, "audit", "--help")
	if !strings.Contains(output, "audit") {
		t.Errorf("help should contain 'audit', got: %s", output)
	}
}
