package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestStatusCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd status", "status")
}

func TestStatusCommand_Success(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-123", "mode": "node"},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "node-123") {
		t.Errorf("output should contain 'node-123', got: %s", output)
	}
}

func TestStatusCommand_Help(t *testing.T) {
	output := executeHelp(t, "status", "--help")
	if !strings.Contains(output, "status") {
		t.Errorf("help should contain 'status', got: %s", output)
	}
	if !strings.Contains(output, "Unix socket") {
		t.Errorf("help should mention 'Unix socket', got: %s", output)
	}
}
