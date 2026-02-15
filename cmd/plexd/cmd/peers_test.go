package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestPeersCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd peers", "peers")
}

func TestPeersCommand_Help(t *testing.T) {
	output := executeHelp(t, "peers", "--help")
	if !strings.Contains(output, "peers") {
		t.Errorf("help should contain 'peers', got: %s", output)
	}
	if !strings.Contains(output, "Unix socket") {
		t.Errorf("help should mention 'Unix socket', got: %s", output)
	}
}

func TestPeersCommand_SuccessPath(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-1"},
	})
	overrideSocketPath(t, socketPath)

	output, err := executeCmd(t, "peers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "peer listing not yet available") {
		t.Errorf("expected 'peer listing not yet available', got: %s", output)
	}
}
