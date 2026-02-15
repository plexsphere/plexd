package cmd

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestStateCommand_AgentNotRunning(t *testing.T) {
	assertCmdError(t, "plexd state", "state")
}

func TestStateGetCommand_RequiresArgs(t *testing.T) {
	_, err := executeCmd(t, "state", "get")
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}

func TestStateGetCommand_InvalidType(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"k": "v"},
	})

	resp, err := socketGet(socketPath, "/v1/state")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	assertCmdError(t, "unknown type", "state", "get", "invalid", "key")
}

func TestStateGetCommand_Success(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{"node_id": "node-123"},
	})

	resp, err := socketGet(socketPath, "/v1/state/metadata/node_id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestStateGetCommand_NotFound(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{
		Metadata: map[string]string{},
	})

	resp, err := socketGet(socketPath, "/v1/state/metadata/missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestStateReportCommand_MissingData(t *testing.T) {
	assertCmdError(t, "--data is required", "state", "report", "mykey")
}

func TestStateReportCommand_InvalidJSON(t *testing.T) {
	oldData := stateReportData
	t.Cleanup(func() { stateReportData = oldData })

	stateReportData = "not-json"
	_, err := executeCmd(t, "state", "report", "mykey", "--data", "not-json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("error should mention 'valid JSON', got: %v", err)
	}
}

func TestStateReportCommand_Success(t *testing.T) {
	socketPath := startFakeAgent(t, nodeapi.StateSummary{})

	client := newSocketClient(socketPath)
	resp, err := client.Get(socketURL("/v1/state"))
	if err != nil {
		t.Fatalf("agent should be running: %v", err)
	}
	resp.Body.Close()
}

func TestStateCommand_Help(t *testing.T) {
	output := executeHelp(t, "state", "--help")
	if !strings.Contains(output, "get") {
		t.Errorf("help should list 'get' subcommand, got: %s", output)
	}
	if !strings.Contains(output, "report") {
		t.Errorf("help should list 'report' subcommand, got: %s", output)
	}
}
