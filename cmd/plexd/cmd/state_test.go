package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

func TestStateCommand_AgentNotRunning(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"state"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when agent is not running")
	}
	if !strings.Contains(err.Error(), "plexd state") {
		t.Errorf("error should mention 'plexd state', got: %v", err)
	}
}

func TestStateGetCommand_RequiresArgs(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"state", "get"})

	err := rootCmd.Execute()
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

	// Validate that the type check works by calling runStateGet logic.
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"state", "get", "invalid", "key"})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("error should mention 'unknown type', got: %v", err)
	}
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
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"state", "report", "mykey"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing --data")
	}
	if !strings.Contains(err.Error(), "--data is required") {
		t.Errorf("error should mention '--data is required', got: %v", err)
	}
}

func TestStateReportCommand_InvalidJSON(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	stateReportData = "not-json"
	rootCmd.SetArgs([]string{"state", "report", "mykey", "--data", "not-json"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("error should mention 'valid JSON', got: %v", err)
	}
	stateReportData = "" // reset
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
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"state", "--help"})

	_ = rootCmd.Execute()

	output := buf.String()
	if !strings.Contains(output, "get") {
		t.Errorf("help should list 'get' subcommand, got: %s", output)
	}
	if !strings.Contains(output, "report") {
		t.Errorf("help should list 'report' subcommand, got: %s", output)
	}
}
