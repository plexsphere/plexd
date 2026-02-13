package actions

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

type mockNodeInfo struct {
	nodeID    string
	meshIP    string
	peerCount int
}

func (m *mockNodeInfo) NodeID() string  { return m.nodeID }
func (m *mockNodeInfo) MeshIP() string  { return m.meshIP }
func (m *mockNodeInfo) PeerCount() int  { return m.peerCount }

func TestBuiltinGatherInfo(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-abc-123",
		meshIP:    "10.99.0.1",
		peerCount: 3,
	}

	fn := GatherInfo(info)
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	expectedKeys := []string{"hostname", "os", "arch", "go_version", "mesh_ip", "peer_count", "node_id"}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}

	if result["os"] != runtime.GOOS {
		t.Errorf("expected os=%q, got %q", runtime.GOOS, result["os"])
	}
	if result["arch"] != runtime.GOARCH {
		t.Errorf("expected arch=%q, got %q", runtime.GOARCH, result["arch"])
	}
	if result["go_version"] != runtime.Version() {
		t.Errorf("expected go_version=%q, got %q", runtime.Version(), result["go_version"])
	}
	if result["mesh_ip"] != "10.99.0.1" {
		t.Errorf("expected mesh_ip=%q, got %q", "10.99.0.1", result["mesh_ip"])
	}
	if int(result["peer_count"].(float64)) != 3 {
		t.Errorf("expected peer_count=3, got %v", result["peer_count"])
	}
	if result["node_id"] != "node-abc-123" {
		t.Errorf("expected node_id=%q, got %q", "node-abc-123", result["node_id"])
	}
}

func TestBuiltinPing_MissingTarget(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := Ping(info)
	_, _, exitCode, err := fn(context.Background(), map[string]string{})

	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if err.Error() != "missing required parameter: target" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBuiltinPing_InvalidTarget(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := Ping(info)
	_, stderr, exitCode, err := fn(context.Background(), map[string]string{"target": "not-an-ip"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stderr == "" || !strings.Contains(stderr, "invalid target IP") {
		t.Errorf("expected stderr to contain 'invalid target IP', got %q", stderr)
	}
}

func TestBuiltinPing_ValidTarget(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping not available")
	}

	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := Ping(info)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{"target": "127.0.0.1"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0 for localhost ping, got %d", exitCode)
	}
	if stdout == "" {
		t.Error("expected non-empty stdout")
	}
}

