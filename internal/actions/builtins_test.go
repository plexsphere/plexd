package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type mockNodeInfo struct {
	nodeID    string
	meshIP    string
	peerCount int
}

func (m *mockNodeInfo) NodeID() string { return m.nodeID }
func (m *mockNodeInfo) MeshIP() string { return m.meshIP }
func (m *mockNodeInfo) PeerCount() int { return m.peerCount }

type mockHealthProvider struct {
	tunnelCount    int
	connectedPeers int
	uptime         time.Duration
	lastHeartbeat  time.Time
	lastReconcile  time.Time
}

func (m *mockHealthProvider) TunnelCount() int        { return m.tunnelCount }
func (m *mockHealthProvider) ConnectedPeers() int     { return m.connectedPeers }
func (m *mockHealthProvider) Uptime() time.Duration   { return m.uptime }
func (m *mockHealthProvider) LastHeartbeat() time.Time { return m.lastHeartbeat }
func (m *mockHealthProvider) LastReconcile() time.Time { return m.lastReconcile }

type mockMeshReconnector struct {
	err error
}

func (m *mockMeshReconnector) Reconnect(_ context.Context) error { return m.err }

type mockConfigProvider struct {
	config string
}

func (m *mockConfigProvider) DumpConfig() string { return m.config }

type mockLogProvider struct {
	lines []string
}

func (m *mockLogProvider) RecentLines(n int) []string {
	if n >= len(m.lines) {
		return m.lines
	}
	return m.lines[:n]
}

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

func TestBuiltinDiagnosticsCollect(t *testing.T) {
	fn := DiagnosticsCollect()
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

	expectedKeys := []string{"hostname", "os", "arch", "cpu_count", "memory_total", "disk_total", "load_avg", "kernel_version"}
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
	if int(result["cpu_count"].(float64)) != runtime.NumCPU() {
		t.Errorf("expected cpu_count=%d, got %v", runtime.NumCPU(), result["cpu_count"])
	}
}

func TestBuiltinTraceroutePeer_MissingTarget(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := DiagnosticsTraceroutePeer(info)
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

func TestBuiltinTraceroutePeer_InvalidTarget(t *testing.T) {
	info := &mockNodeInfo{
		nodeID:    "node-1",
		meshIP:    "10.99.0.1",
		peerCount: 1,
	}

	fn := DiagnosticsTraceroutePeer(info)
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

func TestBuiltinServiceReloadConfig(t *testing.T) {
	// Ignore SIGHUP so the test process isn't killed.
	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)

	fn := ServiceReloadConfig()
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

	if _, ok := result["status"]; !ok {
		t.Error("missing key 'status' in JSON output")
	}
	if result["status"] != "reload_signal_sent" {
		t.Errorf("expected status='reload_signal_sent', got %q", result["status"])
	}
	if _, ok := result["pid"]; !ok {
		t.Error("missing key 'pid' in JSON output")
	}
}

func TestBuiltinServiceUpgrade(t *testing.T) {
	fn := ServiceUpgrade()
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

	if result["status"] != "upgrade_not_available" {
		t.Errorf("expected status='upgrade_not_available', got %q", result["status"])
	}
	if _, ok := result["message"]; !ok {
		t.Error("missing key 'message' in JSON output")
	}
}

func TestBuiltinHealthCheck(t *testing.T) {
	now := time.Now().UTC()
	health := &mockHealthProvider{
		tunnelCount:    2,
		connectedPeers: 5,
		uptime:         10 * time.Minute,
		lastHeartbeat:  now,
		lastReconcile:  now.Add(-1 * time.Minute),
	}

	fn := HealthCheck(health)
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

	expectedKeys := []string{"tunnel_count", "connected_peers", "uptime", "last_heartbeat", "last_reconcile", "status"}
	for _, key := range expectedKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}

	if result["status"] != "healthy" {
		t.Errorf("expected status='healthy', got %q", result["status"])
	}
	if int(result["tunnel_count"].(float64)) != 2 {
		t.Errorf("expected tunnel_count=2, got %v", result["tunnel_count"])
	}
	if int(result["connected_peers"].(float64)) != 5 {
		t.Errorf("expected connected_peers=5, got %v", result["connected_peers"])
	}
}

func TestBuiltinHealthCheck_Degraded(t *testing.T) {
	now := time.Now().UTC()
	health := &mockHealthProvider{
		tunnelCount:    0,
		connectedPeers: 0,
		uptime:         5 * time.Second,
		lastHeartbeat:  now,
		lastReconcile:  now,
	}

	fn := HealthCheck(health)
	stdout, _, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if result["status"] != "degraded" {
		t.Errorf("expected status='degraded', got %q", result["status"])
	}
}

func TestBuiltinMeshReconnect_Success(t *testing.T) {
	reconnector := &mockMeshReconnector{err: nil}

	fn := MeshReconnect(reconnector)
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

	if result["status"] != "reconnected" {
		t.Errorf("expected status='reconnected', got %q", result["status"])
	}
}

func TestBuiltinMeshReconnect_Failure(t *testing.T) {
	reconnector := &mockMeshReconnector{err: fmt.Errorf("connection refused")}

	fn := MeshReconnect(reconnector)
	stdout, _, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected system error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if result["status"] != "failed" {
		t.Errorf("expected status='failed', got %q", result["status"])
	}
	if result["error"] != "connection refused" {
		t.Errorf("expected error='connection refused', got %q", result["error"])
	}
}

func TestBuiltinConfigDump(t *testing.T) {
	provider := &mockConfigProvider{config: "listen_addr: 0.0.0.0:8080\nlog_level: info\n"}

	fn := ConfigDump(provider)
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
	if stdout != "listen_addr: 0.0.0.0:8080\nlog_level: info\n" {
		t.Errorf("expected config output, got %q", stdout)
	}
}

func TestBuiltinLogsSnapshot(t *testing.T) {
	provider := &mockLogProvider{
		lines: []string{"line1", "line2", "line3"},
	}

	fn := LogsSnapshot(provider)
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
	if !strings.Contains(stdout, "line1") || !strings.Contains(stdout, "line2") || !strings.Contains(stdout, "line3") {
		t.Errorf("expected stdout to contain all lines, got %q", stdout)
	}
}

func TestBuiltinLogsSnapshot_CustomLineCount(t *testing.T) {
	provider := &mockLogProvider{
		lines: []string{"line1", "line2", "line3", "line4", "line5"},
	}

	fn := LogsSnapshot(provider)
	stdout, _, exitCode, err := fn(context.Background(), map[string]string{"lines": "2"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	outputLines := strings.Split(stdout, "\n")
	if len(outputLines) != 2 {
		t.Errorf("expected 2 lines, got %d: %q", len(outputLines), stdout)
	}
}

func TestBuiltinLogsSnapshot_BoundaryValues(t *testing.T) {
	provider := &mockLogProvider{
		lines: []string{"line1", "line2", "line3"},
	}

	tests := []struct {
		name      string
		lines     string
		wantCount int
	}{
		{"zero uses default 100", "0", 3},         // parsed > 0 is false, uses default 100
		{"negative uses default 100", "-1", 3},     // parsed > 0 is false, uses default 100
		{"max_int capped", "999999999", 3},         // capped to MaxSnapshotLines, but provider only has 3
		{"over_max capped", "20000", 3},            // capped to MaxSnapshotLines
		{"invalid string uses default", "abc", 3},  // parse error, uses default 100
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := LogsSnapshot(provider)
			stdout, _, exitCode, err := fn(context.Background(), map[string]string{"lines": tt.lines})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("expected exit code 0, got %d", exitCode)
			}

			if stdout == "" {
				if tt.wantCount != 0 {
					t.Errorf("expected non-empty stdout")
				}
				return
			}
			outputLines := strings.Split(stdout, "\n")
			if len(outputLines) != tt.wantCount {
				t.Errorf("expected %d lines, got %d: %q", tt.wantCount, len(outputLines), stdout)
			}
		})
	}
}

func TestBuiltinLogsSnapshot_MaxCap(t *testing.T) {
	// Verify the cap is applied at MaxSnapshotLines.
	requested := 0
	fn := LogsSnapshot(&capturingLogProvider{requestedN: &requested})
	_, _, _, err := fn(context.Background(), map[string]string{"lines": "50000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if requested != MaxSnapshotLines {
		t.Errorf("expected lines capped to %d, got %d", MaxSnapshotLines, requested)
	}
}

// capturingLogProvider records what n was passed to RecentLines.
type capturingLogProvider struct {
	requestedN *int
}

func (c *capturingLogProvider) RecentLines(n int) []string {
	*c.requestedN = n
	return nil
}

