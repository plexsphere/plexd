package api

import (
	"encoding/json"
	"testing"
	"time"
)

// roundTrip marshals v to JSON, then unmarshals back into a new value of the
// same type and returns the raw JSON bytes. It fails the test on any error.
func roundTrip[T any](t *testing.T, v T) ([]byte, T) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got T
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return data, got
}

// requireEqual re-marshals both values and compares JSON bytes. This avoids
// direct struct comparison issues with time.Time and json.RawMessage.
func requireEqual(t *testing.T, want, got any) {
	t.Helper()
	a, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("mismatch\nwant: %s\n got: %s", a, b)
	}
}

func TestTypesRegisterRequest(t *testing.T) {
	orig := RegisterRequest{
		Token:     "tok-abc",
		PublicKey: "pk-xyz",
		Hostname:  "node-1",
		Metadata:  map[string]string{"env": "prod"},
		Capabilities: &CapabilitiesPayload{
			Binary: &BinaryInfo{Version: "1.0.0", Checksum: "sha256:abc"},
			BuiltinActions: []ActionInfo{
				{Name: "reboot", Description: "reboot node", Parameters: []ActionParam{
					{Name: "force", Type: "bool", Required: false, Description: "force reboot"},
				}},
			},
			Hooks: []HookInfo{},
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"token", "public_key", "hostname", "metadata", "capabilities"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesRegisterResponse(t *testing.T) {
	orig := RegisterResponse{
		NodeID:          "n-001",
		MeshIP:          "10.42.0.1",
		SigningPublicKey: "spk-abc",
		NodeSecretKey:   "nsk-xyz",
		Peers: []Peer{
			{
				ID:         "n-002",
				PublicKey:  "pk-002",
				MeshIP:     "10.42.0.2",
				Endpoint:   "1.2.3.4:51820",
				AllowedIPs: []string{"10.42.0.2/32"},
				PSK:        "psk-shared",
			},
		},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesHeartbeatRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := HeartbeatRequest{
		NodeID:         "n-001",
		Timestamp:      now,
		Status:         "healthy",
		Uptime:         "3h25m",
		BinaryChecksum: "sha256:def",
		Mesh: &MeshInfo{
			Interface:  "wg0",
			PeerCount:  3,
			ListenPort: 51820,
		},
		NAT: &NATInfo{
			PublicEndpoint: "1.2.3.4:51820",
			Type:           "full-cone",
		},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesHeartbeatResponse(t *testing.T) {
	orig := HeartbeatResponse{
		Reconcile:  true,
		RotateKeys: false,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesStateResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)
	orig := StateResponse{
		Peers: []Peer{
			{ID: "n-002", PublicKey: "pk", MeshIP: "10.42.0.2", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.42.0.2/32"}, PSK: "psk"},
		},
		Policies: []Policy{
			{ID: "pol-1", Rules: []PolicyRule{
				{Src: "10.42.0.0/24", Dst: "10.42.0.1/32", Port: 443, Protocol: "tcp", Action: "allow"},
			}},
		},
		SigningKeys: &SigningKeys{
			Current:           "key-current",
			Previous:          "key-prev",
			TransitionExpires: &expires,
		},
		Metadata: map[string]string{"region": "us-east"},
		Data: []DataEntry{
			{Key: "config/app", ContentType: "application/json", Payload: json.RawMessage(`{"k":"v"}`), Version: 1, UpdatedAt: now},
		},
		SecretRefs: []SecretRef{
			{Key: "db-password", Version: 2},
		},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesDriftReport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := DriftReport{
		Timestamp: now,
		Corrections: []DriftCorrection{
			{Type: "peer_missing", Detail: "re-added peer n-003"},
		},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesSecretResponse(t *testing.T) {
	orig := SecretResponse{
		Key:        "db-password",
		Ciphertext: "Y2lwaGVy",
		Nonce:      "bm9uY2U=",
		Version:    3,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesMetricPoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := MetricPoint{
		Timestamp: now,
		Group:     "system",
		PeerID:    "",
		Data:      json.RawMessage(`{"cpu":0.42}`),
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// PeerID should be omitted when empty.
	if s := string(data); contains(s, `"peer_id"`) {
		t.Errorf("peer_id should be omitted when empty, got: %s", s)
	}

	// With PeerID set.
	orig.PeerID = "n-002"
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); !contains(s, `"peer_id"`) {
		t.Errorf("peer_id should be present when set, got: %s", s)
	}
}

func TestTypesLogEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := LogEntry{
		Timestamp: now,
		Source:    "systemd",
		Unit:      "plexd.service",
		Message:   "started",
		Severity:  "info",
		Hostname:  "node-1",
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesExecutionAck(t *testing.T) {
	orig := ExecutionAck{
		ExecutionID: "exec-001",
		Status:      "accepted",
		Reason:      "",
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesExecutionResult(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := ExecutionResult{
		ExecutionID: "exec-001",
		Status:      "completed",
		ExitCode:    0,
		Stdout:      "hello",
		Stderr:      "",
		Duration:    "1.23s",
		FinishedAt:  now,
		TriggeredBy: &TriggeredBy{
			Type:      "session",
			SessionID: "sess-abc",
			UserID:    "u-001",
			Email:     "admin@example.com",
		},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Without TriggeredBy.
	orig.TriggeredBy = nil
	data, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data); contains(s, `"triggered_by"`) {
		t.Errorf("triggered_by should be omitted when nil, got: %s", s)
	}
}

func TestTypesSSHSessionSetup(t *testing.T) {
	expires := time.Now().UTC().Truncate(time.Second).Add(30 * time.Minute)
	orig := SSHSessionSetup{
		SessionID:     "sess-001",
		TargetHost:    "10.42.0.5",
		TargetPort:    22,
		AuthorizedKey: "ssh-ed25519 AAAAC3...",
		ExpiresAt:     expires,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"session_id", "target_host", "target_port", "authorized_key", "expires_at"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesTunnelReadyRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := TunnelReadyRequest{
		ListenAddr: "10.42.0.1:34567",
		Timestamp:  now,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesTunnelClosedRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := TunnelClosedRequest{
		Reason:    "expired",
		Duration:  "29m45s",
		Timestamp: now,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestTypesIntegrityViolationReport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := IntegrityViolationReport{
		Type:             "binary",
		Path:             "/usr/local/bin/plexd",
		ExpectedChecksum: "abc123",
		ActualChecksum:   "def456",
		Detail:           "binary checksum mismatch on startup",
		Timestamp:        now,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "path", "expected_checksum", "actual_checksum", "detail", "timestamp"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

// contains is a simple substring check helper.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestBridgeConfig_JSONRoundTrip(t *testing.T) {
	orig := BridgeConfig{
		AccessSubnets:    []string{"192.168.1.0/24", "10.0.0.0/8"},
		EnableNAT:        true,
		EnableForwarding: true,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"access_subnets", "enable_nat", "enable_forwarding"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestBridgeInfo_JSONRoundTrip(t *testing.T) {
	orig := BridgeInfo{
		Enabled:         true,
		AccessInterface: "eth1",
		ActiveRoutes:    5,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "access_interface", "active_routes"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestHeartbeatRequest_WithBridge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := HeartbeatRequest{
		NodeID:         "n-001",
		Timestamp:      now,
		Status:         "healthy",
		Uptime:         "1h10m",
		BinaryChecksum: "sha256:abc",
		Bridge: &BridgeInfo{
			Enabled:         true,
			AccessInterface: "eth1",
			ActiveRoutes:    3,
		},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Bridge field should be omitted when nil.
	orig.Bridge = nil
	data, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data); contains(s, `"bridge"`) {
		t.Errorf("bridge should be omitted when nil, got: %s", s)
	}
}

func TestStateResponse_WithBridgeConfig(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := StateResponse{
		Peers:    []Peer{{ID: "n-002", PublicKey: "pk", MeshIP: "10.42.0.2", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.42.0.2/32"}, PSK: "psk"}},
		Policies: []Policy{},
		BridgeConfig: &BridgeConfig{
			AccessSubnets:    []string{"192.168.1.0/24"},
			EnableNAT:        true,
			EnableForwarding: false,
		},
		Data:       []DataEntry{{Key: "k", ContentType: "text/plain", Payload: json.RawMessage(`"v"`), Version: 1, UpdatedAt: now}},
		SecretRefs: []SecretRef{},
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// BridgeConfig field should be omitted when nil.
	orig.BridgeConfig = nil
	data, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data); contains(s, `"bridge_config"`) {
		t.Errorf("bridge_config should be omitted when nil, got: %s", s)
	}
}
