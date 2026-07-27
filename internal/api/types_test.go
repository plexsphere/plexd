package api

import (
	"encoding/json"
	"strings"
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
	// Spec request example (issue #18 contract).
	orig := RegisterRequest{
		ProjectID:      "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0",
		ResourceHandle: "edge-router-01",
		BootstrapToken: "psb_prod_aebagbafaydqqbrhibbsa3kqaq_node_xxxxxxxxxxxxxxxxxxxxxxxxxx",
		Nonce:          "f3f8c0b8-7a0a-8a0a-a0a0-a0a0a0a0a0a0",
		PublicKey:      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"project_id", "resource_handle", "bootstrap_token", "nonce", "public_key"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// requested_resource_id is omitted when empty.
	if _, ok := raw["requested_resource_id"]; ok {
		t.Error("requested_resource_id should be omitted when empty")
	}

	// requested_resource_id is present when set.
	orig.RequestedResourceID = "substrate-42"
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); !strings.Contains(s, `"requested_resource_id"`) {
		t.Errorf("requested_resource_id should be present when set, got: %s", s)
	}
}

func TestTypesRegisterResponse(t *testing.T) {
	// Spec response example (issue #18 contract).
	orig := RegisterResponse{
		NodeID:           "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3",
		MeshIP:           "100.64.0.1",
		SigningPublicKey: "MCowBQYDK2VwAyEA0123456789abcdefghijklmnopqrstuvwxyz0123=",
		SigningKeyID:     "did:web:plexsphere.com#key-2026-04",
		NSK:              "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		PeerSnapshot:     []RegisterPeer{},
		DomainMeshCIDR:   "100.64.0.0/10",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys, including the new fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"node_id", "mesh_ip", "signing_public_key", "signing_key_id", "nsk", "peer_snapshot", "domain_mesh_cidr"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesRegisterPeer(t *testing.T) {
	orig := RegisterPeer{
		NodeID:           "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
		MeshIP:           "100.64.0.2",
		PublicKey:        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		FallbackEndpoint: "203.0.113.1:51820",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"node_id", "mesh_ip", "public_key", "fallback_endpoint"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// fallback_endpoint is omitted when empty.
	orig.FallbackEndpoint = ""
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"fallback_endpoint"`) {
		t.Errorf("fallback_endpoint should be omitted when empty, got: %s", s)
	}
}

func TestTypesHeartbeatRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := HeartbeatRequest{
		ClientNow:      now,
		BinaryChecksum: "3b0c4429b1a4f1d2e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081920",
		BinaryVersion:  "1.2.3",
		NATSummary: map[string]any{
			"endpoint": "203.0.113.9:51820",
			"nat_type": "full_cone",
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the four contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 {
		t.Errorf("expected exactly 4 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"client_now", "binary_checksum", "binary_version", "nat_summary"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// A nil NATSummary marshals as JSON null, while an empty non-nil map
	// marshals as {}. The contract requires nat_summary to be an object, so
	// builders must pass a non-nil map to avoid emitting null.
	nilData, err := json.Marshal(HeartbeatRequest{ClientNow: now})
	if err != nil {
		t.Fatalf("marshal nil summary: %v", err)
	}
	if !strings.Contains(string(nilData), `"nat_summary":null`) {
		t.Errorf("nil NATSummary should marshal as null, got: %s", nilData)
	}
	emptyData, err := json.Marshal(HeartbeatRequest{ClientNow: now, NATSummary: map[string]any{}})
	if err != nil {
		t.Fatalf("marshal empty summary: %v", err)
	}
	if !strings.Contains(string(emptyData), `"nat_summary":{}`) {
		t.Errorf("empty NATSummary should marshal as {}, got: %s", emptyData)
	}
}

func TestTypesHeartbeatResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := HeartbeatResponse{
		AcceptedAt: now,
		Reconcile:  true,
		RotateKeys: false,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3 {
		t.Errorf("expected exactly 3 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"accepted_at", "reconcile", "rotate_keys"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesEndpointRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := EndpointRequest{
		Endpoint:   "203.0.113.9:51820",
		NATType:    "full_cone",
		ReportedAt: now,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3 {
		t.Errorf("expected exactly 3 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"endpoint", "nat_type", "reported_at"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesEndpointResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := EndpointResponse{
		AcceptedAt: now,
		StaleAfter: now.Add(5 * time.Minute),
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2 {
		t.Errorf("expected exactly 2 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"accepted_at", "stale_after"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesKeyRotateRequest(t *testing.T) {
	orig := KeyRotateRequest{
		NewPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// The v1 contract serializes to exactly one member: the server identifies
	// the node from the NSK bearer credential, so there is no node_id.
	const want = `{"new_public_key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}`
	if string(data) != want {
		t.Errorf("serialized = %s, want %s", data, want)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Errorf("expected exactly 1 JSON key, got %d: %v", len(raw), raw)
	}
	if _, ok := raw["new_public_key"]; !ok {
		t.Errorf("expected JSON key %q", "new_public_key")
	}
	if _, ok := raw["node_id"]; ok {
		t.Error("node_id must not be present in the v1 keys/rotate request")
	}
}

func TestTypesKeyRotateResponse(t *testing.T) {
	const src = `{"rotation_id":"e2e-rotation-0001","kid":"did:web:plexsphere.com#psk-2026-04","wrap_key_version":3}`
	var got KeyRotateResponse
	if err := json.Unmarshal([]byte(src), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RotationID != "e2e-rotation-0001" {
		t.Errorf("RotationID = %q, want %q", got.RotationID, "e2e-rotation-0001")
	}
	if got.KID != "did:web:plexsphere.com#psk-2026-04" {
		t.Errorf("KID = %q, want %q", got.KID, "did:web:plexsphere.com#psk-2026-04")
	}
	if got.WrapKeyVersion != 3 {
		t.Errorf("WrapKeyVersion = %d, want 3", got.WrapKeyVersion)
	}

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3 {
		t.Errorf("expected exactly 3 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"rotation_id", "kid", "wrap_key_version"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestNodeStateSnapshot_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := NodeStateSnapshot{
		Peers: []SnapshotPeer{
			{NodeID: "n-002", MeshIP: "10.42.0.2", PublicKey: "pk", FallbackEndpoint: "1.2.3.4:51820"},
		},
		Reachability: json.RawMessage(`{"state":"healthy","changed_at":"2026-01-01T00:00:00Z"}`),
		Policy: &PolicySnapshot{
			RevisionID:  "rev-1",
			Fingerprint: "0123456789012345678901234567890123456789012=",
			Rules: []PolicyRule{
				{Action: "allow", Protocol: "tcp", SourceCIDR: "10.42.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &PortRange{From: 443, To: 443}},
			},
		},
		Bridge: &BridgeSnapshot{
			Relay: &RelayConfig{Sessions: []RelaySessionAssignment{{SessionID: "r1", ExpiresAt: now}}},
		},
		State: &NodeStateBlock{
			Metadata: []StateEntry{{Key: "region", Value: "us-east"}},
			Data:     []StateEntry{{Key: "app/config", Value: "x"}},
			Reports:  []StateEntry{},
		},
		Reports: &NodeStateBlock{
			Metadata: []StateEntry{},
			Data:     []StateEntry{},
			Reports:  []StateEntry{},
		},
		Executions: []NodeStateExecution{
			{
				ExecutionID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0",
				Action:      "gather_info",
				Type:        ActionKindBuiltin,
				Status:      ExecutionStatusPending,
				RequestedAt: now,
				ExpiresAt:   now.Add(5 * time.Minute),
			},
		},
		Sessions: &[]NodeStateSession{
			{
				SessionID:          "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b0",
				JTI:                "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b0",
				Kind:               SessionKindTCP,
				Target:             SessionTarget{TCP: &SessionTargetTCP{Host: "10.42.0.5", Port: 5432}},
				ExpiresAt:          now.Add(30 * time.Minute),
				IdleTimeoutSeconds: 300,
			},
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the eight contract keys must appear.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 8 {
		t.Errorf("expected exactly 8 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"peers", "reachability", "policy", "bridge", "state", "reports", "executions", "sessions"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestNodeStateSnapshot_NullBlocks(t *testing.T) {
	// Decoding explicit nulls yields nil pointers.
	const nullBlocks = `{"peers":[],"reachability":null,"policy":null,"bridge":null,"state":null,"reports":null,"executions":[],"sessions":[]}`
	var snap NodeStateSnapshot
	if err := json.Unmarshal([]byte(nullBlocks), &snap); err != nil {
		t.Fatalf("unmarshal null blocks: %v", err)
	}
	if snap.Policy != nil || snap.Bridge != nil || snap.State != nil || snap.Reports != nil {
		t.Errorf("null blocks should decode to nil pointers, got %+v", snap)
	}
	if snap.Peers == nil || len(snap.Peers) != 0 {
		t.Errorf("peers = %v, want empty non-nil slice", snap.Peers)
	}
	if snap.Executions == nil || len(snap.Executions) != 0 {
		t.Errorf("executions = %v, want empty non-nil slice", snap.Executions)
	}
	if snap.Sessions == nil || len(*snap.Sessions) != 0 {
		t.Errorf("sessions = %v, want a non-nil pointer to an empty slice", snap.Sessions)
	}

	// A populated zero-value block decodes to a NON-nil pointer — distinct from
	// a null block.
	const populatedPolicy = `{"peers":[],"reachability":null,"policy":{},"bridge":null,"state":null,"reports":null,"executions":[],"sessions":[]}`
	var snap2 NodeStateSnapshot
	if err := json.Unmarshal([]byte(populatedPolicy), &snap2); err != nil {
		t.Fatalf("unmarshal populated policy: %v", err)
	}
	if snap2.Policy == nil {
		t.Error("policy:{} should decode to a non-nil pointer, distinct from null")
	}

	// Marshalling nil blocks emits literal null with all eight keys PRESENT.
	out, err := json.Marshal(NodeStateSnapshot{})
	if err != nil {
		t.Fatalf("marshal zero value: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"peers", "reachability", "policy", "bridge", "state", "reports", "executions", "sessions"} {
		v, ok := raw[key]
		if !ok {
			t.Errorf("key %q absent, want present with null value", key)
			continue
		}
		if key == "peers" || key == "executions" {
			continue // nil slice marshals as null; presence is what matters
		}
		if string(v) != "null" {
			t.Errorf("key %q = %s, want null", key, v)
		}
	}
}

// TestNodeStateSnapshot_SessionsBlock pins the three shapes the sessions block
// can arrive in. [] is the contract form of "no live sessions" and decodes to a
// non-nil pointer; null and an absent key both decode to a nil pointer, which is
// what keeps a control plane that failed to populate the block from reading as a
// teardown of every live session. None of the three is a decode error.
func TestNodeStateSnapshot_SessionsBlock(t *testing.T) {
	const others = `"peers":[],"reachability":null,"policy":null,"bridge":null,"state":null,"reports":null,"executions":[]`
	tests := []struct {
		name    string
		src     string
		wantNil bool
	}{
		{name: "empty array", src: `{` + others + `,"sessions":[]}`},
		{name: "null", src: `{` + others + `,"sessions":null}`, wantNil: true},
		{name: "key absent", src: `{` + others + `}`, wantNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var snap NodeStateSnapshot
			if err := json.Unmarshal([]byte(tt.src), &snap); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if tt.wantNil {
				if snap.Sessions != nil {
					t.Errorf("sessions = %#v, want a nil pointer", snap.Sessions)
				}
				return
			}
			if snap.Sessions == nil || len(*snap.Sessions) != 0 {
				t.Errorf("sessions = %#v, want a non-nil pointer to an empty slice", snap.Sessions)
			}
		})
	}
}

func TestSnapshotPeer_OmitsEmptyFallbackEndpoint(t *testing.T) {
	orig := SnapshotPeer{NodeID: "n-002", MeshIP: "10.42.0.2", PublicKey: "pk"}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
	if s := string(data); strings.Contains(s, `"fallback_endpoint"`) {
		t.Errorf("fallback_endpoint should be omitted when empty, got: %s", s)
	}

	orig.FallbackEndpoint = "203.0.113.1:51820"
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); !strings.Contains(s, `"fallback_endpoint"`) {
		t.Errorf("fallback_endpoint should be present when set, got: %s", s)
	}
}

func TestPolicyRule_PortsOmittedWhenNil(t *testing.T) {
	// Nil Ports → no "ports" key (icmp carries no ports).
	orig := PolicyRule{Action: "allow", Protocol: "icmp", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "10.0.0.0/8"}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
	if s := string(data); strings.Contains(s, `"ports"`) {
		t.Errorf("ports should be omitted when nil, got: %s", s)
	}

	// Set Ports → {"from":443,"to":443}.
	orig.Protocol = "tcp"
	orig.Ports = &PortRange{From: 443, To: 443}
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); !strings.Contains(s, `"ports":{"from":443,"to":443}`) {
		t.Errorf(`ports should serialize as {"from":443,"to":443}, got: %s`, s)
	}
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
	if s := string(data); strings.Contains(s, `"peer_id"`) {
		t.Errorf("peer_id should be omitted when empty, got: %s", s)
	}

	// With PeerID set.
	orig.PeerID = "n-002"
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); !strings.Contains(s, `"peer_id"`) {
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

func TestTypesMetricSample(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := MetricSample{
		Group:     MetricGroupPeerLatency,
		Name:      "rtt_ms",
		Value:     12.5,
		Labels:    map[string]string{"peer_id": "n-002"},
		Timestamp: now,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the five contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 5 {
		t.Errorf("expected exactly 5 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"group", "name", "value", "labels", "timestamp"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// labels is omitted when empty.
	orig.Labels = nil
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"labels"`) {
		t.Errorf("labels should be omitted when empty, got: %s", s)
	}
}

func TestTypesLogLine(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := LogLine{
		Severity:  "info",
		Unit:      "plexd.service",
		Hostname:  "node-1",
		Message:   "started",
		Timestamp: now,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the five contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 5 {
		t.Errorf("expected exactly 5 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"severity", "unit", "hostname", "message", "timestamp"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// unit and hostname are omitted when empty.
	orig.Unit = ""
	orig.Hostname = ""
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"unit"`) {
		t.Errorf("unit should be omitted when empty, got: %s", s)
	}
	if s := string(data2); strings.Contains(s, `"hostname"`) {
		t.Errorf("hostname should be omitted when empty, got: %s", s)
	}
}

func TestTypesAuditEvent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := AuditEvent{
		Source:    "systemd",
		Action:    "unit_start",
		Outcome:   "success",
		Timestamp: now,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the four contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 {
		t.Errorf("expected exactly 4 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"source", "action", "outcome", "timestamp"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesIngestReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := IngestReceipt{
		AcceptedAt: now,
		Records:    17,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the two contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2 {
		t.Errorf("expected exactly 2 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"accepted_at", "records"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesNodeStateReportRequest(t *testing.T) {
	orig := NodeStateReportRequest{
		Value:       "healthy",
		WorkloadTag: "app/web",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the two contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2 {
		t.Errorf("expected exactly 2 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"value", "workload_tag"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// workload_tag is omitted when empty.
	orig.WorkloadTag = ""
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"workload_tag"`) {
		t.Errorf("workload_tag should be omitted when empty, got: %s", s)
	}
}

func TestTypesNodeStateReportResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := NodeStateReportResponse{
		AcceptedAt: now,
		Key:        "app/web",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Exactly the two contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2 {
		t.Errorf("expected exactly 2 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"accepted_at", "key"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestTypesNodeStateExecution(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := NodeStateExecution{
		ExecutionID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0",
		Action:      "gather_info",
		Type:        ActionKindBuiltin,
		Parameters: map[string]json.RawMessage{
			"target":   json.RawMessage(`"10.42.0.5"`),
			"retries":  json.RawMessage(`3`),
			"since_ns": json.RawMessage(`1769500800123456789`),
			"verbose":  json.RawMessage(`true`),
			"label":    json.RawMessage(`null`),
			"tags":     json.RawMessage(`["a","b"]`),
			"nested":   json.RawMessage(`{"k":"v"}`),
		},
		Status:      ExecutionStatusPending,
		RequestedAt: now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys: exactly the seven contract keys, nothing more.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 7 {
		t.Errorf("expected exactly 7 JSON keys, got %d: %v", len(raw), raw)
	}
	for _, key := range []string{"execution_id", "action", "type", "parameters", "status", "requested_at", "expires_at"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// A parameter value keeps the JSON text it arrived as. since_ns is the
	// regression: decoded into an any it would come back as 1769500800123456800,
	// because float64 cannot hold an integer that large.
	wantParams := map[string]string{
		"target":   `"10.42.0.5"`,
		"retries":  `3`,
		"since_ns": `1769500800123456789`,
		"verbose":  `true`,
		"label":    `null`,
		"tags":     `["a","b"]`,
		"nested":   `{"k":"v"}`,
	}
	for name, want := range wantParams {
		if got := string(got.Parameters[name]); got != want {
			t.Errorf("Parameters[%q] = %s, want %s", name, got, want)
		}
	}

	// A null parameters block decodes to a nil map, not an empty one.
	const nullParams = `{"execution_id":"exec-1","action":"restart","type":"hook","parameters":null,` +
		`"status":"ack","requested_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:05:00Z"}`
	var nulled NodeStateExecution
	if err := json.Unmarshal([]byte(nullParams), &nulled); err != nil {
		t.Fatalf("unmarshal null parameters: %v", err)
	}
	if nulled.Parameters != nil {
		t.Errorf("parameters:null should decode to a nil map, got %#v", nulled.Parameters)
	}
	if nulled.Type != ActionKindHook {
		t.Errorf("Type = %q, want %q", nulled.Type, ActionKindHook)
	}
	if nulled.Status != ExecutionStatusAck {
		t.Errorf("Status = %q, want %q", nulled.Status, ExecutionStatusAck)
	}
}

func TestTypesNodeStateSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name       string
		session    NodeStateSession
		targetKey  string
		targetKeys []string
	}{
		{
			name: "ssh",
			session: NodeStateSession{
				SessionID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b0",
				JTI:       "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b0",
				Kind:      SessionKindSSH,
				Target: SessionTarget{SSH: &SessionTargetSSH{
					User:            "operator",
					AllowedCommands: []string{"systemctl restart plexd", "journalctl -u plexd"},
				}},
				ExpiresAt:          now.Add(30 * time.Minute),
				IdleTimeoutSeconds: 300,
			},
			targetKey:  "ssh",
			targetKeys: []string{"user", "allowed_commands"},
		},
		{
			name: "k8s",
			session: NodeStateSession{
				SessionID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
				JTI:       "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1",
				Kind:      SessionKindK8s,
				Target: SessionTarget{K8s: &SessionTargetK8s{
					User:              "alice@example.com",
					ImpersonateGroups: []string{"sre", "oncall"},
				}},
				ExpiresAt:          now.Add(15 * time.Minute),
				IdleTimeoutSeconds: 120,
			},
			targetKey:  "k8s",
			targetKeys: []string{"user", "impersonate_groups"},
		},
		{
			name: "tcp",
			session: NodeStateSession{
				SessionID:          "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
				JTI:                "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b2",
				Kind:               SessionKindTCP,
				Target:             SessionTarget{TCP: &SessionTargetTCP{Host: "10.42.0.5", Port: 5432}},
				ExpiresAt:          now.Add(1 * time.Hour),
				IdleTimeoutSeconds: 60,
			},
			targetKey:  "tcp",
			targetKeys: []string{"host", "port"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, got := roundTrip(t, tt.session)
			requireEqual(t, tt.session, got)

			// Verify snake_case keys: exactly the six contract keys, nothing more.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			if len(raw) != 6 {
				t.Errorf("expected exactly 6 JSON keys, got %d: %v", len(raw), raw)
			}
			for _, key := range []string{"session_id", "jti", "kind", "target", "expires_at", "idle_timeout_seconds"} {
				if _, ok := raw[key]; !ok {
					t.Errorf("expected JSON key %q", key)
				}
			}

			// The target carries exactly the one-of member the kind selects.
			var target map[string]json.RawMessage
			if err := json.Unmarshal(raw["target"], &target); err != nil {
				t.Fatalf("decode target: %v", err)
			}
			if len(target) != 1 {
				t.Errorf("expected exactly 1 one-of member, got %d: %v", len(target), target)
			}
			member, ok := target[tt.targetKey]
			if !ok {
				t.Fatalf("target missing member %q: %v", tt.targetKey, target)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(member, &fields); err != nil {
				t.Fatalf("decode target.%s: %v", tt.targetKey, err)
			}
			for _, key := range tt.targetKeys {
				if _, ok := fields[key]; !ok {
					t.Errorf("target.%s missing key %q", tt.targetKey, key)
				}
			}
		})
	}

	// An entry without idle_timeout_seconds means "no idle window": it decodes
	// to a zero, not to a default.
	const noIdle = `{"session_id":"sess-1","jti":"sess-1","kind":"tcp",` +
		`"target":{"tcp":{"host":"10.42.0.5","port":5432}},"expires_at":"2026-01-01T00:30:00Z"}`
	var got NodeStateSession
	if err := json.Unmarshal([]byte(noIdle), &got); err != nil {
		t.Fatalf("unmarshal without idle_timeout_seconds: %v", err)
	}
	if got.IdleTimeoutSeconds != 0 {
		t.Errorf("IdleTimeoutSeconds = %d, want 0", got.IdleTimeoutSeconds)
	}
	if got.Kind != SessionKindTCP {
		t.Errorf("Kind = %q, want %q", got.Kind, SessionKindTCP)
	}
	if got.Target.TCP == nil || got.Target.TCP.Port != 5432 {
		t.Errorf("Target.TCP = %+v, want host 10.42.0.5 port 5432", got.Target.TCP)
	}
	if got.Target.SSH != nil || got.Target.K8s != nil {
		t.Errorf("unset one-of members should stay nil, got %+v", got.Target)
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

// TestTypesBridgeInfo round-trips BridgeInfo directly. Bridge managers still
// produce this type (issue #23 reuses it), so its wire shape must stay covered
// even though it no longer travels in the heartbeat request.
func TestTypesBridgeInfo(t *testing.T) {
	// Base case.
	orig := BridgeInfo{
		Enabled:         true,
		AccessInterface: "eth1",
		ActiveRoutes:    3,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Relay-fields variant.
	relay := BridgeInfo{
		Enabled:             true,
		AccessInterface:     "eth1",
		ActiveRoutes:        3,
		RelayEnabled:        true,
		ActiveRelaySessions: 2,
	}
	_, gotRelay := roundTrip(t, relay)
	requireEqual(t, relay, gotRelay)
}

func TestRelayConfig_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := RelayConfig{
		Sessions: []RelaySessionAssignment{
			{
				SessionID:     "relay-001",
				PeerAID:       "n-001",
				PeerAEndpoint: "1.2.3.4:51820",
				PeerBID:       "n-002",
				PeerBEndpoint: "5.6.7.8:51820",
				ExpiresAt:     now.Add(1 * time.Hour),
			},
			{
				SessionID:     "relay-002",
				PeerAID:       "n-003",
				PeerAEndpoint: "9.10.11.12:51820",
				PeerBID:       "n-004",
				PeerBEndpoint: "13.14.15.16:51820",
				ExpiresAt:     now.Add(2 * time.Hour),
			},
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case key.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["sessions"]; !ok {
		t.Errorf("expected JSON key %q", "sessions")
	}
}

func TestRelaySessionAssignment_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := RelaySessionAssignment{
		SessionID:     "relay-001",
		PeerAID:       "n-001",
		PeerAEndpoint: "1.2.3.4:51820",
		PeerBID:       "n-002",
		PeerBEndpoint: "5.6.7.8:51820",
		ExpiresAt:     now.Add(1 * time.Hour),
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"session_id", "peer_a_id", "peer_a_endpoint", "peer_b_id", "peer_b_endpoint", "expires_at"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestBridgeInfo_RelayFields_JSONRoundTrip(t *testing.T) {
	orig := BridgeInfo{
		Enabled:             true,
		AccessInterface:     "eth1",
		ActiveRoutes:        5,
		RelayEnabled:        true,
		ActiveRelaySessions: 3,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify relay-specific snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"relay_enabled", "active_relay_sessions"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestUserAccessConfig_JSONRoundTrip(t *testing.T) {
	orig := UserAccessConfig{
		Enabled:       true,
		InterfaceName: "wg-access0",
		ListenPort:    51830,
		Peers: []UserAccessPeer{
			{
				PublicKey:  "ua-pk-001",
				AllowedIPs: []string{"10.99.0.1/32"},
				PSK:        "ua-psk-001",
				Label:      "alice-laptop",
			},
			{
				PublicKey:  "ua-pk-002",
				AllowedIPs: []string{"10.99.0.2/32", "10.99.0.3/32"},
				Label:      "bob-phone",
			},
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "interface_name", "listen_port", "peers"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestUserAccessPeer_JSONRoundTrip(t *testing.T) {
	// With PSK set.
	orig := UserAccessPeer{
		PublicKey:  "ua-pk-001",
		AllowedIPs: []string{"10.99.0.1/32"},
		PSK:        "ua-psk-001",
		Label:      "alice-laptop",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"public_key", "allowed_ips", "psk", "label"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// PSK should be omitted when empty.
	orig.PSK = ""
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"psk"`) {
		t.Errorf("psk should be omitted when empty, got: %s", s)
	}
}

func TestUserAccessInfo_JSONRoundTrip(t *testing.T) {
	orig := UserAccessInfo{
		Enabled:       true,
		InterfaceName: "wg-access0",
		PeerCount:     5,
		ListenPort:    51830,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "interface_name", "peer_count", "listen_port"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

// TestTypesUserAccessInfo round-trips UserAccessInfo directly. The user-access
// manager still produces this type; it no longer travels in the heartbeat.
func TestTypesUserAccessInfo(t *testing.T) {
	orig := UserAccessInfo{
		Enabled:       true,
		InterfaceName: "wg-access0",
		PeerCount:     3,
		ListenPort:    51830,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestIngressConfig_JSONRoundTrip(t *testing.T) {
	orig := IngressConfig{
		Enabled: true,
		Rules: []IngressRule{
			{
				RuleID:     "rule-001",
				ListenPort: 443,
				TargetAddr: "10.42.0.5:8443",
				Mode:       "passthrough",
			},
			{
				RuleID:     "rule-002",
				ListenPort: 8080,
				TargetAddr: "10.42.0.6:80",
				Mode:       "terminate",
				CertPEM:    "-----BEGIN CERTIFICATE-----\nMIIB...",
				KeyPEM:     "-----BEGIN PRIVATE KEY-----\nMIIE...",
			},
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "rules"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestIngressRule_JSONRoundTrip(t *testing.T) {
	// With CertPEM and KeyPEM set.
	orig := IngressRule{
		RuleID:     "rule-001",
		ListenPort: 443,
		TargetAddr: "10.42.0.5:8443",
		Mode:       "terminate",
		CertPEM:    "-----BEGIN CERTIFICATE-----\nMIIB...",
		KeyPEM:     "-----BEGIN PRIVATE KEY-----\nMIIE...",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rule_id", "listen_port", "target_addr", "mode", "cert_pem", "key_pem"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// CertPEM and KeyPEM should be omitted when empty.
	orig.CertPEM = ""
	orig.KeyPEM = ""
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"cert_pem"`) {
		t.Errorf("cert_pem should be omitted when empty, got: %s", s)
	}
	if s := string(data2); strings.Contains(s, `"key_pem"`) {
		t.Errorf("key_pem should be omitted when empty, got: %s", s)
	}
}

func TestIngressInfo_JSONRoundTrip(t *testing.T) {
	orig := IngressInfo{
		Enabled:         true,
		RuleCount:       3,
		ConnectionCount: 42,
		ACMEEnabled:     true,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "rule_count", "connection_count", "acme_enabled"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

// TestTypesIngressInfo round-trips IngressInfo directly. The ingress manager
// still produces this type; it no longer travels in the heartbeat.
func TestTypesIngressInfo(t *testing.T) {
	orig := IngressInfo{
		Enabled:         true,
		RuleCount:       2,
		ConnectionCount: 15,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

func TestBridgeInfo_IngressFields_JSONRoundTrip(t *testing.T) {
	orig := BridgeInfo{
		Enabled:             true,
		AccessInterface:     "eth1",
		ActiveRoutes:        5,
		RelayEnabled:        true,
		ActiveRelaySessions: 3,
		IngressEnabled:      true,
		ActiveIngressRules:  4,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify ingress-specific snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ingress_enabled", "active_ingress_rules"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestSiteToSiteConfig_JSONRoundTrip(t *testing.T) {
	orig := SiteToSiteConfig{
		Enabled: true,
		Tunnels: []SiteToSiteTunnel{
			{
				TunnelID:        "tun-001",
				RemoteEndpoint:  "203.0.113.1:51820",
				RemotePublicKey: "rpk-001",
				LocalSubnets:    []string{"192.168.1.0/24"},
				RemoteSubnets:   []string{"10.0.0.0/8"},
				PSK:             "s2s-psk-001",
				InterfaceName:   "wg-s2s0",
				ListenPort:      51830,
			},
			{
				TunnelID:        "tun-002",
				RemoteEndpoint:  "203.0.113.2:51821",
				RemotePublicKey: "rpk-002",
				LocalSubnets:    []string{"172.16.0.0/12"},
				RemoteSubnets:   []string{"10.10.0.0/16", "10.20.0.0/16"},
				InterfaceName:   "wg-s2s1",
				ListenPort:      51831,
			},
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "tunnels"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestSiteToSiteTunnel_JSONRoundTrip(t *testing.T) {
	// With PSK set.
	orig := SiteToSiteTunnel{
		TunnelID:        "tun-001",
		RemoteEndpoint:  "203.0.113.1:51820",
		RemotePublicKey: "rpk-001",
		LocalSubnets:    []string{"192.168.1.0/24"},
		RemoteSubnets:   []string{"10.0.0.0/8"},
		PSK:             "s2s-psk-001",
		InterfaceName:   "wg-s2s0",
		ListenPort:      51830,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tunnel_id", "remote_endpoint", "remote_public_key", "local_subnets", "remote_subnets", "psk", "interface_name", "listen_port"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}

	// PSK should be omitted when empty.
	orig.PSK = ""
	data2, got2 := roundTrip(t, orig)
	requireEqual(t, orig, got2)
	if s := string(data2); strings.Contains(s, `"psk"`) {
		t.Errorf("psk should be omitted when empty, got: %s", s)
	}
}

func TestSiteToSiteTunnel_ProviderType_JSONRoundTrip(t *testing.T) {
	// With ProviderType set.
	orig := SiteToSiteTunnel{
		TunnelID:        "tun-ipsec-001",
		RemoteEndpoint:  "203.0.113.5:500",
		RemotePublicKey: "",
		LocalSubnets:    []string{"192.168.1.0/24"},
		RemoteSubnets:   []string{"10.0.0.0/8"},
		PSK:             "ipsec-psk",
		InterfaceName:   "",
		ListenPort:      0,
		ProviderType:    "ipsec",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify provider_type key present.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["provider_type"]; !ok {
		t.Errorf("expected JSON key %q", "provider_type")
	}

	// ProviderType should be omitted when empty.
	orig.ProviderType = ""
	data2, _ := roundTrip(t, orig)
	if s := string(data2); strings.Contains(s, `"provider_type"`) {
		t.Errorf("provider_type should be omitted when empty, got: %s", s)
	}
}

func TestSiteToSiteInfo_JSONRoundTrip(t *testing.T) {
	orig := SiteToSiteInfo{
		Enabled:     true,
		TunnelCount: 3,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"enabled", "tunnel_count"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestSiteToSiteInfo_TunnelProviderNames_JSONRoundTrip(t *testing.T) {
	// With TunnelProviderNames set.
	orig := SiteToSiteInfo{
		Enabled:             true,
		TunnelCount:         5,
		TunnelProviderNames: []string{"ipsec", "openvpn"},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify tunnel_provider_names key present.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["tunnel_provider_names"]; !ok {
		t.Errorf("expected JSON key %q", "tunnel_provider_names")
	}

	// TunnelProviderNames should be omitted when nil.
	orig.TunnelProviderNames = nil
	data2, _ := roundTrip(t, orig)
	if s := string(data2); strings.Contains(s, `"tunnel_provider_names"`) {
		t.Errorf("tunnel_provider_names should be omitted when nil, got: %s", s)
	}
}

func TestIngressRule_Hostname_JSONRoundTrip(t *testing.T) {
	// With Hostname set (ACME mode).
	orig := IngressRule{
		RuleID:     "rule-acme-001",
		ListenPort: 443,
		TargetAddr: "10.42.0.5:8443",
		Mode:       "acme",
		Hostname:   "app.example.com",
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify hostname key present.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["hostname"]; !ok {
		t.Errorf("expected JSON key %q", "hostname")
	}

	// Hostname should be omitted when empty.
	orig.Hostname = ""
	data2, _ := roundTrip(t, orig)
	if s := string(data2); strings.Contains(s, `"hostname"`) {
		t.Errorf("hostname should be omitted when empty, got: %s", s)
	}
}

func TestIngressInfo_ACMEEnabled_JSONRoundTrip(t *testing.T) {
	orig := IngressInfo{
		Enabled:         true,
		RuleCount:       2,
		ConnectionCount: 10,
		ACMEEnabled:     true,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["acme_enabled"]; !ok {
		t.Errorf("expected JSON key %q", "acme_enabled")
	}

	// ACMEEnabled false should still be present (not omitempty).
	orig.ACMEEnabled = false
	data2, _ := roundTrip(t, orig)
	if s := string(data2); !strings.Contains(s, `"acme_enabled"`) {
		t.Errorf("acme_enabled should be present even when false, got: %s", s)
	}
}

// TestTypesSiteToSiteInfo round-trips SiteToSiteInfo directly. The
// site-to-site manager still produces this type; it no longer travels in the
// heartbeat.
func TestTypesSiteToSiteInfo(t *testing.T) {
	orig := SiteToSiteInfo{
		Enabled:     true,
		TunnelCount: 2,
	}
	_, got := roundTrip(t, orig)
	requireEqual(t, orig, got)
}

// TestSigningKeyRotation_JSONDecode proves the signing_key_rotated payload
// decodes from the contract's snake_case keys into every field.
func TestSigningKeyRotation_JSONDecode(t *testing.T) {
	raw := `{
		"key_id": "kid-new",
		"public_key": "cHVia2V5LWJhc2U2NA==",
		"previous_key_id": "kid-old",
		"transition_expires": "2025-01-15T10:30:00Z"
	}`

	var rot SigningKeyRotation
	if err := json.Unmarshal([]byte(raw), &rot); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rot.KeyID != "kid-new" {
		t.Errorf("KeyID = %q, want %q", rot.KeyID, "kid-new")
	}
	if rot.PublicKey != "cHVia2V5LWJhc2U2NA==" {
		t.Errorf("PublicKey = %q, want %q", rot.PublicKey, "cHVia2V5LWJhc2U2NA==")
	}
	if rot.PreviousKeyID != "kid-old" {
		t.Errorf("PreviousKeyID = %q, want %q", rot.PreviousKeyID, "kid-old")
	}
	wantTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	if !rot.TransitionExpires.Equal(wantTime) {
		t.Errorf("TransitionExpires = %v, want %v", rot.TransitionExpires, wantTime)
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"key_id", "public_key", "previous_key_id", "transition_expires"} {
		if _, ok := keys[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestLocalEndpointConfig_Validate(t *testing.T) {
	tests := []struct {
		name       string
		cfg        LocalEndpointConfig
		wantErr    bool
		errContain string
	}{
		{
			name: "zero value is valid",
			cfg:  LocalEndpointConfig{},
		},
		{
			name: "valid HTTPS with secret key",
			cfg: LocalEndpointConfig{
				URL:       "https://metrics.local:9090/ingest",
				SecretKey: "my-secret-token",
			},
		},
		{
			name:       "rejects HTTP scheme",
			cfg:        LocalEndpointConfig{URL: "http://metrics.local:9090/ingest", SecretKey: "my-secret-token"},
			wantErr:    true,
			errContain: "must be HTTPS",
		},
		{
			name:       "rejects malformed URL",
			cfg:        LocalEndpointConfig{URL: "://bad", SecretKey: "my-secret-token"},
			wantErr:    true,
			errContain: "invalid",
		},
		{
			name:       "requires secret key when URL is set",
			cfg:        LocalEndpointConfig{URL: "https://metrics.local:9090/ingest"},
			wantErr:    true,
			errContain: "SecretKey is required",
		},
		{
			name: "secret key without URL is harmless no-op",
			cfg:  LocalEndpointConfig{SecretKey: "orphaned-secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate("test")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want error containing %q", tt.errContain)
				}
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errContain)
				}
				return
			}
			if err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestBridgeInfo_SiteToSiteFields_JSONRoundTrip(t *testing.T) {
	orig := BridgeInfo{
		Enabled:                 true,
		AccessInterface:         "eth1",
		ActiveRoutes:            5,
		RelayEnabled:            true,
		ActiveRelaySessions:     3,
		IngressEnabled:          true,
		ActiveIngressRules:      4,
		SiteToSiteEnabled:       true,
		ActiveSiteToSiteTunnels: 2,
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	// Verify site-to-site-specific snake_case keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"site_to_site_enabled", "active_site_to_site_tunnels"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("expected JSON key %q", key)
		}
	}
}

func TestExecutionCallbackRequest_AckOnly(t *testing.T) {
	// The ack-only callback serializes to exactly one member.
	data, err := json.Marshal(ExecutionCallbackRequest{Status: ExecutionStatusAck})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"status":"ack"}`
	if string(data) != want {
		t.Errorf("serialized = %s, want %s", data, want)
	}
}

func TestExecutionCallbackRequest_TerminalInlineOutput(t *testing.T) {
	code := 0
	req := ExecutionCallbackRequest{
		Status:   ExecutionStatusSucceeded,
		ExitCode: &code,
		Output:   &ExecutionOutput{Inline: "aGVsbG8="},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	// The exit_code pointer keeps an explicit zero on the wire.
	if string(raw["exit_code"]) != "0" {
		t.Errorf("exit_code = %s, want 0", raw["exit_code"])
	}
	if string(raw["status"]) != `"succeeded"` {
		t.Errorf("status = %s, want %q", raw["status"], "succeeded")
	}
	// error and declared_output_bytes stay absent when unset.
	if _, ok := raw["error"]; ok {
		t.Error("error should be omitted when empty")
	}
	if _, ok := raw["declared_output_bytes"]; ok {
		t.Error("declared_output_bytes should be omitted when zero")
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw["output"], &out); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if string(out["inline"]) != `"aGVsbG8="` {
		t.Errorf("output.inline = %s, want base64 body", out["inline"])
	}
	if _, ok := out["object_key"]; ok {
		t.Error("object_key should be omitted for inline output")
	}
}

func TestExecutionCallbackRequest_DeclaringForm(t *testing.T) {
	// A large declared output length rides along without an output object.
	data, err := json.Marshal(ExecutionCallbackRequest{
		Status:              ExecutionStatusStarted,
		DeclaredOutputBytes: 32 * 1024,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["declared_output_bytes"]) != "32768" {
		t.Errorf("declared_output_bytes = %s, want 32768", raw["declared_output_bytes"])
	}
	if _, ok := raw["output"]; ok {
		t.Error("output should be omitted when only the length is declared")
	}
}

func TestExecutionCallbackRequest_ObjectKeyOutput(t *testing.T) {
	req := ExecutionCallbackRequest{
		Status: ExecutionStatusSucceeded,
		Output: &ExecutionOutput{
			ObjectKey: "outputs/exec-1.bin",
			SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw["output"], &out); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	for _, key := range []string{"object_key", "sha256"} {
		if _, ok := out[key]; !ok {
			t.Errorf("output missing key %q", key)
		}
	}
	if _, ok := out["inline"]; ok {
		t.Error("inline should be omitted for an already-uploaded output")
	}
}

func TestExecutionCallbackResponse_Decode(t *testing.T) {
	const src = `{"status":"awaiting_output","output_upload_url":"https://store.example.com/outputs/exec-1?sig=abc"}`
	var got ExecutionCallbackResponse
	if err := json.Unmarshal([]byte(src), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status != "awaiting_output" {
		t.Errorf("Status = %q, want %q", got.Status, "awaiting_output")
	}
	if got.OutputUploadURL != "https://store.example.com/outputs/exec-1?sig=abc" {
		t.Errorf("OutputUploadURL = %q, want the presigned URL", got.OutputUploadURL)
	}

	// output_upload_url is omitted when the callback declared no upload.
	data, err := json.Marshal(ExecutionCallbackResponse{Status: "ack"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if s := string(data); strings.Contains(s, "output_upload_url") {
		t.Errorf("output_upload_url should be omitted when empty, got: %s", s)
	}
}

func TestSessionActivityRequest_TCPStarted(t *testing.T) {
	req := SessionActivityRequest{
		TCP: &TCPActivity{
			Phase:            TCPPhaseSessionStarted,
			TargetHost:       "10.42.0.5",
			TargetPort:       5432,
			ListenerEndpoint: "127.0.0.1:34517",
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Exactly one one-of member appears.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 1 {
		t.Errorf("expected exactly 1 one-of member, got %d: %v", len(top), top)
	}
	var tcp map[string]json.RawMessage
	if err := json.Unmarshal(top["tcp"], &tcp); err != nil {
		t.Fatalf("decode tcp: %v", err)
	}
	for _, key := range []string{"phase", "target_host", "target_port", "listener_endpoint"} {
		if _, ok := tcp[key]; !ok {
			t.Errorf("tcp missing key %q", key)
		}
	}
	// A session_started row omits the byte counters and the terminated_by reason.
	for _, key := range []string{"bytes_in", "bytes_out", "terminated_by"} {
		if _, ok := tcp[key]; ok {
			t.Errorf("session_started should omit %q", key)
		}
	}
}

func TestSessionActivityRequest_TCPEnded(t *testing.T) {
	var in, out int64 = 0, 0
	req := SessionActivityRequest{
		TCP: &TCPActivity{
			Phase:        TCPPhaseSessionEnded,
			BytesIn:      &in,
			BytesOut:     &out,
			TerminatedBy: TerminatedByIdleTimeout,
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	var tcp map[string]json.RawMessage
	if err := json.Unmarshal(top["tcp"], &tcp); err != nil {
		t.Fatalf("decode tcp: %v", err)
	}
	// The byte-count pointers keep explicit zeros on a session_ended row.
	if string(tcp["bytes_in"]) != "0" {
		t.Errorf("bytes_in = %s, want 0", tcp["bytes_in"])
	}
	if string(tcp["bytes_out"]) != "0" {
		t.Errorf("bytes_out = %s, want 0", tcp["bytes_out"])
	}
	if string(tcp["terminated_by"]) != `"idle_timeout"` {
		t.Errorf("terminated_by = %s, want %q", tcp["terminated_by"], "idle_timeout")
	}
	// The listener address rides only on the session_started row.
	if _, ok := tcp["listener_endpoint"]; ok {
		t.Error("session_ended should omit listener_endpoint")
	}
}

func TestSessionActivityRequest_SSHRoundTrip(t *testing.T) {
	started := time.Now().UTC().Truncate(time.Second)
	completed := started.Add(90 * time.Second)
	code := 0
	orig := SessionActivityRequest{
		SSH: &SSHActivity{
			Command:     "systemctl restart plexd",
			ExitCode:    &code,
			StartedAt:   &started,
			CompletedAt: &completed,
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	if _, ok := top["ssh"]; !ok {
		t.Error("expected ssh member")
	}
	if _, ok := top["tcp"]; ok {
		t.Error("tcp should be omitted when only ssh is set")
	}
}

func TestSessionActivityRequest_K8sRoundTrip(t *testing.T) {
	orig := SessionActivityRequest{
		K8s: &K8sActivity{
			Verb:         "get",
			ResourceKind: "pods",
			Namespace:    "default",
			Name:         "web-0",
			StatusCode:   200,
			DurationMS:   42,
		},
	}
	data, got := roundTrip(t, orig)
	requireEqual(t, orig, got)

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	var k8s map[string]json.RawMessage
	if err := json.Unmarshal(top["k8s"], &k8s); err != nil {
		t.Fatalf("decode k8s: %v", err)
	}
	for _, key := range []string{"verb", "resource_kind", "namespace", "name", "status_code", "duration_ms"} {
		if _, ok := k8s[key]; !ok {
			t.Errorf("k8s missing key %q", key)
		}
	}
}
