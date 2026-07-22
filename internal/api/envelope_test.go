package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseEnvelope_Valid(t *testing.T) {
	raw := `{
		"id": "evt-001",
		"type": "policy_updated",
		"scope": "node:node-42",
		"key_id": "kid-1",
		"issued_at": "2025-01-15T10:30:00Z",
		"payload": {"revision_id": "rev-7"},
		"signature": "sig-xyz"
	}`

	env, err := ParseEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env.ID != "evt-001" {
		t.Errorf("ID = %q, want %q", env.ID, "evt-001")
	}
	if env.Type != "policy_updated" {
		t.Errorf("Type = %q, want %q", env.Type, "policy_updated")
	}
	if env.Scope != "node:node-42" {
		t.Errorf("Scope = %q, want %q", env.Scope, "node:node-42")
	}
	if env.KeyID != "kid-1" {
		t.Errorf("KeyID = %q, want %q", env.KeyID, "kid-1")
	}
	if env.Signature != "sig-xyz" {
		t.Errorf("Signature = %q, want %q", env.Signature, "sig-xyz")
	}
	wantTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	if !env.IssuedAt.Equal(wantTime) {
		t.Errorf("IssuedAt = %v, want %v", env.IssuedAt, wantTime)
	}

	var payload map[string]string
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload["revision_id"] != "rev-7" {
		t.Errorf("payload[revision_id] = %q, want %q", payload["revision_id"], "rev-7")
	}
}

func TestParseEnvelope_Errors(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string // exact when set
		prefix  string // prefix when set
	}{
		{
			name:    "missing id",
			raw:     `{"type": "policy_updated"}`,
			wantErr: `api: envelope: missing required field "id"`,
		},
		{
			name:    "missing type",
			raw:     `{"id": "evt-001"}`,
			wantErr: `api: envelope: missing required field "type"`,
		},
		{
			name:   "malformed json",
			raw:    `{not json`,
			prefix: "api: envelope: ",
		},
		{
			name:   "empty input",
			raw:    ``,
			prefix: "api: envelope: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEnvelope([]byte(tt.raw))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
			if tt.prefix != "" && !strings.HasPrefix(err.Error(), tt.prefix) {
				t.Errorf("error = %q, want prefix %q", err.Error(), tt.prefix)
			}
		})
	}
}

func TestCanonicalBytes_GoldenOrder(t *testing.T) {
	env := Envelope{
		ID:        "evt-001",
		Type:      "policy_updated",
		Scope:     "node:node-42",
		KeyID:     "kid-1",
		IssuedAt:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Payload:   json.RawMessage(`{"revision_id":"rev-7"}`),
		Signature: "sig-xyz", // must NOT appear in the canonical bytes
	}

	got, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	want := `{"id":"evt-001","type":"policy_updated","scope":"node:node-42","key_id":"kid-1","issued_at":"2025-01-15T10:30:00Z","payload":{"revision_id":"rev-7"}}`
	if string(got) != want {
		t.Errorf("CanonicalBytes =\n  %s\nwant\n  %s", got, want)
	}
	if strings.Contains(string(got), "signature") || strings.Contains(string(got), "sig-xyz") {
		t.Errorf("canonical bytes must not contain the signature: %s", got)
	}
}

func TestCanonicalBytes_NilPayload(t *testing.T) {
	env := Envelope{
		ID:       "evt-nil",
		Type:     "policy_updated",
		IssuedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Payload:  nil,
	}

	got, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	want := `{"id":"evt-nil","type":"policy_updated","scope":"","key_id":"","issued_at":"2025-01-15T10:30:00Z","payload":null}`
	if string(got) != want {
		t.Errorf("CanonicalBytes =\n  %s\nwant\n  %s", got, want)
	}

	// The full envelope round-trips: a nil Payload marshals as null and parses back.
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if !strings.Contains(string(wire), `"payload":null`) {
		t.Errorf("marshaled envelope should contain payload:null, got %s", wire)
	}
	back, err := ParseEnvelope(wire)
	if err != nil {
		t.Fatalf("round-trip ParseEnvelope: %v", err)
	}
	if back.ID != env.ID || back.Type != env.Type {
		t.Errorf("round-trip lost fields: got id=%q type=%q", back.ID, back.Type)
	}
}

func TestNoOpVerifier_AcceptsAll(t *testing.T) {
	v := NoOpVerifier{}

	env := Envelope{
		ID:        "evt-999",
		Type:      "peer_added",
		Signature: "sig",
	}

	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("NoOpVerifier.Verify() returned error: %v", err)
	}

	// Also verify with a zero-value envelope.
	if err := v.Verify(context.Background(), Envelope{}); err != nil {
		t.Fatalf("NoOpVerifier.Verify() returned error for zero-value: %v", err)
	}
}

func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{"EventPeerAdded", EventPeerAdded, "peer_added"},
		{"EventPeerRemoved", EventPeerRemoved, "peer_removed"},
		{"EventPeerKeyRotated", EventPeerKeyRotated, "peer_key_rotated"},
		{"EventPeerEndpointChanged", EventPeerEndpointChanged, "peer_endpoint_changed"},
		{"EventPolicyUpdated", EventPolicyUpdated, "policy_updated"},
		{"EventActionRequest", EventActionRequest, "action_request"},
		{"EventSessionRevoked", EventSessionRevoked, "session_revoked"},
		{"EventSSHSessionSetup", EventSSHSessionSetup, "ssh_session_setup"},
		{"EventRotateKeys", EventRotateKeys, "rotate_keys"},
		{"EventSigningKeyRotated", EventSigningKeyRotated, "signing_key_rotated"},
		{"EventNodeStateUpdated", EventNodeStateUpdated, "node_state_updated"},
		{"EventNodeSecretsUpdated", EventNodeSecretsUpdated, "node_secrets_updated"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.constant, tt.want)
			}
		})
	}
}

func TestParseEnvelope_PreservesPayload(t *testing.T) {
	// The payload contains nested JSON that should be preserved as-is.
	raw := `{
		"id": "evt-002",
		"type": "action_request",
		"payload": {"action": "restart", "params": {"timeout": 30}}
	}`

	env, err := ParseEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	var action string
	if err := json.Unmarshal(payload["action"], &action); err != nil {
		t.Fatalf("failed to unmarshal action: %v", err)
	}
	if action != "restart" {
		t.Errorf("payload action = %q, want %q", action, "restart")
	}

	var params map[string]int
	if err := json.Unmarshal(payload["params"], &params); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}
	if params["timeout"] != 30 {
		t.Errorf("payload params.timeout = %d, want %d", params["timeout"], 30)
	}
}

// strContains reports whether s contains substr.
func strContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
