package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestSignedEnvelope_ParseValid(t *testing.T) {
	raw := `{
		"event_type": "peer_added",
		"event_id": "evt-001",
		"issued_at": "2025-01-15T10:30:00Z",
		"nonce": "abc123",
		"payload": {"peer_id": "node-42"},
		"signature": "sig-xyz"
	}`

	env, err := ParseEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env.EventType != "peer_added" {
		t.Errorf("EventType = %q, want %q", env.EventType, "peer_added")
	}
	if env.EventID != "evt-001" {
		t.Errorf("EventID = %q, want %q", env.EventID, "evt-001")
	}
	if env.Nonce != "abc123" {
		t.Errorf("Nonce = %q, want %q", env.Nonce, "abc123")
	}
	if env.Signature != "sig-xyz" {
		t.Errorf("Signature = %q, want %q", env.Signature, "sig-xyz")
	}
	wantTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	if !env.IssuedAt.Equal(wantTime) {
		t.Errorf("IssuedAt = %v, want %v", env.IssuedAt, wantTime)
	}

	// Payload should be a json.RawMessage containing the object.
	var payload map[string]string
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload["peer_id"] != "node-42" {
		t.Errorf("payload[peer_id] = %q, want %q", payload["peer_id"], "node-42")
	}
}

func TestSignedEnvelope_MissingEventType(t *testing.T) {
	raw := `{"event_id": "evt-001"}`

	_, err := ParseEnvelope([]byte(raw))
	if err == nil {
		t.Fatal("expected error for missing event_type, got nil")
	}
	if got := err.Error(); !strContains(got, "event_type") {
		t.Errorf("error = %q, want it to contain %q", got, "event_type")
	}
}

func TestSignedEnvelope_MissingEventID(t *testing.T) {
	raw := `{"event_type": "peer_added"}`

	_, err := ParseEnvelope([]byte(raw))
	if err == nil {
		t.Fatal("expected error for missing event_id, got nil")
	}
	if got := err.Error(); !strContains(got, "event_id") {
		t.Errorf("error = %q, want it to contain %q", got, "event_id")
	}
}

func TestSignedEnvelope_InvalidJSON(t *testing.T) {
	_, err := ParseEnvelope([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestNoOpVerifier_AcceptsAll(t *testing.T) {
	v := NoOpVerifier{}

	env := SignedEnvelope{
		EventType: "peer_added",
		EventID:   "evt-999",
		Nonce:     "nonce",
		Signature: "sig",
	}

	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("NoOpVerifier.Verify() returned error: %v", err)
	}

	// Also verify with a zero-value envelope.
	if err := v.Verify(context.Background(), SignedEnvelope{}); err != nil {
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
		"event_type": "action_request",
		"event_id": "evt-002",
		"payload": {"action": "restart", "params": {"timeout": 30}}
	}`

	env, err := ParseEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-parse the preserved RawMessage.
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	// Check nested value is preserved.
	var action string
	if err := json.Unmarshal(payload["action"], &action); err != nil {
		t.Fatalf("failed to unmarshal action: %v", err)
	}
	if action != "restart" {
		t.Errorf("payload action = %q, want %q", action, "restart")
	}

	// Check nested object is preserved.
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
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
