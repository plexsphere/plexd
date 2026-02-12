package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// SSE Event Types
// ---------------------------------------------------------------------------

const (
	EventPeerAdded           = "peer_added"
	EventPeerRemoved         = "peer_removed"
	EventPeerKeyRotated      = "peer_key_rotated"
	EventPeerEndpointChanged = "peer_endpoint_changed"
	EventPolicyUpdated       = "policy_updated"
	EventActionRequest       = "action_request"
	EventSessionRevoked      = "session_revoked"
	EventSSHSessionSetup     = "ssh_session_setup"
	EventRotateKeys          = "rotate_keys"
	EventSigningKeyRotated   = "signing_key_rotated"
	EventNodeStateUpdated    = "node_state_updated"
	EventNodeSecretsUpdated  = "node_secrets_updated"
)

// ---------------------------------------------------------------------------
// SignedEnvelope
// ---------------------------------------------------------------------------

// SignedEnvelope is the wire format for SSE events received from the control plane.
type SignedEnvelope struct {
	EventType string          `json:"event_type"`
	EventID   string          `json:"event_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	Nonce     string          `json:"nonce"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// ParseEnvelope unmarshals data into a SignedEnvelope and validates required fields.
func ParseEnvelope(data []byte) (SignedEnvelope, error) {
	var env SignedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return SignedEnvelope{}, fmt.Errorf("api: envelope: %w", err)
	}
	if env.EventType == "" {
		return SignedEnvelope{}, fmt.Errorf("api: envelope: missing required field %q", "event_type")
	}
	if env.EventID == "" {
		return SignedEnvelope{}, fmt.Errorf("api: envelope: missing required field %q", "event_id")
	}
	return env, nil
}

// ---------------------------------------------------------------------------
// EventVerifier
// ---------------------------------------------------------------------------

// EventVerifier verifies the signature of a SignedEnvelope.
type EventVerifier interface {
	Verify(ctx context.Context, envelope SignedEnvelope) error
}

// NoOpVerifier is an EventVerifier that accepts all envelopes without verification.
type NoOpVerifier struct{}

// Verify always returns nil.
func (NoOpVerifier) Verify(_ context.Context, _ SignedEnvelope) error {
	return nil
}
