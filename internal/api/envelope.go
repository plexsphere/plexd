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
	// Contract types are emitted by the control plane per the OpenAPI events
	// document. Their payloads are treated as opaque: the reconciler pull is
	// authoritative, so each of these events triggers a reconcile.
	EventNodeStateUpdated    = "node_state_updated"
	EventPolicyUpdated       = "policy_updated"
	EventBridgeConfigUpdated = "bridge_config_updated"

	// EventActionRequest exists as a push-latency optimisation: action
	// dispatches are delivered in the executions block of the state pull, so the
	// event's payload is opaque and it triggers a reconcile like the rest of the
	// tier — the resulting pull carries the dispatch.
	EventActionRequest = "action_request"

	// EventSessionSetup is the same push-latency optimisation for mediated
	// access: sessions are delivered in the sessions block of the state pull, so
	// the event's payload is opaque and it triggers a reconcile like the rest of
	// the tier — the resulting pull carries the session.
	EventSessionSetup = "session_setup"

	// Documented-coming family: types that land with the platform's 14-type
	// taxonomy. They are already named so the agent can subscribe to them once
	// the control plane starts emitting them; every one triggers a reconcile.
	EventPeerRegistered      = "peer_registered"
	EventPeerPSKAssigned     = "peer_psk_assigned"
	EventPeerDeregistered    = "peer_deregistered"
	EventPeerEndpointChanged = "peer_endpoint_changed"
	EventRotateKeys          = "rotate_keys"
	EventPeerKeyRotated      = "peer_key_rotated"
	EventSigningKeyRotated   = "signing_key_rotated"

	// EventSessionRevoked carries no teardown of its own: a session leaving the
	// pull's sessions block is what closes it, so this event only pulls the
	// observing reconcile forward.
	EventSessionRevoked = "session_revoked"
)

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

// Envelope is the wire format for signed events the control plane streams over
// SSE. It matches the control plane's OpenAPI v1 events contract.
type Envelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Scope     string          `json:"scope"`
	KeyID     string          `json:"key_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// ParseEnvelope unmarshals data into an Envelope and validates required fields.
func ParseEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("api: envelope: %w", err)
	}
	if env.ID == "" {
		return Envelope{}, fmt.Errorf("api: envelope: missing required field %q", "id")
	}
	if env.Type == "" {
		return Envelope{}, fmt.Errorf("api: envelope: missing required field %q", "type")
	}
	return env, nil
}

// canonicalEnvelope is the deterministic representation over which an envelope
// signature is computed. Its members and order are fixed: id, type, scope,
// key_id, issued_at, payload — and never the signature.
type canonicalEnvelope struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Scope    string          `json:"scope"`
	KeyID    string          `json:"key_id"`
	IssuedAt time.Time       `json:"issued_at"`
	Payload  json.RawMessage `json:"payload"`
}

// CanonicalBytes returns the canonical signing bytes for an envelope: a JSON
// object with exactly the fields id, type, scope, key_id, issued_at, payload in
// that order and no signature member. A nil Payload serializes as
// "payload":null. It is the single canonical-form seam shared between the agent
// and the mock control plane; the control plane's own helper is unpublished, so
// this shape is an author-approved assumption until the platform documents it.
func CanonicalBytes(env Envelope) ([]byte, error) {
	return json.Marshal(canonicalEnvelope{
		ID:       env.ID,
		Type:     env.Type,
		Scope:    env.Scope,
		KeyID:    env.KeyID,
		IssuedAt: env.IssuedAt,
		Payload:  env.Payload,
	})
}

// ---------------------------------------------------------------------------
// EventVerifier
// ---------------------------------------------------------------------------

// EventVerifier verifies the signature of an Envelope.
type EventVerifier interface {
	Verify(ctx context.Context, envelope Envelope) error
}

// NoOpVerifier is an EventVerifier that accepts all envelopes without verification.
type NoOpVerifier struct{}

// Verify always returns nil.
func (NoOpVerifier) Verify(_ context.Context, _ Envelope) error {
	return nil
}
