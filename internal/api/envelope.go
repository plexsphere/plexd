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
	EventPeerAdded                = "peer_added"
	EventPeerRemoved              = "peer_removed"
	EventPeerKeyRotated           = "peer_key_rotated"
	EventPeerEndpointChanged      = "peer_endpoint_changed"
	EventPolicyUpdated            = "policy_updated"
	EventActionRequest            = "action_request"
	EventSessionRevoked           = "session_revoked"
	EventSSHSessionSetup          = "ssh_session_setup"
	EventRotateKeys               = "rotate_keys"
	EventSigningKeyRotated        = "signing_key_rotated"
	EventNodeStateUpdated         = "node_state_updated"
	EventNodeSecretsUpdated       = "node_secrets_updated"
	EventBridgeConfigUpdated      = "bridge_config_updated"
	EventRelaySessionAssigned     = "relay_session_assigned"
	EventRelaySessionRevoked      = "relay_session_revoked"
	EventUserAccessConfigUpdated  = "user_access_config_updated"
	EventUserAccessPeerAssigned   = "user_access_peer_assigned"
	EventUserAccessPeerRevoked    = "user_access_peer_revoked"
	EventIngressConfigUpdated     = "ingress_config_updated"
	EventIngressRuleAssigned      = "ingress_rule_assigned"
	EventIngressRuleRevoked       = "ingress_rule_revoked"
	EventSiteToSiteConfigUpdated  = "site_to_site_config_updated"
	EventSiteToSiteTunnelAssigned = "site_to_site_tunnel_assigned"
	EventSiteToSiteTunnelRevoked  = "site_to_site_tunnel_revoked"
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
