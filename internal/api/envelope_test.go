package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
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

// The worked example of the agent contract's "Signed event envelope" section
// (plexsphere docs/reference/api/plexd-agent-contract.md): the data: line a node
// receives, its canonical bytes, their SHA-512 digest, and the public key of
// RFC 8032 section 7.1 TEST 1 the signature verifies under.
const (
	contractExampleData      = `{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","type":"policy_updated","scope":"domain:0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1","key_id":"signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000","issued_at":"2026-05-27T10:00:00Z","payload":{"node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a2","policy_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3","revision_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a4","fingerprint":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=","rules":[]},"signature":"6KztbqXrBOMO6zRemUQKvyjno1s2nSA4l0p1ZVJxfnhwB183pnw1DmRmv71cL6C7uXw3KZOfIAuAKZBAj9FTCA=="}`
	contractExampleSignature = "6KztbqXrBOMO6zRemUQKvyjno1s2nSA4l0p1ZVJxfnhwB183pnw1DmRmv71cL6C7uXw3KZOfIAuAKZBAj9FTCA=="
	contractExampleCanonical = `{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a0","issued_at":"2026-05-27T10:00:00.000000000Z","key_id":"signing-domain-0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1-1767225600000000000","payload":{"fingerprint":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=","node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a2","policy_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a3","revision_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a4","rules":[]},"scope":{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1","kind":"domain"},"type":"policy_updated"}`
	contractExampleDigest    = "836b0de19c82abbf8a12c019964789f06918894af27e168caa62bb21f736ac5ec7582962e8f9eca2ef1a38f5169f253a6f9bad5b06f5ce659fe1a1dc8ecc940d"
	contractExamplePublicKey = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
)

// TestCanonicalBytes_AgentContractWorkedExample rebuilds the contract's worked
// example from its data: line alone: the canonical bytes, the digest, and a
// signature that verifies over the digest and not over the bytes. It is the
// proof that an envelope the real control plane signed verifies here; Verify
// itself would refuse it as stale, so the test checks the steps Verify takes.
func TestCanonicalBytes_AgentContractWorkedExample(t *testing.T) {
	env, err := ParseEnvelope([]byte(contractExampleData))
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}

	canonical, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if string(canonical) != contractExampleCanonical {
		t.Fatalf("CanonicalBytes =\n  %s\nwant\n  %s", canonical, contractExampleCanonical)
	}
	if len(canonical) != 504 {
		t.Errorf("canonical bytes are %d long, want the contract's 504", len(canonical))
	}

	msg, err := SignedMessage(env)
	if err != nil {
		t.Fatalf("SignedMessage: %v", err)
	}
	if got := hex.EncodeToString(msg); got != contractExampleDigest {
		t.Errorf("SignedMessage = %s, want %s", got, contractExampleDigest)
	}

	pub, err := base64.StdEncoding.DecodeString(contractExamplePublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature does not verify over the SHA-512 digest")
	}
	if ed25519.Verify(pub, canonical, sig) {
		t.Error("signature verifies over the raw canonical bytes, want only over their digest")
	}
}

func TestCanonicalBytes_GoldenOrder(t *testing.T) {
	env := Envelope{
		ID:       "evt-001",
		Type:     "policy_updated",
		Scope:    testDomainScope,
		KeyID:    "kid-1",
		IssuedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Payload:  json.RawMessage(`{"revision_id":"rev-7"}`),
	}

	got, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	want := `{"id":"evt-001","issued_at":"2025-01-15T10:30:00.000000000Z","key_id":"kid-1","payload":{"revision_id":"rev-7"},"scope":{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1","kind":"domain"},"type":"policy_updated"}`
	if string(got) != want {
		t.Errorf("CanonicalBytes =\n  %s\nwant\n  %s", got, want)
	}
}

// TestCanonicalBytes_NeverCarriesTheSignature pins that the signature stays out
// of the signed bytes, whatever the Signature field holds.
func TestCanonicalBytes_NeverCarriesTheSignature(t *testing.T) {
	for _, sig := range []string{"", "sig-xyz", `"signature"`, contractExampleSignature} {
		env := Envelope{
			ID: "evt-001", Type: "policy_updated", Scope: "platform", KeyID: "kid-1",
			IssuedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), Signature: sig,
		}
		got, err := CanonicalBytes(env)
		if err != nil {
			t.Fatalf("CanonicalBytes(signature %q): %v", sig, err)
		}
		if strings.Contains(string(got), "signature") || (sig != "" && strings.Contains(string(got), sig)) {
			t.Errorf("canonical bytes carry the signature %q: %s", sig, got)
		}
	}
}

// canonicalWithPayload returns the canonical bytes of a fixed platform-scoped
// envelope carrying payload, and the bytes it expects for a canonical payload
// want.
func canonicalWithPayload(t *testing.T, payload json.RawMessage, want string) (got, wantAll string) {
	t.Helper()
	env := Envelope{
		ID: "evt-1", Type: "policy_updated", Scope: "platform", KeyID: "kid-1",
		IssuedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), Payload: payload,
	}
	b, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("CanonicalBytes(%s): %v", payload, err)
	}
	return string(b), `{"id":"evt-1","issued_at":"2025-01-15T10:30:00.000000000Z","key_id":"kid-1","payload":` + want +
		`,"scope":{"id":"00000000-0000-0000-0000-000000000000","kind":"platform"},"type":"policy_updated"}`
}

// TestCanonicalBytes_PayloadNormalisation pins the contract's payload rules:
// keys sorted at every depth, arrays in order, numbers normalised, and strings
// written as encoding/json writes them with HTML escaping off.
func TestCanonicalBytes_PayloadNormalisation(t *testing.T) {
	// The escapes are assembled so the source holds no literal separator.
	escaped := func(hex4 string) string { return `"` + "\\" + "u" + hex4 + `"` }
	tests := []struct {
		name, payload, want string
	}{
		{"keys sorted at every depth", `{"b":1, "a":{"d":[3,1],"c":"x"}}`, `{"a":{"c":"x","d":[3,1]},"b":1}`},
		{"trailing zero dropped", `1.50`, `1.5`},
		{"integral float", `1.0`, `1`},
		{"exponent expanded", `1e3`, `1000`},
		{"small float", `0.00001`, `1e-05`},
		{"large float", `1e21`, `1e+21`},
		{"negative integer", `-7`, `-7`},
		{"uint64 maximum", `18446744073709551615`, `18446744073709551615`},
		{"html characters stay raw", `"<a&b>"`, `"<a&b>"`},
		{"U+2028 escaped", escaped("2028"), escaped("2028")},
		{"control character escaped", escaped("0001"), escaped("0001")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, want := canonicalWithPayload(t, json.RawMessage(tt.payload), tt.want)
			if got != want {
				t.Errorf("CanonicalBytes =\n  %s\nwant\n  %s", got, want)
			}
		})
	}
}

// TestCanonicalBytes_EmptyPayloads pins that an absent or empty payload is
// null, and that empty JSON values stay what they are.
func TestCanonicalBytes_EmptyPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload json.RawMessage
		want    string
	}{
		{"nil", nil, `null`},
		{"zero length", json.RawMessage{}, `null`},
		{"empty object", json.RawMessage(`{}`), `{}`},
		{"empty array", json.RawMessage(`[]`), `[]`},
		{"empty string", json.RawMessage(`""`), `""`},
		{"null literal", json.RawMessage(`null`), `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, want := canonicalWithPayload(t, tt.payload, tt.want)
			if got != want {
				t.Errorf("CanonicalBytes =\n  %s\nwant\n  %s", got, want)
			}
		})
	}
}

// TestCanonicalBytes_IssuedAt pins the canonical instant: UTC with exactly nine
// fractional digits, the zero time included.
func TestCanonicalBytes_IssuedAt(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
		want string
	}{
		{"offset converted to UTC", time.Date(2026, 5, 27, 12, 0, 0, 0, time.FixedZone("", 2*60*60)), "2026-05-27T10:00:00.000000000Z"},
		{"fraction padded", time.Date(2026, 5, 27, 10, 0, 0, 500*int(time.Millisecond), time.UTC), "2026-05-27T10:00:00.500000000Z"},
		{"zero time", time.Time{}, "0001-01-01T00:00:00.000000000Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalBytes(Envelope{ID: "evt-1", Type: "policy_updated", Scope: "platform", IssuedAt: tt.at})
			if err != nil {
				t.Fatalf("CanonicalBytes: %v", err)
			}
			if want := `"issued_at":"` + tt.want + `"`; !strings.Contains(string(got), want) {
				t.Errorf("CanonicalBytes = %s, want it to carry %s", got, want)
			}
		})
	}
}

// TestCanonicalBytes_Scope pins the two scopes the contract defines and the
// error for anything else.
func TestCanonicalBytes_Scope(t *testing.T) {
	for _, tt := range []struct{ scope, want string }{
		{"platform", `{"id":"00000000-0000-0000-0000-000000000000","kind":"platform"}`},
		{testDomainScope, `{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0a1","kind":"domain"}`},
	} {
		got, err := CanonicalBytes(Envelope{ID: "evt-1", Type: "policy_updated", Scope: tt.scope})
		if err != nil {
			t.Fatalf("CanonicalBytes(scope %q): %v", tt.scope, err)
		}
		if want := `"scope":` + tt.want + `,`; !strings.Contains(string(got), want) {
			t.Errorf("CanonicalBytes(scope %q) = %s, want it to carry %s", tt.scope, got, want)
		}
	}

	for _, scope := range []string{
		"",
		"node",
		"domain:",
		"platform:x",
		"domain:0190A8B8-A0C0-7A0A-8A0A-A0A0A0A0A0A1",
		"domain:0190a8b8a0c07a0a8a0aa0a0a0a0a0a1",
	} {
		_, err := CanonicalBytes(Envelope{ID: "evt-1", Type: "policy_updated", Scope: scope})
		if err == nil || !strings.HasPrefix(err.Error(), "api: envelope: canonical scope") {
			t.Errorf("CanonicalBytes(scope %q) error = %v, want prefix %q", scope, err, "api: envelope: canonical scope")
		}
	}
}

// TestCanonicalBytes_PayloadErrors pins the errors a payload the canonical form
// cannot carry produces, and that SignedMessage returns each unchanged.
func TestCanonicalBytes_PayloadErrors(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		check   func(error) bool
		want    string
	}{
		{"truncated", `{"a":`, func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }, "errors.Is io.ErrUnexpectedEOF"},
		{"two values", `null 1`, func(err error) bool {
			return err.Error() == "api: envelope: canonical payload: more than one JSON value"
		}, "api: envelope: canonical payload: more than one JSON value"},
		{"float out of range", `1e400`, func(err error) bool { return errors.Is(err, strconv.ErrRange) }, "errors.Is strconv.ErrRange"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := Envelope{ID: "evt-1", Type: "policy_updated", Scope: "platform", Payload: json.RawMessage(tt.payload)}
			_, err := CanonicalBytes(env)
			if err == nil || !tt.check(err) {
				t.Fatalf("CanonicalBytes error = %v, want %s", err, tt.want)
			}
			_, msgErr := SignedMessage(env)
			if msgErr == nil || msgErr.Error() != err.Error() || !tt.check(msgErr) {
				t.Errorf("SignedMessage error = %v, want CanonicalBytes' %v unchanged", msgErr, err)
			}
		})
	}
}

func TestCanonicalBytes_NilPayload(t *testing.T) {
	env := Envelope{
		ID:       "evt-nil",
		Type:     "policy_updated",
		Scope:    "platform",
		IssuedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Payload:  nil,
	}

	got, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	want := `{"id":"evt-nil","issued_at":"2025-01-15T10:30:00.000000000Z","key_id":"","payload":null,"scope":{"id":"00000000-0000-0000-0000-000000000000","kind":"platform"},"type":"policy_updated"}`
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
		Type:      "node_state_updated",
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

// TestEventTypeConstants locks the wire string of every event-type constant so
// a rename breaks a test. The two tiers mirror the taxonomy in envelope.go:
// contract types and the documented-coming family.
func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		// Contract types.
		{"EventNodeStateUpdated", EventNodeStateUpdated, "node_state_updated"},
		{"EventPolicyUpdated", EventPolicyUpdated, "policy_updated"},
		{"EventBridgeConfigUpdated", EventBridgeConfigUpdated, "bridge_config_updated"},
		{"EventActionRequest", EventActionRequest, "action_request"},
		{"EventSessionSetup", EventSessionSetup, "session_setup"},
		{"EventNodeSecretsUpdated", EventNodeSecretsUpdated, "node_secrets_updated"},

		// Documented-coming family.
		{"EventPeerRegistered", EventPeerRegistered, "peer_registered"},
		{"EventPeerPSKAssigned", EventPeerPSKAssigned, "peer_psk_assigned"},
		{"EventPeerDeregistered", EventPeerDeregistered, "peer_deregistered"},
		{"EventPeerEndpointChanged", EventPeerEndpointChanged, "peer_endpoint_changed"},
		{"EventRotateKeys", EventRotateKeys, "rotate_keys"},
		{"EventPeerKeyRotated", EventPeerKeyRotated, "peer_key_rotated"},
		{"EventSigningKeyRotated", EventSigningKeyRotated, "signing_key_rotated"},
		{"EventSessionRevoked", EventSessionRevoked, "session_revoked"},
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
