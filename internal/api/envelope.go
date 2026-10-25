package api

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
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

	// EventNodeSecretsUpdated carries the node's full secret inventory, but the
	// inventory also rides the secrets block of the state pull, which is
	// authoritative: the payload is treated as opaque and the event triggers a
	// reconcile like the rest of the tier, so an event that arrives late can
	// never roll the node API's secret index back.
	EventNodeSecretsUpdated = "node_secrets_updated"

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

// canonicalTimeLayout is how issued_at appears in the canonical bytes: UTC with
// exactly nine fractional digits, whatever the wire carried.
const canonicalTimeLayout = "2006-01-02T15:04:05.000000000Z"

// platformScopeID is the id the canonical bytes give the platform scope, which
// has no id of its own on the wire.
const platformScopeID = "00000000-0000-0000-0000-000000000000"

// CanonicalBytes returns the bytes an envelope's signature covers, as the
// "Signed event envelope" section of plexsphere's agent contract
// (docs/reference/api/plexd-agent-contract.md) defines them: one JSON object
// with exactly the members id, issued_at, key_id, payload, scope and type in
// that order, no whitespace, and never the signature. issued_at is UTC with
// nine fractional digits, scope is an object rather than the wire string, and
// the payload is decoded and written again with sorted keys and normalised
// numbers. An absent or empty Payload is null.
//
// The frame's data: line is not the signed message: its member order, time
// format and payload spelling are whatever the control plane's encoder wrote,
// so the bytes are rebuilt from the decoded values. This is the single
// canonical-form seam shared by the agent's verifier and the mock control
// plane, and it mirrors the control plane's own CanonicalBytes
// (internal/signing/envelope/canonical.go in plexsphere).
func CanonicalBytes(env Envelope) ([]byte, error) {
	scope, err := canonicalScope(env.Scope)
	if err != nil {
		return nil, err
	}
	payload, err := canonicalPayload(env.Payload)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(`{"id":`)
	buf.Write(encodeString(env.ID))
	buf.WriteString(`,"issued_at":`)
	buf.Write(encodeString(env.IssuedAt.UTC().Format(canonicalTimeLayout)))
	buf.WriteString(`,"key_id":`)
	buf.Write(encodeString(env.KeyID))
	buf.WriteString(`,"payload":`)
	buf.Write(payload)
	buf.WriteString(`,"scope":`)
	buf.Write(scope)
	buf.WriteString(`,"type":`)
	buf.Write(encodeString(env.Type))
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// SignedMessage returns the message an envelope's Ed25519 signature is made
// over: the 64-byte SHA-512 digest of its CanonicalBytes. The control plane
// signs the digest, not the canonical bytes themselves, so verifying the bytes
// directly fails for every envelope.
func SignedMessage(env Envelope) ([]byte, error) {
	canonical, err := CanonicalBytes(env)
	if err != nil {
		return nil, err
	}
	sum := sha512.Sum512(canonical)
	return sum[:], nil
}

// canonicalScope renders the wire scope as the canonical object
// {"id":…,"kind":…}. "platform" carries the zero UUID; "domain:<uuid>" carries
// its UUID, which must be in the lowercase hyphenated form the control plane
// writes. The zero UUID needs no special case under domain: the control plane
// never signs that scope, so no signature over it exists.
func canonicalScope(scope string) ([]byte, error) {
	kind, id := "platform", platformScopeID
	if scope != "platform" {
		rest, ok := strings.CutPrefix(scope, "domain:")
		if !ok || !isCanonicalUUID(rest) {
			return nil, fmt.Errorf("api: envelope: canonical scope %q: want \"platform\" or \"domain:<uuid>\"", scope)
		}
		kind, id = "domain", rest
	}
	// Both values are plain hex, hyphens and letters, so they need no escaping.
	return []byte(`{"id":"` + id + `","kind":"` + kind + `"}`), nil
}

// isCanonicalUUID reports whether s is 36 characters of lowercase hex in
// 8-4-4-4-12 groups.
func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// canonicalPayload decodes the payload and writes it again in canonical form.
// Decoding with UseNumber keeps each number's literal so canonicalNumber can
// normalise it, and a second JSON value after the first is refused rather than
// silently dropped.
func canonicalPayload(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("null"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("api: envelope: canonical payload: %w", err)
	}
	if dec.More() {
		return nil, errors.New("api: envelope: canonical payload: more than one JSON value")
	}
	var buf bytes.Buffer
	if err := canonicalValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// canonicalValue writes one decoded JSON value: object members sorted by key
// at every depth (byte order, which is UTF-8 order), array elements in order.
// The cases are exactly what encoding/json produces with UseNumber.
func canonicalValue(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case string:
		buf.Write(encodeString(t))
	case json.Number:
		n, err := canonicalNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(n)
	case map[string]any:
		buf.WriteByte('{')
		for i, k := range slices.Sorted(maps.Keys(t)) {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(encodeString(k))
			buf.WriteByte(':')
			if err := canonicalValue(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalValue(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("api: envelope: canonical payload: unsupported JSON value %T", v)
	}
	return nil
}

// canonicalNumber normalises a number literal so numerically equal payloads
// give equal bytes: a literal that parses as a 64-bit signed or unsigned
// integer is written in plain decimal, and any other is parsed as a float64
// and written in its shortest round-trip form (1.50 is 1.5, 1e3 is 1000).
func canonicalNumber(s string) (string, error) {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return strconv.FormatInt(i, 10), nil
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		return strconv.FormatUint(u, 10), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("api: envelope: canonical payload: number %q: %w", s, err)
	}
	return strconv.FormatFloat(f, 'g', -1, 64), nil
}

// encodeString writes s as a JSON string the way encoding/json does with HTML
// escaping turned off: <, > and & stay raw, while control characters, U+2028
// and U+2029 are escaped.
func encodeString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encoding a string never fails: invalid UTF-8 becomes U+FFFD.
	_ = enc.Encode(s)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
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
