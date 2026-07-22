package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// DefaultStalenessWindow is the maximum age of an event before it is considered stale.
const DefaultStalenessWindow = 5 * time.Minute

// ---------------------------------------------------------------------------
// Ed25519Verifier
// ---------------------------------------------------------------------------

// Ed25519Verifier verifies Envelope signatures using Ed25519 keys selected by
// key id. It supports rotation by holding a current key and an optional
// previous key that stays accepted until a transition deadline.
type Ed25519Verifier struct {
	mu                sync.RWMutex
	currentKID        string
	currentKey        ed25519.PublicKey
	previousKID       string
	previousKey       ed25519.PublicKey
	transitionExpires time.Time
}

// NewEd25519Verifier returns a new verifier that accepts envelopes signed with
// the given key and carrying the given key id.
func NewEd25519Verifier(keyID string, key ed25519.PublicKey) *Ed25519Verifier {
	return &Ed25519Verifier{
		currentKID: keyID,
		currentKey: key,
	}
}

// Rotate installs a new current signing key from a signing_key_rotated event.
// The previous key is retained as a grace entry only when the rotation names a
// previous key id the verifier currently holds and a non-zero transition
// deadline; otherwise no grace entry is kept. On any error the installed keys
// are left unchanged.
func (v *Ed25519Verifier) Rotate(rot SigningKeyRotation) error {
	if rot.KeyID == "" {
		return fmt.Errorf("api: verifier: rotation missing key_id")
	}
	decoded, err := base64.StdEncoding.DecodeString(rot.PublicKey)
	if err != nil {
		return fmt.Errorf("api: verifier: rotation public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return fmt.Errorf("api: verifier: rotation public key: invalid length: got %d, want %d", len(decoded), ed25519.PublicKeySize)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	var graceKID string
	var graceKey ed25519.PublicKey
	if rot.PreviousKeyID != "" && !rot.TransitionExpires.IsZero() {
		switch rot.PreviousKeyID {
		case v.currentKID:
			graceKID, graceKey = v.currentKID, v.currentKey
		case v.previousKID:
			graceKID, graceKey = v.previousKID, v.previousKey
		}
	}

	v.currentKID = rot.KeyID
	v.currentKey = ed25519.PublicKey(decoded)
	if len(graceKey) > 0 {
		v.previousKID = graceKID
		v.previousKey = graceKey
		v.transitionExpires = rot.TransitionExpires
	} else {
		v.previousKID = ""
		v.previousKey = nil
		v.transitionExpires = time.Time{}
	}
	return nil
}

// Verify checks the freshness and Ed25519 signature of an envelope. It selects
// the verifying key by the envelope's key id, honouring the rotation grace
// window for the previous key.
func (v *Ed25519Verifier) Verify(_ context.Context, env Envelope) error {
	if env.Signature == "" {
		return fmt.Errorf("api: verifier: missing signature")
	}
	if env.IssuedAt.IsZero() {
		return fmt.Errorf("api: verifier: missing issued_at")
	}
	if time.Since(env.IssuedAt) > DefaultStalenessWindow {
		return fmt.Errorf("api: verifier: event is stale")
	}
	if env.IssuedAt.After(time.Now().Add(DefaultStalenessWindow)) {
		return fmt.Errorf("api: verifier: event timestamp is in the future")
	}

	v.mu.RLock()
	var key ed25519.PublicKey
	switch {
	case env.KeyID != "" && env.KeyID == v.currentKID:
		key = v.currentKey
	case env.KeyID != "" && env.KeyID == v.previousKID && time.Now().Before(v.transitionExpires):
		key = v.previousKey
	}
	v.mu.RUnlock()

	if len(key) == 0 {
		return fmt.Errorf("api: verifier: unknown signing key id")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("api: verifier: signature verification failed")
	}
	canonical, err := CanonicalBytes(env)
	if err != nil {
		return fmt.Errorf("api: verifier: signature verification failed")
	}
	if !ed25519.Verify(key, canonical, sigBytes) {
		return fmt.Errorf("api: verifier: signature verification failed")
	}

	// No replay-tracking step, by design: the events contract carries no nonce,
	// so there is nothing unique to record here. Replay protection is delegated
	// to (a) the TLS transport, which keeps captured envelopes off the wire, and
	// (b) the idempotence of what a verified event triggers — every production
	// event drives an authoritative reconcile pull, and a replayed rotate_keys
	// only re-requests a rotation the control plane rejects (409) when none is
	// pending. This is a deliberate trade-off of the no-nonce contract, not an
	// oversight; see docs/reference/core/event-verification.md.
	return nil
}
