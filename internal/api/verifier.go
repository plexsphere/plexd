package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// DefaultStalenessWindow is the maximum age of an event before it is considered stale.
const DefaultStalenessWindow = 5 * time.Minute

// nonceTTL is the duration for which a nonce is remembered.
const nonceTTL = 5 * time.Minute

// nonceCleanupInterval is how often the nonce store runs cleanup.
const nonceCleanupInterval = 60 * time.Second

// ---------------------------------------------------------------------------
// NonceStore
// ---------------------------------------------------------------------------

// NonceStore tracks recently seen nonces to prevent replay attacks.
type NonceStore struct {
	mu          sync.Mutex
	seen        map[string]time.Time
	lastCleanup time.Time
}

// NewNonceStore returns an initialised NonceStore.
func NewNonceStore() *NonceStore {
	return &NonceStore{
		seen:        make(map[string]time.Time),
		lastCleanup: time.Now(),
	}
}

// Add records a nonce. It returns an error if the nonce has already been seen.
func (s *NonceStore) Add(nonce string, issuedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.lastCleanup) >= nonceCleanupInterval {
		s.cleanup()
	}

	if _, ok := s.seen[nonce]; ok {
		return fmt.Errorf("api: verifier: duplicate nonce")
	}
	s.seen[nonce] = issuedAt
	return nil
}

// cleanup removes expired nonces. Must be called with mu held.
func (s *NonceStore) cleanup() {
	cutoff := time.Now().Add(-nonceTTL)
	for k, v := range s.seen {
		if v.Before(cutoff) {
			delete(s.seen, k)
		}
	}
	s.lastCleanup = time.Now()
}

// ---------------------------------------------------------------------------
// Ed25519Verifier
// ---------------------------------------------------------------------------

// Ed25519Verifier verifies SignedEnvelope signatures using Ed25519 keys.
// It supports key rotation by holding both a current and an optional previous key.
type Ed25519Verifier struct {
	mu                sync.RWMutex
	currentKey        ed25519.PublicKey
	previousKey       ed25519.PublicKey
	transitionExpires time.Time

	nonces *NonceStore
}

// NewEd25519Verifier returns a new verifier using the given public key.
func NewEd25519Verifier(currentKey ed25519.PublicKey) *Ed25519Verifier {
	return &Ed25519Verifier{
		currentKey: currentKey,
		nonces:     NewNonceStore(),
	}
}

// SetKeys updates the verifier with a new current key, an optional previous key,
// and a deadline after which the previous key is no longer accepted.
func (v *Ed25519Verifier) SetKeys(current, previous ed25519.PublicKey, transitionExpires time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.currentKey = current
	v.previousKey = previous
	v.transitionExpires = transitionExpires
}

// canonicalEnvelope is the deterministic representation used for signature verification.
type canonicalEnvelope struct {
	EventType string          `json:"event_type"`
	EventID   string          `json:"event_id"`
	IssuedAt  time.Time       `json:"issued_at"`
	Nonce     string          `json:"nonce"`
	Payload   json.RawMessage `json:"payload"`
}

// Verify checks the signature and freshness of a SignedEnvelope.
// The nonce is recorded only after signature verification succeeds to prevent
// nonce exhaustion attacks via forged envelopes.
func (v *Ed25519Verifier) Verify(_ context.Context, envelope SignedEnvelope) error {
	if envelope.Signature == "" {
		return fmt.Errorf("api: verifier: missing signature")
	}
	if envelope.Nonce == "" {
		return fmt.Errorf("api: verifier: missing nonce")
	}
	if envelope.IssuedAt.IsZero() {
		return fmt.Errorf("api: verifier: missing issued_at")
	}
	if time.Since(envelope.IssuedAt) > DefaultStalenessWindow {
		return fmt.Errorf("api: verifier: event is stale")
	}
	if envelope.IssuedAt.After(time.Now().Add(DefaultStalenessWindow)) {
		return fmt.Errorf("api: verifier: event timestamp is in the future")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("api: verifier: signature verification failed")
	}

	canonical, err := json.Marshal(canonicalEnvelope{
		EventType: envelope.EventType,
		EventID:   envelope.EventID,
		IssuedAt:  envelope.IssuedAt,
		Nonce:     envelope.Nonce,
		Payload:   envelope.Payload,
	})
	if err != nil {
		return fmt.Errorf("api: verifier: signature verification failed")
	}

	v.mu.RLock()
	currentKey := v.currentKey
	previousKey := v.previousKey
	transitionExpires := v.transitionExpires
	v.mu.RUnlock()

	verified := ed25519.Verify(currentKey, canonical, sigBytes)
	if !verified && len(previousKey) > 0 && time.Now().Before(transitionExpires) {
		verified = ed25519.Verify(previousKey, canonical, sigBytes)
	}
	if !verified {
		return fmt.Errorf("api: verifier: signature verification failed")
	}

	// Record nonce only after successful signature verification.
	return v.nonces.Add(envelope.Nonce, envelope.IssuedAt)
}
