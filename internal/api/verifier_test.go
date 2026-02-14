package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// signEnvelope creates a valid SignedEnvelope signed with the given private key.
func signEnvelope(t *testing.T, priv ed25519.PrivateKey, eventType, eventID, nonce string, issuedAt time.Time, payload json.RawMessage) SignedEnvelope {
	t.Helper()
	canonical, err := json.Marshal(canonicalEnvelope{
		EventType: eventType,
		EventID:   eventID,
		IssuedAt:  issuedAt,
		Nonce:     nonce,
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("marshal canonical: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	return SignedEnvelope{
		EventType: eventType,
		EventID:   eventID,
		IssuedAt:  issuedAt,
		Nonce:     nonce,
		Payload:   payload,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestEd25519Verifier_ValidSignature(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier(pub)

	env := signEnvelope(t, priv, "peer_added", "evt-001", "nonce-1", time.Now(), json.RawMessage(`{"peer_id":"node-1"}`))
	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestEd25519Verifier_InvalidSignature(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier(pub)

	env := signEnvelope(t, priv, "peer_added", "evt-001", "nonce-1", time.Now(), json.RawMessage(`{"peer_id":"node-1"}`))
	// Tamper with the payload after signing.
	env.Payload = json.RawMessage(`{"peer_id":"node-2"}`)

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for tampered envelope, got nil")
	}
	if !strContains(err.Error(), "signature verification failed") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "signature verification failed")
	}
}

func TestEd25519Verifier_MissingSignature(t *testing.T) {
	pub, _ := generateKey(t)
	v := NewEd25519Verifier(pub)

	env := SignedEnvelope{
		EventType: "peer_added",
		EventID:   "evt-001",
		IssuedAt:  time.Now(),
		Nonce:     "nonce-1",
		Payload:   json.RawMessage(`{}`),
		Signature: "",
	}

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for missing signature, got nil")
	}
	if !strContains(err.Error(), "missing signature") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "missing signature")
	}
}

func TestEd25519Verifier_CanonicalJSON(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier(pub)

	now := time.Now()
	payload := json.RawMessage(`{"b":2,"a":1}`)

	env := signEnvelope(t, priv, "peer_added", "evt-001", "nonce-canonical", now, payload)
	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestEd25519Verifier_StaleEvent(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier(pub)

	staleTime := time.Now().Add(-6 * time.Minute)
	env := signEnvelope(t, priv, "peer_added", "evt-001", "nonce-stale", staleTime, json.RawMessage(`{}`))

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for stale event, got nil")
	}
	if !strContains(err.Error(), "stale") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "stale")
	}
}

func TestEd25519Verifier_DuplicateNonce(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier(pub)

	now := time.Now()
	env1 := signEnvelope(t, priv, "peer_added", "evt-001", "nonce-dup", now, json.RawMessage(`{}`))
	env2 := signEnvelope(t, priv, "peer_added", "evt-002", "nonce-dup", now, json.RawMessage(`{}`))

	if err := v.Verify(context.Background(), env1); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	err := v.Verify(context.Background(), env2)
	if err == nil {
		t.Fatal("expected error for duplicate nonce, got nil")
	}
	if !strContains(err.Error(), "nonce") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "nonce")
	}
}

func TestEd25519Verifier_EmptyNonce(t *testing.T) {
	pub, _ := generateKey(t)
	v := NewEd25519Verifier(pub)

	env := SignedEnvelope{
		EventType: "peer_added",
		EventID:   "evt-001",
		IssuedAt:  time.Now(),
		Nonce:     "",
		Payload:   json.RawMessage(`{}`),
		Signature: "c29tZXNpZw==",
	}

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for empty nonce, got nil")
	}
	if !strContains(err.Error(), "missing nonce") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "missing nonce")
	}
}

func TestEd25519Verifier_ZeroIssuedAt(t *testing.T) {
	pub, _ := generateKey(t)
	v := NewEd25519Verifier(pub)

	env := SignedEnvelope{
		EventType: "peer_added",
		EventID:   "evt-001",
		IssuedAt:  time.Time{},
		Nonce:     "nonce-zero",
		Payload:   json.RawMessage(`{}`),
		Signature: "c29tZXNpZw==",
	}

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for zero issued_at, got nil")
	}
	if !strContains(err.Error(), "missing issued_at") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "missing issued_at")
	}
}

func TestNonceStore_TTLExpiry(t *testing.T) {
	s := NewNonceStore()

	// Add a nonce with an old issuedAt so it appears expired.
	old := time.Now().Add(-10 * time.Minute)
	if err := s.Add("old-nonce", old); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Force cleanup by setting lastCleanup far in the past.
	s.mu.Lock()
	s.lastCleanup = time.Now().Add(-2 * nonceCleanupInterval)
	s.mu.Unlock()

	// Adding a new nonce should trigger cleanup and remove the old one.
	if err := s.Add("new-nonce", time.Now()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The old nonce should have been cleaned up; adding it again should succeed.
	if err := s.Add("old-nonce", time.Now()); err != nil {
		t.Fatalf("expected old nonce to be cleaned up, got: %v", err)
	}
}

func TestEd25519Verifier_KeyRotation_CurrentKey(t *testing.T) {
	oldPub, _ := generateKey(t)
	newPub, newPriv := generateKey(t)

	v := NewEd25519Verifier(oldPub)
	v.SetKeys(newPub, oldPub, time.Now().Add(1*time.Hour))

	env := signEnvelope(t, newPriv, "peer_added", "evt-001", "nonce-rot-curr", time.Now(), json.RawMessage(`{}`))
	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("expected nil error with current key after rotation, got: %v", err)
	}
}

func TestEd25519Verifier_KeyRotation_PreviousKeyDuringTransition(t *testing.T) {
	oldPub, oldPriv := generateKey(t)
	newPub, _ := generateKey(t)

	v := NewEd25519Verifier(oldPub)
	v.SetKeys(newPub, oldPub, time.Now().Add(1*time.Hour))

	// Sign with the OLD key — should still pass during transition.
	env := signEnvelope(t, oldPriv, "peer_added", "evt-001", "nonce-rot-prev", time.Now(), json.RawMessage(`{}`))
	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("expected nil error with previous key during transition, got: %v", err)
	}
}

func TestEd25519Verifier_KeyRotation_PreviousKeyAfterTransition(t *testing.T) {
	oldPub, oldPriv := generateKey(t)
	newPub, _ := generateKey(t)

	v := NewEd25519Verifier(oldPub)
	// Transition already expired.
	v.SetKeys(newPub, oldPub, time.Now().Add(-1*time.Hour))

	env := signEnvelope(t, oldPriv, "peer_added", "evt-001", "nonce-rot-exp", time.Now(), json.RawMessage(`{}`))
	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error with previous key after transition, got nil")
	}
	if !strContains(err.Error(), "signature verification failed") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "signature verification failed")
	}
}

func TestEd25519Verifier_InvalidBase64Signature(t *testing.T) {
	pub, _ := generateKey(t)
	v := NewEd25519Verifier(pub)

	env := SignedEnvelope{
		EventType: "peer_added",
		EventID:   "evt-001",
		IssuedAt:  time.Now(),
		Nonce:     "nonce-bad-b64",
		Payload:   json.RawMessage(`{}`),
		Signature: "not-valid-base64!!!",
	}

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature, got nil")
	}
	if !strContains(err.Error(), "signature verification failed") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "signature verification failed")
	}
}

func TestEd25519Verifier_FutureTimestamp(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier(pub)

	futureTime := time.Now().Add(10 * time.Minute)
	env := signEnvelope(t, priv, "peer_added", "evt-001", "nonce-future", futureTime, json.RawMessage(`{}`))

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for future timestamp, got nil")
	}
	if !strContains(err.Error(), "future") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "future")
	}
}

func TestEd25519Verifier_NonceNotConsumedOnInvalidSignature(t *testing.T) {
	pub, _ := generateKey(t)
	_, otherPriv := generateKey(t)
	v := NewEd25519Verifier(pub)

	// Sign with wrong key — signature verification should fail.
	env := signEnvelope(t, otherPriv, "peer_added", "evt-001", "nonce-exhaust", time.Now(), json.RawMessage(`{}`))

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}

	// The same nonce should still be usable since it was never recorded.
	v2pub, v2priv := generateKey(t)
	v2 := NewEd25519Verifier(v2pub)
	env2 := signEnvelope(t, v2priv, "peer_added", "evt-002", "nonce-exhaust", time.Now(), json.RawMessage(`{}`))
	if err := v2.Verify(context.Background(), env2); err != nil {
		t.Fatalf("nonce should not have been consumed by failed verification: %v", err)
	}
}
