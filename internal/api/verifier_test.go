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

// signEnvelope returns an envelope signed over its canonical bytes with priv,
// carrying the given key id, issued_at and payload.
func signEnvelope(t *testing.T, priv ed25519.PrivateKey, keyID string, issuedAt time.Time, payload json.RawMessage) Envelope {
	t.Helper()
	env := Envelope{
		ID:       "evt-001",
		Type:     "policy_updated",
		KeyID:    keyID,
		IssuedAt: issuedAt,
		Payload:  payload,
	}
	canonical, err := CanonicalBytes(env)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))
	return env
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
	v := NewEd25519Verifier("kid-1", pub)

	env := signEnvelope(t, priv, "kid-1", time.Now(), json.RawMessage(`{"peer_id":"node-1"}`))
	if err := v.Verify(context.Background(), env); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestEd25519Verifier_TamperedPayload(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier("kid-1", pub)

	env := signEnvelope(t, priv, "kid-1", time.Now(), json.RawMessage(`{"peer_id":"node-1"}`))
	env.Payload = json.RawMessage(`{"peer_id":"node-2"}`)

	err := v.Verify(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for tampered envelope, got nil")
	}
	if err.Error() != "api: verifier: signature verification failed" {
		t.Errorf("error = %q, want %q", err.Error(), "api: verifier: signature verification failed")
	}
}

func TestEd25519Verifier_UnknownAndEmptyKeyID(t *testing.T) {
	pub, priv := generateKey(t)
	v := NewEd25519Verifier("kid-1", pub)

	tests := []struct {
		name  string
		keyID string
	}{
		{"unknown key id", "kid-unknown"},
		{"empty key id", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := signEnvelope(t, priv, tt.keyID, time.Now(), json.RawMessage(`{}`))
			err := v.Verify(context.Background(), env)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != "api: verifier: unknown signing key id" {
				t.Errorf("error = %q, want %q", err.Error(), "api: verifier: unknown signing key id")
			}
		})
	}
}

func TestEd25519Verifier_Rotation(t *testing.T) {
	oldPub, oldPriv := generateKey(t)
	newPub, newPriv := generateKey(t)
	newPubB64 := base64.StdEncoding.EncodeToString(newPub)

	t.Run("previous kid accepted during transition", func(t *testing.T) {
		v := NewEd25519Verifier("kid-old", oldPub)
		if err := v.Rotate(SigningKeyRotation{
			KeyID:             "kid-new",
			PublicKey:         newPubB64,
			PreviousKeyID:     "kid-old",
			TransitionExpires: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		// New key + new kid verifies.
		if err := v.Verify(context.Background(), signEnvelope(t, newPriv, "kid-new", time.Now(), json.RawMessage(`{}`))); err != nil {
			t.Errorf("new kid failed to verify: %v", err)
		}
		// Old key + old kid still verifies within the grace window.
		if err := v.Verify(context.Background(), signEnvelope(t, oldPriv, "kid-old", time.Now(), json.RawMessage(`{}`))); err != nil {
			t.Errorf("previous kid failed to verify during transition: %v", err)
		}
	})

	t.Run("previous kid rejected after transition", func(t *testing.T) {
		v := NewEd25519Verifier("kid-old", oldPub)
		// Inject an already-expired transition deadline.
		if err := v.Rotate(SigningKeyRotation{
			KeyID:             "kid-new",
			PublicKey:         newPubB64,
			PreviousKeyID:     "kid-old",
			TransitionExpires: time.Now().Add(-time.Hour),
		}); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		err := v.Verify(context.Background(), signEnvelope(t, oldPriv, "kid-old", time.Now(), json.RawMessage(`{}`)))
		if err == nil {
			t.Fatal("expected error for expired previous kid, got nil")
		}
		if err.Error() != "api: verifier: unknown signing key id" {
			t.Errorf("error = %q, want %q", err.Error(), "api: verifier: unknown signing key id")
		}
	})

	t.Run("empty previous key id installs no grace", func(t *testing.T) {
		v := NewEd25519Verifier("kid-old", oldPub)
		if err := v.Rotate(SigningKeyRotation{
			KeyID:             "kid-new",
			PublicKey:         newPubB64,
			TransitionExpires: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		err := v.Verify(context.Background(), signEnvelope(t, oldPriv, "kid-old", time.Now(), json.RawMessage(`{}`)))
		if err == nil || err.Error() != "api: verifier: unknown signing key id" {
			t.Errorf("error = %v, want %q", err, "api: verifier: unknown signing key id")
		}
	})

	t.Run("zero transition expires installs no grace", func(t *testing.T) {
		v := NewEd25519Verifier("kid-old", oldPub)
		if err := v.Rotate(SigningKeyRotation{
			KeyID:         "kid-new",
			PublicKey:     newPubB64,
			PreviousKeyID: "kid-old",
		}); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		err := v.Verify(context.Background(), signEnvelope(t, oldPriv, "kid-old", time.Now(), json.RawMessage(`{}`)))
		if err == nil || err.Error() != "api: verifier: unknown signing key id" {
			t.Errorf("error = %v, want %q", err, "api: verifier: unknown signing key id")
		}
	})
}

func TestEd25519Verifier_RotateErrors(t *testing.T) {
	oldPub, oldPriv := generateKey(t)
	newPub, _ := generateKey(t)

	tests := []struct {
		name    string
		rot     SigningKeyRotation
		wantErr string // exact when set
		prefix  string // prefix when set
	}{
		{
			name:    "empty key id",
			rot:     SigningKeyRotation{PublicKey: base64.StdEncoding.EncodeToString(newPub)},
			wantErr: "api: verifier: rotation missing key_id",
		},
		{
			name:   "non-base64 public key",
			rot:    SigningKeyRotation{KeyID: "kid-new", PublicKey: "not-base64!!!"},
			prefix: "api: verifier: rotation public key: ",
		},
		{
			name:   "wrong length public key",
			rot:    SigningKeyRotation{KeyID: "kid-new", PublicKey: base64.StdEncoding.EncodeToString([]byte("short"))},
			prefix: "api: verifier: rotation public key: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewEd25519Verifier("kid-old", oldPub)
			err := v.Rotate(tt.rot)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
			if tt.prefix != "" && !strContains(err.Error(), tt.prefix) {
				t.Errorf("error = %q, want prefix %q", err.Error(), tt.prefix)
			}
			// Keys unchanged: an envelope under the old kid still verifies.
			if err := v.Verify(context.Background(), signEnvelope(t, oldPriv, "kid-old", time.Now(), json.RawMessage(`{}`))); err != nil {
				t.Errorf("old kid failed to verify after rejected rotation: %v", err)
			}
		})
	}
}

func TestEd25519Verifier_FreshnessAndSignatureErrors(t *testing.T) {
	pub, priv := generateKey(t)

	tests := []struct {
		name    string
		env     Envelope
		wantErr string
	}{
		{
			name: "missing signature",
			env: Envelope{
				ID: "evt-1", Type: "policy_updated", KeyID: "kid-1",
				IssuedAt: time.Now(), Payload: json.RawMessage(`{}`), Signature: "",
			},
			wantErr: "api: verifier: missing signature",
		},
		{
			name: "zero issued_at",
			env: Envelope{
				ID: "evt-1", Type: "policy_updated", KeyID: "kid-1",
				IssuedAt: time.Time{}, Payload: json.RawMessage(`{}`), Signature: "c29tZXNpZw==",
			},
			wantErr: "api: verifier: missing issued_at",
		},
		{
			name: "stale issued_at",
			env: Envelope{
				ID: "evt-1", Type: "policy_updated", KeyID: "kid-1",
				IssuedAt: time.Now().Add(-6 * time.Minute), Payload: json.RawMessage(`{}`), Signature: "c29tZXNpZw==",
			},
			wantErr: "api: verifier: event is stale",
		},
		{
			name: "future issued_at",
			env: Envelope{
				ID: "evt-1", Type: "policy_updated", KeyID: "kid-1",
				IssuedAt: time.Now().Add(10 * time.Minute), Payload: json.RawMessage(`{}`), Signature: "c29tZXNpZw==",
			},
			wantErr: "api: verifier: event timestamp is in the future",
		},
		{
			name: "undecodable base64 signature",
			env: Envelope{
				ID: "evt-1", Type: "policy_updated", KeyID: "kid-1",
				IssuedAt: time.Now(), Payload: json.RawMessage(`{}`), Signature: "not-valid-base64!!!",
			},
			wantErr: "api: verifier: signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewEd25519Verifier("kid-1", pub)
			err := v.Verify(context.Background(), tt.env)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}

	// Sanity: a genuinely signed envelope under the same kid verifies, proving the
	// cases above fail on their specific defect rather than a mis-seeded key.
	if err := NewEd25519Verifier("kid-1", pub).Verify(context.Background(), signEnvelope(t, priv, "kid-1", time.Now(), json.RawMessage(`{}`))); err != nil {
		t.Fatalf("valid envelope should verify: %v", err)
	}
}
