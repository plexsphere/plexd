package tunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Ed25519JWTVerifier verifies compact JWS tokens (alg=EdDSA) using an
// Ed25519 public key. It validates the signature and checks the "exp" claim
// without relying on any external JWT library.
type Ed25519JWTVerifier struct {
	publicKey ed25519.PublicKey
}

// NewEd25519JWTVerifier creates a new verifier with the given Ed25519 public key.
func NewEd25519JWTVerifier(publicKey ed25519.PublicKey) *Ed25519JWTVerifier {
	return &Ed25519JWTVerifier{publicKey: publicKey}
}

// Verify validates a compact JWS token (header.payload.signature).
// It checks the Ed25519 signature over the signing input and verifies the
// "exp" claim has not elapsed.
func (v *Ed25519JWTVerifier) Verify(token string) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return errors.New("tunnel: jwt: malformed token: expected 3 parts")
	}

	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	// Decode and validate header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("tunnel: jwt: decode header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("tunnel: jwt: parse header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return fmt.Errorf("tunnel: jwt: unsupported algorithm: %s", header.Alg)
	}

	// Decode signature.
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("tunnel: jwt: decode signature: %w", err)
	}

	// Verify Ed25519 signature over "header.payload" signing input.
	signingInput := []byte(headerB64 + "." + payloadB64)
	if !ed25519.Verify(v.publicKey, signingInput, sig) {
		return errors.New("tunnel: jwt: invalid signature")
	}

	// Decode and validate payload claims.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return fmt.Errorf("tunnel: jwt: decode payload: %w", err)
	}

	var claims struct {
		Exp *float64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("tunnel: jwt: parse payload: %w", err)
	}

	if claims.Exp != nil {
		expTime := time.Unix(int64(*claims.Exp), 0)
		if time.Now().After(expTime) {
			return errors.New("tunnel: jwt: token expired")
		}
	}

	return nil
}
