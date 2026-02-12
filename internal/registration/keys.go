package registration

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Keypair holds a Curve25519 keypair for WireGuard.
type Keypair struct {
	PrivateKey []byte // 32 bytes, never logged
	PublicKey  []byte // 32 bytes
}

// GenerateKeypair generates a new Curve25519 keypair for WireGuard mesh encryption.
func GenerateKeypair() (*Keypair, error) {
	// Generate 32 random bytes for the private key.
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("registration: generate keypair: %w", err)
	}

	// Clamp the private key per Curve25519 spec.
	privateKey[0] &^= 0x07 // clear bits 0, 1, 2
	privateKey[31] &^= 0x80 // clear bit 7
	privateKey[31] |= 0x40  // set bit 6

	// Derive the public key.
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("registration: derive public key: %w", err)
	}

	return &Keypair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// EncodePublicKey returns the standard base64 encoding of the public key.
func (k *Keypair) EncodePublicKey() string {
	return base64.StdEncoding.EncodeToString(k.PublicKey)
}
