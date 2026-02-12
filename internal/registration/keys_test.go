package registration

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeypair_ValidKeys(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if len(kp.PrivateKey) != 32 {
		t.Fatalf("private key length = %d, want 32", len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != 32 {
		t.Fatalf("public key length = %d, want 32", len(kp.PublicKey))
	}

	// Verify the public key matches Curve25519(privateKey, Basepoint).
	want, err := curve25519.X25519(kp.PrivateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519: %v", err)
	}
	if string(kp.PublicKey) != string(want) {
		t.Fatalf("public key does not match Curve25519(privateKey, Basepoint)")
	}
}

func TestGenerateKeypair_Base64Encoding(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	encoded := kp.EncodePublicKey()

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
	if string(decoded) != string(kp.PublicKey) {
		t.Fatalf("decoded key does not match original public key")
	}
}

func TestGenerateKeypair_Uniqueness(t *testing.T) {
	kp1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (1): %v", err)
	}
	kp2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (2): %v", err)
	}

	if string(kp1.PrivateKey) == string(kp2.PrivateKey) {
		t.Fatal("two consecutive keypairs have identical private keys")
	}
	if string(kp1.PublicKey) == string(kp2.PublicKey) {
		t.Fatal("two consecutive keypairs have identical public keys")
	}
}

func TestGenerateKeypair_Clamping(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// byte[0] bits 0,1,2 must be clear.
	if kp.PrivateKey[0]&0x07 != 0 {
		t.Fatalf("byte[0]&7 = %d, want 0", kp.PrivateKey[0]&0x07)
	}
	// byte[31] bit 7 must be clear.
	if kp.PrivateKey[31]&0x80 != 0 {
		t.Fatalf("byte[31]&128 = %d, want 0", kp.PrivateKey[31]&0x80)
	}
	// byte[31] bit 6 must be set.
	if kp.PrivateKey[31]&0x40 != 0x40 {
		t.Fatalf("byte[31]&64 = %d, want 64", kp.PrivateKey[31]&0x40)
	}
}
