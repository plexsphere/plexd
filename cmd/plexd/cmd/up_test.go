package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func TestDecodeSigningKeys_CurrentOnly(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	logger := slog.Default()

	keys := api.SigningKeys{Current: encoded}
	current, previous, expires := decodeSigningKeys(keys, logger)

	if len(current) != ed25519.PublicKeySize {
		t.Errorf("current key length = %d, want %d", len(current), ed25519.PublicKeySize)
	}
	if len(previous) != 0 {
		t.Errorf("previous key should be nil, got len %d", len(previous))
	}
	if !expires.IsZero() {
		t.Errorf("expires should be zero, got %v", expires)
	}
}

func TestDecodeSigningKeys_WithPreviousAndExpiry(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Add(time.Hour)
	keys := api.SigningKeys{
		Current:           base64.StdEncoding.EncodeToString(pub1),
		Previous:          base64.StdEncoding.EncodeToString(pub2),
		TransitionExpires: &now,
	}
	logger := slog.Default()

	current, previous, expires := decodeSigningKeys(keys, logger)

	if len(current) != ed25519.PublicKeySize {
		t.Errorf("current key length = %d, want %d", len(current), ed25519.PublicKeySize)
	}
	if len(previous) != ed25519.PublicKeySize {
		t.Errorf("previous key length = %d, want %d", len(previous), ed25519.PublicKeySize)
	}
	if !expires.Equal(now) {
		t.Errorf("expires = %v, want %v", expires, now)
	}
}

func TestDecodeSigningKeys_InvalidBase64(t *testing.T) {
	keys := api.SigningKeys{
		Current:  "not-valid-base64!",
		Previous: "also-invalid!!",
	}
	logger := slog.Default()

	current, previous, _ := decodeSigningKeys(keys, logger)

	if len(current) != 0 {
		t.Errorf("current should be nil for invalid base64, got len %d", len(current))
	}
	if len(previous) != 0 {
		t.Errorf("previous should be nil for invalid base64, got len %d", len(previous))
	}
}

func TestDecodeSigningKeys_Empty(t *testing.T) {
	keys := api.SigningKeys{}
	logger := slog.Default()

	current, previous, expires := decodeSigningKeys(keys, logger)

	if len(current) != 0 {
		t.Errorf("current should be nil for empty keys, got len %d", len(current))
	}
	if len(previous) != 0 {
		t.Errorf("previous should be nil for empty keys, got len %d", len(previous))
	}
	if !expires.IsZero() {
		t.Errorf("expires should be zero for empty keys, got %v", expires)
	}
}
