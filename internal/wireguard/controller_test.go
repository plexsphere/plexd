package wireguard

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func TestPeerConfigFromAPI_AllFields(t *testing.T) {
	pubKey := make([]byte, 32)
	pubKey[0] = 0xAA
	psk := make([]byte, 32)
	psk[0] = 0xBB

	peer := api.Peer{
		ID:         "node-1",
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
		MeshIP:     "10.0.0.2/32",
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"10.0.0.2/32", "10.0.1.0/24"},
		PSK:        base64.StdEncoding.EncodeToString(psk),
	}

	cfg, err := PeerConfigFromAPI(peer)
	if err != nil {
		t.Fatalf("PeerConfigFromAPI: %v", err)
	}

	if !bytes.Equal(cfg.PublicKey, pubKey) {
		t.Fatalf("PublicKey = %x, want %x", cfg.PublicKey, pubKey)
	}
	if cfg.Endpoint != "203.0.113.1:51820" {
		t.Fatalf("Endpoint = %q, want %q", cfg.Endpoint, "203.0.113.1:51820")
	}
	if len(cfg.AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs length = %d, want 2", len(cfg.AllowedIPs))
	}
	if cfg.AllowedIPs[0] != "10.0.0.2/32" || cfg.AllowedIPs[1] != "10.0.1.0/24" {
		t.Fatalf("AllowedIPs = %v, want [10.0.0.2/32 10.0.1.0/24]", cfg.AllowedIPs)
	}
	if !bytes.Equal(cfg.PSK, psk) {
		t.Fatalf("PSK = %x, want %x", cfg.PSK, psk)
	}
	if cfg.PersistentKeepalive != 0 {
		t.Fatalf("PersistentKeepalive = %d, want 0", cfg.PersistentKeepalive)
	}
}

func TestPeerConfigFromAPI_NoEndpoint(t *testing.T) {
	pubKey := make([]byte, 32)

	peer := api.Peer{
		ID:         "node-2",
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
		MeshIP:     "10.0.0.3/32",
		Endpoint:   "",
		AllowedIPs: []string{"10.0.0.3/32"},
	}

	cfg, err := PeerConfigFromAPI(peer)
	if err != nil {
		t.Fatalf("PeerConfigFromAPI: %v", err)
	}

	if cfg.Endpoint != "" {
		t.Fatalf("Endpoint = %q, want empty string", cfg.Endpoint)
	}
}

func TestPeerConfigFromAPI_NoPSK(t *testing.T) {
	pubKey := make([]byte, 32)

	peer := api.Peer{
		ID:         "node-3",
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
		MeshIP:     "10.0.0.4/32",
		Endpoint:   "203.0.113.2:51820",
		AllowedIPs: []string{"10.0.0.4/32"},
		PSK:        "",
	}

	cfg, err := PeerConfigFromAPI(peer)
	if err != nil {
		t.Fatalf("PeerConfigFromAPI: %v", err)
	}

	if cfg.PSK != nil {
		t.Fatalf("PSK = %x, want nil", cfg.PSK)
	}
}

func TestPeerConfigFromAPI_InvalidPublicKey(t *testing.T) {
	peer := api.Peer{
		ID:         "node-4",
		PublicKey:  "not-valid-base64!!!",
		MeshIP:     "10.0.0.5/32",
		AllowedIPs: []string{"10.0.0.5/32"},
	}

	_, err := PeerConfigFromAPI(peer)
	if err == nil {
		t.Fatal("PeerConfigFromAPI: expected error for invalid public key, got nil")
	}
}

func TestPeerConfigFromAPI_InvalidPSK(t *testing.T) {
	pubKey := make([]byte, 32)

	peer := api.Peer{
		ID:         "node-5",
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
		MeshIP:     "10.0.0.6/32",
		AllowedIPs: []string{"10.0.0.6/32"},
		PSK:        "not-valid-base64!!!",
	}

	_, err := PeerConfigFromAPI(peer)
	if err == nil {
		t.Fatal("PeerConfigFromAPI: expected error for invalid PSK, got nil")
	}
}
