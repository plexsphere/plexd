package wireguard

import (
	"encoding/base64"
	"fmt"

	"github.com/plexsphere/plexd/internal/api"
)

// WGController abstracts OS-level WireGuard operations for testability.
type WGController interface {
	CreateInterface(name string, privateKey []byte, listenPort int) error
	// DeleteInterface deletes the named WireGuard interface.
	// Implementations must be idempotent: deleting a non-existent interface must return nil.
	DeleteInterface(name string) error
	ConfigureAddress(name string, address string) error
	SetInterfaceUp(name string) error
	SetMTU(name string, mtu int) error
	AddPeer(iface string, cfg PeerConfig) error
	RemovePeer(iface string, publicKey []byte) error
}

// PeerConfig holds the WireGuard-native configuration for a single peer.
type PeerConfig struct {
	PublicKey           []byte
	Endpoint            string
	AllowedIPs          []string
	PSK                 []byte // nil if no PSK
	PersistentKeepalive int
}

// PeerConfigFromAPI translates an api.Peer to a WireGuard PeerConfig.
// PublicKey and PSK are decoded from base64; an empty PSK is allowed.
func PeerConfigFromAPI(peer api.Peer) (PeerConfig, error) {
	pubKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return PeerConfig{}, fmt.Errorf("wireguard: decode public key: %w", err)
	}

	var psk []byte
	if peer.PSK != "" {
		psk, err = base64.StdEncoding.DecodeString(peer.PSK)
		if err != nil {
			return PeerConfig{}, fmt.Errorf("wireguard: decode psk: %w", err)
		}
	}

	return PeerConfig{
		PublicKey:           pubKey,
		Endpoint:            peer.Endpoint,
		AllowedIPs:          peer.AllowedIPs,
		PSK:                 psk,
		PersistentKeepalive: 0,
	}, nil
}
