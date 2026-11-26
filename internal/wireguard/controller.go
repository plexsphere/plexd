package wireguard

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"time"

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
	// SetPrivateKey replaces the named device's private key without touching
	// its listen port or peers.
	SetPrivateKey(name string, privateKey []byte) error
}

// OSInterfaceNamer is implemented by controllers on platforms where the kernel,
// not the configuration, names the interface. macOS is the case: WireGuard
// there runs on a utun device the kernel calls utunN, while plexd keys the
// device, its UAPI endpoint and its log lines by the configured name.
//
// Only code that hands the name back to the operating system needs this: the
// readiness check, which resolves the interface with net.InterfaceByName; the
// pf enforcer, whose rules match on the kernel name; and the route calls of
// the manager's peer routes, because route(8) takes the kernel name.
// Everything addressing the device through plexd keeps the configured name.
type OSInterfaceNamer interface {
	// OSInterfaceName returns the kernel's name for the interface created
	// under the configured name, and false when no such interface exists.
	OSInterfaceName(name string) (string, bool)
}

// PeerStat is one peer's runtime state as the device reports it.
type PeerStat struct {
	PublicKey     [32]byte
	Endpoint      netip.AddrPort // invalid when the device knows no endpoint
	LastHandshake time.Time      // zero when no handshake has completed
	RxBytes       uint64
	TxBytes       uint64
	// AllowedIPs are the peer's allowed IPs in the device's order, nil when
	// it has none.
	AllowedIPs []netip.Prefix
}

// PeerStatsReader is implemented by controllers that can read peer runtime state.
//
// It is optional, like OSInterfaceNamer, rather than a WGController method:
// only the handshake report and the tunnel metrics read the device, and adding
// the method to WGController would force it onto every test double that
// implements the interface for unrelated reasons. Callers type-assert, and a
// controller without it reports nothing.
type PeerStatsReader interface {
	// PeerStats returns every peer on the named device, in the device's order.
	// A device that does not exist returns an error wrapping os.ErrNotExist.
	PeerStats(name string) ([]PeerStat, error)
}

// AddressReplacer is implemented by controllers that can swap the address
// of a live interface. oldAddress and newAddress are CIDRs of one length.
//
// It is optional, as OSInterfaceNamer and PeerStatsReader are, so no test
// double has to grow. A call that failed halfway succeeds when it is repeated
// with the same arguments: an implementation tolerates an address that is
// already there on an add, and one that is not there on a remove.
type AddressReplacer interface {
	ReplaceAddress(name, oldAddress, newAddress string) error
}

// MSSClamper is implemented by controllers that can lower the MSS option of
// the IPv4 TCP SYN packets that cross the interface, in both directions.
// It is optional, as AddressReplacer is. Both methods are idempotent.
type MSSClamper interface {
	// ClampMSS lowers every such MSS above mss to mss. A second call replaces
	// the value of the first.
	ClampMSS(name string, mss int) error
	// UnclampMSS removes the clamp. An interface that has none, or does not
	// exist, returns nil.
	UnclampMSS(name string) error
}

// replacePrefixes parses the two CIDRs a ReplaceAddress swaps. Both have to
// be IPv4 and of one length: the mesh address is IPv4 alone, and every
// controller's swap is written for IPv4.
func replacePrefixes(oldAddress, newAddress string) (netip.Prefix, netip.Prefix, error) {
	oldPrefix, err := netip.ParsePrefix(oldAddress)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("wireguard: replace address: parse %q: %w", oldAddress, err)
	}
	newPrefix, err := netip.ParsePrefix(newAddress)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("wireguard: replace address: parse %q: %w", newAddress, err)
	}
	for _, p := range []netip.Prefix{oldPrefix, newPrefix} {
		if !p.Addr().Is4() {
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("wireguard: replace address: %s is not an IPv4 CIDR", p)
		}
	}
	if oldPrefix.Bits() != newPrefix.Bits() {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("wireguard: replace address: %s and %s are not of one length", oldPrefix, newPrefix)
	}
	return oldPrefix, newPrefix, nil
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
