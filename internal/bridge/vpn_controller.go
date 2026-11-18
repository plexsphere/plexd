package bridge

import "time"

// The prefixes of the links plexd creates for site-to-site tunnels, one per
// kind. A tunnel's link is named by its prefix and the last 8 hex digits of
// the tunnel's id, which gives 15 characters, the kernel's limit. The
// prefixes are how a start finds the links a killed process left behind.
const (
	// SiteToSiteWireGuardPrefix begins the name of the WireGuard interface
	// of a wireguard tunnel.
	SiteToSiteWireGuardPrefix = "wg-s2s-"

	// SiteToSiteXfrmPrefix begins the name of the xfrm interface of an
	// ipsec tunnel.
	SiteToSiteXfrmPrefix = "xf-s2s-"

	// SiteToSiteTunPrefix begins the name of the tun device of an openvpn
	// tunnel.
	SiteToSiteTunPrefix = "ov-s2s-"
)

// SiteToSiteInterfacePrefixes lists the prefixes of every kind of
// site-to-site link, in the order wireguard, ipsec, openvpn. It is what a
// start hands to RemoveTunnelInterfaces.
var SiteToSiteInterfacePrefixes = []string{
	SiteToSiteWireGuardPrefix,
	SiteToSiteXfrmPrefix,
	SiteToSiteTunPrefix,
}

// VPNController abstracts the OS-level links of site-to-site tunnels for
// testability: the WireGuard interface of a wireguard tunnel, the xfrm
// interface of an ipsec tunnel and the tun device of an openvpn tunnel.
// Every method except the three Create methods must be idempotent: repeating
// an operation that is already applied returns nil.
type VPNController interface {
	// CreateTunnelInterface creates a WireGuard interface for a site-to-site
	// tunnel with the given name, configures privateKey (32 raw bytes) and
	// listenPort (the UDP port) on it and brings it up. The caller owns the
	// key, so an interface created again under the same key keeps its public
	// key.
	//
	// A failure after the interface exists removes it again. A listen port
	// another socket holds fails with an error wrapping ErrListenPortInUse
	// where the implementation can tell; NetlinkVPNController does.
	//
	// Not idempotent: a name that already exists fails with an error wrapping
	// os.ErrExist, which is what EEXIST is on Linux. The caller owns the
	// interface names it hands in, so a collision is a bug, not a state to
	// converge on.
	CreateTunnelInterface(name string, privateKey []byte, listenPort int) error

	// CreateXfrmInterface creates the xfrm interface of an ipsec tunnel with
	// the given name and the interface id ifID, which strongSwan binds the
	// connection to, and brings it up. ifID 0 is refused, since it binds
	// nothing. A failure after the interface exists removes it again.
	//
	// Not idempotent: a name that already exists fails with an error wrapping
	// os.ErrExist on Linux. A platform without xfrm interfaces fails with an
	// error wrapping errors.ErrUnsupported.
	CreateXfrmInterface(name string, ifID uint32) error

	// CreateTunInterface creates the persistent tun device of an openvpn
	// tunnel with the given name, without packet information and without an
	// address, and brings it up. A failure after the device exists removes it
	// again.
	//
	// Not idempotent: a name that a link of another kind holds fails. On
	// Linux a tun device that already carries the name and that no process
	// holds open is taken over rather than refused, as the kernel attaches
	// to it. A platform without persistent tun devices fails with an error
	// wrapping errors.ErrUnsupported.
	CreateTunInterface(name string) error

	// RemoveTunnelInterface removes the tunnel link with the given name,
	// whatever its kind.
	// Idempotent: removing a non-existent interface returns nil.
	RemoveTunnelInterface(name string) error

	// RemoveTunnelInterfaces removes every site-to-site link whose name
	// starts with one of prefixes, which is how a start clears the links a
	// killed process left behind. An empty list and an empty prefix are
	// refused, since either would match links plexd does not own.
	// Idempotent: with no such link it returns nil.
	RemoveTunnelInterfaces(prefixes []string) error

	// ConfigureTunnelPeer configures the remote peer on the given tunnel interface.
	// publicKey is base64-encoded, allowedIPs are the remote subnets, endpoint is host:port.
	// psk may be empty if not used.
	// Idempotent: re-applying the same config returns nil.
	ConfigureTunnelPeer(iface string, publicKey string, allowedIPs []string, endpoint string, psk string) error

	// RemoveTunnelPeer removes the remote peer from the given tunnel interface.
	// Idempotent: removing a non-existent peer returns nil.
	RemoveTunnelPeer(iface string, publicKey string) error

	// TunnelPeerHandshake returns the time of the latest handshake of the
	// peer with the given public key (standard base64) on the given tunnel
	// interface. A peer that never completed a handshake, and a peer the
	// interface does not hold, give the zero time and no error.
	TunnelPeerHandshake(iface string, publicKey string) (time.Time, error)
}
