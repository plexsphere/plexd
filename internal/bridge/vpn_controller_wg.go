package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/wireguard"
)

// WGVPNController implements VPNController on top of the platform
// WGController: DarwinController on a utun device, WindowsController on a
// Wintun adapter, both running on UserspaceBackend. Every tunnel interface
// carries the private key its caller passes. It creates WireGuard interfaces
// only: the xfrm interface and the tun device the other tunnel kinds need
// exist on Linux alone.
//
// A repeated CreateTunnelInterface for the same name fails with an error
// wrapping os.ErrExist, which is what EEXIST is for the Linux netlink
// controller. RemoveTunnelInterface, RemoveTunnelInterfaces and
// RemoveTunnelPeer are idempotent.
type WGVPNController struct {
	wgOps

	// mu guards address, which SetAddress changes while the site-to-site
	// manager may create an interface.
	mu      sync.Mutex
	address string // CIDR assigned after creation; empty leaves the interface unnumbered
}

var (
	_ VPNController              = (*WGVPNController)(nil)
	_ wireguard.OSInterfaceNamer = (*WGVPNController)(nil)
)

// NewWGVPNController returns a WGVPNController over wg. address is the CIDR
// the tunnel interface carries.
//
// macOS needs it: route(8) refuses a route over a utun without an IPv4
// address with "Network is unreachable", so plexd up passes the node's mesh
// IP as a /32 there. An empty address leaves the interface unnumbered, which
// is what Linux and Windows use.
func NewWGVPNController(wg wireguard.WGController, address string, logger *slog.Logger) *WGVPNController {
	return &WGVPNController{
		wgOps: wgOps{
			wg:     wg,
			prefix: "vpn",
			noun:   "tunnel",
			logger: logger,
		},
		address: address,
	}
}

// CreateTunnelInterface creates a WireGuard interface for a site-to-site
// tunnel with the given private key and listen port, carrying the address the
// controller was built with or the last SetAddress gave it. The key is checked
// before anything is created.
func (c *WGVPNController) CreateTunnelInterface(name string, privateKey []byte, listenPort int) error {
	c.mu.Lock()
	address := c.address
	c.mu.Unlock()
	return c.create(name, privateKey, listenPort, address)
}

// SetAddress sets the CIDR every tunnel interface created from now on
// carries; empty leaves them unnumbered. An interface that exists keeps the
// address it was created with: on macOS, where the address is the node's mesh
// IP, SiteToSiteManager.Rebuild creates the tunnels again after a move.
func (c *WGVPNController) SetAddress(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.address = address
}

// CreateXfrmInterface creates nothing and returns an error wrapping
// errors.ErrUnsupported: xfrm interfaces are a Linux kernel feature, so an
// ipsec tunnel has no link on macOS and Windows.
func (c *WGVPNController) CreateXfrmInterface(name string, _ uint32) error {
	return fmt.Errorf("bridge: vpn: create xfrm interface %s: %w", name, errors.ErrUnsupported)
}

// CreateTunInterface creates nothing and returns an error wrapping
// errors.ErrUnsupported: the persistent tun device an openvpn tunnel runs on
// is a Linux kernel feature, so such a tunnel has no link on macOS and
// Windows.
func (c *WGVPNController) CreateTunInterface(name string) error {
	return fmt.Errorf("bridge: vpn: create tun interface %s: %w", name, errors.ErrUnsupported)
}

// RemoveTunnelInterface deletes the named WireGuard tunnel interface.
// It is idempotent: removing a non-existent interface returns nil.
func (c *WGVPNController) RemoveTunnelInterface(name string) error {
	return c.remove(name)
}

// RemoveTunnelInterfaces returns nil without touching anything. A userspace
// device lives in the process that created it and ends with it, so a killed
// process leaves no interface behind for a start to clear.
func (c *WGVPNController) RemoveTunnelInterfaces([]string) error {
	return nil
}

// ConfigureTunnelPeer adds or updates the remote peer on the tunnel interface.
func (c *WGVPNController) ConfigureTunnelPeer(iface, publicKey string, allowedIPs []string, endpoint, psk string) error {
	return c.configurePeer(iface, publicKey, allowedIPs, endpoint, psk)
}

// RemoveTunnelPeer removes the remote peer from the tunnel interface by public key.
// It is idempotent: removing an unknown peer returns nil.
func (c *WGVPNController) RemoveTunnelPeer(iface, publicKey string) error {
	return c.removePeer(iface, publicKey)
}

// TunnelPeerHandshake reads the tunnel interface through the wrapped
// controller's wireguard.PeerStatsReader and returns the latest handshake of
// the peer with the given public key: the zero time for a peer that never
// completed one and for a peer the device does not hold. The key is checked
// before the device is read. A controller that cannot read peer stats fails
// with an error wrapping wireguard.ErrPeerStatsUnsupported.
func (c *WGVPNController) TunnelPeerHandshake(iface, publicKey string) (time.Time, error) {
	pub, err := c.peerKey(publicKey)
	if err != nil {
		return time.Time{}, err
	}

	reader, ok := c.wg.(wireguard.PeerStatsReader)
	if !ok {
		return time.Time{}, fmt.Errorf("bridge: vpn: peer handshake: %w", wireguard.ErrPeerStatsUnsupported)
	}

	stats, err := reader.PeerStats(iface)
	if err != nil {
		return time.Time{}, fmt.Errorf("bridge: vpn: peer handshake: %w", err)
	}

	for _, s := range stats {
		if s.PublicKey == pub {
			return s.LastHandshake, nil
		}
	}

	return time.Time{}, nil
}

// OSInterfaceName returns the kernel's name for the tunnel interface created
// under name, and false when there is no such interface. A platform that keeps
// the configured name, as Windows does, reports that name.
func (c *WGVPNController) OSInterfaceName(name string) (string, bool) {
	return c.osName(name)
}
