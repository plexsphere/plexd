package bridge

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/wireguard"
)

// WGVPNController implements VPNController on top of the platform
// WGController: DarwinController on a utun device, WindowsController on a
// Wintun adapter, both running on UserspaceBackend. Every tunnel interface
// gets a fresh private key.
//
// A repeated CreateTunnelInterface for the same name fails with an error
// wrapping os.ErrExist, which is what EEXIST is for the Linux netlink
// controller. RemoveTunnelInterface and RemoveTunnelPeer are idempotent.
type WGVPNController struct {
	wgOps
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
	return &WGVPNController{wgOps{
		wg:      wg,
		address: address,
		prefix:  "vpn",
		noun:    "tunnel",
		logger:  logger,
	}}
}

// CreateTunnelInterface creates a WireGuard interface for a site-to-site tunnel.
func (c *WGVPNController) CreateTunnelInterface(name string, listenPort int) error {
	return c.create(name, listenPort)
}

// RemoveTunnelInterface deletes the named WireGuard tunnel interface.
// It is idempotent: removing a non-existent interface returns nil.
func (c *WGVPNController) RemoveTunnelInterface(name string) error {
	return c.remove(name)
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

// OSInterfaceName returns the kernel's name for the tunnel interface created
// under name, and false when there is no such interface. A platform that keeps
// the configured name, as Windows does, reports that name.
func (c *WGVPNController) OSInterfaceName(name string) (string, bool) {
	return c.osName(name)
}
