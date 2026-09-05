package bridge

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/wireguard"
)

// WGAccessController implements AccessController on top of the platform
// WGController: DarwinController on a utun device, WindowsController on a
// Wintun adapter, both running on UserspaceBackend. Every interface gets a
// fresh private key.
//
// A repeated CreateInterface for the same name fails with an error wrapping
// os.ErrExist, which is what EEXIST is for the Linux netlink controller.
// RemoveInterface and RemovePeer are idempotent.
type WGAccessController struct {
	wgOps
}

var _ AccessController = (*WGAccessController)(nil)

// NewWGAccessController returns a WGAccessController over wg. The access
// interface stays unnumbered on every platform, as it is on Linux.
func NewWGAccessController(wg wireguard.WGController, logger *slog.Logger) *WGAccessController {
	return &WGAccessController{wgOps{
		wg:     wg,
		prefix: "access",
		noun:   "access",
		logger: logger,
	}}
}

// CreateInterface creates a WireGuard interface for user access.
func (c *WGAccessController) CreateInterface(name string, listenPort int) error {
	return c.create(name, listenPort)
}

// RemoveInterface deletes the named WireGuard access interface.
// It is idempotent: removing a non-existent interface returns nil.
func (c *WGAccessController) RemoveInterface(name string) error {
	return c.remove(name)
}

// ConfigurePeer adds or updates a peer on the access interface. User-access
// peers dial the node, so they carry no endpoint.
func (c *WGAccessController) ConfigurePeer(iface, publicKey string, allowedIPs []string, psk string) error {
	return c.configurePeer(iface, publicKey, allowedIPs, "", psk)
}

// RemovePeer removes a peer from the access interface by public key.
// It is idempotent: removing an unknown peer returns nil.
func (c *WGAccessController) RemovePeer(iface, publicKey string) error {
	return c.removePeer(iface, publicKey)
}
