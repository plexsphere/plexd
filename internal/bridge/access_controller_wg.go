package bridge

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/wireguard"
)

// WGAccessController implements AccessController on top of the platform
// WGController: DarwinController on a utun device, WindowsController on a
// Wintun adapter, both running on UserspaceBackend. Every interface carries
// the private key and the address its caller passes.
//
// A repeated CreateInterface for the same name fails with an error wrapping
// os.ErrExist, which is what EEXIST is for the Linux netlink controller.
// RemoveInterface, RemoveInterfaces and RemovePeer are idempotent.
type WGAccessController struct {
	wgOps
}

var _ AccessController = (*WGAccessController)(nil)

// NewWGAccessController returns a WGAccessController over wg.
func NewWGAccessController(wg wireguard.WGController, logger *slog.Logger) *WGAccessController {
	return &WGAccessController{wgOps{
		wg:     wg,
		prefix: "access",
		noun:   "access",
		logger: logger,
	}}
}

// CreateInterface creates a WireGuard interface for user access with the
// given private key and listen port, and assigns address when it is not empty.
func (c *WGAccessController) CreateInterface(name string, privateKey []byte, listenPort int, address string) error {
	return c.create(name, privateKey, listenPort, address)
}

// RemoveInterface deletes the named WireGuard access interface.
// It is idempotent: removing a non-existent interface returns nil.
func (c *WGAccessController) RemoveInterface(name string) error {
	return c.remove(name)
}

// RemoveInterfaces returns nil without touching anything. A userspace device
// lives in the process that created it and ends with it, so a killed process
// leaves no interface behind for a start to clear.
func (c *WGAccessController) RemoveInterfaces(string) error {
	return nil
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

// PeerHandshakes reads the access interface through the wrapped controller's
// wireguard.PeerStatsReader and returns the latest handshake of every peer,
// keyed by its public key in standard base64. A controller that cannot read
// peer stats fails with an error wrapping wireguard.ErrPeerStatsUnsupported.
func (c *WGAccessController) PeerHandshakes(iface string) (map[string]time.Time, error) {
	reader, ok := c.wg.(wireguard.PeerStatsReader)
	if !ok {
		return nil, fmt.Errorf("bridge: access: peer handshakes: %w", wireguard.ErrPeerStatsUnsupported)
	}

	stats, err := reader.PeerStats(iface)
	if err != nil {
		return nil, fmt.Errorf("bridge: access: peer handshakes: %w", err)
	}

	handshakes := make(map[string]time.Time, len(stats))
	for _, s := range stats {
		handshakes[base64.StdEncoding.EncodeToString(s.PublicKey[:])] = s.LastHandshake
	}

	return handshakes, nil
}
