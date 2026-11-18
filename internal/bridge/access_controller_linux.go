//go:build linux

package bridge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// linkListAttempts bounds how often removeLinks lists the links while the
// kernel reports the dump as interrupted, which it does when a link changes
// during the dump.
const linkListAttempts = 3

// NetlinkAccessController implements AccessController using Linux netlink
// and wgctrl for managing WireGuard user-access interfaces.
type NetlinkAccessController struct {
	logger *slog.Logger
}

var _ AccessController = (*NetlinkAccessController)(nil)

// NewNetlinkAccessController returns a new NetlinkAccessController.
func NewNetlinkAccessController(logger *slog.Logger) *NetlinkAccessController {
	return &NetlinkAccessController{logger: logger}
}

// CreateInterface creates a WireGuard interface for user access: it adds the
// link, configures privateKey and listenPort through wgctrl, assigns address
// when it is not empty and brings the link up.
//
// The key and the address are checked before the link is added, so malformed
// input leaves nothing behind. A failure after the link exists deletes it
// before the error returns, so a retry does not fail on the name. A listen
// port another socket holds fails with an error wrapping ErrListenPortInUse,
// see listenPortErr.
func (c *NetlinkAccessController) CreateInterface(name string, privateKey []byte, listenPort int, address string) (err error) {
	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("bridge: access: parse private key: %w", err)
	}

	var addr *netlink.Addr
	if address != "" {
		addr, err = netlink.ParseAddr(address)
		if err != nil {
			return fmt.Errorf("bridge: access: parse address %q: %w", address, err)
		}
	}

	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("bridge: access: create interface %s: %w", name, err)
	}

	defer func() {
		if err == nil {
			return
		}
		if delErr := netlink.LinkDel(link); delErr != nil {
			err = errors.Join(err, fmt.Errorf("bridge: access: remove interface %s after a failed create: %w", name, delErr))
		}
	}()

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: access: open wgctrl: %w", err)
	}
	defer client.Close()

	if err := client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	}); err != nil {
		return listenPortErr("access", "configure device", err)
	}

	if addr != nil {
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("bridge: access: configure address %s: %w", address, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return listenPortErr("access", "set interface up", err)
	}

	c.logger.Info("access interface created",
		"component", "bridge",
		"interface", name,
		"listen_port", listenPort,
	)

	if address != "" {
		c.logger.Debug("access interface addressed",
			"component", "bridge",
			"interface", name,
			"address", address,
		)
	}

	return nil
}

// listenPortErr wraps err from the step named step of a WireGuard create, under
// the error prefix of the calling controller, "access" or "vpn". The kernel
// binds a WireGuard device's listen port when the device comes up, and again
// when the port changes on a device that is already up, so a port another
// socket holds surfaces as EADDRINUSE from LinkSetUp or from ConfigureDevice.
// Such an error wraps ErrListenPortInUse besides its cause, which is what lets
// the caller tell a taken port from a failed setup. The unit test proves the
// mapping; that the kernel answers EADDRINUSE is proven only on a real kernel.
func listenPortErr(prefix, step string, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("bridge: %s: %s: %w: %w", prefix, step, ErrListenPortInUse, err)
	}
	return fmt.Errorf("bridge: %s: %s: %w", prefix, step, err)
}

// RemoveInterfaces deletes every link of type wireguard whose name starts with
// prefix. An empty prefix is refused, since it would match the mesh interface
// and every tunnel. removeLinks says how a link that is already gone and an
// interrupted link dump count.
func (c *NetlinkAccessController) RemoveInterfaces(prefix string) error {
	if prefix == "" {
		return errors.New("bridge: access: remove interfaces: empty prefix")
	}

	err := removeLinks(c.logger, "access interface removed", func(link netlink.Link) bool {
		return link.Type() == "wireguard" && strings.HasPrefix(link.Attrs().Name, prefix)
	})
	if err != nil {
		return fmt.Errorf("bridge: access: remove interfaces: %w", err)
	}

	return nil
}

// removeLinks deletes every link match accepts and logs each deletion at Info
// on logger with the message removed, the line each controller logs when it
// removes one of its links by name. It is the sweep NetlinkAccessController.RemoveInterfaces and
// NetlinkVPNController.RemoveTunnelInterfaces share; each wraps the error in
// its own prefix. A link that is gone by the time it is deleted counts as
// removed; the errors of the other deletions are joined.
//
// The kernel marks a link dump interrupted when a link changes while the dump
// runs. The list is then taken again, up to linkListAttempts times. When the
// last attempt is still interrupted, the links that dump named are deleted
// and the error wraps netlink.ErrDumpInterrupted: a link the dump missed would
// make the next create under its name fail, so the caller has to know the
// sweep may be incomplete.
func removeLinks(logger *slog.Logger, removed string, match func(netlink.Link) bool) error {
	links, err := listLinks()
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return fmt.Errorf("list links: %w", err)
	}

	var errs []error
	if err != nil {
		errs = append(errs, fmt.Errorf("list links: %w", err))
	}

	for _, link := range links {
		if !match(link) {
			continue
		}

		name := link.Attrs().Name
		if err := netlink.LinkDel(link); err != nil {
			if !errors.Is(err, syscall.ENODEV) {
				errs = append(errs, fmt.Errorf("remove interface %s: %w", name, err))
			}
			continue
		}

		logger.Info(removed,
			"component", "bridge",
			"interface", name,
		)
	}

	return errors.Join(errs...)
}

// listLinks lists every link, taking the dump again while the kernel reports
// it interrupted, up to linkListAttempts times. It returns the last result
// with its error, which is netlink.ErrDumpInterrupted when every attempt was
// interrupted.
func listLinks() ([]netlink.Link, error) {
	var (
		links []netlink.Link
		err   error
	)
	for range linkListAttempts {
		links, err = netlink.LinkList()
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	return links, err
}

// PeerHandshakes reads the access interface through wgctrl and returns the
// latest handshake of every peer, keyed by its public key in standard base64.
// wgctrl gives a zero LastHandshakeTime for a peer that never completed a
// handshake, so it passes through unchanged.
func (c *NetlinkAccessController) PeerHandshakes(iface string) (map[string]time.Time, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("bridge: access: open wgctrl: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(iface)
	if err != nil {
		return nil, fmt.Errorf("bridge: access: peer handshakes: read device: %w", err)
	}

	handshakes := make(map[string]time.Time, len(dev.Peers))
	for _, p := range dev.Peers {
		handshakes[p.PublicKey.String()] = p.LastHandshakeTime
	}

	return handshakes, nil
}

// RemoveInterface deletes the named WireGuard access interface.
// It is idempotent: removing a non-existent interface returns nil.
func (c *NetlinkAccessController) RemoveInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("bridge: access: remove interface: %w", err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("bridge: access: remove interface: %w", err)
	}

	c.logger.Info("access interface removed",
		"component", "bridge",
		"interface", name,
	)

	return nil
}

// ConfigurePeer adds or updates a peer on the access interface.
func (c *NetlinkAccessController) ConfigurePeer(iface, publicKey string, allowedIPs []string, psk string) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: access: open wgctrl: %w", err)
	}
	defer client.Close()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("bridge: access: decode public key: %w", err)
	}
	pubKey, err := wgtypes.NewKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("bridge: access: parse public key: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		ReplaceAllowedIPs: true,
	}

	for _, cidr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("bridge: access: parse allowed IP %q: %w", cidr, err)
		}
		peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, *ipNet)
	}

	if psk != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(psk)
		if err != nil {
			return fmt.Errorf("bridge: access: decode psk: %w", err)
		}
		pskKey, err := wgtypes.NewKey(pskBytes)
		if err != nil {
			return fmt.Errorf("bridge: access: parse psk: %w", err)
		}
		peerCfg.PresharedKey = &pskKey
	}

	if err := client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("bridge: access: configure peer: %w", err)
	}

	c.logger.Debug("access peer configured",
		"component", "bridge",
		"interface", iface,
	)

	return nil
}

// RemovePeer removes a peer from the access interface by public key.
func (c *NetlinkAccessController) RemovePeer(iface, publicKey string) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: access: open wgctrl: %w", err)
	}
	defer client.Close()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("bridge: access: decode public key: %w", err)
	}
	pubKey, err := wgtypes.NewKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("bridge: access: parse public key: %w", err)
	}

	if err := client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: pubKey,
				Remove:   true,
			},
		},
	}); err != nil {
		return fmt.Errorf("bridge: access: remove peer: %w", err)
	}

	c.logger.Debug("access peer removed",
		"component", "bridge",
		"interface", iface,
	)

	return nil
}
