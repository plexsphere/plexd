//go:build linux

package bridge

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetlinkAccessController implements AccessController using Linux netlink
// and wgctrl for managing WireGuard user-access interfaces.
type NetlinkAccessController struct {
	logger *slog.Logger
}

// NewNetlinkAccessController returns a new NetlinkAccessController.
func NewNetlinkAccessController(logger *slog.Logger) *NetlinkAccessController {
	return &NetlinkAccessController{logger: logger}
}

// CreateInterface creates a WireGuard interface for user access.
func (c *NetlinkAccessController) CreateInterface(name string, listenPort int) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("bridge: access: create interface %s: %w", name, err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: access: open wgctrl: %w", err)
	}
	defer client.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("bridge: access: generate key: %w", err)
	}

	if err := client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("bridge: access: configure device: %w", err)
	}

	if err := netlink.LinkSetUp(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		return fmt.Errorf("bridge: access: set interface up: %w", err)
	}

	c.logger.Info("access interface created",
		"component", "bridge",
		"interface", name,
		"listen_port", listenPort,
	)

	return nil
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
