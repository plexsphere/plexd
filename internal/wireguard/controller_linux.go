//go:build linux

package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetlinkController implements WGController using Linux netlink and wgctrl.
type NetlinkController struct {
	logger *slog.Logger
}

// NewNetlinkController returns a new NetlinkController.
func NewNetlinkController(logger *slog.Logger) *NetlinkController {
	return &NetlinkController{logger: logger}
}

// CreateInterface creates a WireGuard interface with the given name,
// configures it with the provided private key and listen port.
func (c *NetlinkController) CreateInterface(name string, privateKey []byte, listenPort int) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("wireguard: create interface: %w", err)
	}

	c.logger.Debug("netlink interface created",
		"component", "wireguard",
		"interface", name,
	)

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard: create interface: open wgctrl: %w", err)
	}
	defer client.Close()

	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("wireguard: create interface: parse private key: %w", err)
	}

	err = client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	})
	if err != nil {
		return fmt.Errorf("wireguard: create interface: configure device: %w", err)
	}

	c.logger.Info("wireguard interface created",
		"component", "wireguard",
		"interface", name,
		"listen_port", listenPort,
	)

	return nil
}

// DeleteInterface deletes the named WireGuard interface.
// It is idempotent: deleting a non-existent interface returns nil.
func (c *NetlinkController) DeleteInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		// Interface does not exist — idempotent success.
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("wireguard: delete interface: %w", err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("wireguard: delete interface: %w", err)
	}

	c.logger.Info("wireguard interface deleted",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// ConfigureAddress adds a CIDR address to the named interface.
func (c *NetlinkController) ConfigureAddress(name string, address string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("wireguard: configure address: %w", err)
	}

	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("wireguard: configure address: parse %q: %w", address, err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("wireguard: configure address: %w", err)
	}

	c.logger.Debug("address configured",
		"component", "wireguard",
		"interface", name,
		"address", address,
	)

	return nil
}

// SetInterfaceUp brings the named interface up.
func (c *NetlinkController) SetInterfaceUp(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("wireguard: set interface up: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("wireguard: set interface up: %w", err)
	}

	c.logger.Debug("interface brought up",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// SetMTU sets the MTU on the named interface.
func (c *NetlinkController) SetMTU(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("wireguard: set mtu: %w", err)
	}

	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("wireguard: set mtu: %w", err)
	}

	c.logger.Debug("mtu configured",
		"component", "wireguard",
		"interface", name,
		"mtu", mtu,
	)

	return nil
}

// AddPeer adds or updates a peer on the named WireGuard interface.
// A new wgctrl client is created per call to avoid stale netlink socket issues
// across long-lived controller instances. The creation cost is negligible.
func (c *NetlinkController) AddPeer(iface string, cfg PeerConfig) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard: add peer: open wgctrl: %w", err)
	}
	defer client.Close()

	pubKey, err := wgtypes.NewKey(cfg.PublicKey)
	if err != nil {
		return fmt.Errorf("wireguard: add peer: parse public key: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		ReplaceAllowedIPs: true,
	}

	if cfg.Endpoint != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err != nil {
			return fmt.Errorf("wireguard: add peer: resolve endpoint: %w", err)
		}
		peerCfg.Endpoint = udpAddr
	}

	for _, cidr := range cfg.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("wireguard: add peer: parse allowed IP %q: %w", cidr, err)
		}
		peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, *ipNet)
	}

	if len(cfg.PSK) > 0 {
		psk, err := wgtypes.NewKey(cfg.PSK)
		if err != nil {
			return fmt.Errorf("wireguard: add peer: parse psk: %w", err)
		}
		peerCfg.PresharedKey = &psk
	}

	if cfg.PersistentKeepalive > 0 {
		keepalive := time.Duration(cfg.PersistentKeepalive) * time.Second
		peerCfg.PersistentKeepaliveInterval = &keepalive
	}

	err = client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	})
	if err != nil {
		return fmt.Errorf("wireguard: add peer: configure device: %w", err)
	}

	c.logger.Debug("peer added",
		"component", "wireguard",
		"interface", iface,
	)

	return nil
}

// RemovePeer removes a peer from the named WireGuard interface by public key.
func (c *NetlinkController) RemovePeer(iface string, publicKey []byte) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard: remove peer: open wgctrl: %w", err)
	}
	defer client.Close()

	pubKey, err := wgtypes.NewKey(publicKey)
	if err != nil {
		return fmt.Errorf("wireguard: remove peer: parse public key: %w", err)
	}

	err = client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: pubKey,
				Remove:   true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("wireguard: remove peer: configure device: %w", err)
	}

	c.logger.Debug("peer removed",
		"component", "wireguard",
		"interface", iface,
	)

	return nil
}
