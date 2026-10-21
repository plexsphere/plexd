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

// SetPrivateKey replaces the named device's private key without touching its
// listen port or peers.
func (c *NetlinkController) SetPrivateKey(name string, privateKey []byte) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard: set private key: open wgctrl: %w", err)
	}
	defer client.Close()

	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("wireguard: set private key: parse private key: %w", err)
	}

	if err := client.ConfigureDevice(name, wgtypes.Config{PrivateKey: &key}); err != nil {
		return fmt.Errorf("wireguard: set private key: configure device: %w", err)
	}

	c.logger.Info("wireguard private key rotated",
		"component", "wireguard",
		"interface", name,
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
	peerCfg, err := netlinkPeerConfig(cfg)
	if err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wireguard: add peer: open wgctrl: %w", err)
	}
	defer client.Close()

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

// netlinkPeerConfig translates cfg into the wgctrl peer configuration AddPeer
// writes. An empty Endpoint leaves the device peer's endpoint as it is, and an
// empty PSK its preshared key.
//
// The keepalive interval is always set. wgctrl leaves the device's interval
// as it is for a nil PersistentKeepaliveInterval and clears it for a pointer
// to 0, so a 0 here has to reach the device as a pointer: that is how a
// keepalive an earlier run left on a peer is cleared.
func netlinkPeerConfig(cfg PeerConfig) (wgtypes.PeerConfig, error) {
	pubKey, err := wgtypes.NewKey(cfg.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("wireguard: add peer: parse public key: %w", err)
	}

	keepalive := time.Duration(cfg.PersistentKeepalive) * time.Second
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: &keepalive,
	}

	if cfg.Endpoint != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("wireguard: add peer: resolve endpoint: %w", err)
		}
		peerCfg.Endpoint = udpAddr
	}

	for _, cidr := range cfg.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("wireguard: add peer: parse allowed IP %q: %w", cidr, err)
		}
		peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, *ipNet)
	}

	if len(cfg.PSK) > 0 {
		psk, err := wgtypes.NewKey(cfg.PSK)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("wireguard: add peer: parse psk: %w", err)
		}
		peerCfg.PresharedKey = &psk
	}

	return peerCfg, nil
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

// PeerStats reads every peer's runtime state from the named interface. Like
// AddPeer it opens a wgctrl client per call; the handshake reporter and the
// tunnel collector each call it once per interval, so a long-lived netlink
// socket would buy nothing. A missing interface returns an error wrapping
// os.ErrNotExist, which wgctrl maps from ENODEV.
//
// wgctrl already gives a zero LastHandshakeTime for a peer that never
// completed a handshake, so it passes through unchanged.
func (c *NetlinkController) PeerStats(name string) ([]PeerStat, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wireguard: peer stats: open wgctrl: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("wireguard: peer stats: read device: %w", err)
	}

	stats := make([]PeerStat, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		stat := PeerStat{
			PublicKey:     p.PublicKey,
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       uint64(p.ReceiveBytes),
			TxBytes:       uint64(p.TransmitBytes),
		}
		// A peer the kernel knows no endpoint for has a nil Endpoint; its
		// PeerStat keeps the invalid zero AddrPort.
		if p.Endpoint != nil {
			stat.Endpoint = p.Endpoint.AddrPort()
		}
		stats = append(stats, stat)
	}

	return stats, nil
}
