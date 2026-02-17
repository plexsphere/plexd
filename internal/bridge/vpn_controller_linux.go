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

// NetlinkVPNController implements VPNController using Linux netlink and
// wgctrl for managing WireGuard site-to-site tunnel interfaces.
type NetlinkVPNController struct {
	logger *slog.Logger
}

// NewNetlinkVPNController returns a new NetlinkVPNController.
func NewNetlinkVPNController(logger *slog.Logger) *NetlinkVPNController {
	return &NetlinkVPNController{logger: logger}
}

// CreateTunnelInterface creates a WireGuard interface for a site-to-site tunnel.
func (c *NetlinkVPNController) CreateTunnelInterface(name string, listenPort int) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("bridge: vpn: create interface %s: %w", name, err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: vpn: open wgctrl: %w", err)
	}
	defer client.Close()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("bridge: vpn: generate key: %w", err)
	}

	if err := client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("bridge: vpn: configure device: %w", err)
	}

	if err := netlink.LinkSetUp(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		return fmt.Errorf("bridge: vpn: set interface up: %w", err)
	}

	c.logger.Info("tunnel interface created",
		"component", "bridge",
		"interface", name,
		"listen_port", listenPort,
	)

	return nil
}

// RemoveTunnelInterface deletes the named WireGuard tunnel interface.
// It is idempotent: removing a non-existent interface returns nil.
func (c *NetlinkVPNController) RemoveTunnelInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("bridge: vpn: remove interface: %w", err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("bridge: vpn: remove interface: %w", err)
	}

	c.logger.Info("tunnel interface removed",
		"component", "bridge",
		"interface", name,
	)

	return nil
}

// ConfigureTunnelPeer adds or updates a peer on the tunnel interface.
func (c *NetlinkVPNController) ConfigureTunnelPeer(iface, publicKey string, allowedIPs []string, endpoint, psk string) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: vpn: open wgctrl: %w", err)
	}
	defer client.Close()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("bridge: vpn: decode public key: %w", err)
	}
	pubKey, err := wgtypes.NewKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("bridge: vpn: parse public key: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		ReplaceAllowedIPs: true,
	}

	if endpoint != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return fmt.Errorf("bridge: vpn: resolve endpoint: %w", err)
		}
		peerCfg.Endpoint = udpAddr
	}

	for _, cidr := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("bridge: vpn: parse allowed IP %q: %w", cidr, err)
		}
		peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, *ipNet)
	}

	if psk != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(psk)
		if err != nil {
			return fmt.Errorf("bridge: vpn: decode psk: %w", err)
		}
		pskKey, err := wgtypes.NewKey(pskBytes)
		if err != nil {
			return fmt.Errorf("bridge: vpn: parse psk: %w", err)
		}
		peerCfg.PresharedKey = &pskKey
	}

	if err := client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("bridge: vpn: configure peer: %w", err)
	}

	c.logger.Debug("tunnel peer configured",
		"component", "bridge",
		"interface", iface,
	)

	return nil
}

// RemoveTunnelPeer removes a peer from the tunnel interface by public key.
func (c *NetlinkVPNController) RemoveTunnelPeer(iface, publicKey string) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: vpn: open wgctrl: %w", err)
	}
	defer client.Close()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("bridge: vpn: decode public key: %w", err)
	}
	pubKey, err := wgtypes.NewKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("bridge: vpn: parse public key: %w", err)
	}

	if err := client.ConfigureDevice(iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: pubKey,
				Remove:   true,
			},
		},
	}); err != nil {
		return fmt.Errorf("bridge: vpn: remove peer: %w", err)
	}

	c.logger.Debug("tunnel peer removed",
		"component", "bridge",
		"interface", iface,
	)

	return nil
}
