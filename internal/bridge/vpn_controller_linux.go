//go:build linux

package bridge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// NetlinkVPNController implements VPNController using Linux netlink and
// wgctrl for managing the links of site-to-site tunnels: WireGuard
// interfaces, xfrm interfaces and persistent tun devices.
type NetlinkVPNController struct {
	logger *slog.Logger
}

var _ VPNController = (*NetlinkVPNController)(nil)

// NewNetlinkVPNController returns a new NetlinkVPNController.
func NewNetlinkVPNController(logger *slog.Logger) *NetlinkVPNController {
	return &NetlinkVPNController{logger: logger}
}

// CreateTunnelInterface creates a WireGuard interface for a site-to-site
// tunnel: it adds the link, configures privateKey and listenPort through
// wgctrl and brings the link up. It works as
// NetlinkAccessController.CreateInterface does, without an address.
//
// The key is checked before the link is added, so a malformed key leaves
// nothing behind. A failure after the link exists deletes it before the error
// returns, so a retry does not fail on the name. A listen port another socket
// holds fails with an error wrapping ErrListenPortInUse, see listenPortErr.
func (c *NetlinkVPNController) CreateTunnelInterface(name string, privateKey []byte, listenPort int) (err error) {
	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("bridge: vpn: parse private key: %w", err)
	}

	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("bridge: vpn: create interface %s: %w", name, err)
	}

	defer deleteLinkAfterFailure(&err, link)

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("bridge: vpn: open wgctrl: %w", err)
	}
	defer client.Close()

	if err := client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &listenPort,
	}); err != nil {
		return listenPortErr("vpn", "configure device", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return listenPortErr("vpn", "set interface up", err)
	}

	c.logger.Info("tunnel interface created",
		"component", "bridge",
		"interface", name,
		"listen_port", listenPort,
	)

	return nil
}

// CreateXfrmInterface creates the xfrm interface of an ipsec tunnel, what
// ip link add <name> type xfrm dev lo if_id <ifID> creates, and brings it up.
// The loopback link is its parent, so the interface depends on no uplink.
// ifID 0 is refused before anything is added, since strongSwan binds a
// connection to the interface by a non-zero id. A failure after the link
// exists deletes it before the error returns.
func (c *NetlinkVPNController) CreateXfrmInterface(name string, ifID uint32) (err error) {
	if ifID == 0 {
		return fmt.Errorf("bridge: vpn: create xfrm interface %s: interface id 0 binds no connection", name)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("bridge: vpn: create xfrm interface %s: look up the loopback link: %w", name, err)
	}

	la := netlink.NewLinkAttrs()
	la.Name = name
	la.ParentIndex = lo.Attrs().Index
	link := &netlink.Xfrmi{LinkAttrs: la, Ifid: ifID}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("bridge: vpn: create xfrm interface %s: %w", name, err)
	}

	defer deleteLinkAfterFailure(&err, link)

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bridge: vpn: set interface up: %w", err)
	}

	c.logger.Info("tunnel interface created",
		"component", "bridge",
		"interface", name,
		"if_id", ifID,
	)

	return nil
}

// CreateTunInterface creates the tun device of an openvpn tunnel, what
// ip tuntap add <name> mode tun creates, and brings it up. The device is
// persistent, so it outlives the descriptor that created it and the openvpn
// process attaches to it by name. It carries no packet information header
// and no address. A failure after the device exists deletes it before the
// error returns.
//
// The kernel attaches to a tun device that already carries the name and that
// no process holds open, rather than refusing it, so such a device is taken
// over. A name that a link of another kind holds fails.
func (c *NetlinkVPNController) CreateTunInterface(name string) (err error) {
	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_NO_PI,
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("bridge: vpn: create tun interface %s: %w", name, err)
	}

	defer deleteLinkAfterFailure(&err, link)

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bridge: vpn: set interface up: %w", err)
	}

	c.logger.Info("tunnel interface created",
		"component", "bridge",
		"interface", name,
	)

	return nil
}

// deleteLinkAfterFailure deletes link when *err is set, which is how the
// creates of NetlinkVPNController leave no link behind once the link exists
// and a later step failed. A failed delete is joined to *err.
func deleteLinkAfterFailure(err *error, link netlink.Link) {
	if *err == nil {
		return
	}
	if delErr := netlink.LinkDel(link); delErr != nil {
		*err = errors.Join(*err, fmt.Errorf("bridge: vpn: remove interface %s after a failed create: %w", link.Attrs().Name, delErr))
	}
}

// RemoveTunnelInterface deletes the named tunnel link, whatever its kind.
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

// RemoveTunnelInterfaces deletes every link of type wireguard, xfrm or tuntap
// whose name starts with one of prefixes. An empty list and an empty prefix
// are refused before any link is listed: an empty prefix would match the mesh
// interface and every user access interface. A link of another type is kept,
// whatever its name starts with. removeLinks says how a link that is already
// gone and an interrupted link dump count.
func (c *NetlinkVPNController) RemoveTunnelInterfaces(prefixes []string) error {
	if len(prefixes) == 0 {
		return errors.New("bridge: vpn: remove tunnel interfaces: no prefix")
	}
	if slices.Contains(prefixes, "") {
		return errors.New("bridge: vpn: remove tunnel interfaces: empty prefix")
	}

	if err := removeLinks(c.logger, "tunnel interface removed", tunnelLinkMatch(prefixes)); err != nil {
		return fmt.Errorf("bridge: vpn: remove tunnel interfaces: %w", err)
	}

	return nil
}

// tunnelLinkMatch returns the match RemoveTunnelInterfaces sweeps with: true
// for a link of type wireguard, xfrm or tuntap, the three kinds of
// site-to-site link, whose name starts with one of prefixes.
func tunnelLinkMatch(prefixes []string) func(netlink.Link) bool {
	return func(link netlink.Link) bool {
		switch link.Type() {
		case "wireguard", "xfrm", "tuntap":
		default:
			return false
		}
		name := link.Attrs().Name
		return slices.ContainsFunc(prefixes, func(prefix string) bool {
			return strings.HasPrefix(name, prefix)
		})
	}
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

// TunnelPeerHandshake reads the tunnel interface through wgctrl and returns
// the latest handshake of the peer with the given public key. wgctrl gives a
// zero LastHandshakeTime for a peer that never completed a handshake, which
// passes through unchanged, and a peer the device does not hold gives the zero
// time as well. The key is checked before the device is read.
func (c *NetlinkVPNController) TunnelPeerHandshake(iface, publicKey string) (time.Time, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return time.Time{}, fmt.Errorf("bridge: vpn: decode public key: %w", err)
	}
	pubKey, err := wgtypes.NewKey(pubKeyBytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("bridge: vpn: parse public key: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return time.Time{}, fmt.Errorf("bridge: vpn: open wgctrl: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(iface)
	if err != nil {
		return time.Time{}, fmt.Errorf("bridge: vpn: peer handshake: read device: %w", err)
	}

	for _, p := range dev.Peers {
		if p.PublicKey == pubKey {
			return p.LastHandshakeTime, nil
		}
	}

	return time.Time{}, nil
}
