package bridge

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/plexsphere/plexd/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// endpointResolveTimeout bounds a name lookup for a remote site the control
// plane supplies. SiteToSiteManager resolves a tunnel's remote_host with
// SiteToSiteDeps.Resolve under it, outside its mutex, and hands
// ConfigureTunnelPeer an IP endpoint, so a nameserver that blackholes queries
// holds up one attempt for at most 5 s and never a status read, a removal or
// the teardown. resolveEndpoint bounds the lookup of an endpoint that names a
// host with it too, since net.ResolveUDPAddr, which would otherwise resolve
// it, takes no deadline.
const endpointResolveTimeout = 5 * time.Second

// wgOps holds the WireGuard work the access and the VPN controller share.
// The two differ only in the wording of their errors and log lines, so the
// operations live here once and each controller supplies the wording.
type wgOps struct {
	wg     wireguard.WGController
	prefix string // "access" or "vpn": the error prefix
	noun   string // "access" or "tunnel": the log wording
	logger *slog.Logger
}

// create creates the interface under name with privateKey (32 raw bytes) and
// listenPort, assigns address (a CIDR) when it is not empty and brings the
// interface up. The key is checked before anything is created. A failure after
// the interface exists deletes it again, so a retry starts from a clean state.
//
// A second create for the same name fails: DarwinController and
// WindowsController return an error wrapping os.ErrExist, which is what
// EEXIST is for the Linux netlink controllers.
//
// A listen port another socket holds fails with an error wrapping
// ErrListenPortInUse besides its cause. wireguard-go binds the port when it
// brings the device up, inside the wrapped CreateInterface, and the bind's
// error arrives wrapped. isAddrInUse tells a taken port by that error:
// EADDRINUSE, and on Windows also WSAEADDRINUSE, which Go does not equate
// with syscall.EADDRINUSE. A port inside one of Windows' reserved ranges
// fails with WSAEACCES, which is no taken port, and stays a plain failure.
func (o *wgOps) create(name string, privateKey []byte, listenPort int, address string) error {
	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("bridge: %s: parse private key: %w", o.prefix, err)
	}

	if err := o.wg.CreateInterface(name, key[:], listenPort); err != nil {
		if isAddrInUse(err) {
			return fmt.Errorf("bridge: %s: create interface %s: %w: %w", o.prefix, name, ErrListenPortInUse, err)
		}
		return fmt.Errorf("bridge: %s: create interface %s: %w", o.prefix, name, err)
	}

	if address != "" {
		if err := o.wg.ConfigureAddress(name, address); err != nil {
			_ = o.wg.DeleteInterface(name)
			return fmt.Errorf("bridge: %s: configure address %s: %w", o.prefix, address, err)
		}
	}

	if err := o.wg.SetInterfaceUp(name); err != nil {
		_ = o.wg.DeleteInterface(name)
		return fmt.Errorf("bridge: %s: set interface up: %w", o.prefix, err)
	}

	o.logger.Info(o.noun+" interface created",
		"component", "bridge",
		"interface", name,
		"listen_port", listenPort,
	)

	if address != "" {
		o.logger.Debug(o.noun+" interface addressed",
			"component", "bridge",
			"interface", name,
			"address", address,
		)
	}

	return nil
}

// remove deletes the named interface. It is idempotent: the wrapped
// controllers return nil for a name they do not know.
func (o *wgOps) remove(name string) error {
	if err := o.wg.DeleteInterface(name); err != nil {
		return fmt.Errorf("bridge: %s: remove interface: %w", o.prefix, err)
	}

	o.logger.Info(o.noun+" interface removed",
		"component", "bridge",
		"interface", name,
	)

	return nil
}

// configurePeer validates the peer material and programs the peer. The
// validation order and the error texts match the Linux netlink controllers,
// so a misconfigured peer reads the same on every platform.
func (o *wgOps) configurePeer(iface, publicKey string, allowedIPs []string, endpoint, psk string) error {
	pub, err := o.peerKey(publicKey)
	if err != nil {
		return err
	}

	if endpoint != "" {
		// The resolved address travels on in place of the name, so the device
		// is programmed with the address that was checked and nothing looks
		// the name up a second time. NetlinkVPNController resolves once the
		// same way, which is what keeps the error prefixes in step.
		resolved, err := resolveEndpoint(endpoint)
		if err != nil {
			return fmt.Errorf("bridge: %s: resolve endpoint: %w", o.prefix, err)
		}
		endpoint = resolved
	}

	for _, cidr := range allowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("bridge: %s: parse allowed IP %q: %w", o.prefix, cidr, err)
		}
	}

	var pskBytes []byte
	if psk != "" {
		raw, err := base64.StdEncoding.DecodeString(psk)
		if err != nil {
			return fmt.Errorf("bridge: %s: decode psk: %w", o.prefix, err)
		}
		pskKey, err := wgtypes.NewKey(raw)
		if err != nil {
			return fmt.Errorf("bridge: %s: parse psk: %w", o.prefix, err)
		}
		pskBytes = pskKey[:]
	}

	if err := o.wg.AddPeer(iface, wireguard.PeerConfig{
		PublicKey:  pub[:],
		Endpoint:   endpoint,
		AllowedIPs: allowedIPs,
		PSK:        pskBytes,
	}); err != nil {
		return fmt.Errorf("bridge: %s: configure peer: %w", o.prefix, err)
	}

	o.logger.Debug(o.noun+" peer configured",
		"component", "bridge",
		"interface", iface,
	)

	return nil
}

// removePeer drops the peer with the given public key from the interface.
func (o *wgOps) removePeer(iface, publicKey string) error {
	pub, err := o.peerKey(publicKey)
	if err != nil {
		return err
	}

	if err := o.wg.RemovePeer(iface, pub[:]); err != nil {
		return fmt.Errorf("bridge: %s: remove peer: %w", o.prefix, err)
	}

	o.logger.Debug(o.noun+" peer removed",
		"component", "bridge",
		"interface", iface,
	)

	return nil
}

// osName returns the kernel's name for the interface, which is what
// wireguard.OSInterfaceNamer promises: the name the operating system knows the
// device by, and false when there is no such device. A controller that does
// not rename devices, as WindowsController does not, keeps the configured
// name, so that name is the answer rather than "no mapping".
func (o *wgOps) osName(name string) (string, bool) {
	namer, ok := o.wg.(wireguard.OSInterfaceNamer)
	if !ok {
		return name, true
	}
	return namer.OSInterfaceName(name)
}

// osInterfaceName returns the name the operating system knows the interface
// created under name by: the name ctrl reports when it implements
// wireguard.OSInterfaceNamer and finds the interface, and name in every other
// case, a nil ctrl, one without a namer or one that does not find it. The
// managers hand this name to forwarding, the mesh source rewrite and the
// routes, which reach sysctl, pf and route(8) on macOS, and keep name for
// everything that goes through plexd.
func osInterfaceName(ctrl any, name string) string {
	if namer, ok := ctrl.(wireguard.OSInterfaceNamer); ok {
		if osName, found := namer.OSInterfaceName(name); found {
			return osName
		}
	}
	return name
}

// resolveEndpoint turns a host:port endpoint into an address:port literal
// under endpointResolveTimeout. The port is resolved first, as
// net.ResolveUDPAddr does it, so a malformed endpoint is rejected without a
// nameserver being asked anything.
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), endpointResolveTimeout)
	defer cancel()

	number, err := net.DefaultResolver.LookupPort(ctx, "udp", port)
	if err != nil {
		return "", err
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no address for host %q", host)
	}

	return netip.AddrPortFrom(preferIPv4(addrs), uint16(number)).String(), nil
}

// preferIPv4 returns the first IPv4 address among addrs, and the first address
// of any family when there is none. SiteToSiteManager picks a tunnel's remote
// address with it, and resolveEndpoint an endpoint's. net.ResolveUDPAddr
// prefers IPv4 for network "udp" unless the host is an IPv6 literal, and
// keeping that preference is what lets one control-plane endpoint reach the
// same peer on every platform. Without it a dual-stack name is pinned to
// whichever family the system resolver happened to return first, so a gateway
// with no IPv6 egress would be programmed with an address it cannot reach and
// the handshake would never complete.
func preferIPv4(addrs []netip.Addr) netip.Addr {
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			return addr.Unmap()
		}
	}
	return addrs[0].Unmap()
}

// peerKey decodes a base64 peer public key into a WireGuard key. Key material
// stays out of the errors and out of the log lines.
func (o *wgOps) peerKey(publicKey string) (wgtypes.Key, error) {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("bridge: %s: decode public key: %w", o.prefix, err)
	}

	key, err := wgtypes.NewKey(raw)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("bridge: %s: parse public key: %w", o.prefix, err)
	}

	return key, nil
}
