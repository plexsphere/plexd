package bridge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"regexp"

	"github.com/plexsphere/plexd/internal/api"
)

// TunnelConfig is what a TunnelProvider needs to run the daemon's side of one
// site-to-site tunnel of the ipsec or openvpn kind. The SiteToSiteManager
// builds it from the tunnel's entry and owns everything else: the link, the
// routes, forwarding and the mesh source rewrite. Every member a provider
// writes into a file passes ValidateTunnelConfig first.
type TunnelConfig struct {
	// TunnelID is the tunnel's id, lower case. It names the provider's files
	// and its strongSwan connection.
	TunnelID string
	// InterfaceName is the link the manager created for the tunnel: the
	// xfrm interface of an ipsec tunnel, the tun device of an openvpn one.
	InterfaceName string
	// InterfaceID is the id of an ipsec tunnel's xfrm interface, which
	// strongSwan binds the connection to; 0 for openvpn.
	InterfaceID uint32
	// RemoteHost is the remote site's host name or IP address, as the pull
	// carries it; the daemon resolves a name itself.
	RemoteHost string
	// RemotePort is the remote site's port.
	RemotePort int
	// LocalSubnets are the networks on the bridge's side of the tunnel: the
	// Domain mesh CIDR.
	LocalSubnets []string
	// RemoteSubnets are the networks behind the remote site, the tunnel's
	// allowed_subnets.
	RemoteSubnets []string
	// Key is the value of the tunnel's Secret, trimmed of surrounding white
	// space: an IKE pre-shared key or an OpenVPN static key. It is never
	// logged.
	Key string
}

// tunnelRemoteHostPattern is the grammar of a remote host a provider writes
// into a file: a host name or an IP address, without white space, quotes or
// any other character a daemon's configuration syntax reads.
var tunnelRemoteHostPattern = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)

// tunnelInterfaceNamePattern is the grammar of a link name: the kernel's 15
// characters in the alphabet of the site-to-site prefixes.
var tunnelInterfaceNamePattern = regexp.MustCompile(`^[a-z0-9-]{1,15}$`)

// ValidateTunnelConfig checks what a provider writes into a file before it
// writes it: TunnelID passes api.ValidSiteToSiteTunnelID, RemoteHost matches
// ^[A-Za-z0-9.:-]{1,253}$, RemotePort is 1 to 65535, every subnet parses as a
// prefix, and InterfaceName matches ^[a-z0-9-]{1,15}$. Key is not checked
// here: each provider checks it for its own form. An error never quotes Key.
func ValidateTunnelConfig(cfg TunnelConfig) error {
	if !api.ValidSiteToSiteTunnelID(cfg.TunnelID) {
		return fmt.Errorf("bridge: tunnel: invalid tunnel id %q", cfg.TunnelID)
	}
	if !tunnelRemoteHostPattern.MatchString(cfg.RemoteHost) {
		return fmt.Errorf("bridge: tunnel %s: invalid remote host %q", cfg.TunnelID, cfg.RemoteHost)
	}
	if cfg.RemotePort < 1 || cfg.RemotePort > 65535 {
		return fmt.Errorf("bridge: tunnel %s: remote port %d is outside 1 to 65535", cfg.TunnelID, cfg.RemotePort)
	}
	for _, s := range cfg.LocalSubnets {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("bridge: tunnel %s: invalid local subnet %q", cfg.TunnelID, s)
		}
	}
	for _, s := range cfg.RemoteSubnets {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("bridge: tunnel %s: invalid remote subnet %q", cfg.TunnelID, s)
		}
	}
	if !tunnelInterfaceNamePattern.MatchString(cfg.InterfaceName) {
		return fmt.Errorf("bridge: tunnel %s: invalid interface name %q", cfg.TunnelID, cfg.InterfaceName)
	}
	return nil
}

// DefaultTunnelConfigDir is the directory the OpenVPNProvider keeps the files
// of its tunnels in. It lies under the run directory, so it is gone after a
// reboot, and it is created with mode 0700, so no other user reads a key.
const DefaultTunnelConfigDir = "/run/plexd/tunnels"

// ensureTunnelConfigDir creates the given directory, and its parents, with
// mode 0700 when it does not exist. A directory that exists keeps its mode.
func ensureTunnelConfigDir(dir string) error {
	return os.MkdirAll(dir, 0700)
}

// removeIfExists removes path and reports whether it existed. A path that
// does not exist is no error.
func removeIfExists(path string) (bool, error) {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// TunnelProvider runs the daemon's side of the site-to-site tunnels of one
// kind, ipsec or openvpn, each on a link the SiteToSiteManager created
// before. The manager owns the link, the routes, forwarding and the mesh
// source rewrite for every kind; a provider writes the daemon's files and runs
// its commands.
//
// Every command a provider runs gets the caller's context, and an error from
// the executor stays wrapped, so a missing binary stays visible to
// errors.Is(err, exec.ErrNotFound). All methods are safe for concurrent use.
type TunnelProvider interface {
	// Name returns the kind the provider serves: "ipsec" or "openvpn".
	Name() string

	// CreateTunnel brings up the daemon's side of the tunnel cfg describes.
	// A failure leaves no file of the tunnel behind. A daemon the provider
	// starts runs under ctx and ends with it.
	CreateTunnel(ctx context.Context, cfg TunnelConfig) error

	// RemoveTunnel tears down the tunnel with the given id and removes its
	// files. Idempotent: a tunnel the provider holds no file of returns nil.
	RemoveTunnel(ctx context.Context, tunnelID string) error

	// Established reports whether the remote site of the tunnel answers: for
	// ipsec the IKE and child security associations stand, for openvpn the
	// peer is connected. A failed read returns the error.
	Established(ctx context.Context, tunnelID string) (bool, error)

	// Reset removes the files of every tunnel of the provider, also those a
	// process that was killed left behind; the ipsec provider also unloads
	// their connections from strongSwan. A provider without any file
	// returns nil.
	Reset(ctx context.Context) error
}
