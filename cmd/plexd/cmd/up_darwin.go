//go:build darwin

package cmd

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/meshdns"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/packaging"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/tunnel"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// newSystemReader creates the sysctl, Mach and routing-socket backed reader
// for system metrics on macOS. It needs no privilege: every source is readable
// by an unprivileged process.
func newSystemReader(logger *slog.Logger) metrics.SystemReader {
	return metrics.NewDarwinSystemReader(logger, "", "")
}

// newSystemLogSource tails the file launchd writes the daemon's output to
// (the plist's StandardErrorPath) and reads the time and level off each line.
// A console run writes to the terminal instead of to that file, so the source
// then forwards nothing new. It is registered regardless, because the file
// source tolerates an absent file and the daemon is what this serves.
func newSystemLogSource(hostname string, logger *slog.Logger) logfwd.LogSource {
	return logfwd.NewDaemonLogSource(filepath.Join(packaging.DefaultLogDir, packaging.DaemonLogFile), packaging.DefaultServiceName, hostname, logger)
}

// newWGController creates the utun-backed controller for WireGuard on macOS.
// It needs root: creating a utun device is a privileged operation.
func newWGController(logger *slog.Logger) wireguard.WGController {
	return wireguard.NewDarwinController(logger)
}

// newMeshDNSRegistrar returns the registrar that registers the mesh resolver
// with the macOS resolver: it writes the resolver's entries for the search
// domain, the zones, the reverse zones and the forward zones, and with a
// catch-all a default-resolver entry, into configd's dynamic store with
// scutil, under keys plexd owns. It needs root, as plexd on macOS does
// already for its utun.
func newMeshDNSRegistrar(logger *slog.Logger) meshdns.Registrar {
	return meshdns.NewScutilRegistrar(logger)
}

// meshDNSLeftoversOutliveTheRun is true on macOS: the registrar's keys live in
// configd's dynamic store, bound to no interface, so a killed run leaves them
// behind although its utun went with the process. Until the next run's first
// pull they would send the mesh zones, and with a catch-all every other name
// the host looks up, the control plane's own name included, to a resolver
// that holds no names yet and refuses them all.
const meshDNSLeftoversOutliveTheRun = true

// meshDNSListensOnLoopback is true on macOS: a Mac cannot reach its own utun
// mesh IP, because the mesh address's alias makes the route to that IP lead
// into the utun, where wireguard-go drops what the host sends itself
// (measured on the CI macOS runner: route -n get <mesh IP> names the utun,
// and a capture shows mDNSResponder's queries leave through it). The
// resolver therefore listens on 127.0.0.1, which mDNSResponder reaches, and
// the dynamic-store entries name that address.
const meshDNSListensOnLoopback = true

// meshDNSBindHint is logged when the resolver cannot bind its port, which the
// dynamic-store entries name beside the address, so any port works.
const meshDNSBindHint = "set dns.listen_port to a free port"

// policyCapabilityHint is carried by both firewall-baseline failures. Every
// pfctl call that opens /dev/pf answers an unprivileged caller with a bare
// "Permission denied", and an anchor the main ruleset never references loads
// without an error and filters nothing. Neither outcome names what the node is
// missing nor the setting that turns the whole path off, so the operator's two
// next steps go in the message rather than in the source.
const policyCapabilityHint = "policy enforcement needs root and a pf main ruleset that " +
	"references anchor \"com.apple/*\", " +
	"run plexd as root or set policy.enabled: false to run this node without enforcement"

// newFirewallController creates the pf-backed controller for policy
// enforcement on macOS. It needs root: loading an anchor ruleset through
// pfctl(8) is a privileged operation. The same instance carries the bridge NAT
// rule, because pf keeps the translation rule and the policy chains in one
// anchor.
func newFirewallController(logger *slog.Logger, _ string) policy.FirewallController {
	return policy.NewPFController(logger)
}

// newRouteController creates the route(8) and sysctl(8) backed controller for
// bridge routing on macOS. It needs root: altering the routing table and the
// forwarding sysctl are privileged operations.
//
// The pf controller supplies NAT masquerade, so fw doubles as the route
// controller's NAT backend. A nil fw (tests) yields a nil backend and leaves
// AddNATMasquerade failing with bridge.ErrNATUnavailable.
func newRouteController(logger *slog.Logger, fw policy.FirewallController) bridge.RouteController {
	nat, _ := fw.(bridge.NATController)
	return bridge.NewDarwinRouteController(logger, nat)
}

// newMeshRewriter returns nil on macOS: PFController rewrites the source of
// user access and site-to-site traffic in pf, so no device of this process
// needs the in-process rewriter.
func newMeshRewriter(_ bool, _ *slog.Logger) *wireguard.MeshRewriter {
	return nil
}

// newAccessController creates the utun-backed controller for bridge user
// access on macOS. It needs root: creating a utun device is a privileged
// operation. The DarwinController is its own, so the mesh, the access and the
// tunnel devices live in three backends, each keyed by the names it created.
//
// A wireguard provider's utun carries the first address of its pool, which
// the user access manager passes, and the on-link route for the pool, which
// the replies to its devices take. The manager hands the utunN name the
// controller reports to forwarding and to the pf rewrite, and keeps the
// configured name for the device and the status report. The in-process
// rewriter is unused: pf rewrites what leaves the utun.
func newAccessController(logger *slog.Logger, _ *wireguard.MeshRewriter) bridge.AccessController {
	return bridge.NewWGAccessController(wireguard.NewDarwinController(logger), logger)
}

// newMeshSourceRewriter returns the firewall controller: PFController
// rewrites the source of what a user access provider or a site-to-site
// tunnel forwards into the mesh, in the anchor that holds the policy chains
// and the bridge NAT. A fw that implements no MeshSourceRewriter, nil or a
// test's fake, yields an untyped nil, which serves no provider and no tunnel.
// The in-process rewriter plays no part here.
func newMeshSourceRewriter(_ bridge.RouteController, fw policy.FirewallController, _ *wireguard.MeshRewriter) bridge.MeshSourceRewriter {
	if r, ok := fw.(bridge.MeshSourceRewriter); ok {
		return r
	}
	return nil
}

// newTunnelProviders returns no provider on macOS: the xfrm interface of an
// ipsec tunnel and the persistent tun device of an openvpn tunnel are Linux
// kernel features, so such a tunnel reads kind_not_served rather than
// failing its link create. A wireguard tunnel needs no provider.
func newTunnelProviders(_ string, _ *slog.Logger) map[string]bridge.TunnelProvider {
	return nil
}

// newNATExempter returns nil on macOS: the bridge NAT translates only what
// leaves through bridge.access_interface, so it never translates what is
// forwarded between the mesh and a tunnel's link.
func newNATExempter(_ policy.FirewallController) bridge.NATExempter {
	return nil
}

// forwardingKnobIsShared is true on macOS: net.inet.ip.forwarding is one knob
// for the whole host, so the user access and site-to-site managers give back
// each forwarding pair they claim, and the route controller restores the knob
// once the last pair lets go.
const forwardingKnobIsShared = true

// newVPNController creates the utun-backed controller for bridge
// site-to-site tunnels on macOS. It needs root for the same reason, and it
// holds its own DarwinController.
//
// The tunnel utun carries the node's mesh IP as a /32, because route(8)
// refuses a route to the remote subnet over a utun without an IPv4 address
// and reports "Network is unreachable". DarwinController.addOnLinkRoute skips
// the on-link route for a host prefix, so only the alias is programmed
// (ifconfig utunN inet <meshIP>/32 <meshIP> alias), which the kernel accepts
// although the mesh utun already carries that address. That is the
// unnumbered-interface idiom: traffic the node originates towards the remote
// site leaves with the mesh IP as its source, which the remote site routes
// back through the tunnel. An identity without a mesh IP leaves the utun
// unnumbered instead of failing ConfigureAddress on the string "/32". The
// in-process rewriter is unused: pf rewrites what leaves the utun.
func newVPNController(logger *slog.Logger, meshIP string, _ *wireguard.MeshRewriter) bridge.VPNController {
	return bridge.NewWGVPNController(wireguard.NewDarwinController(logger), tunnelAddress(meshIP), logger)
}

// newVPNReaddresser returns the site-to-site follower of a changed mesh
// address on macOS. It gives vpn the new address as the host prefix every
// tunnel utun carries, then has s2s build every wireguard tunnel that is up
// again on it, when the manager exists. A bridge that opts out of
// site-to-site has no manager and creates no tunnel, so only the address
// moves. It returns nil for a controller that cannot change its address.
//
// DECISION: on macOS a site-to-site tunnel is built again, because its utun
// carries the mesh address (newVPNController). Swapping the alias on the
// live utun was rejected: it needs facts about routes over a utun that only
// the CI runner can measure, for a path the stop-and-attempt code of
// SiteToSiteManager already covers.
func newVPNReaddresser(vpn bridge.VPNController, s2s *bridge.SiteToSiteManager) func(context.Context, netip.Addr) error {
	addressed, ok := vpn.(interface{ SetAddress(address string) })
	if !ok {
		return nil
	}
	return func(ctx context.Context, addr netip.Addr) error {
		addressed.SetAddress(tunnelAddress(addr.String()))
		if s2s != nil {
			s2s.Rebuild(ctx)
		}
		return nil
	}
}

// tunnelAddress returns the CIDR a site-to-site tunnel utun carries: the
// node's mesh IP as a host prefix, and nothing for an identity that has no
// mesh IP, which leaves the utun unnumbered rather than failing
// ConfigureAddress on the string "/32".
func tunnelAddress(meshIP string) string {
	if meshIP == "" {
		return ""
	}
	return meshIP + "/32"
}

// newSessionLauncher returns the launcher ssh sessions start their processes
// through: this binary run as `plexd session-helper --child`, trusting the
// verifier's keys. macOS has no helper socket, so the client gets an empty
// path. The child's log lines go through the daemon log writer, which follows
// newsyslog's rotation of the daemon log; on fd 2 they would land in the file
// newsyslog renamed away.
func newSessionLauncher(verifier *api.Ed25519Verifier, logger *slog.Logger) tunnel.SessionLauncher {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	child := func(keys []ed25519.PublicKey) *exec.Cmd {
		cmd := exec.Command(exe, sessionHelperChildArgs(keys)...)
		cmd.Stderr = sessionHelperStderr()
		return cmd
	}
	return tunnel.NewSessionHelperClient("", child, verifier, logger)
}
