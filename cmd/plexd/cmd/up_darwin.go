//go:build darwin

package cmd

import (
	"crypto/ed25519"
	"log/slog"
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

// newAccessController creates the utun-backed controller for bridge user
// access on macOS. It needs root: creating a utun device is a privileged
// operation. The DarwinController is its own, so the mesh, the access and the
// tunnel devices live in three backends, each keyed by the names it created.
//
// The access utun stays unnumbered. User access needs forwarding between the
// access and the mesh interface, and no route is installed over the device.
func newAccessController(logger *slog.Logger) bridge.AccessController {
	return bridge.NewWGAccessController(wireguard.NewDarwinController(logger), logger)
}

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
// unnumbered instead of failing ConfigureAddress on the string "/32".
func newVPNController(logger *slog.Logger, meshIP string) bridge.VPNController {
	return bridge.NewWGVPNController(wireguard.NewDarwinController(logger), tunnelAddress(meshIP), logger)
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
