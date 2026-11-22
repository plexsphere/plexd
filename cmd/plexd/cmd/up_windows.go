//go:build windows

package cmd

import (
	"log/slog"

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

// newSystemReader creates the kernel32 and IP Helper backed reader for system
// metrics on Windows. It needs no privilege: every source is readable by an
// unprivileged process.
func newSystemReader(logger *slog.Logger) metrics.SystemReader {
	return metrics.NewWindowsSystemReader(logger, "", "")
}

// newSystemLogSource reads the events the service writes under provider plexd
// to the Application log. A console run logs to stderr instead of to the Event
// Log, so the source then forwards only what the service wrote.
func newSystemLogSource(hostname string, logger *slog.Logger) logfwd.LogSource {
	return logfwd.NewEventLogSource(logfwd.NewWevtapiReader(packaging.DefaultServiceName, logger), hostname)
}

// newWGController creates the Wintun-backed controller for WireGuard on
// Windows. It needs Administrator: creating an adapter is privileged, which
// the LocalSystem service satisfies.
func newWGController(logger *slog.Logger) wireguard.WGController {
	return wireguard.NewWindowsController(logger)
}

// newMeshDNSRegistrar returns the registrar that registers the mesh resolver
// with the Windows DNS Client through the Name Resolution Policy Table: it
// writes rules for the search domain, the zones, the reverse zones and the
// forward zones, and with a catch-all a rule for every name, into the
// registry under keys plexd owns, into the Group Policy store too while
// Group Policy configures the table, and sets the search domain as the mesh
// adapter's search list. It needs Administrator, which the LocalSystem
// service satisfies.
func newMeshDNSRegistrar(logger *slog.Logger) meshdns.Registrar {
	return meshdns.NewNRPTRegistrar(logger)
}

// meshDNSLeftoversOutliveTheRun is true on Windows: the registrar's rule keys
// are bound to no interface, so a killed run leaves them behind until the
// next reboot although its adapter went with the process, and the adapter's
// search list stays in the registry, keyed by the GUID that adapterGUID
// derives from the interface name, so the next run's adapter inherits it.
// Until the next run's first pull the rules would send the mesh zones, and
// with a catch-all every other name the host looks up, the control plane's
// own name included, to a resolver that holds no names yet and refuses them
// all.
const meshDNSLeftoversOutliveTheRun = true

// meshDNSListensOnLoopback is true on Windows. plexd's WFP filters match the
// mesh adapter's LUID, and nothing documents whether WFP counts a local query
// to the mesh IP as arriving on that adapter, where a Domain's default deny
// would drop it. No plexd filter can match a query to 127.0.0.1, so the
// resolver listens there and the Name Resolution Policy Table rules name that
// address, on port 53, the only port the DNS Client sends a rule's queries
// to.
const meshDNSListensOnLoopback = true

// meshDNSBindHint is logged when the resolver cannot bind its port. On Windows
// the port is 53, because the DNS Client sends a rule's queries nowhere else,
// so the way out is freeing it or turning the resolver off.
const meshDNSBindHint = "free port 53 on 127.0.0.1, the only port the Name Resolution Policy Table sends to, " +
	"or set dns.enabled: false"

// policyCapabilityHint is carried by both firewall-baseline failures. The
// filter engine answers an unprivileged caller with ERROR_ACCESS_DENIED, whose
// message is a bare "Access is denied" that names neither the privilege the
// call wanted nor the setting that turns the whole path off, so the operator's
// two next steps go in the message rather than in the source.
const policyCapabilityHint = "policy enforcement needs Administrator, " +
	"run plexd elevated or as the LocalSystem service, " +
	"or set policy.enabled: false to run this node without enforcement"

// newFirewallController creates the WFP-backed controller for policy
// enforcement on Windows. It needs Administrator, which the LocalSystem
// service satisfies. meshIface is the adapter the mesh prefix sits on, which
// the filters and the same instance's bridge NAT rule bind to.
func newFirewallController(logger *slog.Logger, meshIface string) policy.FirewallController {
	return policy.NewWFPController(logger, meshIface)
}

// newRouteController creates the IP Helper backed controller for bridge
// routing on Windows. It needs Administrator, which the LocalSystem service
// satisfies.
//
// The WFP controller supplies NAT masquerade through WinNAT, so fw doubles as
// the route controller's NAT backend. A nil fw (tests) yields a nil backend
// and leaves AddNATMasquerade failing with bridge.ErrNATUnavailable.
func newRouteController(logger *slog.Logger, fw policy.FirewallController) bridge.RouteController {
	nat, _ := fw.(bridge.NATController)
	return bridge.NewWindowsRouteController(logger, nat)
}

// The in-process rewriter stands in for the kernel rewrites of Linux and
// macOS, and the WFP controller exempts a tunnel's adapter from the bridge
// NAT. internal/wireguard and internal/policy do not import internal/bridge,
// so the compiler checks both interfaces here, beside the wiring.
var (
	_ bridge.MeshSourceRewriter = (*wireguard.MeshRewriter)(nil)
	_ bridge.NATExempter        = (*policy.WFPController)(nil)

	// up.go hands the rewriter to the mesh controller through an assertion
	// to this interface, which turns false without an error when the
	// signature of SetMeshRewriter drifts. The mesh device would then run
	// unwrapped, and every wireguard provider and tunnel would fail its
	// rewrite with "the mesh interface is no device of this process", so the
	// compiler checks the controller against it here.
	_ interface{ SetMeshRewriter(*wireguard.MeshRewriter) } = (*wireguard.WindowsController)(nil)
)

// newMeshRewriter returns the rewriter of a Windows bridge that serves user
// access or site-to-site, and nil when serves is false. It rewrites, inside
// the process, the source of what a wireguard provider's or a wireguard
// tunnel's far end sends into the mesh to the bridge's mesh address, between
// plexd's own wireguard-go devices: Windows has no kernel mechanism that fits,
// since WinNAT translates nothing into the mesh beside the bridge NAT's object
// for the mesh prefix, and what it translates passes no WFP forward filter.
// Every device the rewriter knows runs over its wrapper, which copies each
// packet, so no other Windows node is given one.
func newMeshRewriter(serves bool, logger *slog.Logger) *wireguard.MeshRewriter {
	if !serves {
		return nil
	}
	return wireguard.NewMeshRewriter(logger)
}

// newRewritingWindowsController returns a WindowsController of its own whose
// adapters run over rewriter's wrapper, so the rewriter knows them, or plain
// adapters when rewriter is nil.
func newRewritingWindowsController(logger *slog.Logger, rewriter *wireguard.MeshRewriter) *wireguard.WindowsController {
	ctrl := wireguard.NewWindowsController(logger)
	if rewriter != nil {
		ctrl.SetMeshRewriter(rewriter)
	}
	return ctrl
}

// newAccessController creates the Wintun-backed controller for bridge user
// access on Windows. It needs Administrator: creating an adapter is
// privileged, which the LocalSystem service satisfies. The WindowsController
// is its own, so the mesh, the access and the tunnel adapters live in three
// backends, each keyed by the names it created, and with a rewriter it wraps
// every adapter it creates, as the mesh controller does.
//
// A wireguard provider's adapter carries the first address of its pool,
// which the user access manager passes, and Windows installs the on-link
// route for the pool, which the replies to its devices take. The rewriter
// reads that prefix: what a device sends to an address in it is for the host,
// and what it sends into the mesh is translated and handed to the mesh
// device in the process. The IP Helper route controller addresses the
// adapter by its LUID rather than by an address on it.
func newAccessController(logger *slog.Logger, rewriter *wireguard.MeshRewriter) bridge.AccessController {
	return bridge.NewWGAccessController(newRewritingWindowsController(logger, rewriter), logger)
}

// newMeshSourceRewriter returns the in-process rewriter newMeshRewriter
// built: it serves the three user access kinds and wireguard tunnels on a
// Windows bridge. A wireguard provider and a wireguard tunnel are translated
// between their device and the mesh device. A tailscale or netbird provider
// gets no rewrite, because its vendor client's adapter is no device of this
// process, and both vendors document that what their Windows client forwards
// leaves with the host's address. A nil rewriter yields an untyped nil, never
// a typed nil in the interface, which serves no provider and no tunnel.
func newMeshSourceRewriter(_ bridge.RouteController, _ policy.FirewallController, rewriter *wireguard.MeshRewriter) bridge.MeshSourceRewriter {
	if rewriter == nil {
		return nil
	}
	return rewriter
}

// newNATExempter returns the firewall controller as the exempter of each
// site-to-site tunnel's adapter from the bridge NAT: while the NetNat object
// of the bridge NAT covers the mesh prefix, WFPController gives the adapter a
// 169.254 /30 and a NetNat object of its own, so what a mesh node sends to
// the site keeps its source and stays under the bridge's policy. A fw that
// implements no NATExempter, nil or a test's fake, yields an untyped nil.
func newNATExempter(fw policy.FirewallController) bridge.NATExempter {
	if e, ok := fw.(bridge.NATExempter); ok {
		return e
	}
	return nil
}

// newTunnelProviders builds no ipsec and no openvpn provider on Windows, as
// on macOS: the xfrm interface of an ipsec tunnel and the persistent tun
// device of an openvpn tunnel are Linux kernel features, so such a tunnel
// reads kind_not_served rather than failing its link create. A wireguard
// tunnel needs no provider.
func newTunnelProviders(_ string, _ *slog.Logger) map[string]bridge.TunnelProvider {
	return nil
}

// forwardingKnobIsShared is false on Windows: the user access and
// site-to-site managers claim the forwarding flags of the mesh adapter and of
// each provider's and tunnel's adapter, and give none back. A provider's or
// a tunnel's adapter goes with the provider or the tunnel and the mesh
// adapter with the process, and a release after the adapter is gone would
// fail on its LUID. A vendor client's adapter keeps the flag plexd set, as
// tailscale0 does on Linux.
const forwardingKnobIsShared = false

// newVPNController creates the Wintun-backed controller for bridge
// site-to-site tunnels on Windows. It needs Administrator for the same
// reason, and it holds its own WindowsController, which with a rewriter wraps
// every adapter it creates, so a wireguard tunnel's far end is translated
// into the mesh in the process.
//
// The controller leaves the tunnel adapter unnumbered, as on Linux: the route
// to the remote subnet is installed by adapter LUID, so it does not depend on
// the adapter carrying an address. The mesh IP is therefore unused here.
// While the bridge NAT's NetNat object covers the mesh prefix, the
// site-to-site manager's NAT exempter gives the adapter a 169.254 /30 of its
// own before forwarding is switched on.
func newVPNController(logger *slog.Logger, _ string, rewriter *wireguard.MeshRewriter) bridge.VPNController {
	return bridge.NewWGVPNController(newRewritingWindowsController(logger, rewriter), "", logger)
}

// newSessionLauncher returns nil: mediated ssh sessions are served on Linux
// only, so ssh entries stay settled as unsupported on Windows.
func newSessionLauncher(_ *api.Ed25519Verifier, _ *slog.Logger) tunnel.SessionLauncher {
	return nil
}
