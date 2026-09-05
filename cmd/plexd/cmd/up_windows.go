//go:build windows

package cmd

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/packaging"
	"github.com/plexsphere/plexd/internal/policy"
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

// newAccessController creates the Wintun-backed controller for bridge user
// access on Windows. It needs Administrator: creating an adapter is
// privileged, which the LocalSystem service satisfies. The WindowsController
// is its own, so the mesh, the access and the tunnel adapters live in three
// backends, each keyed by the names it created.
//
// The adapter stays unnumbered, as on Linux. Nothing routes over the access
// adapter, and the IP Helper route controller addresses an interface by its
// LUID rather than by an address on it.
func newAccessController(logger *slog.Logger) bridge.AccessController {
	return bridge.NewWGAccessController(wireguard.NewWindowsController(logger), logger)
}

// newVPNController creates the Wintun-backed controller for bridge
// site-to-site tunnels on Windows. It needs Administrator for the same
// reason, and it holds its own WindowsController.
//
// The tunnel adapter stays unnumbered, as on Linux: the route to the remote
// subnet is installed by adapter LUID, so it does not depend on the adapter
// carrying an address. The mesh IP is therefore unused here.
func newVPNController(logger *slog.Logger, _ string) bridge.VPNController {
	return bridge.NewWGVPNController(wireguard.NewWindowsController(logger), "", logger)
}
