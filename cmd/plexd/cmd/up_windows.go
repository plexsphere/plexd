//go:build windows

package cmd

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// newSystemReader returns nil until the Windows metrics reader lands (#13).
func newSystemReader() metrics.SystemReader {
	return nil
}

// newJournalReader returns nil until Windows log forwarding lands (#14). The
// service writes to the Application Event Log, which no source reads yet.
func newJournalReader(_ *slog.Logger) logfwd.JournalReader {
	return nil
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

// newAccessController returns nil until the bridge user-access controller
// lands (#12).
func newAccessController(_ *slog.Logger) bridge.AccessController {
	return nil
}

// newVPNController returns nil until the bridge site-to-site controller lands
// (#12).
func newVPNController(_ *slog.Logger) bridge.VPNController {
	return nil
}
