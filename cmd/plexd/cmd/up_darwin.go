//go:build darwin

package cmd

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// newSystemReader returns nil until the macOS metrics reader lands (#13).
func newSystemReader() metrics.SystemReader {
	return nil
}

// newJournalReader returns nil until macOS log forwarding lands (#14). The
// launchd daemon writes to a file, which the existing file source reads.
func newJournalReader(_ *slog.Logger) logfwd.JournalReader {
	return nil
}

// newWGController creates the utun-backed controller for WireGuard on macOS.
// It needs root: creating a utun device is a privileged operation.
func newWGController(logger *slog.Logger) wireguard.WGController {
	return wireguard.NewDarwinController(logger)
}

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
