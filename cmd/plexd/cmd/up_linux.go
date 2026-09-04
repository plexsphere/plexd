//go:build linux

package cmd

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// newSystemReader creates a LinuxSystemReader on Linux.
func newSystemReader(_ *slog.Logger) metrics.SystemReader {
	return metrics.NewLinuxSystemReader("", "")
}

// newJournalReader creates a JournalctlReader on Linux. It returns nil when
// journalctl is missing so the caller skips the journald log source entirely
// rather than warning about an unusable facility on every collect cycle.
func newJournalReader(logger *slog.Logger) logfwd.JournalReader {
	if !logfwd.JournalctlAvailable() {
		logger.Info("journald not available, journald log source disabled")
		return nil
	}
	return logfwd.NewJournalctlReader()
}

// newWGController creates a NetlinkController for WireGuard on Linux.
func newWGController(logger *slog.Logger) wireguard.WGController {
	return wireguard.NewNetlinkController(logger)
}

// policyCapabilityHint is carried by both firewall-baseline failures. The
// kernel reports a dropped capability as a bare EPERM on a netlink call, which
// names neither what the process is missing nor the setting that turns the
// whole path off, so the operator's two next steps go in the message rather
// than in the source.
const policyCapabilityHint = "policy enforcement needs CAP_NET_ADMIN, " +
	"grant it to the container or set policy.enabled: false to run this node without enforcement"

// newFirewallController creates an NftablesController for policy enforcement on Linux.
func newFirewallController(logger *slog.Logger, _ string) policy.FirewallController {
	return policy.NewNftablesController(logger)
}

// newRouteController creates a NetlinkRouteController for bridge routing on Linux.
func newRouteController(logger *slog.Logger, _ policy.FirewallController) bridge.RouteController {
	return bridge.NewNetlinkRouteController(logger)
}

// newAccessController creates a NetlinkAccessController for user access on Linux.
func newAccessController(logger *slog.Logger) bridge.AccessController {
	return bridge.NewNetlinkAccessController(logger)
}

// newVPNController creates a NetlinkVPNController for site-to-site tunnels on Linux.
func newVPNController(logger *slog.Logger) bridge.VPNController {
	return bridge.NewNetlinkVPNController(logger)
}
