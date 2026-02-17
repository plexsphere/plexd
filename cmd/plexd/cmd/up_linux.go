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
func newSystemReader() metrics.SystemReader {
	return metrics.NewLinuxSystemReader("", "")
}

// newJournalReader creates a JournalctlReader on Linux.
func newJournalReader() logfwd.JournalReader {
	return logfwd.NewJournalctlReader()
}

// newWGController creates a NetlinkController for WireGuard on Linux.
func newWGController(logger *slog.Logger) wireguard.WGController {
	return wireguard.NewNetlinkController(logger)
}

// newFirewallController creates an NftablesController for policy enforcement on Linux.
func newFirewallController(logger *slog.Logger) policy.FirewallController {
	return policy.NewNftablesController(logger)
}

// newRouteController creates a NetlinkRouteController for bridge routing on Linux.
func newRouteController(logger *slog.Logger) bridge.RouteController {
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
