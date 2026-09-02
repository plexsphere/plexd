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

// newFirewallController returns nil until the WFP controller lands (#11).
func newFirewallController(_ *slog.Logger) policy.FirewallController {
	return nil
}

// newRouteController creates the IP Helper backed controller for bridge
// routing on Windows. It needs Administrator, which the LocalSystem service
// satisfies.
//
// NAT masquerade has no backend yet — those rules belong to the WFP controller
// (#11) — so a bridge on Windows needs bridge.enable_nat: false until it
// lands, and says so when it does not have it.
func newRouteController(logger *slog.Logger) bridge.RouteController {
	return bridge.NewWindowsRouteController(logger, nil)
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
