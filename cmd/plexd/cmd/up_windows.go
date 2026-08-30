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

// newRouteController returns nil until the Windows route controller lands
// (#10). Bridge mode is unavailable on Windows until then.
func newRouteController(_ *slog.Logger) bridge.RouteController {
	return nil
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
