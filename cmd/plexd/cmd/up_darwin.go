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

// newFirewallController returns nil until the pf controller lands (#11).
func newFirewallController(_ *slog.Logger) policy.FirewallController {
	return nil
}

// newRouteController returns nil until the macOS route controller lands (#10).
// Bridge mode is unavailable on macOS until then.
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
