//go:build !linux && !darwin

package cmd

import (
	"log/slog"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// newSystemReader returns nil on platforms without an implementation.
func newSystemReader() metrics.SystemReader {
	return nil
}

// newJournalReader returns nil on platforms without an implementation.
func newJournalReader(_ *slog.Logger) logfwd.JournalReader {
	return nil
}

// newWGController returns nil on platforms without an implementation.
func newWGController(_ *slog.Logger) wireguard.WGController {
	return nil
}

// newFirewallController returns nil on platforms without an implementation.
func newFirewallController(_ *slog.Logger) policy.FirewallController {
	return nil
}

// newRouteController returns nil on platforms without an implementation.
func newRouteController(_ *slog.Logger) bridge.RouteController {
	return nil
}

// newAccessController returns nil on platforms without an implementation.
func newAccessController(_ *slog.Logger) bridge.AccessController {
	return nil
}

// newVPNController returns nil on platforms without an implementation.
func newVPNController(_ *slog.Logger) bridge.VPNController {
	return nil
}
