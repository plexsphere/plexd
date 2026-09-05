//go:build !linux && !darwin && !windows

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
func newSystemReader(_ *slog.Logger) metrics.SystemReader {
	return nil
}

// newSystemLogSource returns nil on platforms without an implementation.
func newSystemLogSource(_ string, _ *slog.Logger) logfwd.LogSource {
	return nil
}

// newWGController returns nil on platforms without an implementation.
func newWGController(_ *slog.Logger) wireguard.WGController {
	return nil
}

// policyCapabilityHint exists because up.go references it on every platform.
// Without a backend Preflight and ApplyFirewallRules are both no-ops, so
// neither failure path can reach this text: the node comes up unenforced with
// a warning instead. It names only the setting that makes that state
// deliberate, since there is no privilege to grant either.
const policyCapabilityHint = "policy enforcement has no backend on this platform, " +
	"set policy.enabled: false to run this node without enforcement"

// newFirewallController returns nil on platforms without an implementation.
func newFirewallController(_ *slog.Logger, _ string) policy.FirewallController {
	return nil
}

// newRouteController returns nil on platforms without an implementation.
func newRouteController(_ *slog.Logger, _ policy.FirewallController) bridge.RouteController {
	return nil
}

// newAccessController returns nil on platforms without an implementation.
func newAccessController(_ *slog.Logger) bridge.AccessController {
	return nil
}

// newVPNController returns nil on platforms without an implementation.
func newVPNController(_ *slog.Logger, _ string) bridge.VPNController {
	return nil
}
