//go:build !linux && !darwin && !windows

package cmd

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/meshdns"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/tunnel"
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

// newMeshDNSRegistrar returns nil on platforms without an implementation,
// which skips the mesh DNS resolver without a log line.
func newMeshDNSRegistrar(_ *slog.Logger) meshdns.Registrar {
	return nil
}

// meshDNSLeftoversOutliveTheRun is false on platforms that register nothing.
const meshDNSLeftoversOutliveTheRun = false

// meshDNSListensOnLoopback is false on platforms that run no resolver.
const meshDNSListensOnLoopback = false

// meshDNSBindHint exists because up.go references it on every platform.
const meshDNSBindHint = "set dns.listen_port to a free port"

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

// newMeshRewriter returns nil on platforms without an implementation.
func newMeshRewriter(_ bool, _ *slog.Logger) *wireguard.MeshRewriter {
	return nil
}

// newAccessController returns nil on platforms without an implementation.
func newAccessController(_ *slog.Logger, _ *wireguard.MeshRewriter) bridge.AccessController {
	return nil
}

// newMeshSourceRewriter returns nil on platforms without an implementation.
func newMeshSourceRewriter(_ bridge.RouteController, _ policy.FirewallController, _ *wireguard.MeshRewriter) bridge.MeshSourceRewriter {
	return nil
}

// newTunnelProviders returns the providers of the site-to-site kinds other
// than wireguard: strongSwan for ipsec, with its connection files in
// swanctlDir, and an openvpn process for openvpn.
func newTunnelProviders(swanctlDir string, logger *slog.Logger) map[string]bridge.TunnelProvider {
	return map[string]bridge.TunnelProvider{
		api.SiteToSiteKindIPsec:   bridge.NewIPsecProvider(bridge.NewStdCommandExecutor(), swanctlDir, logger),
		api.SiteToSiteKindOpenVPN: bridge.NewOpenVPNProvider(bridge.NewStdCommandExecutor(), bridge.DefaultTunnelConfigDir, logger),
	}
}

// newNATExempter returns nil on platforms without an implementation.
func newNATExempter(_ policy.FirewallController) bridge.NATExempter {
	return nil
}

// forwardingKnobIsShared is false on platforms that serve no provider and no
// tunnel.
const forwardingKnobIsShared = false

// newVPNController returns nil on platforms without an implementation.
func newVPNController(_ *slog.Logger, _ string, _ *wireguard.MeshRewriter) bridge.VPNController {
	return nil
}

// newVPNReaddresser returns nil on platforms without an implementation.
func newVPNReaddresser(_ bridge.VPNController, _ *bridge.SiteToSiteManager) func(context.Context, netip.Addr) error {
	return nil
}

// newSessionLauncher returns nil on platforms without an implementation.
func newSessionLauncher(_ *api.Ed25519Verifier, _ *slog.Logger) tunnel.SessionLauncher {
	return nil
}
