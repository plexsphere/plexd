//go:build linux

package cmd

import (
	"crypto/ed25519"
	"log/slog"
	"os"
	"os/exec"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/meshdns"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/tunnel"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// newSystemReader creates a LinuxSystemReader on Linux.
func newSystemReader(_ *slog.Logger) metrics.SystemReader {
	return metrics.NewLinuxSystemReader("", "")
}

// newSystemLogSource builds the journald source on Linux. It returns nil when
// journalctl is missing so the caller skips the journald log source entirely
// rather than warning about an unusable facility on every collect cycle.
func newSystemLogSource(hostname string, logger *slog.Logger) logfwd.LogSource {
	if !logfwd.JournalctlAvailable() {
		logger.Info("journald not available, journald log source disabled")
		return nil
	}
	return logfwd.NewJournaldSource(logfwd.NewJournalctlReader(), hostname, logger)
}

// newWGController creates a NetlinkController for WireGuard on Linux.
func newWGController(logger *slog.Logger) wireguard.WGController {
	return wireguard.NewNetlinkController(logger)
}

// newMeshDNSRegistrar returns the registrar that registers the mesh resolver
// with systemd-resolved over D-Bus. It opens no connection here: each Apply and
// Revert opens its own, so a host without the bus or without systemd-resolved
// still runs the resolver and learns that on the first pull.
func newMeshDNSRegistrar(logger *slog.Logger) meshdns.Registrar {
	return meshdns.NewResolvedRegistrar(logger)
}

// meshDNSLeftoversOutliveTheRun is false on Linux: the registration lives on
// the mesh interface's link, and a start whose resolver listens has just
// created that link, so nothing a killed run registered is left to remove.
const meshDNSLeftoversOutliveTheRun = false

// meshDNSListensOnLoopback is false on Linux: systemd-resolved sends a query
// for a per-link server out through the mesh link, so only a listener on the
// node's own mesh IP is reached, which the kernel delivers locally.
const meshDNSListensOnLoopback = false

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

// newVPNController creates a NetlinkVPNController for site-to-site tunnels on
// Linux. The mesh IP is unused: the tunnel link stays unnumbered, because a
// netlink route names the link itself.
func newVPNController(logger *slog.Logger, _ string) bridge.VPNController {
	return bridge.NewNetlinkVPNController(logger)
}

// newSessionLauncher returns the launcher ssh sessions start their processes
// through: plexd-session-helper.socket when it listens, else this binary run
// as `plexd session-helper --child`, trusting the verifier's keys.
//
// Under systemd plexd runs sandboxed, and a child helper inherits the sandbox:
// its shells cannot switch users. A missing socket there is a unit that was
// not installed, so it is warned about once.
func newSessionLauncher(verifier *api.Ed25519Verifier, logger *slog.Logger) tunnel.SessionLauncher {
	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}
	child := func(keys []ed25519.PublicKey) *exec.Cmd {
		cmd := exec.Command(exe, sessionHelperChildArgs(keys)...)
		cmd.Stderr = sessionHelperStderr()
		return cmd
	}
	if os.Getenv("INVOCATION_ID") != "" {
		if info, err := os.Stat(tunnel.DefaultSessionHelperSocket); err != nil || info.Mode()&os.ModeSocket == 0 {
			logger.Warn("plexd-session-helper.socket is not listening; ssh sessions run inside plexd's own sandbox and cannot switch users",
				"socket", tunnel.DefaultSessionHelperSocket,
			)
		}
	}
	return tunnel.NewSessionHelperClient(tunnel.DefaultSessionHelperSocket, child, verifier, logger)
}
