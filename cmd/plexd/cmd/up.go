package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/actions"
	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/auditfwd"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/health"
	"github.com/plexsphere/plexd/internal/integrity"
	"github.com/plexsphere/plexd/internal/kubernetes"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/nodeapi"
	"github.com/plexsphere/plexd/internal/packaging"
	"github.com/plexsphere/plexd/internal/peerexchange"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/tunnel"
	"github.com/plexsphere/plexd/internal/upgrade"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// drainTimeout is the maximum time for graceful shutdown.
const drainTimeout = 30 * time.Second

// sessionEndedReportTimeout bounds a single session_ended report. Sessions are
// closed one after another on shutdown, so this also bounds how long tunnel
// teardown can hold up the drain.
const sessionEndedReportTimeout = 2 * time.Second

// firewallController indirects the platform-specific constructor so tests can
// drive the pre-flight path without depending on the host's netfilter state.
var firewallController = newFirewallController

// wgController indirects the platform-specific constructor so tests can pin a
// failed WireGuard setup without depending on the host's privilege: the
// Windows runner is elevated, and Wintun creates an adapter under any name a
// test configures, the loopback's included.
var wgController = newWGController

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the plexd agent",
	Long: "Start the plexd agent daemon. Registers with the control plane,\n" +
		"connects to the SSE event stream, and enters steady state.",
	RunE: runUp,
}

func init() {
	rootCmd.AddCommand(upCmd)
}

// runUp resolves the context the agent runs under and hands it to runAgent,
// unless the process was started by the host's service manager as a service. On
// Windows that means the Service Control Manager, which needs the status
// protocol runAsService implements; everywhere else runAsService declines and
// the agent runs in the foreground, which is what a systemd or launchd daemon
// is.
func runUp(cmd *cobra.Command, _ []string) error {
	// The command's context is the parent, so a caller that owns one can shut
	// the daemon down without a signal. Under Execute that context is always
	// non-nil; a direct call (a test) may leave it unset.
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}

	// This has to precede setupLogger, which runAgent calls, because it decides
	// what that logger writes through. It changes nothing unless stderr is the
	// service manager's own log file. The writer is closed on the way out; a
	// line logged after that reopens the path, so nothing is lost.
	if w := useDaemonLogFile(); w != nil {
		defer func() { _ = w.Close() }()
	}

	if handled, err := runAsService(runAgent); handled {
		return err
	}
	return runAgent(parent)
}

// runAgent is the agent itself, from the configuration load to the last log
// line. It ends when ctx is cancelled.
func runAgent(ctx context.Context) error {
	// 1. Parse config and merge the flag and environment overrides on top.
	cfg, cfgFound, err := loadMergedConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("plexd up: %w", err)
	}

	// 2. Set up structured logger.
	logger := setupLogger(cfg.LogLevel)

	// Validate the merged result, not the file: a required value may come from
	// any layer. The warning goes out first so a missing file is named even
	// when validation then fails on a value that file would have supplied.
	warnIfConfigAbsent(cfgFound, cfgFile, cfg.DataDir)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("plexd up: %w", err)
	}

	// actions_enabled is reported because nothing else announces it. It is the
	// only switch that stops the control plane from running commands and hooks
	// on this node, it defaults to on, and it is reached from three layers
	// (file, absent-file fallback, PLEXD_ACTIONS_ENABLED) — so the effective
	// value belongs in the startup record rather than in an operator's head.
	logger.Info("starting plexd",
		"version", buildVersion,
		"mode", cfg.Mode,
		"actions_enabled", cfg.Actions.IsEnabled(),
	)

	// 2a. Build the policy enforcer and pre-flight its firewall backend before
	// anything reaches the control plane. Installing the deny-by-default
	// baseline is fatal (step 5c) but happens after registration, which spends a
	// one-shot bootstrap token and persists the identity the control plane hands
	// back — so without this check a node that can never install a chain claims
	// an identity it will never use, and then crash-loops on the same step
	// forever. Where data_dir is ephemeral (a Pod without a persistent volume, a
	// fresh VM image) the restart has no identity to reload and no unspent token
	// to register with either, which strands the deployment until an operator
	// issues a new one.
	//
	// The probe changes no kernel state and is a no-op whenever the baseline
	// install would be one, so this is an early exit for the fatal case only —
	// the enforcement itself stays where it was.
	policyEngine := policy.NewPolicyEngine(logger)
	// The argument is the Windows adapter name the WinNAT source prefix is read
	// from, and there the configured name is the kernel's. macOS and Linux
	// discard it: their rules take policyIface further down, which wgMgr cannot
	// supply yet — it does not exist this early.
	fwCtrl := firewallController(logger, cfg.WireGuard.InterfaceName)
	enforcer := policy.NewEnforcer(policyEngine, fwCtrl, cfg.Policy, logger)
	if err := enforcer.Preflight(); err != nil {
		return fmt.Errorf("plexd up: firewall baseline pre-flight: %s: %w", policyCapabilityHint, err)
	}

	// 3. Create control plane client.
	client, err := api.NewControlPlane(cfg.API, buildVersion, logger)
	if err != nil {
		return fmt.Errorf("plexd up: create client: %w", err)
	}

	// 4. Register (or load existing identity).
	registrar := newRegistrar(client, cfg.Registration, logger)

	// Under a service manager no signal arrives and this call is harmless; in
	// the foreground it is how Ctrl-C and systemd's SIGTERM reach the drain.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Wait group for all goroutines.
	var wg sync.WaitGroup

	// 4a. Start the health listener before registration begins, so a probe
	// issued during a slow first registration sees 200 on /healthz and 503 on
	// /readyz rather than a connection refused (which the kubelet treats as a
	// liveness failure and restarts the container mid-registration).
	var healthSrv *health.Server
	if cfg.Health.IsEnabled() {
		healthSrv = health.NewServer(cfg.Health, logger)
		healthLn, err := healthSrv.Listen()
		if err != nil {
			// Under hostNetwork: true the address lives in the node's global
			// port space, shared with every other host-networked workload, so
			// a collision is the likely cause and worth naming: the container
			// exits and the failure otherwise reads as a plexd bug.
			return fmt.Errorf("plexd up: health listener cannot bind %s (port already in use on the host network?): %w", cfg.Health.Listen, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := healthSrv.Serve(ctx, healthLn); err != nil && ctx.Err() == nil {
				// Every other terminal subsystem failure is routed to readiness
				// so the kubelet does not restart the node and tear its data
				// plane down. This one cannot be: without a listener there is no
				// probe target at all, the kubelet fails liveness three times and
				// restarts the container anyway. Cancelling the root context
				// makes that shutdown deliberate and logged, instead of a
				// connection-refused 90 seconds later with no trace of the cause.
				logger.Error("health listener stopped, terminating", "error", err)
				stop()
			}
		}()
	}

	identity, err := registrar.Register(ctx)
	if err != nil {
		return fmt.Errorf("plexd up: registration: %w", err)
	}

	logger.Info("registered",
		"node_id", identity.NodeID,
		"mesh_ip", identity.MeshIP,
	)

	// The health listener reports ready only once the node holds a registered
	// identity. Register returns a persisted identity without a network
	// round-trip on restart, so this also covers the restart case.
	if healthSrv != nil {
		healthSrv.SetRegistered()
	}

	// The bearer credential is deliberately not set here. Register arms the
	// shared client with the bearer envelope on both of its paths — resumed
	// identity and fresh registration — and that envelope is the only credential
	// the control plane admits (see NodeIdentity.BearerToken). Re-arming it from
	// identity.NodeSecretKey, the raw base64 nsk, is answered with 401 on every
	// subsequent call, which is what this line used to do.

	// 5. Create Ed25519 verifier from the control plane's signing public key.
	sigKey, err := base64.StdEncoding.DecodeString(identity.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("plexd up: decode signing key: %w", err)
	}
	if len(sigKey) != ed25519.PublicKeySize {
		return fmt.Errorf("plexd up: invalid signing key length: got %d, want %d", len(sigKey), ed25519.PublicKeySize)
	}
	verifier := api.NewEd25519Verifier(identity.SigningKeyID, ed25519.PublicKey(sigKey))

	// 5a. Initialize WireGuard subsystem.
	wgCtrl := wgController(logger)
	wgMgr := wireguard.NewManager(wgCtrl, cfg.WireGuard, logger)
	wgReady := false
	if wgCtrl != nil {
		// Setup sizes the interface to what the uplink carries, measured with
		// the STUN servers NAT discovery uses, unless wireguard.mtu pins it.
		if probe := meshMTUProbe(cfg.NAT); probe != nil {
			wgMgr.SetPathMTUProbe(probe)
		} else if cfg.WireGuard.MTU == 0 {
			logger.Info("mesh mtu detection disabled by nat.enabled")
		}
		if err := wgMgr.Setup(ctx, identity); err != nil {
			logger.Warn("wireguard setup failed, continuing without WireGuard",
				"error", err,
			)
		} else {
			wgReady = true
		}
	}

	// 5a-1. Edge PSKs. With the interface up, plexd fetches each edge's PSK and
	// programs it on the peer, unless wireguard.edge_psk turns that off for a
	// rolling upgrade: WireGuard needs the same PSK on both ends of a tunnel, so
	// an edge to a node that installs none fails until both ends match.
	var edgePSKs *wireguard.EdgePSKs
	if wgReady {
		if cfg.WireGuard.EdgePSKEnabled() {
			if nsk, err := identity.SecretKey(); err != nil {
				logger.Warn("edge psk disabled, the node secret key does not decode", "error", err)
			} else {
				edgePSKs = wireguard.NewEdgePSKs(client, identity.NodeID, nsk, wgMgr, logger)
				clear(nsk)
			}
		} else {
			logger.Info("edge psk disabled by wireguard.edge_psk")
		}
	}

	// 5a-2. Local endpoint candidates. The candidate publisher (step 24a)
	// reports this node's interface addresses, and the WireGuard reconcile
	// handler orders a peer's candidates on a subnet this node shares first.
	// Both read the interfaces through one filter, which leaves out the mesh
	// interface under both its names and every address of the mesh prefix:
	// a peer dialing one of those would route WireGuard into its own tunnel.
	var candidateFilter nat.CandidateFilter
	if wgReady {
		candidateFilter = nat.CandidateFilter{
			Interfaces:        cfg.NAT.CandidateInterfaces,
			ExcludeInterfaces: []string{cfg.WireGuard.InterfaceName, wgMgr.OSInterfaceName()},
			ExcludePrefix:     wgMgr.MeshPrefix(),
		}
		wgMgr.SetLocalPrefixes(func() ([]netip.Prefix, error) {
			ifaces, err := nat.SystemInterfaces()
			if err != nil {
				return nil, err
			}
			return nat.EligiblePrefixes(ifaces, candidateFilter), nil
		})
	}

	// 5b. Initialize NAT traversal and peer exchange.
	stunClient := &nat.UDPSTUNClient{Timeout: cfg.NAT.Timeout}
	natDiscoverer := nat.NewDiscoverer(stunClient, cfg.NAT, cfg.WireGuard.ListenPort, logger)
	exchanger := peerexchange.NewExchanger(natDiscoverer, client, cfg.PeerExchange, logger)

	// The policy enforcer addresses the interface by the name the kernel knows
	// it by: pf on macOS matches its rules against the utunN the controller
	// created, not against the configured plexd0. OSInterfaceName returns the
	// configured name on every other platform, so the baseline below and the
	// reconcile handler further down take one name everywhere.
	policyIface := wgMgr.OSInterfaceName()

	// 5c. Install the deny-by-default baseline immediately, independent of the
	// reconcile diff. A nil policy yields a default-deny-only ruleset, so the
	// node is never left unfiltered while waiting for the control plane to
	// publish its first policy revision (the differ short-circuits when both
	// snapshots lack a policy block, so the reconcile handler alone would never
	// install a chain). The reconcile handler replaces this baseline once a
	// policy revision arrives.
	//
	// Failure aborts startup. ApplyFirewallRules only returns an error once
	// enforcement was actually requested and a backend exists — the disabled
	// and no-backend cases are no-ops that return nil — so continuing here
	// would bring up WireGuard and join the mesh with no chain installed,
	// exactly the unfiltered state this call exists to prevent.
	//
	// The pre-flight probe in step 2a already cleared the backend, so reaching
	// this failure means the capability was lost between the two calls or the
	// chain itself was refused. It carries the same hint regardless: the operator
	// reading this line has the same two options either way.
	//
	// Gated on the device being this node's mesh interface, not on wgReady:
	// Manager.Setup creates the interface before any of the steps that can fail
	// and rolls none of them back, so a failed setup regularly leaves the
	// device behind — on Linux it usually fails because the device is already
	// there, EEXIST from a run whose teardown never got to it. That node peers,
	// carries mesh traffic and would run unfiltered for the rest of its life:
	// the reconcile handler short-circuits while the policy revision is
	// unchanged, so nothing installs the chain afterwards.
	//
	// The mesh address is what proves the device is ours, and a name alone
	// proves nothing: wireguard.Config never asks whether the configured name
	// is free, so a copy-pasted eth0 or a name a VPN already holds resolves
	// here exactly as a leftover plexd0 does — and this baseline is
	// deny-by-default, so installing it on the node's uplink drops every
	// packet that host forwards.
	//
	// A name this node's mesh address does not answer to is skipped, which is
	// also the Windows case this gate exists for: the backend resolves the
	// adapter through the OS and refuses a chain naming one that was never
	// created, turning a warning macOS and Linux both survive into a fatal
	// abort reported under a hint about Administrator that names the wrong
	// cause. Failing to read the interface table is not that case and aborts:
	// the read is a netlink dump on Linux and answers ENOBUFS on a node with a
	// large, churning link table, so treating it as an absent interface would
	// leave exactly the unfiltered node this call exists to prevent.
	installBaseline := true
	if cfg.Policy.IsEnabled() && !wgReady {
		owned, err := meshInterfaceOwned(policyIface, identity.MeshIP)
		if err != nil {
			return fmt.Errorf("plexd up: resolve the mesh interface for the firewall baseline: %s: %w", policyCapabilityHint, err)
		}
		if !owned {
			logger.Warn("no interface carries the mesh address under the mesh name, skipping the firewall baseline",
				"interface", policyIface,
				"mesh_ip", identity.MeshIP,
			)
			installBaseline = false
		}
	}
	if installBaseline {
		if _, err := enforcer.ApplyFirewallRules(nil, policyIface); err != nil {
			return fmt.Errorf("plexd up: install deny-by-default firewall baseline: %s: %w", policyCapabilityHint, err)
		}
	}

	// The mesh data plane is complete only here: the interface is up and the
	// baseline chain is installed. Readiness is announced at this point rather
	// than next to SetRegistered above, because WireGuard setup failure is
	// non-fatal by design — without this gate a node whose interface never came
	// up would report ready for the rest of its life, and a rolling update
	// would march across the fleet leaving no node with a tunnel.
	//
	// The announcement is a latch, so readiness also gets a check that a
	// background poller re-runs: the interface is kernel state that outlives this
	// function and other actors delete it (a node admin, a kernel upgrade that
	// drops the wireguard module). Without the check a node that lost its tunnel
	// hours after startup keeps reporting ready and the next rolling update
	// sweeps the fleet anyway. The poller is what keeps the cost fixed —
	// net.InterfaceByName dumps the node's whole interface table (one entry per
	// pod veth, bridge and tunnel) and scans it for the name, so running it per
	// probe would let anyone reaching the unauthenticated port drive that dump.
	//
	// The name resolved here is the operating system's, not the configured one:
	// on macOS the controller creates a utun the kernel calls utunN, and that
	// is what net.InterfaceByName finds.
	if healthSrv != nil && wgReady {
		iface := wgMgr.OSInterfaceName()
		healthSrv.SetDataPlaneCheck(ctx, func() error {
			link, err := net.InterfaceByName(iface)
			if err != nil {
				return fmt.Errorf("wireguard interface %s: %w", iface, err)
			}
			if link.Flags&net.FlagUp == 0 {
				return fmt.Errorf("wireguard interface %s is down", iface)
			}
			return nil
		})
		healthSrv.SetDataPlaneReady()
	}

	// 5d. Initialize tunnel subsystem.
	hostKey, err := tunnel.LoadOrGenerateHostKey(cfg.DataDir, logger)
	if err != nil {
		return fmt.Errorf("plexd up: tunnel host key: %w", err)
	}
	jwtVerifier := tunnel.NewEd25519JWTVerifier(ed25519.PublicKey(sigKey))
	meshServer := tunnel.NewMeshServer(cfg.Tunnel, identity.MeshIP, hostKey, jwtVerifier, logger)
	sessionReporter := &controlPlaneSessionReporter{cp: client, nodeID: identity.NodeID}

	// Report a session_ended row for every close reason (revoke, TTL expiry,
	// local close, node shutdown) via the manager's on-closed callback. The row
	// is the only carrier of a session's byte counters, so the shutdown path
	// must report it too — and by then ctx is already cancelled, hence the
	// detached, bounded context.
	meshServer.SessionManager().SetOnClosed(func(sessionID, reason string, info *tunnel.ClosedSessionInfo) {
		reportCtx, cancelReport := context.WithTimeout(context.WithoutCancel(ctx), sessionEndedReportTimeout)
		defer cancelReport()
		sessionReporter.ReportSessionEnded(reportCtx, sessionID, info, tunnel.TerminatedByFromReason(reason))
	})

	// Mediated ssh sessions start their processes through the session helper,
	// which Linux and macOS have. Elsewhere ssh entries stay settled as
	// unsupported. A node that serves no ssh sessions skips the wiring, and
	// with it the warning about a missing helper socket; the manager settles
	// its ssh entries as disabled.
	if cfg.Tunnel.Enabled && cfg.Tunnel.SSHSessionsAllowed() {
		if launcher := newSessionLauncher(verifier, logger); launcher != nil {
			meshServer.SessionManager().SetSSHSessionDeps(tunnel.SSHSessionDeps{
				HostKey:  hostKey,
				Keys:     verifier,
				Commands: sessionReporter,
				Launcher: launcher,
			})
		}
	}

	// 5e. Initialize bridge subsystem (conditional on bridge mode).
	var (
		bridgeMgr     *bridge.Manager
		ingressMgr    *bridge.IngressManager
		userAccessMgr *bridge.UserAccessManager
		s2sMgr        *bridge.SiteToSiteManager
		acmeMgr       *bridge.ACMEManager
	)
	if cfg.Mode == "bridge" && cfg.Bridge.Enabled {
		routeCtrl := newRouteController(logger, fwCtrl)
		bridgeMgr = bridge.NewManager(routeCtrl, cfg.Bridge, logger)
		if err := bridgeMgr.Setup(cfg.WireGuard.InterfaceName); err != nil {
			return fmt.Errorf("plexd up: bridge setup: %w", err)
		}

		// ACME manager (before ingress, which may need TLS config).
		if cfg.Bridge.ACMEEnabled {
			acmeMgr = bridge.NewACMEManager(bridge.ACMEConfig{
				Enabled:          cfg.Bridge.ACMEEnabled,
				CacheDir:         cfg.Bridge.ACMECacheDir,
				AllowedHosts:     cfg.Bridge.ACMEAllowedHosts,
				Email:            cfg.Bridge.ACMEEmail,
				ACMEDirectoryURL: cfg.Bridge.ACMEDirectoryURL,
			}, logger)
			if err := acmeMgr.Setup(); err != nil {
				return fmt.Errorf("plexd up: acme setup: %w", err)
			}
		}

		// Ingress manager.
		if cfg.Bridge.IngressEnabled {
			ingressCtrl := bridge.NewStdIngressController(logger)
			ingressMgr = bridge.NewIngressManager(ingressCtrl, cfg.Bridge, logger, acmeMgr)
			if err := ingressMgr.Setup(); err != nil {
				return fmt.Errorf("plexd up: ingress setup: %w", err)
			}
		}

		// User access manager.
		if cfg.Bridge.UserAccessEnabled {
			accessCtrl := newAccessController(logger)
			userAccessMgr = bridge.NewUserAccessManager(accessCtrl, routeCtrl, cfg.Bridge, logger, nil)
			if err := userAccessMgr.Setup(); err != nil {
				return fmt.Errorf("plexd up: user access setup: %w", err)
			}
		}

		// Site-to-site VPN manager.
		if cfg.Bridge.SiteToSiteEnabled {
			vpnCtrl := newVPNController(logger, identity.MeshIP)
			s2sMgr = bridge.NewSiteToSiteManager(vpnCtrl, routeCtrl, cfg.Bridge, logger, nil)
			if err := s2sMgr.Setup(cfg.WireGuard.InterfaceName); err != nil {
				return fmt.Errorf("plexd up: site-to-site setup: %w", err)
			}
		}

		logger.Info("bridge subsystem initialized",
			"relay", cfg.Bridge.RelayEnabled,
			"ingress", cfg.Bridge.IngressEnabled,
			"user_access", cfg.Bridge.UserAccessEnabled,
			"site_to_site", cfg.Bridge.SiteToSiteEnabled,
		)
	}

	// 6. Create SSE manager.
	sseMgr := api.NewSSEManager(client, verifier, logger)

	// Register signing_key_rotated SSE handler to update verifier keys.
	sseMgr.RegisterHandler(api.EventSigningKeyRotated, signingKeyRotatedHandler(verifier, logger))

	// 7. Create reconciler.
	reconciler := reconcile.NewReconciler(client, cfg.Reconcile, logger)

	// Wire the reconciler as the SSE reconcile trigger so the client covers
	// replay gaps with one full pull per successful connect, and honor the
	// configured SSE idle timeout and pull-only re-probe cadence. cfg.API is
	// post-ApplyDefaults here, so both durations are non-zero.
	sseMgr.SetReconcileTrigger(reconciler)
	sseMgr.SetIdleTimeout(cfg.API.SSEIdleTimeout)
	sseMgr.SetReprobeInterval(cfg.API.SSEReprobeInterval)

	// Key rotator: completes rotate_keys signals against POST /v1/keys/rotate.
	// The typed device variable keeps the interface a true nil when WireGuard is
	// unavailable, so rotation still commits and reconciles without a device.
	var device agent.DeviceKeyUpdater
	if wgReady {
		device = wgMgr
	}
	// A completed rotation is the contract's third re-fetch trigger for edge
	// PSKs, so the rotator's reconcile trigger marks them stale first.
	var rotationTrigger agent.ReconcileTrigger = reconciler
	if edgePSKs != nil {
		rotationTrigger = rotationReconcileTrigger{rt: reconciler, psks: edgePSKs}
	}
	rotator := agent.NewKeyRotator(client, identity, cfg.DataDir, device, rotationTrigger, logger)

	// Register rotate_keys SSE handler (starts a single-flight key rotation;
	// the rotator triggers the reconcile itself after the swap). Unlike the
	// heartbeat flag, which repeats every interval and is rate-limited by the
	// rotator's cooldown, the SSE event arrives once per rotation decision, so
	// it rotates immediately via RotateNow. ctx is the runUp context so the
	// rotation outlives this event handler returning.
	sseMgr.RegisterHandler(api.EventRotateKeys, func(_ context.Context, _ api.Envelope) error {
		logger.Info("rotate_keys received via SSE, starting key rotation")
		go func() {
			if err := rotator.RotateNow(ctx); err != nil {
				logger.Error("key rotation failed", "error", err)
			}
		}()
		return nil
	})

	// Register policy SSE handler (needs reconciler as trigger).
	sseMgr.RegisterHandler(api.EventPolicyUpdated, policy.HandlePolicyUpdated(reconciler))

	// The control plane's pull (the reconciler snapshot) is authoritative, so
	// bridge_config_updated carries an opaque payload and only triggers a
	// reconcile. Registered unconditionally: the bridge reconcile handlers apply
	// whatever bridge subtree the snapshot carries, regardless of local config.
	sseMgr.RegisterHandler(api.EventBridgeConfigUpdated, bridge.HandleBridgeConfigUpdated(reconciler))

	// Every remaining pull-authoritative event simply requests a reconcile: the
	// snapshot is the source of truth, so the payloads are opaque. One shared
	// closure covers the node_state_updated contract type and the peer-family
	// types from the documented-coming taxonomy. action_request and
	// session_setup join them as push-latency optimisations: the dispatch and
	// the session themselves are delivered in the pull's executions and sessions
	// blocks, the events only pull them forward. session_revoked and
	// session_connect are registered with the session dispatcher below, because
	// the first closes the session it names and the second opens a connection
	// for it.
	// node_secrets_updated carries the node's full secret inventory, but the
	// inventory also rides the pull's secrets block, which feeds the node API's
	// secret index, so the event only pulls that forward too: an event that
	// arrives late can never roll the index back.
	triggerReconcile := func(_ context.Context, _ api.Envelope) error {
		reconciler.TriggerReconcile()
		return nil
	}
	for _, eventType := range []string{
		api.EventNodeStateUpdated,
		api.EventActionRequest,
		api.EventSessionSetup,
		api.EventNodeSecretsUpdated,
		api.EventPeerRegistered,
		api.EventPeerPSKAssigned,
		api.EventPeerDeregistered,
		api.EventPeerEndpointChanged,
		api.EventPeerKeyRotated,
	} {
		sseMgr.RegisterHandler(eventType, triggerReconcile)
	}

	selfChecksum, err := integrity.SelfChecksum()
	if err != nil {
		return fmt.Errorf("plexd up: binary checksum: %w", err)
	}
	// Both operations that carry this digest declare it `format: byte`, so the
	// wire form is the raw 32 bytes in base64 — the hex form this package works
	// in is refused (heartbeat: 400 binary_checksum_empty, capabilities: 400
	// binary_checksum_invalid).
	wireChecksum, err := integrity.WireChecksum(selfChecksum)
	if err != nil {
		return fmt.Errorf("plexd up: binary checksum: %w", err)
	}

	// 8. Create heartbeat service.
	hbCfg := agent.HeartbeatConfig{
		Interval: cfg.Heartbeat.Interval,
		NodeID:   identity.NodeID,
	}
	hbCfg.ApplyDefaults()
	if err := hbCfg.Validate(); err != nil {
		return fmt.Errorf("plexd up: %w", err)
	}
	heartbeat := agent.NewHeartbeatService(hbCfg, client, logger)
	heartbeat.SetReconcileTrigger(reconciler)
	heartbeat.SetOnRotateKeys(func() {
		logger.Info("heartbeat signaled key rotation, starting key rotation")
		go func() {
			if err := rotator.Rotate(ctx); err != nil {
				logger.Error("key rotation failed", "error", err)
			}
		}()
	})

	heartbeat.SetBuildRequest(func() api.HeartbeatRequest {
		return buildHeartbeatRequest(wireChecksum, buildVersion, exchanger.LastResult())
	})

	// 9. Create integrity verifier for hook execution.
	integrityStore, err := integrity.NewStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("plexd up: integrity store: %w", err)
	}
	integrityVerifier := integrity.NewVerifier(cfg.Integrity, integrityStore, &controlPlaneReporter{cp: client}, logger)

	// Record start time for uptime calculations.
	startTime := time.Now()

	// Build the release fetcher and Sigstore verifier for service.upgrade, and
	// the controller both service actions restart the daemon through: systemd
	// here, launchd on macOS, the Service Control Manager on Windows. The
	// empty InstallConfig is the default installation, which is the one this
	// process is running from.
	upgradeFetcher := upgrade.NewFetcher(cfg.Upgrade)
	upgradeVerifier, err := upgrade.NewVerifier(cfg.Upgrade)
	if err != nil {
		return fmt.Errorf("plexd up: upgrade verifier: %w", err)
	}
	svcCtl := packaging.NewService(packaging.NewServiceManager(logger), packaging.InstallConfig{})

	// The platform system reader serves both diagnostics.collect and the
	// metrics collector, so it is built once. It is nil where no reader exists.
	sysReader := newSystemReader(logger)

	// 10. Create action executor and register built-in actions.
	executor := actions.NewExecutor(cfg.Actions, client, integrityVerifier, logger)

	nodeInfo := &agentNodeInfo{nodeID: identity.NodeID, meshIP: identity.MeshIP}
	executor.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics (CPU, memory, disk, network)",
		[]api.ActionParam{
			{Name: "include_network", Type: "bool", Required: false, Default: "true", Description: "Include network interface info"},
			{Name: "include_processes", Type: "bool", Required: false, Default: "true", Description: "Include process listing"},
		}, actions.DiagnosticsCollect(sysReader))
	executor.RegisterBuiltin("diagnostics.ping_peer", "Ping a mesh peer and report latency",
		[]api.ActionParam{
			{Name: "peer_id", Type: "string", Required: true, Description: "Peer mesh IP address"},
			{Name: "count", Type: "string", Required: false, Default: "1", Description: "Number of pings"},
		}, actions.PingPeer(nodeInfo))
	executor.RegisterBuiltin("diagnostics.traceroute_peer", "Traceroute to a mesh peer",
		[]api.ActionParam{
			{Name: "peer_id", Type: "string", Required: true, Description: "Peer mesh IP address"},
			{Name: "max_hops", Type: "string", Required: false, Default: "15", Description: "Maximum number of hops"},
		}, actions.DiagnosticsTraceroutePeer(nodeInfo))
	executor.RegisterBuiltin("service.restart", "Restart plexd through the host's service manager", nil, actions.ServiceRestart(svcCtl))
	executor.RegisterBuiltin("service.reload_config", "Reload configuration without restart", nil, actions.ServiceReloadConfig())
	executor.RegisterBuiltin("service.upgrade", "Upgrade plexd to a specified version",
		[]api.ActionParam{
			{Name: "version", Type: "string", Required: true, Description: "Target version"},
			{Name: "checksum", Type: "string", Required: true, Description: "Expected SHA-256 checksum"},
		}, actions.ServiceUpgrade(upgradeFetcher, upgradeVerifier, svcCtl))
	executor.RegisterBuiltin("system.info", "Report OS, kernel, hardware, and runtime info", nil, actions.GatherInfo(nodeInfo))
	executor.RegisterBuiltin("health.check", "Run all health checks and report status",
		[]api.ActionParam{
			{Name: "include_peers", Type: "bool", Required: false, Default: "true", Description: "Include per-peer status"},
		}, actions.HealthCheck(&agentHealthProvider{startTime: startTime, wgMgr: wgMgr, meshServer: meshServer}))
	executor.RegisterBuiltin("mesh.reconnect", "Tear down and re-establish all mesh tunnels", nil,
		actions.MeshReconnect(&agentMeshReconnector{reconciler: reconciler}))
	executor.RegisterBuiltin("config.dump", "Return current effective configuration (secrets redacted)", nil,
		actions.ConfigDump(&agentConfigProvider{cfg: cfg}))
	logRingBuffer := logfwd.NewRingBuffer(logfwd.DefaultRingBufferCapacity)
	executor.RegisterBuiltin("logs.snapshot", "Capture recent logs and return as compressed archive",
		[]api.ActionParam{
			{Name: "lines", Type: "string", Required: false, Description: "Number of lines (default 100, max 10000)"},
			{Name: "since", Type: "string", Required: false, Description: "Duration filter (e.g. 5m, 1h)"},
		}, actions.LogsSnapshot(&agentLogProvider{ringBuffer: logRingBuffer}))

	// Report the capability manifest to the control plane. The manifest carries
	// the binary version and digest, the SSH host-key fingerprint the integrity
	// correlator watches for rotation, the declared hooks, and two inventories.
	// builtin_actions is the executor's name-sorted action list, sent whole: the
	// builtins registered above sit far below the contract's 128-action and
	// 64-parameter caps. plexd_hooks carries the PlexdHook resources a pod finds
	// in its ServiceAccount's namespace, listed once here and never watched.
	// Outside a cluster that costs one environment lookup, and a failed list only
	// leaves the key off.
	kubeEnv := (&kubernetes.DefaultDetector{Logger: logger}).Detect()
	plexdHooks := discoverPlexdHooks(ctx, kubeEnv, newInClusterHookLister, logger)
	capsActions, capsHooks := executor.Capabilities()
	caps := api.CapabilityManifestRequest{
		BinaryVersion:         buildVersion,
		BinaryChecksum:        wireChecksum,
		SSHHostKeyFingerprint: tunnel.HostKeyFingerprint(hostKey),
		DeclaredHooks:         declaredHooks(capsHooks, logger),
		PlexdHooks:            discoveredPlexdHooks(plexdHooks, logger),
		BuiltinActions:        capsActions,
	}
	if err := client.UpdateCapabilities(ctx, identity.NodeID, caps); err != nil {
		logger.Warn("capabilities report failed", "error", err)
	}

	// 11. Create hook watcher.
	hookWatcher := actions.NewHookWatcher(
		cfg.Actions.HooksDir,
		executor.SetHooks,
		func(hookName, oldChecksum, newChecksum string) {
			logger.Warn("hook integrity change detected",
				"hook", hookName,
				"old_checksum", oldChecksum,
				"new_checksum", newChecksum,
			)
		},
		logger,
	)

	// 12. Create node API server.
	cfg.NodeAPI.SecretAuthEnabled = true
	nsk, err := identity.SecretKey()
	if err != nil {
		return fmt.Errorf("plexd up: %w", err)
	}
	nodeAPISrv := nodeapi.NewServer(cfg.NodeAPI, client, nsk, logger)
	nodeAPISrv.SetActionProvider(executor)
	nodeAPISrv.SetHookReloader(hookWatcher)

	// Set up peer and policy snapshot providers for the node API.
	peerSnap := &peerSnapshot{}
	if wgReady {
		peerSnap.mesh = wgMgr.MeshPrefix()
	}
	policySnap := &policySnapshot{}
	nodeAPISrv.SetPeerProvider(peerSnap)
	nodeAPISrv.SetPolicyProvider(policySnap)

	// Publish the SSE delivery mode as node-API cache metadata so `plexd status`
	// surfaces it, and feed it to the health listener's readiness state. Seed it
	// once so both read streaming from startup, then update them on every
	// transition (e.g. into pull-only on a 501 descope).
	publishDeliveryMode := deliveryModePublisher(nodeAPISrv.Cache(), logger)
	onModeChange := publishDeliveryMode
	if healthSrv != nil {
		// SetOnModeChange holds a single callback slot: fan the transition out
		// to both the node-API cache metadata and the health listener's
		// readiness state.
		onModeChange = func(m api.DeliveryMode) {
			publishDeliveryMode(m)
			healthSrv.SetDeliveryMode(m)
		}
	}
	sseMgr.SetOnModeChange(onModeChange)
	onModeChange(sseMgr.Mode())

	// When the heartbeat parks on a credential the control plane keeps
	// refusing, gate the shared client and surface the refusal in `plexd
	// status` and readiness; an accepted probe lifts all three again. The
	// heartbeat starts below, so the callback is in place before its first send.
	heartbeat.SetOnCredentialRefused(credentialRefusedPublisher(client, nodeAPISrv.Cache(), healthSrv))

	// Register nodeapi reconcile handler so cache updates on drift. The pull is
	// authoritative: node_state_updated triggers a reconcile (see above), and
	// this handler refreshes the node API cache from the resulting snapshot.
	reconciler.RegisterHandler(nodeAPISrv.ReconcileHandler())

	// The pull carries the Domain signing key on every successful cycle. It is
	// installed into the verifier that checks envelopes and ssh session tokens
	// and persisted, first among the dispatch handlers, so the rest of the
	// cycle already runs under it. A node enrolled before its Domain had a key
	// of its own learns the key here.
	reconciler.RegisterDispatchHandler(signingKeyDispatchHandler(verifier, cfg.DataDir, api.NodeStateSigningKey{
		KeyID:     identity.SigningKeyID,
		PublicKey: identity.SigningPublicKey,
	}, logger))

	// The pull's secrets block is the node's secret inventory, names and
	// versions only. It replaces the node API's secret index on every
	// successful cycle, drift or not, so GET /v1/state/secrets lists what the
	// node may read; node_secrets_updated only pulls it forward (see above).
	reconciler.RegisterDispatchHandler(nodeAPISrv.SecretIndexDispatchHandler())

	// Action dispatches are consumed from the pull's executions block on every
	// successful cycle, drift or not: the block is a delivery queue that
	// redelivers each entry until its execution settles through the callback.
	dispatcher := actions.NewDispatcher(executor, identity.NodeID, logger)
	reconciler.RegisterDispatchHandler(dispatcher.Handle)

	// Mediated-access sessions are consumed from the pull's sessions block on
	// every successful cycle too, but that block is desired state: a listener is
	// provisioned when its entry appears and torn down when the entry drains,
	// unless a verified session_revoked event closed it first (registered
	// below).
	sessionDispatcher := tunnel.NewDispatcher(meshServer.SessionManager(), sessionReporter, logger)
	reconciler.RegisterDispatchHandler(sessionDispatcher.Handle)

	// A verified session_revoked event names the session the control plane
	// revoked, so the dispatcher closes that session at once and reports the
	// reason the event carries, then pulls. The drain stays the teardown for a
	// revocation whose event never arrives. Registered before sseMgr.Start, like
	// every other SSE handler.
	sseMgr.RegisterHandler(api.EventSessionRevoked, sessionDispatcher.SessionRevokedHandler(reconciler))

	// A verified session_connect event asks for one connection of a live ssh
	// session, so the dispatcher opens it to the control plane and serves the
	// session's login on it. It carries no desired state and triggers no pull.
	// Registered whatever the tunnel configuration says, so a node that serves
	// no ssh sessions logs why it opens nothing instead of dropping the event.
	sseMgr.RegisterHandler(api.EventSessionConnect, sessionDispatcher.SessionConnectHandler(&controlPlaneSessionConnector{cp: client, nodeID: identity.NodeID}))

	// The reachability block is the control plane's own verdict about this node,
	// not desired state: it is observed and logged on every successful pull, and
	// never stored or converged on. A node whose heartbeats stop being admitted
	// while its state pulls keep succeeding has no other way to learn that.
	reconciler.RegisterDispatchHandler(reconcile.NewReachabilityObserver(logger).Handle)

	// Edge PSKs are fetched on every successful pull, drift or not: a failed
	// fetch must retry without failing the WireGuard reconcile handler, which
	// would hold the snapshot back on every control plane that does not serve
	// the operation. Dispatch handlers run before the reconcile handlers, so a
	// new peer's PSK is in the store when the WireGuard handler adds the peer.
	if edgePSKs != nil {
		reconciler.RegisterDispatchHandler(wireguard.EdgePSKDispatchHandler(edgePSKs))
	}

	// Register the WireGuard reconcile handler only when the interface came up.
	// A handler that fails every cycle would hold back the reconciler snapshot,
	// so the fingerprint short-circuit could never converge on such hosts. The
	// handshake reporter (step 17a), the tunnel collector (step 13), endpoint
	// selection (step 17b) and the endpoint candidate publisher (step 24a)
	// need the same device and are skipped on the same condition, so this one
	// line accounts for all five.
	if wgReady {
		// The typed lookup keeps the interface a true nil when edge PSKs are
		// off, as the rotator's device variable does.
		var psksLookup wireguard.EdgePSKLookup
		if edgePSKs != nil {
			psksLookup = edgePSKs
		}
		reconciler.RegisterHandler(wireguard.ReconcileHandler(wgMgr, psksLookup))
	} else {
		logger.Warn("wireguard unavailable, skipping peer reconcile handler, handshake reports, tunnel metrics, endpoint selection and endpoint candidates")
	}

	// Register policy reconcile handler.
	reconciler.RegisterHandler(policy.ReconcileHandler(enforcer, policyIface))

	// Register peer/policy snapshot reconcile handler for node API queries.
	reconciler.RegisterHandler(func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		peerSnap.update(desired.Peers)
		policySnap.update(desired.Policy)
		return nil
	})

	// Register bridge reconcile handlers (conditional). The relay handler runs
	// whenever bridge mode does: the state pull starts and stops the relay,
	// and with local consent off (a nil relay) the handler says that the
	// control plane asks for one.
	if bridgeMgr != nil {
		reconciler.RegisterHandler(bridge.RelayReconcileHandler(bridgeMgr.Relay(), logger))
		if ingressMgr != nil {
			reconciler.RegisterHandler(bridge.IngressReconcileHandler(ingressMgr, logger))
		}
		if userAccessMgr != nil {
			reconciler.RegisterHandler(bridge.UserAccessReconcileHandler(userAccessMgr, logger))
		}
		if s2sMgr != nil {
			reconciler.RegisterHandler(bridge.SiteToSiteReconcileHandler(s2sMgr, logger))
		}
	}

	// 13. Create metrics collectors and manager. The tunnel collector reads the
	// mesh device, so it exists only when the interface came up. The typed
	// reader variable keeps the interface a true nil otherwise, which is what
	// buildMetricsCollectors checks: a nil *wgTunnelStatsReader stored in it
	// would compare non-nil and register a collector that fails every cycle.
	var tunnelReader metrics.TunnelStatsReader
	if wgReady {
		tunnelReader = &wgTunnelStatsReader{mgr: wgMgr}
	}
	metricsCollectors := buildMetricsCollectors(tunnelReader, sysReader, startTime, logger)

	var metricsReporter metrics.MetricsReporter = metrics.NewPlatformReporter(client, logger)
	if cfg.Metrics.LocalEndpoint.URL != "" {
		localMetrics := metrics.NewLocalReporter(cfg.Metrics.LocalEndpoint, client, nsk, identity.NodeID, logger)
		metricsReporter = metrics.NewMultiReporter(metricsReporter, localMetrics, logger)
		logger.Info("local endpoint enabled", "pipeline", "metrics", "url", cfg.Metrics.LocalEndpoint.URL)
	}
	metricsMgr := metrics.NewManager(cfg.Metrics, metricsCollectors, metricsReporter, identity.NodeID, logger)

	// 14. Create log forwarding sources and forwarder.
	hostname, _ := os.Hostname()
	var logSources []logfwd.LogSource
	if src := newSystemLogSource(hostname, logger); src != nil {
		logSources = append(logSources, src)
	}
	for _, pattern := range cfg.LogFwd.FilePatterns {
		logSources = append(logSources, logfwd.NewFileSource(pattern, hostname, logger))
	}
	var logReporter logfwd.LogReporter = logfwd.NewPlatformReporter(client, logger)
	if cfg.LogFwd.LocalEndpoint.URL != "" {
		localLogs := logfwd.NewLocalReporter(cfg.LogFwd.LocalEndpoint, client, nsk, identity.NodeID, logger)
		logReporter = logfwd.NewMultiReporter(logReporter, localLogs, logger)
		logger.Info("local endpoint enabled", "pipeline", "logfwd", "url", cfg.LogFwd.LocalEndpoint.URL)
	}
	logForwarder := logfwd.NewForwarder(cfg.LogFwd, logSources, logReporter, identity.NodeID, hostname, logger)
	logForwarder.SetRingBuffer(logRingBuffer)

	// 15. Create audit forwarding sources and forwarder.
	var auditSources []auditfwd.AuditSource
	auditSources = append(auditSources, auditfwd.NewProcessSource(hostname))
	var auditReporter auditfwd.AuditReporter = auditfwd.NewPlatformReporter(client, logger)
	if cfg.AuditFwd.LocalEndpoint.URL != "" {
		localAudit := auditfwd.NewLocalReporter(cfg.AuditFwd.LocalEndpoint, client, nsk, identity.NodeID, logger)
		auditReporter = auditfwd.NewMultiReporter(auditReporter, localAudit, logger)
		logger.Info("local endpoint enabled", "pipeline", "auditfwd", "url", cfg.AuditFwd.LocalEndpoint.URL)
	}
	auditForwarder := auditfwd.NewForwarder(cfg.AuditFwd, auditSources, auditReporter, identity.NodeID, hostname, logger)

	// Wire forwarder status providers to the node API server.
	nodeAPISrv.SetLogStatus(&logForwarderStatus{fwd: logForwarder})
	nodeAPISrv.SetAuditStatus(&auditForwarderStatus{fwd: auditForwarder})

	// Publish the mesh/bridge/user-access/ingress/site-to-site status blocks as
	// per-key state reports through the node API cache and syncer. These blocks
	// were removed from the heartbeat in issue #19 and re-homed here (issue #23),
	// so they keep their old heartbeat cadence rather than a new config knob.
	statusInterval := cfg.Heartbeat.Interval
	if statusInterval == 0 {
		statusInterval = agent.DefaultHeartbeatInterval
	}
	statusReports := &statusReportPublisher{
		publisher:     nodeAPISrv,
		peerCount:     wgMgr.PeerIndex().Count,
		bridgeMgr:     bridgeMgr,
		userAccessMgr: userAccessMgr,
		ingressMgr:    ingressMgr,
		s2sMgr:        s2sMgr,
		ifaceName:     cfg.WireGuard.InterfaceName,
		listenPort:    cfg.WireGuard.ListenPort,
		interval:      statusInterval,
		logger:        logger.With("component", "status-reports"),
	}

	// 16. Start SSE manager.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sseMgr.Start(ctx, identity.NodeID); err != nil {
			logger.Error("SSE manager stopped", "error", err)
		}
		// Start returning means event delivery is over for this process: the
		// reconnect engine gives up on a permanent failure or a rejected node
		// secret without ever transitioning the delivery mode, so readiness
		// would otherwise keep reporting the last mode while nothing arrives.
		// The ctx guard keeps an ordinary shutdown from flapping readiness.
		if healthSrv != nil && ctx.Err() == nil {
			healthSrv.SetDeliveryStopped()
		}
	}()

	// 17. Start heartbeat.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = heartbeat.Run(ctx)
	}()

	// 17a. Start handshake reporter. It ticks at the heartbeat's interval
	// because the contract asks for one report per heartbeat interval, and it
	// runs beside the heartbeat rather than inside it so a slow report never
	// delays the liveness signal. Without the interface there is no device to
	// read, and a reporter that fails every tick would only log.
	if wgReady {
		handshakeReporter := agent.NewHandshakeReporter(hbCfg.Interval, identity.NodeID, client, wgMgr, logger)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = handshakeReporter.Run(ctx)
		}()
	}

	// 17b. Start endpoint selection. It tries each peer's dial order until a
	// handshake completes, reading the same device as the handshake reporter.
	if wgReady {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = wgMgr.RunEndpointSelection(ctx, wireguard.EndpointSelectionInterval)
		}()
	}

	// 17c. Start the mesh MTU re-probe. Setup measured the uplink once; the
	// loop measures it again, because an uplink can get worse after startup
	// (LTE failover, a laptop changing networks) and a mesh MTU it no longer
	// carries is lost without an error.
	if wgReady {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = wgMgr.RunMTUProbe(ctx, wireguard.MTUProbeInterval)
		}()
	}

	// 18. Start reconciler.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := reconciler.Run(ctx, identity.NodeID); err != nil {
			logger.Error("reconciler stopped", "error", err)
		}
		// Nothing restarts this goroutine, so an exit before shutdown leaves the
		// process alive while it no longer converges on the desired state.
		// Readiness has to say so — liveness is a constant by design, so the
		// kubelet would otherwise keep a half-dead node in rotation.
		if healthSrv != nil && ctx.Err() == nil {
			healthSrv.SetSubsystemStopped("reconciler")
		}
	}()

	// Start key-rotation crash recovery.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rotator.RecoverPending(ctx)
	}()

	// 19. Start node API server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := nodeAPISrv.Start(ctx, identity.NodeID); err != nil {
			logger.Error("node API server stopped", "error", err)
		}
		// Start returns before it serves anything when the on-disk cache fails
		// to load — a truncated file after an unclean reboot, a full disk, a
		// changed permission. The socket and the state-report syncer are then
		// gone for the life of the process, so readiness must stop reporting 200.
		if healthSrv != nil && ctx.Err() == nil {
			healthSrv.SetSubsystemStopped("node-api")
		}
	}()

	// 19a. Start status report publisher. Started after the node API server so
	// its cache and syncer are running before the first publish lands.
	wg.Add(1)
	go func() {
		defer wg.Done()
		statusReports.run(ctx)
	}()

	// 20. Start hook watcher.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := hookWatcher.Watch(ctx); err != nil {
			logger.Error("hook watcher stopped", "error", err)
		}
	}()

	// 21. Start metrics manager.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := metricsMgr.Run(ctx); err != nil {
			logger.Error("metrics manager stopped", "error", err)
		}
	}()

	// 22. Start log forwarder.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := logForwarder.Run(ctx); err != nil {
			logger.Error("log forwarder stopped", "error", err)
		}
	}()

	// 23. Start audit forwarder.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := auditForwarder.Run(ctx); err != nil {
			logger.Error("audit forwarder stopped", "error", err)
		}
	}()

	// 24. Start peer exchange loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := exchanger.Run(ctx, identity.NodeID); err != nil {
			logger.Error("peer exchange stopped", "error", err)
		}
	}()

	// 24a. Start endpoint candidate publisher. It runs on its own loop, apart
	// from STUN and peer_exchange: a node whose STUN servers are unreachable
	// still publishes its LAN addresses. A node without the WireGuard
	// interface accepts no tunnel, so it publishes nothing.
	if wgReady && cfg.NAT.LocalCandidatesEnabled() {
		candidatePublisher := nat.NewCandidatePublisher(func() ([]string, int, error) {
			return nat.GatherCandidates(cfg.WireGuard.ListenPort, candidateFilter)
		}, cfg.NAT, logger)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = candidatePublisher.Run(ctx, client, identity.NodeID)
		}()
	}

	// 25. Start tunnel mesh server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := meshServer.Start(ctx); err != nil {
			logger.Error("mesh server stopped", "error", err)
		}
	}()

	// Wait for shutdown signal.
	<-ctx.Done()
	logger.Info("shutting down", "reason", ctx.Err())

	// Graceful drain: stop subsystems in reverse dependency order.
	sseMgr.Shutdown()
	executor.Shutdown(context.Background())

	if err := meshServer.Shutdown(); err != nil {
		logger.Error("mesh server shutdown error", "error", err)
	}
	if ingressMgr != nil {
		if err := ingressMgr.Teardown(); err != nil {
			logger.Error("ingress teardown error", "error", err)
		}
	}
	if userAccessMgr != nil {
		if err := userAccessMgr.Teardown(); err != nil {
			logger.Error("user access teardown error", "error", err)
		}
	}
	if s2sMgr != nil {
		if err := s2sMgr.Teardown(); err != nil {
			logger.Error("site-to-site teardown error", "error", err)
		}
	}
	if acmeMgr != nil {
		if err := acmeMgr.Teardown(); err != nil {
			logger.Error("acme teardown error", "error", err)
		}
	}
	if bridgeMgr != nil {
		if err := bridgeMgr.Teardown(); err != nil {
			logger.Error("bridge teardown error", "error", err)
		}
	}
	if err := enforcer.Teardown(); err != nil {
		logger.Error("policy enforcer teardown error", "error", err)
	}
	// WireGuard last — other subsystems depend on the interface being up.
	// Without a controller there is no interface to delete, and Teardown would
	// dereference the nil newWGController returns off Linux (see up_other.go).
	if wgCtrl != nil {
		if err := wgMgr.Teardown(); err != nil {
			logger.Error("wireguard teardown error", "error", err)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines exited cleanly.
	case <-time.After(drainTimeout):
		logger.Warn("drain timeout exceeded, forcing exit")
	}

	logger.Info("plexd stopped")
	return nil
}

// meshInterfaceOwned reports whether the interface named name carries meshIP,
// the address the control plane assigned this node. Only the mesh interface
// answers to it, so it tells the device plexd manages — the one this run
// created or the one a previous run left behind — apart from a foreign device
// that happens to carry the configured name.
//
// A name no interface carries is (false, nil): that is the ordinary case the
// caller skips. An error means the interface table itself could not be read,
// which net.InterfaceByName reports the same way as an absent name and callers
// must not: on Linux the table is a netlink dump that answers ENOBUFS on a node
// with a large, churning link table and EMFILE when the process is out of
// descriptors, and neither says the interface is gone.
func meshInterfaceOwned(name, meshIP string) (bool, error) {
	want := net.ParseIP(meshIP)
	if want == nil {
		return false, fmt.Errorf("mesh ip %q is not an address", meshIP)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Name != name {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return false, fmt.Errorf("read the addresses of %s: %w", name, err)
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(want) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}

// meshMTUProbe returns the function the WireGuard manager measures the uplink
// with: one round of padded STUN probes against the configured servers. It
// returns nil when nat.enabled is off, which turns the MTU probe off; Validate
// checks the server list only while it is on.
func meshMTUProbe(natCfg nat.Config) func(context.Context) (int, error) {
	if !natCfg.Enabled {
		return nil
	}
	servers := natCfg.STUNServers
	return func(ctx context.Context) (int, error) {
		return nat.ProbePathMTU(ctx, servers, nat.MTUProbeTimeout)
	}
}

// agentNodeInfo adapts agent identity to actions.NodeInfoProvider.
type agentNodeInfo struct {
	nodeID    string
	meshIP    string
	peerCount int
}

func (a *agentNodeInfo) NodeID() string { return a.nodeID }
func (a *agentNodeInfo) MeshIP() string { return a.meshIP }
func (a *agentNodeInfo) PeerCount() int { return a.peerCount }

// agentHealthProvider adapts agent state to actions.HealthProvider.
type agentHealthProvider struct {
	startTime  time.Time
	wgMgr      *wireguard.Manager
	meshServer *tunnel.MeshServer
}

func (a *agentHealthProvider) TunnelCount() int {
	if a.meshServer != nil {
		return a.meshServer.SessionManager().ActiveCount()
	}
	return 0
}
func (a *agentHealthProvider) ConnectedPeers() int {
	if a.wgMgr != nil {
		return a.wgMgr.PeerIndex().Count()
	}
	return 0
}
func (a *agentHealthProvider) Uptime() time.Duration    { return time.Since(a.startTime) }
func (a *agentHealthProvider) LastHeartbeat() time.Time { return time.Time{} }
func (a *agentHealthProvider) LastReconcile() time.Time { return time.Time{} }

// wgTunnelStatsReader adapts the WireGuard manager to metrics.TunnelStatsReader,
// so the tunnel_health group carries each mesh peer's transfer counters and
// handshake state. It reads the device through Manager.MeshPeerStats, the same
// path the handshake reporter takes, and reports every peer the peer index
// maps, a peer that never completed a handshake included: that peer is the
// one handshake_succeeded 0 exists for.
//
// DECISION: PacketLossPercent is -1, the documented "no measurement" value.
// plexd sends no probes and the device counts no lost packets, so a 0 would
// claim a loss-free link nobody measured.
type wgTunnelStatsReader struct{ mgr *wireguard.Manager }

func (r *wgTunnelStatsReader) ReadTunnelStats(_ context.Context) ([]metrics.TunnelStats, error) {
	peers, err := r.mgr.MeshPeerStats()
	if err != nil {
		return nil, fmt.Errorf("plexd up: tunnel stats: %w", err)
	}
	stats := make([]metrics.TunnelStats, 0, len(peers))
	for _, p := range peers {
		stats = append(stats, metrics.TunnelStats{
			PeerID:             p.NodeID,
			LastHandshakeTime:  p.LastHandshake,
			RxBytes:            p.RxBytes,
			TxBytes:            p.TxBytes,
			HandshakeSucceeded: !p.LastHandshake.IsZero(),
			PacketLossPercent:  -1,
		})
	}
	return stats, nil
}

// agentMeshReconnector adapts the reconciler to actions.MeshReconnector.
type agentMeshReconnector struct {
	reconciler *reconcile.Reconciler
}

func (a *agentMeshReconnector) Reconnect(_ context.Context) error {
	a.reconciler.TriggerReconcile()
	return nil
}

// agentConfigProvider adapts agent config to actions.ConfigProvider.
type agentConfigProvider struct {
	cfg *agent.AgentConfig
}

func (a *agentConfigProvider) DumpConfig() string {
	data, err := yaml.Marshal(a.cfg)
	if err != nil {
		return "# error dumping config: " + err.Error()
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		lines[i] = redactSensitiveLine(line)
	}
	return strings.Join(lines, "\n")
}

// sensitiveKeywords are YAML key substrings that trigger value redaction.
var sensitiveKeywords = []string{"secret", "token", "key", "password"}

// redactSensitiveLine replaces the value portion of a YAML line if its key
// contains a sensitive keyword. Lines without a colon or with empty/quoted-empty
// values are returned unchanged.
func redactSensitiveLine(line string) string {
	if !strings.Contains(line, ":") {
		return line
	}
	lower := strings.ToLower(line)
	for _, kw := range sensitiveKeywords {
		if !strings.Contains(lower, kw) {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return line
		}
		val := strings.TrimSpace(parts[1])
		if val == "" || val == "''" || val == `""` {
			return line
		}
		return parts[0] + ": '[REDACTED]'"
	}
	return line
}

// agentLogProvider adapts the log forwarder's ring buffer to actions.LogProvider.
type agentLogProvider struct {
	ringBuffer *logfwd.RingBuffer
}

func (a *agentLogProvider) RecentLines(n int) []string {
	if a.ringBuffer == nil {
		return nil
	}
	return a.ringBuffer.RecentLines(n)
}

// peerSnapshot implements nodeapi.PeerProvider with a thread-safe cached peer list.
type peerSnapshot struct {
	mu    sync.RWMutex
	peers []nodeapi.PeerStatus
	// mesh is the Domain mesh prefix the dial order checks direct endpoints
	// against, so each peer reports the endpoint the pull gives it without
	// its candidates, as wireguard.ProgrammedEndpoint picks it.
	mesh netip.Prefix
}

func (ps *peerSnapshot) PeerStatuses() []nodeapi.PeerStatus {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.peers
}

func (ps *peerSnapshot) update(apiPeers []api.SnapshotPeer) {
	statuses := make([]nodeapi.PeerStatus, len(apiPeers))
	for i, p := range apiPeers {
		statuses[i] = nodeapi.PeerStatus{
			ID:        p.NodeID,
			PublicKey: p.PublicKey,
			MeshIP:    p.MeshIP,
		}
		statuses[i].Endpoint, _ = wireguard.ProgrammedEndpoint(p, ps.mesh)
	}
	ps.mu.Lock()
	ps.peers = statuses
	ps.mu.Unlock()
}

// rotationReconcileTrigger is the reconcile trigger the key rotator fires once a
// rotation committed. It marks every edge PSK stale before it triggers the
// reconcile, so the pull that follows fetches each peer's PSK again: this node's
// rotation reissues its half of every edge key.
type rotationReconcileTrigger struct {
	rt   agent.ReconcileTrigger
	psks *wireguard.EdgePSKs
}

func (t rotationReconcileTrigger) TriggerReconcile() {
	t.psks.InvalidateAll()
	t.rt.TriggerReconcile()
}

// policySnapshot implements nodeapi.PolicyProvider with a thread-safe cached
// merged policy.
type policySnapshot struct {
	mu     sync.RWMutex
	policy *api.PolicySnapshot
}

func (ps *policySnapshot) ActivePolicy() *api.PolicySnapshot {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.policy
}

func (ps *policySnapshot) update(policy *api.PolicySnapshot) {
	ps.mu.Lock()
	ps.policy = policy
	ps.mu.Unlock()
}

// logForwarderStatus adapts logfwd.Forwarder to nodeapi.ForwarderStatusProvider.
type logForwarderStatus struct {
	fwd *logfwd.Forwarder
}

func (s *logForwarderStatus) ForwarderStatus() nodeapi.ForwarderStatus {
	enabled, bufSize, srcCount, errCount, lastReport := s.fwd.Status()
	var lastReportStr string
	if !lastReport.IsZero() {
		lastReportStr = lastReport.Format(time.RFC3339)
	}
	return nodeapi.ForwarderStatus{
		Enabled:      enabled,
		BufferSize:   bufSize,
		SourceCount:  srcCount,
		ErrorCount:   errCount,
		LastReportAt: lastReportStr,
	}
}

// auditForwarderStatus adapts auditfwd.Forwarder to nodeapi.ForwarderStatusProvider.
type auditForwarderStatus struct {
	fwd *auditfwd.Forwarder
}

func (s *auditForwarderStatus) ForwarderStatus() nodeapi.ForwarderStatus {
	enabled, bufSize, srcCount, errCount, lastReport := s.fwd.Status()
	var lastReportStr string
	if !lastReport.IsZero() {
		lastReportStr = lastReport.Format(time.RFC3339)
	}
	return nodeapi.ForwarderStatus{
		Enabled:      enabled,
		BufferSize:   bufSize,
		SourceCount:  srcCount,
		ErrorCount:   errCount,
		LastReportAt: lastReportStr,
	}
}

// controlPlaneSessionReporter reports session activity rows to the control
// plane. A tcp session is an opaque TCP forward, so it gets tcp rows: a
// session_started row when the listener is up and a session_ended row carrying
// byte counters and a terminated_by reason on close. An ssh session gets the
// ssh lifecycle rows, a session_started row when it is ready to serve
// connections and a session_ended row carrying the terminated_by reason, and
// one command row before and one after every command it runs.
type controlPlaneSessionReporter struct {
	cp     *api.ControlPlane
	nodeID string
}

// ReportSessionStarted returns the post's error rather than logging it away: a
// tcp row carries the listener endpoint the operator connects to, and an ssh
// row is what the control plane waits for before it asks for a connection, so
// the dispatcher has to know whether it arrived. An ssh session binds no
// listener, so its row carries no endpoint.
func (r *controlPlaneSessionReporter) ReportSessionStarted(ctx context.Context, entry api.NodeStateSession, listenerEndpoint string) error {
	var req api.SessionActivityRequest
	if entry.Kind == api.SessionKindSSH {
		req.SSH = &api.SSHActivity{Phase: api.SSHPhaseSessionStarted}
	} else {
		req.TCP = &api.TCPActivity{
			Phase:            api.TCPPhaseSessionStarted,
			TargetHost:       entry.Target.TCP.Host,
			TargetPort:       entry.Target.TCP.Port,
			ListenerEndpoint: listenerEndpoint,
		}
	}
	return r.cp.ReportSessionActivity(ctx, r.nodeID, entry.SessionID, req)
}

func (r *controlPlaneSessionReporter) ReportSessionEnded(ctx context.Context, sessionID string, info *tunnel.ClosedSessionInfo, terminatedBy string) {
	bytesIn, bytesOut := info.BytesIn, info.BytesOut
	var req api.SessionActivityRequest
	if info.Kind == api.SessionKindSSH {
		req.SSH = &api.SSHActivity{Phase: api.SSHPhaseSessionEnded, TerminatedBy: terminatedBy}
	} else {
		req.TCP = &api.TCPActivity{
			Phase:        api.TCPPhaseSessionEnded,
			TargetHost:   info.TargetHost,
			TargetPort:   info.TargetPort,
			BytesIn:      &bytesIn,
			BytesOut:     &bytesOut,
			TerminatedBy: terminatedBy,
		}
	}
	if err := r.cp.ReportSessionActivity(ctx, r.nodeID, sessionID, req); err != nil {
		// A close caused by a drain or a session_revoked event posts its row into
		// a session the control plane already holds as revoked or expired. A
		// control plane since plexsphere/plexsphere#931 records the ending row of
		// such a session once, so this refusal now means the end of this
		// listener is already recorded, or that the control plane predates that
		// change and refuses every row on a dead session. Either way it is not a
		// fault of this node. It is still audit data going missing, and for
		// exactly the sessions an investigation asks about: the row is
		// fire-once, nothing re-posts it, and it is the sole carrier of the
		// terminating reason and, for a tcp session, of the transfer volumes. So
		// the answer is warned about rather than noted, and the row's payload is
		// carried into the line, which is the only place it survives. An ssh
		// session counts no bytes, so its line carries none.
		if api.IsSessionRevokedOrExpired(err) {
			msg := "ssh session ended row refused; its terminating reason is recorded only here"
			attrs := []any{"session_id", sessionID, "kind", info.Kind}
			if req.TCP != nil {
				msg = "tunnel session ended row refused; its counters are recorded only here"
				attrs = append(attrs, "bytes_in", bytesIn, "bytes_out", bytesOut)
			}
			slog.Warn(msg, append(attrs, "terminated_by", terminatedBy, "error", err)...)
			return
		}
		slog.Error("tunnel session ended report failed", "session_id", sessionID, "error", err)
	}
}

// ReportSSHCommandStarted posts the command row of an exec request before it
// runs. The error is returned: the listener runs the command only once the row
// was accepted.
func (r *controlPlaneSessionReporter) ReportSSHCommandStarted(ctx context.Context, sessionID, command string, startedAt time.Time) error {
	started := startedAt.UTC()
	return r.cp.ReportSessionActivity(ctx, r.nodeID, sessionID, api.SessionActivityRequest{
		SSH: &api.SSHActivity{Command: command, StartedAt: &started},
	})
}

// ReportSSHCommandExited posts the command row of an exec request that exited,
// with its exit code.
func (r *controlPlaneSessionReporter) ReportSSHCommandExited(ctx context.Context, sessionID, command string, exitCode int, startedAt, completedAt time.Time) error {
	started, completed := startedAt.UTC(), completedAt.UTC()
	return r.cp.ReportSessionActivity(ctx, r.nodeID, sessionID, api.SessionActivityRequest{
		SSH: &api.SSHActivity{Command: command, ExitCode: &exitCode, StartedAt: &started, CompletedAt: &completed},
	})
}

// controlPlaneSessionConnector opens the connections session_connect events
// ask for, to the control plane, under this node's id.
type controlPlaneSessionConnector struct {
	cp     *api.ControlPlane
	nodeID string
}

func (c *controlPlaneSessionConnector) OpenSessionConnection(ctx context.Context, sessionID, connectionID string) (net.Conn, error) {
	return c.cp.OpenSessionConnection(ctx, c.nodeID, sessionID, connectionID)
}

// buildHeartbeatRequest assembles the v1 heartbeat request. NATSummary is
// an empty non-nil map when NAT discovery has not produced a result yet:
// the contract requires nat_summary as an object, and a nil map marshals
// to null, which the server rejects as malformed.
func buildHeartbeatRequest(checksum, version string, natInfo *nat.DiscoveryResult) api.HeartbeatRequest {
	summary := map[string]any{}
	if natInfo != nil {
		summary["endpoint"] = natInfo.Endpoint
		summary["nat_type"] = natInfo.NATType.Wire()
	}
	return api.HeartbeatRequest{
		ClientNow:      time.Now().UTC(),
		BinaryChecksum: checksum,
		BinaryVersion:  version,
		NATSummary:     summary,
	}
}

// signingKeyRotatedHandler returns the SSE handler for signing_key_rotated
// events. It unmarshals the payload into an api.SigningKeyRotation and applies
// it to the verifier. A malformed payload or a rejected rotation is logged and
// returned as an error, leaving the installed keys unchanged.
func signingKeyRotatedHandler(verifier *api.Ed25519Verifier, logger *slog.Logger) api.EventHandler {
	return func(_ context.Context, env api.Envelope) error {
		var rot api.SigningKeyRotation
		if err := json.Unmarshal(env.Payload, &rot); err != nil {
			logger.Error("failed to parse signing_key_rotated payload", "error", err)
			return fmt.Errorf("plexd up: parse signing_key_rotated: %w", err)
		}
		if err := verifier.Rotate(rot); err != nil {
			logger.Error("failed to rotate signing keys", "error", err)
			return fmt.Errorf("plexd up: rotate signing keys: %w", err)
		}
		logger.Info("signing keys rotated via SSE", "key_id", rot.KeyID)
		return nil
	}
}

// signingKeyDispatchHandler returns the dispatch handler that installs the
// signing key every state pull carries and persists it into the identity files,
// so the verifier that checks envelopes and ssh session tokens follows the
// Domain key, and a restart starts from it. A null block keeps the installed
// key. A key the verifier refuses leaves the keys as they were and is logged
// once, and not again until a pull carries a different key, since a control
// plane serving a broken block serves it on every pull. A pulled key that
// differs from the persisted pair is committed whether or not it changed the
// verifier, so a failed commit is retried on the next pull.
//
// persisted is the pair the identity files hold at startup. The reconcile
// goroutine is the only caller, one cycle at a time, so the closure's state
// needs no mutex.
func signingKeyDispatchHandler(verifier *api.Ed25519Verifier, dataDir string, persisted api.NodeStateSigningKey, logger *slog.Logger) reconcile.DispatchHandler {
	var lastRejected *api.NodeStateSigningKey
	return func(_ context.Context, desired *api.NodeStateSnapshot) {
		if desired.SigningKey == nil {
			logger.Debug("state pull carried no signing key; keeping the installed one")
			return
		}
		pulled := *desired.SigningKey

		changed, err := verifier.Install(pulled)
		if err != nil {
			if lastRejected == nil || *lastRejected != pulled {
				logger.Warn("signing key from state pull rejected", "key_id", pulled.KeyID, "error", err)
				lastRejected = &pulled
			}
			return
		}
		lastRejected = nil
		if changed {
			// public_key is the value an operator copies into
			// tunnel.session_signing_public_key for a session helper that pinned
			// the previous key.
			logger.Info("installed signing key from state pull", "key_id", pulled.KeyID, "public_key", pulled.PublicKey)
		}

		if pulled == persisted {
			return
		}
		if err := registration.CommitSigningKey(dataDir, pulled.KeyID, pulled.PublicKey); err != nil {
			logger.Warn("signing key not persisted; retrying on the next pull", "key_id", pulled.KeyID, "error", err)
			return
		}
		persisted = pulled
	}
}

// declaredHooks converts the executor's hook inventory into the manifest's
// declared_hooks entries, re-encoding each checksum from the hex the integrity
// package works in into the base64 the contract carries.
//
// A hook whose checksum is missing or not a SHA-256 digest is dropped with a
// warning rather than sent: the manifest is validated as a whole, so one
// unusable entry would cost the binary version and digest of the entire report.
func declaredHooks(hooks []api.HookInfo, logger *slog.Logger) []api.DeclaredHook {
	if len(hooks) == 0 {
		return nil
	}
	out := make([]api.DeclaredHook, 0, len(hooks))
	for _, h := range hooks {
		checksum, err := integrity.WireChecksum(h.Checksum)
		if err != nil {
			logger.Warn("hook omitted from the capability manifest",
				"hook", h.Name, "error", err)
			continue
		}
		out = append(out, api.DeclaredHook{Name: h.Name, Checksum: checksum})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// plexdHookDiscoveryTimeout bounds the boot-time PlexdHook list, so an API
// server that does not answer holds the capability manifest back by at most
// this long.
const plexdHookDiscoveryTimeout = 10 * time.Second

// maxPlexdHooks is the manifest's plexd_hooks ceiling. A manifest carrying more
// is refused whole with 422 plexd_hooks_too_many.
const maxPlexdHooks = 128

// imageDigestRe matches the one image digest form the contract accepts in a
// plexd_hooks entry.
var imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// plexdHookLister lists the PlexdHook resources in one namespace;
// kubernetes.HookLister is the production implementation.
type plexdHookLister interface {
	ListPlexdHooks(ctx context.Context, namespace string) ([]kubernetes.PlexdHook, error)
}

// newInClusterHookLister adapts kubernetes.NewInClusterHookLister to the
// constructor discoverPlexdHooks takes.
func newInClusterHookLister(env *kubernetes.KubernetesEnvironment) (plexdHookLister, error) {
	lister, err := kubernetes.NewInClusterHookLister(env)
	if err != nil {
		return nil, err
	}
	return lister, nil
}

// discoverPlexdHooks lists the PlexdHook resources in the namespace the pod's
// ServiceAccount runs in: one list at boot, never a watch, so a hook created
// later appears at the next restart. Outside a cluster it returns nil without a
// word. Inside one, every failure (no namespace, no lister, a list refused for
// want of RBAC or a CRD, or one that outlives its budget) logs one warning and
// returns nil: the manifest goes out without plexd_hooks and boot carries on.
func discoverPlexdHooks(ctx context.Context, env *kubernetes.KubernetesEnvironment, newLister func(*kubernetes.KubernetesEnvironment) (plexdHookLister, error), logger *slog.Logger) []kubernetes.PlexdHook {
	if env == nil || !env.InCluster {
		return nil
	}
	namespace := strings.TrimSpace(env.Namespace)
	if namespace == "" {
		logger.Warn("plexd hook discovery skipped: the ServiceAccount namespace is empty")
		return nil
	}
	lister, err := newLister(env)
	if err != nil {
		logger.Warn("plexd hook discovery skipped", "error", err)
		return nil
	}

	listCtx, cancel := context.WithTimeout(ctx, plexdHookDiscoveryTimeout)
	defer cancel()
	hooks, err := lister.ListPlexdHooks(listCtx, namespace)
	if err != nil {
		logger.Warn("plexd hook discovery failed", "namespace", namespace, "error", err)
		return nil
	}
	return hooks
}

// discoveredPlexdHooks converts listed PlexdHook resources into the manifest's
// plexd_hooks entries. Like declaredHooks it drops what it cannot report, with a
// warning, because one entry the control plane refuses costs the whole
// manifest.
//
//   - image_digest is the digest after the last `@` of the image the controller
//     runs for the hook. plexd has no registry access to resolve a tag, so a hook
//     whose image is not pinned by a canonical sha256 digest (the busybox:latest
//     default included) is dropped.
//   - parameters folds the spec's name/value list into a map; a repeated name
//     keeps the later value.
//   - sandbox mirrors the controller, which runs every hook that is not
//     privileged with a read-only root filesystem and all capabilities dropped.
//   - timeout_seconds stays unset: the CRD has no field to fill it from.
//
// Resource names are unique within the one namespace listed, so entries cannot
// collide. They are sorted by name and capped at maxPlexdHooks. Nothing to
// report returns nil, so the key stays off the wire.
func discoveredPlexdHooks(hooks []kubernetes.PlexdHook, logger *slog.Logger) []api.DiscoveredPlexdHook {
	if len(hooks) == 0 {
		return nil
	}
	out := make([]api.DiscoveredPlexdHook, 0, len(hooks))
	for _, h := range hooks {
		image := h.Spec.Image()
		digest := ""
		if at := strings.LastIndex(image, "@"); at >= 0 {
			digest = image[at+1:]
		}
		if !imageDigestRe.MatchString(digest) {
			logger.Warn("plexd hook omitted from the capability manifest",
				"hook", h.Name, "image", image, "reason", "image is not pinned by a sha256 digest")
			continue
		}

		var params map[string]string
		for _, p := range h.Spec.Parameters {
			if params == nil {
				params = make(map[string]string, len(h.Spec.Parameters))
			}
			if _, repeated := params[p.Name]; repeated {
				logger.Warn("plexd hook parameter repeated; the later value is reported",
					"hook", h.Name, "parameter", p.Name)
			}
			params[p.Name] = p.Value
		}

		out = append(out, api.DiscoveredPlexdHook{
			Name:        h.Name,
			ImageDigest: digest,
			Parameters:  params,
			Sandbox:     !h.Spec.Privileged,
		})
	}
	if len(out) == 0 {
		return nil
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > maxPlexdHooks {
		logger.Warn("plexd hooks beyond the capability manifest cap omitted",
			"cap", maxPlexdHooks, "dropped", len(out)-maxPlexdHooks)
		out = out[:maxPlexdHooks]
	}
	return out
}

// controlPlaneReporter adapts api.ControlPlane to the integrity.ViolationReporter interface.
type controlPlaneReporter struct{ cp *api.ControlPlane }

func (r *controlPlaneReporter) ReportViolations(ctx context.Context, nodeID string, reports []api.IntegrityViolationReport) error {
	return r.cp.ReportIntegrityViolations(ctx, nodeID, api.IntegrityViolationsRequest{Violations: reports})
}

// deliveryModePublisher returns a callback that records the SSE delivery mode in
// a dedicated node-API cache field, so `plexd status` shows which channel is
// currently delivering control-plane state. The mode is held apart from the
// snapshot-owned metadata map, which the authoritative pull reconcile rebuilds
// from scratch on every cycle and would otherwise clobber.
func deliveryModePublisher(cache *nodeapi.StateCache, logger *slog.Logger) func(api.DeliveryMode) {
	return func(mode api.DeliveryMode) {
		cache.SetDeliveryMode(string(mode))
		logger.Info("event delivery mode changed", "mode", mode)
	}
}

// credentialRefusedPublisher returns the heartbeat's credential-refused
// callback, which fans one transition out to the shared client's gate, the
// node-API cache metadata and the health listener's readiness state. healthSrv
// is nil when the health listener is disabled.
//
// The client goes first, so no loop sends a request between the heartbeat's
// decision to park and the gate that stops it. It logs nothing: the heartbeat
// logs the refusal and the recovery itself.
func credentialRefusedPublisher(client *api.ControlPlane, cache *nodeapi.StateCache, healthSrv *health.Server) func(bool) {
	return func(refused bool) {
		client.SetCredentialRefused(refused)
		cache.SetCredentialRefused(refused)
		if healthSrv != nil {
			healthSrv.SetCredentialRefused(refused)
		}
	}
}

// systemCollectors returns the node_resources collector for a platform that
// has a system reader, and nothing for a platform without one. sysReader is
// nil on the latter (see up_other.go), where a collector would dereference it
// on every cycle, so such a node reports agent stats alone.
func systemCollectors(sysReader metrics.SystemReader, logger *slog.Logger) []metrics.Collector {
	if sysReader == nil {
		return nil
	}
	return []metrics.Collector{metrics.NewSystemCollector(sysReader, logger)}
}

// buildMetricsCollectors returns the collectors the metrics manager runs, in
// the order it runs them: the tunnel collector when tunnelReader is non-nil,
// then the node_resources collector when the platform has a system reader (see
// systemCollectors), then the agent stats collector, which every node has.
// tunnelReader is nil when the WireGuard interface did not come up.
//
// DECISION: the tunnel collector runs first. The manager's buffer keeps at
// most 2 × batch_size points (200 by default) and drops the oldest when a
// collect overflows it (metrics.Manager.enforceCapacity). A node collects one
// tunnel point per peer every 15 s, so above 48 peers the buffer trims within
// one 60 s report window. Collected first, the tunnel points are always older
// than the system and agent points of the same cycle, so a trim drops tunnel
// points before it drops the newest node_resources and agent_stats points.
// Keeping the order in this one function is what lets a test pin it.
func buildMetricsCollectors(tunnelReader metrics.TunnelStatsReader, sysReader metrics.SystemReader, startTime time.Time, logger *slog.Logger) []metrics.Collector {
	var collectors []metrics.Collector
	if tunnelReader != nil {
		collectors = append(collectors, metrics.NewTunnelCollector(tunnelReader, logger))
	}
	collectors = append(collectors, systemCollectors(sysReader, logger)...)
	return append(collectors, metrics.NewAgentStatsCollector(startTime, nil, logger))
}

// loadMergedConfig parses the config file at path — an absent one is not fatal
// — and merges the CLI flag values and then the PLEXD_* environment overrides
// on top. The returned bool reports whether the file was found. The merged
// result is what the caller validates.
func loadMergedConfig(path string) (*agent.AgentConfig, bool, error) {
	cfg, found, err := agent.ParseConfig(path)
	if err != nil {
		return nil, false, err
	}
	if apiURL != "" {
		cfg.API.BaseURL = apiURL
	}
	if mode != "" {
		cfg.Mode = mode
	}
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}
	if projectID != "" {
		cfg.Registration.ProjectID = projectID
	}
	if resourceHandle != "" {
		cfg.Registration.ResourceHandle = resourceHandle
	}
	if requestedResourceID != "" {
		cfg.Registration.RequestedResourceID = requestedResourceID
	}
	applyEnvOverrides(cfg)
	return cfg, found, nil
}

// applyEnvOverrides applies PLEXD_* environment variable overrides to the config.
// Environment variables take precedence over the config file but not CLI flags
// (CLI flags are applied separately and may have already overridden values).
func applyEnvOverrides(cfg *agent.AgentConfig) {
	if v := os.Getenv("PLEXD_BOOTSTRAP_TOKEN_FILE"); v != "" {
		cfg.Registration.TokenFile = v
	}
	if v := os.Getenv("PLEXD_ACTIONS_ENABLED"); v != "" {
		// Parsed rather than compared against "true"/"1": on the file-less path
		// this variable is the only way to turn action execution back on, so a
		// "True" or a "yes" rendered from a values file must not be read as a
		// deliberate disable. An unparseable value leaves the setting alone and
		// says so, like PLEXD_ACTIONS_MAX_CONCURRENT below.
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			slog.Warn("invalid PLEXD_ACTIONS_ENABLED, leaving actions.enabled unchanged", "value", v)
		} else {
			cfg.Actions.Enabled = &enabled
		}
	}
	if v := os.Getenv("PLEXD_HOOKS_ENABLED"); v != "" {
		cfg.Integrity.WatchEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("PLEXD_HOOKS_DIR"); v != "" {
		cfg.Actions.HooksDir = v
		cfg.Integrity.HooksDir = v
	}
	if v := os.Getenv("PLEXD_ACTIONS_MAX_CONCURRENT"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &cfg.Actions.MaxConcurrent); n != 1 || err != nil {
			slog.Warn("invalid PLEXD_ACTIONS_MAX_CONCURRENT", "value", v)
		}
	}
	if v := os.Getenv("PLEXD_NODE_API_SOCKET"); v != "" {
		cfg.NodeAPI.SocketPath = v
	}
	if v := os.Getenv("PLEXD_NODE_API_HTTP_ENABLED"); v != "" {
		cfg.NodeAPI.HTTPEnabled = v == "true" || v == "1"
	}
	if v := os.Getenv("PLEXD_NODE_API_HTTP_LISTEN"); v != "" {
		cfg.NodeAPI.HTTPListen = v
	}
	if v := os.Getenv("PLEXD_POLICY_ENABLED"); v != "" {
		// Parsed like PLEXD_ACTIONS_ENABLED rather than compared against
		// "true"/"1": on the file-less path this is the only way to reach the
		// opt-out that keeps a container without CAP_NET_ADMIN from aborting on
		// the pre-flight, so a "True" rendered from a values file must not read
		// as an enable that changes nothing. An unparseable value leaves the
		// deny-by-default posture standing and says so — the safe direction, and
		// the opposite of what a bare == "false" comparison would do to a typo.
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			slog.Warn("invalid PLEXD_POLICY_ENABLED, leaving policy.enabled unchanged", "value", v)
		} else {
			cfg.Policy.Enabled = &enabled
		}
	}
	if v := os.Getenv("PLEXD_HEALTH_ENABLED"); v != "" {
		// Same tri-state parsing, and the same reason to prefer leaving the
		// setting alone: an unparseable value that disabled the listener would
		// unbind the probe target, and the kubelet answers that with a restart
		// loop that tears down the data plane on every pass.
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			slog.Warn("invalid PLEXD_HEALTH_ENABLED, leaving health.enabled unchanged", "value", v)
		} else {
			cfg.Health.Enabled = &enabled
		}
	}
	if v := os.Getenv("PLEXD_HEALTH_LISTEN"); v != "" {
		// Verbatim, like PLEXD_NODE_API_HTTP_LISTEN: an address the kernel
		// refuses surfaces through the bind error in runUp, which names the
		// address and the likely cause, rather than through a second syntax
		// check here that would only restate it earlier.
		cfg.Health.Listen = v
	}
}

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(newLogHandler(lvl))
}

// newLogHandler builds the handler setupLogger writes through. It is a var so
// the Windows service entry can redirect the daemon's output to the Event Log,
// which is the only sink a process without a console has.
var newLogHandler = func(lvl slog.Level) slog.Handler {
	return slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
}

// imdsBaseURL is the link-local address of the cloud instance metadata service.
const imdsBaseURL = "http://169.254.169.254"

// newRegistrar builds a Registrar and, when use_metadata is enabled, attaches
// the IMDS provider. Without it the metadata sources for the bootstrap token,
// project_id, resource_handle, and requested_resource_id are never consulted.
func newRegistrar(client *api.ControlPlane, cfg registration.Config, logger *slog.Logger) *registration.Registrar {
	registrar := registration.NewRegistrar(client, cfg, logger)
	if cfg.UseMetadata {
		cfg.ApplyDefaults()
		registrar.SetMetadataProvider(registration.NewIMDSProvider(cfg.MetadataTimeout, imdsBaseURL))
	}
	return registrar
}
