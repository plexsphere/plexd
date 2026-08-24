package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
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
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/nat"
	"github.com/plexsphere/plexd/internal/nodeapi"
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

// policyCapabilityHint is carried by both firewall-baseline failures. The kernel
// reports a dropped capability as a bare EPERM on a netlink call, which names
// neither what the process is missing nor the setting that turns the whole path
// off — so the operator's two next steps go in the message rather than in the
// source.
const policyCapabilityHint = "policy enforcement needs CAP_NET_ADMIN, " +
	"grant it to the container or set policy.enabled: false to run this node without enforcement"

// firewallController indirects the platform-specific constructor so tests can
// drive the pre-flight path without depending on the host's netfilter state.
var firewallController = newFirewallController

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

func runUp(cmd *cobra.Command, _ []string) error {
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
	fwCtrl := firewallController(logger)
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

	// The command's context is the parent, so a caller that owns one can shut the
	// daemon down without a signal. Under Execute that context is always
	// non-nil; a direct call (a test) may leave it unset, which NotifyContext
	// would panic on.
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
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
	wgCtrl := newWGController(logger)
	wgMgr := wireguard.NewManager(wgCtrl, cfg.WireGuard, logger)
	wgReady := false
	if wgCtrl != nil {
		if err := wgMgr.Setup(ctx, identity); err != nil {
			logger.Warn("wireguard setup failed, continuing without WireGuard",
				"error", err,
			)
		} else {
			wgReady = true
		}
	}

	// 5b. Initialize NAT traversal and peer exchange.
	stunClient := &nat.UDPSTUNClient{Timeout: cfg.NAT.Timeout}
	natDiscoverer := nat.NewDiscoverer(stunClient, cfg.NAT, cfg.WireGuard.ListenPort, logger)
	exchanger := peerexchange.NewExchanger(natDiscoverer, client, cfg.PeerExchange, logger)

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
	if _, err := enforcer.ApplyFirewallRules(nil, cfg.WireGuard.InterfaceName); err != nil {
		return fmt.Errorf("plexd up: install deny-by-default firewall baseline: %s: %w", policyCapabilityHint, err)
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
	if healthSrv != nil && wgReady {
		iface := cfg.WireGuard.InterfaceName
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
		sessionReporter.ReportSessionEnded(reportCtx, sessionID, info.TargetHost, info.TargetPort, info.BytesIn, info.BytesOut, tunnel.TerminatedByFromReason(reason))
	})

	// 5e. Initialize bridge subsystem (conditional on bridge mode).
	var (
		bridgeMgr     *bridge.Manager
		ingressMgr    *bridge.IngressManager
		userAccessMgr *bridge.UserAccessManager
		s2sMgr        *bridge.SiteToSiteManager
		acmeMgr       *bridge.ACMEManager
	)
	if cfg.Mode == "bridge" && cfg.Bridge.Enabled {
		routeCtrl := newRouteController(logger)
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
			vpnCtrl := newVPNController(logger)
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
	rotator := agent.NewKeyRotator(client, identity, cfg.DataDir, device, reconciler, logger)

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
	// blocks, the events only pull them forward. session_revoked is the same
	// shape from the other end — a session leaving the sessions block is what
	// tears it down, so the event only pulls the observing reconcile forward.
	triggerReconcile := func(_ context.Context, _ api.Envelope) error {
		reconciler.TriggerReconcile()
		return nil
	}
	for _, eventType := range []string{
		api.EventNodeStateUpdated,
		api.EventActionRequest,
		api.EventSessionSetup,
		api.EventSessionRevoked,
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
	heartbeat.SetOnAuthFailure(reRegisterOnAuthFailure(ctx, registrar, logger))
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

	// Build the release fetcher and Sigstore verifier for service.upgrade.
	upgradeFetcher := upgrade.NewFetcher(cfg.Upgrade)
	upgradeVerifier, err := upgrade.NewVerifier(cfg.Upgrade)
	if err != nil {
		return fmt.Errorf("plexd up: upgrade verifier: %w", err)
	}

	// 10. Create action executor and register built-in actions.
	executor := actions.NewExecutor(cfg.Actions, client, integrityVerifier, logger)

	nodeInfo := &agentNodeInfo{nodeID: identity.NodeID, meshIP: identity.MeshIP}
	executor.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics (CPU, memory, disk, network)",
		[]api.ActionParam{
			{Name: "include_network", Type: "bool", Required: false, Default: "true", Description: "Include network interface info"},
			{Name: "include_processes", Type: "bool", Required: false, Default: "true", Description: "Include process listing"},
		}, actions.DiagnosticsCollect())
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
	executor.RegisterBuiltin("service.restart", "Restart the plexd service", nil, actions.ServiceRestart())
	executor.RegisterBuiltin("service.reload_config", "Reload configuration without restart", nil, actions.ServiceReloadConfig())
	executor.RegisterBuiltin("service.upgrade", "Upgrade plexd to a specified version",
		[]api.ActionParam{
			{Name: "version", Type: "string", Required: true, Description: "Target version"},
			{Name: "checksum", Type: "string", Required: true, Description: "Expected SHA-256 checksum"},
		}, actions.ServiceUpgrade(upgradeFetcher, upgradeVerifier))
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
	// correlator watches for rotation, and the declared hooks. The builtin
	// action list is deliberately not sent: the contract has no field for it and
	// the handler rejects unknown ones, so an action list on the wire refuses
	// the whole manifest. `plexd actions` reads it from the node API instead.
	_, capsHooks := executor.Capabilities()
	caps := api.CapabilityManifestRequest{
		BinaryVersion:         buildVersion,
		BinaryChecksum:        wireChecksum,
		SSHHostKeyFingerprint: tunnel.HostKeyFingerprint(hostKey),
		DeclaredHooks:         declaredHooks(capsHooks, logger),
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

	// Register nodeapi reconcile handler so cache updates on drift. The pull is
	// authoritative: node_state_updated triggers a reconcile (see above), and
	// this handler refreshes the node API cache from the resulting snapshot.
	reconciler.RegisterHandler(nodeAPISrv.ReconcileHandler())

	// Action dispatches are consumed from the pull's executions block on every
	// successful cycle, drift or not: the block is a delivery queue that
	// redelivers each entry until its execution settles through the callback.
	dispatcher := actions.NewDispatcher(executor, identity.NodeID, logger)
	reconciler.RegisterDispatchHandler(dispatcher.Handle)

	// Mediated-access sessions are consumed from the pull's sessions block on
	// every successful cycle too, but that block is desired state: a listener is
	// provisioned when its entry appears and torn down when the entry drains,
	// which is the only teardown signal there is.
	sessionDispatcher := tunnel.NewDispatcher(meshServer.SessionManager(), sessionReporter, logger)
	reconciler.RegisterDispatchHandler(sessionDispatcher.Handle)

	// The reachability block is the control plane's own verdict about this node,
	// not desired state: it is observed and logged on every successful pull, and
	// never stored or converged on. A node whose heartbeats stop being admitted
	// while its state pulls keep succeeding has no other way to learn that.
	reconciler.RegisterDispatchHandler(reconcile.NewReachabilityObserver(logger).Handle)

	// Register the WireGuard reconcile handler only when the interface came up.
	// A handler that fails every cycle would hold back the reconciler snapshot,
	// so the fingerprint short-circuit could never converge on such hosts.
	if wgReady {
		reconciler.RegisterHandler(wireguard.ReconcileHandler(wgMgr))
	} else {
		logger.Warn("wireguard unavailable, skipping peer reconcile handler")
	}

	// Register policy reconcile handler.
	reconciler.RegisterHandler(policy.ReconcileHandler(enforcer, cfg.WireGuard.InterfaceName))

	// Register peer/policy snapshot reconcile handler for node API queries.
	reconciler.RegisterHandler(func(_ context.Context, desired *api.NodeStateSnapshot, _ reconcile.StateDiff) error {
		peerSnap.update(desired.Peers)
		policySnap.update(desired.Policy)
		return nil
	})

	// Register bridge reconcile handlers (conditional).
	if bridgeMgr != nil {
		if relay := bridgeMgr.Relay(); relay != nil {
			reconciler.RegisterHandler(bridge.RelayReconcileHandler(relay, logger))
		}
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

	// 13. Create metrics collectors and manager.
	var metricsCollectors []metrics.Collector
	if sysReader := newSystemReader(); sysReader != nil {
		metricsCollectors = append(metricsCollectors, metrics.NewSystemCollector(sysReader, logger))
	}
	metricsCollectors = append(metricsCollectors, metrics.NewAgentStatsCollector(startTime, nil, logger))

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
	if journalReader := newJournalReader(logger); journalReader != nil {
		logSources = append(logSources, logfwd.NewJournaldSource(journalReader, hostname, logger))
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

	// 25. Start tunnel mesh server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := meshServer.Start(ctx); err != nil {
			logger.Error("mesh server stopped", "error", err)
		}
	}()

	// 26. Start bridge relay (bridge mode only).
	if bridgeMgr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bridgeMgr.StartRelay(ctx); err != nil {
				logger.Error("bridge relay stopped", "error", err)
			}
		}()
	}

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
			Endpoint:  p.FallbackEndpoint,
		}
	}
	ps.mu.Lock()
	ps.peers = statuses
	ps.mu.Unlock()
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

// controlPlaneSessionReporter reports tcp-phase session activity rows to the
// control plane. plexd's tunnel subsystem is an opaque TCP forwarder, so it
// emits tcp rows: a session_started row when the listener is up and a
// session_ended row carrying byte counters and a terminated_by reason on close.
type controlPlaneSessionReporter struct {
	cp     *api.ControlPlane
	nodeID string
}

// ReportSessionStarted returns the post's error rather than logging it away: the
// row carries the listener endpoint the operator connects to, so the dispatcher
// has to know whether it arrived.
func (r *controlPlaneSessionReporter) ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int, listenerEndpoint string) error {
	return r.cp.ReportSessionActivity(ctx, r.nodeID, sessionID, api.SessionActivityRequest{
		TCP: &api.TCPActivity{
			Phase:            api.TCPPhaseSessionStarted,
			TargetHost:       targetHost,
			TargetPort:       targetPort,
			ListenerEndpoint: listenerEndpoint,
		},
	})
}

func (r *controlPlaneSessionReporter) ReportSessionEnded(ctx context.Context, sessionID, targetHost string, targetPort int, bytesIn, bytesOut int64, terminatedBy string) {
	if err := r.cp.ReportSessionActivity(ctx, r.nodeID, sessionID, api.SessionActivityRequest{
		TCP: &api.TCPActivity{
			Phase:        api.TCPPhaseSessionEnded,
			TargetHost:   targetHost,
			TargetPort:   targetPort,
			BytesIn:      &bytesIn,
			BytesOut:     &bytesOut,
			TerminatedBy: terminatedBy,
		},
	}); err != nil {
		slog.Error("tunnel session ended report failed", "session_id", sessionID, "error", err)
	}
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

// reRegisterOnAuthFailure returns the heartbeat's auth-failure callback: a
// heartbeat the control plane refuses means the node's credential is no longer
// accepted, and re-registering is the only recovery the agent can perform on
// its own.
//
// The callback deliberately leaves the credential alone. Register arms the
// shared client with the bearer envelope itself, on both of its paths, so the
// recovery is complete when it returns. Setting the token here from the
// returned identity — as this callback once did, with the raw base64
// NodeSecretKey — replaces the envelope with a credential the control plane
// answers 401 to, so the next heartbeat fails the same way and the fallback
// that exists to recover the node is what keeps it broken.
func reRegisterOnAuthFailure(ctx context.Context, registrar *registration.Registrar, logger *slog.Logger) func() {
	return func() {
		logger.Warn("heartbeat auth failure, attempting re-registration")
		newIdentity, err := registrar.Register(ctx)
		if err != nil {
			logger.Error("re-registration failed", "error", err)
			return
		}
		logger.Info("re-registration successful", "node_id", newIdentity.NodeID)
	}
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
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
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
