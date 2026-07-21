package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
	"github.com/plexsphere/plexd/internal/wireguard"
)

// drainTimeout is the maximum time for graceful shutdown.
const drainTimeout = 30 * time.Second

// sessionEndedReportTimeout bounds a single session_ended report. Sessions are
// closed one after another on shutdown, so this also bounds how long tunnel
// teardown can hold up the drain.
const sessionEndedReportTimeout = 2 * time.Second

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
	// 1. Parse config.
	cfg, err := agent.ParseConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("plexd up: %w", err)
	}

	// Apply CLI flag overrides.
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

	// Apply environment variable overrides.
	applyEnvOverrides(cfg)

	// 2. Set up structured logger.
	logger := setupLogger(cfg.LogLevel)

	logger.Info("starting plexd",
		"version", buildVersion,
		"mode", cfg.Mode,
	)

	// 3. Create control plane client.
	client, err := api.NewControlPlane(cfg.API, buildVersion, logger)
	if err != nil {
		return fmt.Errorf("plexd up: create client: %w", err)
	}

	// 4. Register (or load existing identity).
	cfg.Registration.DataDir = cfg.DataDir
	registrar := newRegistrar(client, cfg.Registration, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	identity, err := registrar.Register(ctx)
	if err != nil {
		return fmt.Errorf("plexd up: registration: %w", err)
	}

	logger.Info("registered",
		"node_id", identity.NodeID,
		"mesh_ip", identity.MeshIP,
	)

	// Set auth token (Register already does this, but be explicit).
	client.SetAuthToken(identity.NodeSecretKey)

	// 5. Create Ed25519 verifier from the control plane's signing public key.
	sigKey, err := base64.StdEncoding.DecodeString(identity.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("plexd up: decode signing key: %w", err)
	}
	if len(sigKey) != ed25519.PublicKeySize {
		return fmt.Errorf("plexd up: invalid signing key length: got %d, want %d", len(sigKey), ed25519.PublicKeySize)
	}
	verifier := api.NewEd25519Verifier(ed25519.PublicKey(sigKey))

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
	exchanger := peerexchange.NewExchanger(natDiscoverer, wgMgr, client, cfg.PeerExchange, logger)

	// 5c. Initialize network policy engine.
	policyEngine := policy.NewPolicyEngine(logger)
	fwCtrl := newFirewallController(logger)
	enforcer := policy.NewEnforcer(policyEngine, fwCtrl, cfg.Policy, logger)

	// Install the deny-by-default baseline immediately, independent of the
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
	if _, err := enforcer.ApplyFirewallRules(nil, cfg.WireGuard.InterfaceName); err != nil {
		return fmt.Errorf("plexd up: install deny-by-default firewall baseline: %w", err)
	}

	// 5d. Initialize tunnel subsystem.
	hostKey, err := tunnel.LoadOrGenerateHostKey(cfg.DataDir, logger)
	if err != nil {
		return fmt.Errorf("plexd up: tunnel host key: %w", err)
	}
	jwtVerifier := tunnel.NewEd25519JWTVerifier(ed25519.PublicKey(sigKey))
	meshServer := tunnel.NewMeshServer(cfg.Tunnel, hostKey, jwtVerifier, logger)
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
	sseMgr.RegisterHandler(api.EventSigningKeyRotated, func(_ context.Context, env api.SignedEnvelope) error {
		var keys api.SigningKeys
		if err := json.Unmarshal(env.Payload, &keys); err != nil {
			logger.Error("failed to parse signing_key_rotated payload", "error", err)
			return fmt.Errorf("plexd up: parse signing_key_rotated: %w", err)
		}
		current, prev, expires := decodeSigningKeys(keys, logger)
		verifier.SetKeys(current, prev, expires)
		logger.Info("signing keys rotated via SSE")
		return nil
	})

	// Register WireGuard SSE handlers.
	sseMgr.RegisterHandler(api.EventPeerAdded, wireguard.HandlePeerAdded(wgMgr))
	sseMgr.RegisterHandler(api.EventPeerRemoved, wireguard.HandlePeerRemoved(wgMgr))
	sseMgr.RegisterHandler(api.EventPeerKeyRotated, wireguard.HandlePeerKeyRotated(wgMgr))

	// Register peer exchange SSE handler (peer_endpoint_changed).
	exchanger.RegisterHandlers(sseMgr)

	// Register tunnel SSE handlers.
	sseMgr.RegisterHandler(api.EventSSHSessionSetup, tunnel.HandleSSHSessionSetup(meshServer.SessionManager(), sessionReporter))
	sseMgr.RegisterHandler(api.EventSessionRevoked, tunnel.HandleSessionRevoked(meshServer.SessionManager()))

	// 7. Create reconciler.
	reconciler := reconcile.NewReconciler(client, cfg.Reconcile, logger)

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
	sseMgr.RegisterHandler(api.EventRotateKeys, func(_ context.Context, _ api.SignedEnvelope) error {
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

	// Register bridge SSE handlers (needs reconciler and bridge managers).
	if bridgeMgr != nil {
		sseMgr.RegisterHandler(api.EventBridgeConfigUpdated, bridge.HandleBridgeConfigUpdated(reconciler))

		if relay := bridgeMgr.Relay(); relay != nil {
			sseMgr.RegisterHandler(api.EventRelaySessionAssigned, bridge.HandleRelaySessionAssigned(relay, logger))
			sseMgr.RegisterHandler(api.EventRelaySessionRevoked, bridge.HandleRelaySessionRevoked(relay, logger))
		}
		if ingressMgr != nil {
			sseMgr.RegisterHandler(api.EventIngressRuleAssigned, bridge.HandleIngressRuleAssigned(ingressMgr, logger))
			sseMgr.RegisterHandler(api.EventIngressRuleRevoked, bridge.HandleIngressRuleRevoked(ingressMgr, logger))
			sseMgr.RegisterHandler(api.EventIngressConfigUpdated, bridge.HandleIngressConfigUpdated(reconciler))
		}
		if userAccessMgr != nil {
			sseMgr.RegisterHandler(api.EventUserAccessPeerAssigned, bridge.HandleUserAccessPeerAssigned(userAccessMgr, logger))
			sseMgr.RegisterHandler(api.EventUserAccessPeerRevoked, bridge.HandleUserAccessPeerRevoked(userAccessMgr, logger))
			sseMgr.RegisterHandler(api.EventUserAccessConfigUpdated, bridge.HandleUserAccessConfigUpdated(reconciler))
		}
		if s2sMgr != nil {
			sseMgr.RegisterHandler(api.EventSiteToSiteTunnelAssigned, bridge.HandleSiteToSiteTunnelAssigned(s2sMgr, logger))
			sseMgr.RegisterHandler(api.EventSiteToSiteTunnelRevoked, bridge.HandleSiteToSiteTunnelRevoked(s2sMgr, logger))
			sseMgr.RegisterHandler(api.EventSiteToSiteConfigUpdated, bridge.HandleSiteToSiteConfigUpdated(reconciler))
		}
	}

	selfChecksum, err := integrity.SelfChecksum()
	if err != nil {
		return fmt.Errorf("plexd up: binary checksum: %w", err)
	}

	// 8. Create heartbeat service.
	hbCfg := agent.HeartbeatConfig{
		Interval: cfg.Heartbeat.Interval,
		NodeID:   identity.NodeID,
	}
	hbCfg.ApplyDefaults()
	heartbeat := agent.NewHeartbeatService(hbCfg, client, logger)
	heartbeat.SetReconcileTrigger(reconciler)
	heartbeat.SetOnAuthFailure(func() {
		logger.Warn("heartbeat auth failure, attempting re-registration")
		newIdentity, err := registrar.Register(ctx)
		if err != nil {
			logger.Error("re-registration failed", "error", err)
			return
		}
		client.SetAuthToken(newIdentity.NodeSecretKey)
		logger.Info("re-registration successful", "node_id", newIdentity.NodeID)
	})
	heartbeat.SetOnRotateKeys(func() {
		logger.Info("heartbeat signaled key rotation, starting key rotation")
		go func() {
			if err := rotator.Rotate(ctx); err != nil {
				logger.Error("key rotation failed", "error", err)
			}
		}()
	})

	heartbeat.SetBuildRequest(func() api.HeartbeatRequest {
		return buildHeartbeatRequest(selfChecksum, buildVersion, exchanger.LastResult())
	})

	// 9. Create integrity verifier for hook execution.
	integrityStore, err := integrity.NewStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("plexd up: integrity store: %w", err)
	}
	integrityVerifier := integrity.NewVerifier(cfg.Integrity, integrityStore, &controlPlaneReporter{cp: client}, logger)

	// Record start time for uptime calculations.
	startTime := time.Now()

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
		}, actions.ServiceUpgrade(client))
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

	// Report capabilities to the control plane.
	caps := api.CapabilitiesPayload{
		Binary: &api.BinaryInfo{Version: buildVersion},
	}
	capsActions, capsHooks := executor.Capabilities()
	caps.BuiltinActions = capsActions
	caps.Hooks = capsHooks
	if err := client.UpdateCapabilities(ctx, identity.NodeID, caps); err != nil {
		logger.Warn("capabilities report failed", "error", err)
	}

	// Register action_request SSE handler.
	sseMgr.RegisterHandler(api.EventActionRequest, actions.HandleActionRequest(executor, identity.NodeID, logger))

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
	cfg.NodeAPI.DataDir = cfg.DataDir
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

	// Register node_state_updated and node_secrets_updated SSE handlers for
	// real-time cache updates (in addition to reconcile-loop fallback).
	sseMgr.RegisterHandler(api.EventNodeStateUpdated, func(ctx context.Context, env api.SignedEnvelope) error {
		return nodeapi.HandleNodeStateUpdated(nodeAPISrv.Cache(), logger, env)
	})
	sseMgr.RegisterHandler(api.EventNodeSecretsUpdated, func(ctx context.Context, env api.SignedEnvelope) error {
		return nodeapi.HandleNodeSecretsUpdated(nodeAPISrv.Cache(), logger, env)
	})

	// Register nodeapi reconcile handler so cache updates on drift.
	reconciler.RegisterHandler(nodeAPISrv.ReconcileHandler())

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
	if journalReader := newJournalReader(); journalReader != nil {
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

	// Wait group for all goroutines.
	var wg sync.WaitGroup

	// 16. Start SSE manager.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sseMgr.Start(ctx, identity.NodeID); err != nil {
			logger.Error("SSE manager stopped", "error", err)
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
	if err := wgMgr.Teardown(); err != nil {
		logger.Error("wireguard teardown error", "error", err)
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

func (r *controlPlaneSessionReporter) ReportSessionStarted(ctx context.Context, sessionID, targetHost string, targetPort int) {
	if err := r.cp.ReportSessionActivity(ctx, r.nodeID, sessionID, api.SessionActivityRequest{
		TCP: &api.TCPActivity{
			Phase:      api.TCPPhaseSessionStarted,
			TargetHost: targetHost,
			TargetPort: targetPort,
		},
	}); err != nil {
		slog.Error("tunnel session started report failed", "session_id", sessionID, "error", err)
	}
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

// decodeSigningKeys decodes base64-encoded signing keys from an api.SigningKeys
// struct into ed25519 public keys for use with the Ed25519Verifier.
func decodeSigningKeys(keys api.SigningKeys, logger *slog.Logger) (current, previous ed25519.PublicKey, transitionExpires time.Time) {
	if keys.Current != "" {
		decoded, err := base64.StdEncoding.DecodeString(keys.Current)
		if err != nil {
			logger.Error("failed to decode current signing key", "error", err)
		} else {
			current = ed25519.PublicKey(decoded)
		}
	}
	if keys.Previous != "" {
		decoded, err := base64.StdEncoding.DecodeString(keys.Previous)
		if err != nil {
			logger.Error("failed to decode previous signing key", "error", err)
		} else {
			previous = ed25519.PublicKey(decoded)
		}
	}
	if keys.TransitionExpires != nil {
		transitionExpires = *keys.TransitionExpires
	}
	return current, previous, transitionExpires
}

// controlPlaneReporter adapts api.ControlPlane to the integrity.ViolationReporter interface.
type controlPlaneReporter struct{ cp *api.ControlPlane }

func (r *controlPlaneReporter) ReportViolation(ctx context.Context, nodeID string, report api.IntegrityViolationReport) error {
	return r.cp.ReportIntegrityViolation(ctx, nodeID, report)
}

// applyEnvOverrides applies PLEXD_* environment variable overrides to the config.
// Environment variables take precedence over the config file but not CLI flags
// (CLI flags are applied separately and may have already overridden values).
func applyEnvOverrides(cfg *agent.AgentConfig) {
	if v := os.Getenv("PLEXD_BOOTSTRAP_TOKEN_FILE"); v != "" {
		cfg.Registration.TokenFile = v
	}
	if v := os.Getenv("PLEXD_ACTIONS_ENABLED"); v != "" {
		cfg.Actions.Enabled = v == "true" || v == "1"
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
	if v := os.Getenv("PLEXD_NODE_API_ENABLED"); v != "" {
		// Node API doesn't have an Enabled field; it's always active.
		// This env var is documented but effectively a no-op in current code.
		_ = v
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
