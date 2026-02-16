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
	"github.com/plexsphere/plexd/internal/integrity"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/nodeapi"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
)

// drainTimeout is the maximum time for graceful shutdown.
const drainTimeout = 30 * time.Second

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
	registrar := registration.NewRegistrar(client, cfg.Registration, logger)

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

	// 7. Create reconciler.
	reconciler := reconcile.NewReconciler(client, cfg.Reconcile, logger)

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
		logger.Info("heartbeat signaled key rotation, triggering reconcile")
		reconciler.TriggerReconcile()
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
	executor.RegisterBuiltin("gather_info", "Collect system and mesh info", nil, actions.GatherInfo(nodeInfo))
	executor.RegisterBuiltin("ping", "Test connectivity to a target IP",
		[]api.ActionParam{{Name: "target", Type: "string", Required: true, Description: "Target IP address"}},
		actions.Ping(nodeInfo))
	executor.RegisterBuiltin("diagnostics.collect", "Collect system diagnostics", nil, actions.DiagnosticsCollect())
	executor.RegisterBuiltin("diagnostics.traceroute_peer", "Traceroute to a peer",
		[]api.ActionParam{{Name: "target", Type: "string", Required: true, Description: "Target IP address"}},
		actions.DiagnosticsTraceroutePeer(nodeInfo))
	executor.RegisterBuiltin("service.restart", "Restart plexd service", nil, actions.ServiceRestart())
	executor.RegisterBuiltin("service.reload_config", "Reload configuration (SIGHUP)", nil, actions.ServiceReloadConfig())
	executor.RegisterBuiltin("service.upgrade", "Upgrade plexd (placeholder)", nil, actions.ServiceUpgrade())
	executor.RegisterBuiltin("health.check", "Check node health status", nil,
		actions.HealthCheck(&agentHealthProvider{startTime: startTime}))
	executor.RegisterBuiltin("mesh.reconnect", "Reconnect mesh tunnels", nil,
		actions.MeshReconnect(&agentMeshReconnector{reconciler: reconciler}))
	executor.RegisterBuiltin("config.dump", "Dump sanitized configuration", nil,
		actions.ConfigDump(&agentConfigProvider{cfg: cfg}))
	executor.RegisterBuiltin("logs.snapshot", "Snapshot recent log lines",
		[]api.ActionParam{{Name: "lines", Type: "string", Required: false, Description: "Number of lines (default 100, max 10000)"}},
		actions.LogsSnapshot(&agentLogProvider{}))

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
	nsk := []byte(identity.NodeSecretKey)
	nodeAPISrv := nodeapi.NewServer(cfg.NodeAPI, client, nsk, logger)
	nodeAPISrv.SetActionProvider(executor)
	nodeAPISrv.SetHookReloader(hookWatcher)

	// Register nodeapi reconcile handler so cache updates on drift.
	reconciler.RegisterHandler(nodeAPISrv.ReconcileHandler())

	// Register signing keys reconcile handler to update verifier on drift.
	reconciler.RegisterHandler(func(_ context.Context, desired *api.StateResponse, diff reconcile.StateDiff) error {
		if diff.SigningKeysChanged && diff.NewSigningKeys != nil {
			current, prev, expires := decodeSigningKeys(*diff.NewSigningKeys, logger)
			verifier.SetKeys(current, prev, expires)
			logger.Info("signing keys updated via reconcile")
		}
		return nil
	})

	// 13. Create metrics collectors and manager.
	var metricsCollectors []metrics.Collector
	if sysReader := newSystemReader(); sysReader != nil {
		metricsCollectors = append(metricsCollectors, metrics.NewSystemCollector(sysReader, logger))
	}
	metricsCollectors = append(metricsCollectors, metrics.NewAgentStatsCollector(startTime, nil, logger))
	metricsMgr := metrics.NewManager(cfg.Metrics, metricsCollectors, client, identity.NodeID, logger)

	// 14. Create log forwarding sources and forwarder.
	hostname, _ := os.Hostname()
	var logSources []logfwd.LogSource
	if journalReader := newJournalReader(); journalReader != nil {
		logSources = append(logSources, logfwd.NewJournaldSource(journalReader, hostname, logger))
	}
	for _, pattern := range cfg.LogFwd.FilePatterns {
		logSources = append(logSources, logfwd.NewFileSource(pattern, hostname, logger))
	}
	logForwarder := logfwd.NewForwarder(cfg.LogFwd, logSources, client, identity.NodeID, hostname, logger)

	// Wait group for all goroutines.
	var wg sync.WaitGroup

	// 15. Start SSE manager.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sseMgr.Start(ctx, identity.NodeID); err != nil {
			logger.Error("SSE manager stopped", "error", err)
		}
	}()

	// 16. Start heartbeat.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = heartbeat.Run(ctx)
	}()

	// 17. Start reconciler.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := reconciler.Run(ctx, identity.NodeID); err != nil {
			logger.Error("reconciler stopped", "error", err)
		}
	}()

	// 18. Start node API server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := nodeAPISrv.Start(ctx, identity.NodeID); err != nil {
			logger.Error("node API server stopped", "error", err)
		}
	}()

	// 19. Start hook watcher.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := hookWatcher.Watch(ctx); err != nil {
			logger.Error("hook watcher stopped", "error", err)
		}
	}()

	// 20. Start metrics manager.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := metricsMgr.Run(ctx); err != nil {
			logger.Error("metrics manager stopped", "error", err)
		}
	}()

	// 21. Start log forwarder.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := logForwarder.Run(ctx); err != nil {
			logger.Error("log forwarder stopped", "error", err)
		}
	}()

	// Wait for shutdown signal.
	<-ctx.Done()
	logger.Info("shutting down", "reason", ctx.Err())

	// Graceful drain: stop subsystems and wait for goroutines.
	sseMgr.Shutdown()
	executor.Shutdown(context.Background())

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
	startTime time.Time
}

func (a *agentHealthProvider) TunnelCount() int        { return 0 }
func (a *agentHealthProvider) ConnectedPeers() int     { return 0 }
func (a *agentHealthProvider) Uptime() time.Duration   { return time.Since(a.startTime) }
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

// agentLogProvider adapts to actions.LogProvider.
// Currently returns an empty snapshot; will be wired to a ring buffer
// when the log capture component is available.
type agentLogProvider struct{}

func (a *agentLogProvider) RecentLines(_ int) []string { return nil }

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
