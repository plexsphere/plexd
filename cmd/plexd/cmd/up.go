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
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/plexsphere/plexd/internal/agent"
	"github.com/plexsphere/plexd/internal/api"
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

	// 9. Create node API server.
	cfg.NodeAPI.DataDir = cfg.DataDir
	cfg.NodeAPI.SecretAuthEnabled = true
	nsk := []byte(identity.NodeSecretKey)
	nodeAPISrv := nodeapi.NewServer(cfg.NodeAPI, client, nsk, logger)

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

	// Wait group for all goroutines.
	var wg sync.WaitGroup

	// 10. Start SSE manager.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sseMgr.Start(ctx, identity.NodeID); err != nil {
			logger.Error("SSE manager stopped", "error", err)
		}
	}()

	// 11. Start heartbeat.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = heartbeat.Run(ctx)
	}()

	// 12. Start reconciler.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := reconciler.Run(ctx, identity.NodeID); err != nil {
			logger.Error("reconciler stopped", "error", err)
		}
	}()

	// 13. Start node API server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := nodeAPISrv.Start(ctx, identity.NodeID); err != nil {
			logger.Error("node API server stopped", "error", err)
		}
	}()

	// Wait for shutdown signal.
	<-ctx.Done()
	logger.Info("shutting down", "reason", ctx.Err())

	// Graceful drain: stop SSE manager and wait for goroutines.
	sseMgr.Shutdown()

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
