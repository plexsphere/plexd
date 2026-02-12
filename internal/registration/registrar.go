package registration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// defaultClock implements api.Clock using real time.
type defaultClock struct{}

func (defaultClock) Now() time.Time                         { return time.Now() }
func (defaultClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Registrar orchestrates node registration with the control plane.
type Registrar struct {
	client   *api.ControlPlane
	cfg      Config
	logger   *slog.Logger
	metadata MetadataProvider
	caps     *api.CapabilitiesPayload
	clock    api.Clock
}

// NewRegistrar creates a new Registrar with the given client, config, and logger.
func NewRegistrar(client *api.ControlPlane, cfg Config, logger *slog.Logger) *Registrar {
	cfg.ApplyDefaults()
	return &Registrar{
		client: client,
		cfg:    cfg,
		logger: logger.With("component", "registration"),
		clock:  defaultClock{},
	}
}

// SetMetadataProvider sets an optional metadata provider for token resolution.
func (r *Registrar) SetMetadataProvider(mp MetadataProvider) { r.metadata = mp }

// SetCapabilities sets the optional capabilities payload for registration.
func (r *Registrar) SetCapabilities(caps *api.CapabilitiesPayload) { r.caps = caps }

// SetClock sets a custom clock for testing.
func (r *Registrar) SetClock(c api.Clock) { r.clock = c }

// Register orchestrates the full registration flow. If a valid identity already
// exists on disk, it is returned without contacting the control plane.
func (r *Registrar) Register(ctx context.Context) (*NodeIdentity, error) {
	// 1. Check existing identity.
	identity, err := LoadIdentity(r.cfg.DataDir)
	if err == nil {
		r.client.SetAuthToken(identity.NodeSecretKey)
		r.logger.Info("existing identity loaded", "node_id", identity.NodeID, "mesh_ip", identity.MeshIP)
		return identity, nil
	}
	if !errors.Is(err, ErrNotRegistered) {
		r.logger.Warn("corrupt identity files, proceeding with fresh registration", "error", err)
	}

	// 2. Resolve bootstrap token.
	tokenResult, err := NewTokenResolver(&r.cfg, r.metadata).Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("registration: resolve token: %w", err)
	}

	// 3. Generate keypair.
	keypair, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("registration: generate keypair: %w", err)
	}

	// 4. Resolve hostname.
	hostname := r.cfg.Hostname
	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("registration: resolve hostname: %w", err)
		}
	}

	// 5. Set bootstrap token as auth.
	r.client.SetAuthToken(tokenResult.Value)

	// 6. Build request.
	req := api.RegisterRequest{
		Token:        tokenResult.Value,
		PublicKey:    keypair.EncodePublicKey(),
		Hostname:     hostname,
		Metadata:     r.cfg.Metadata,
		Capabilities: r.caps,
	}

	// 7. Register with retry.
	resp, err := r.registerWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("registration: register: %w", err)
	}

	// 8. Build identity from response.
	identity = &NodeIdentity{
		NodeID:          resp.NodeID,
		MeshIP:          resp.MeshIP,
		SigningPublicKey: resp.SigningPublicKey,
		NodeSecretKey:   resp.NodeSecretKey,
		PrivateKey:      keypair.PrivateKey,
	}

	// 9. Persist identity.
	if err := SaveIdentity(r.cfg.DataDir, identity); err != nil {
		return nil, fmt.Errorf("registration: save identity: %w", err)
	}

	// 10. Delete token file if applicable.
	if tokenResult.FilePath != "" {
		if err := os.Remove(tokenResult.FilePath); err != nil {
			r.logger.Warn("failed to delete token file", "path", tokenResult.FilePath, "error", err)
		}
	}

	// 11. Set node_secret_key as auth token.
	r.client.SetAuthToken(resp.NodeSecretKey)

	r.logger.Info("registration successful", "node_id", identity.NodeID, "mesh_ip", identity.MeshIP)
	return identity, nil
}

// IsRegistered returns true if a valid identity exists on disk.
func (r *Registrar) IsRegistered() bool {
	_, err := LoadIdentity(r.cfg.DataDir)
	return err == nil
}

// registerWithRetry calls Register with exponential backoff retry.
func (r *Registrar) registerWithRetry(ctx context.Context, req api.RegisterRequest) (*api.RegisterResponse, error) {
	start := r.clock.Now()
	currentInterval := 1 * time.Second
	attempt := 0

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		attempt++
		resp, err := r.client.Register(ctx, req)
		if err == nil {
			return resp, nil
		}

		// Classify the error.
		action := api.ClassifyError(err)

		// Permanent errors: stop immediately.
		if action == api.RetryAuth || action == api.PermanentFailure {
			return nil, err
		}
		if errors.Is(err, api.ErrConflict) || errors.Is(err, api.ErrBadRequest) {
			return nil, err
		}

		// Check timeout.
		if r.clock.Now().Sub(start) >= r.cfg.MaxRetryDuration {
			return nil, fmt.Errorf("registration: retry timeout after %v: %w", r.cfg.MaxRetryDuration, err)
		}

		// Determine delay.
		var delay time.Duration
		if action == api.RespectServer {
			var apiErr *api.APIError
			if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
				delay = apiErr.RetryAfter
			} else {
				delay = currentInterval
			}
		} else {
			delay = jitter(currentInterval, 0.25)
		}

		r.logger.Warn("registration attempt failed, retrying",
			"attempt", attempt, "error", err, "delay", delay)

		// Wait.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.clock.After(delay):
		}

		// Increment interval.
		currentInterval = time.Duration(math.Min(
			float64(currentInterval)*2,
			float64(60*time.Second),
		))
	}
}

// jitter adds random jitter (plus or minus fraction) to a duration.
func jitter(d time.Duration, fraction float64) time.Duration {
	jit := float64(d) * fraction
	delta := (rand.Float64()*2 - 1) * jit
	return time.Duration(float64(d) + delta)
}
