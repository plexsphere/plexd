package registration

import (
	"context"
	crand "crypto/rand"
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

// SetClock sets a custom clock for testing.
func (r *Registrar) SetClock(c api.Clock) { r.clock = c }

// Register orchestrates the full registration flow. If a valid identity already
// exists on disk, it is returned without contacting the control plane.
func (r *Registrar) Register(ctx context.Context) (*NodeIdentity, error) {
	// 1. Check existing identity. An identity that loads but cannot form the
	// bearer envelope (a node_id that is not a canonical UUID) is treated
	// exactly like corrupt identity files: it predates the real control-plane
	// contract and can only ever be refused, so a fresh registration is the
	// one recovery that can work.
	identity, err := LoadIdentity(r.cfg.DataDir)
	if err == nil {
		var bearer string
		bearer, err = identity.BearerToken()
		if err == nil {
			r.client.SetAuthToken(bearer)
			r.logger.Info("existing identity loaded", "node_id", identity.NodeID, "mesh_ip", identity.MeshIP)
			return identity, nil
		}
	}
	if !errors.Is(err, ErrNotRegistered) {
		r.logger.Warn("corrupt identity files, proceeding with fresh registration", "error", err)
	}

	// 2. Resolve bootstrap token. Reuse the resolver for the other inputs.
	resolver := NewTokenResolver(&r.cfg, r.metadata)
	tokenResult, err := resolver.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("registration: resolve token: %w", err)
	}

	// 3. Generate keypair.
	keypair, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("registration: generate keypair: %w", err)
	}

	// 4. Resolve project_id, resource_handle, and requested_resource_id. Each
	// resolution may itself hit the metadata service, so check a required
	// input as soon as it is resolved rather than paying for the later
	// lookups when the request is already guaranteed to fail.
	projectID, err := resolver.ResolveValue(ctx, "project_id", r.cfg.ProjectID, DefaultMetadataProjectIDPath)
	if err != nil {
		return nil, fmt.Errorf("registration: resolve project_id: %w", err)
	}
	if projectID == "" {
		return nil, errors.New("registration: project_id is required (set registration.project_id, --project-id, or PLEXD_PROJECT_ID)")
	}
	resourceHandle, err := resolver.ResolveValue(ctx, "resource_handle", r.cfg.ResourceHandle, DefaultMetadataResourceHandlePath)
	if err != nil {
		return nil, fmt.Errorf("registration: resolve resource_handle: %w", err)
	}
	if resourceHandle == "" {
		return nil, errors.New("registration: resource_handle is required (set registration.resource_handle, --resource-handle, or PLEXD_RESOURCE_HANDLE)")
	}
	requestedResourceID, err := resolver.ResolveValue(ctx, "requested_resource_id", r.cfg.RequestedResourceID, DefaultMetadataRequestedResourceIDPath)
	if err != nil {
		return nil, fmt.Errorf("registration: resolve requested_resource_id: %w", err)
	}

	// 5. Build request. The nonce is server-side replay protection, not an
	// idempotency key: a nonce the control plane has already recorded is
	// answered with 403 nonce_collision, never with the committed result. One
	// nonce per logical registration, so a retry of a request that may already
	// have been committed is denied rather than granted a second node. It is
	// deliberately not persisted — reusing it after a restart could only ever
	// produce that denial.
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	req := api.RegisterRequest{
		ProjectID:           projectID,
		ResourceHandle:      resourceHandle,
		BootstrapToken:      tokenResult.Value,
		Nonce:               nonce,
		PublicKey:           keypair.EncodePublicKey(),
		RequestedResourceID: requestedResourceID,
	}

	// 6. Register with retry.
	resp, err := r.registerWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("registration: register: %w", err)
	}

	// 7. Build identity from response and assemble the bearer envelope every
	// post-registration call presents (see BearerToken). Doing both before
	// the identity is persisted rejects a response whose nsk does not decode
	// to an AES-256-GCM key — per the register contract nsk is
	// standard-padded base64 — or whose node_id cannot form the credential,
	// instead of persisting a node that can never authenticate or open
	// secrets.
	identity = &NodeIdentity{
		NodeID:           resp.NodeID,
		MeshIP:           resp.MeshIP,
		SigningPublicKey: resp.SigningPublicKey,
		SigningKeyID:     resp.SigningKeyID,
		DomainMeshCIDR:   resp.DomainMeshCIDR,
		NodeSecretKey:    resp.NSK,
		PrivateKey:       keypair.PrivateKey,
	}
	bearer, err := identity.BearerToken()
	if err != nil {
		return nil, err
	}

	// 8. Persist identity. The control plane has already allocated the node and
	// consumed the bootstrap token at this point, so a write failure strands an
	// orphan record holding a mesh IP that no retry can reclaim: the nsk exists
	// only in this process. Say so explicitly — recovery needs an operator.
	if err := SaveIdentity(r.cfg.DataDir, identity); err != nil {
		r.logger.Error("node allocated but not persisted, manual cleanup required",
			"node_id", identity.NodeID, "mesh_ip", identity.MeshIP,
			"data_dir", r.cfg.DataDir, "error", err)
		return nil, fmt.Errorf("registration: save identity: %w", err)
	}

	// 9. Delete token file if applicable.
	if tokenResult.FilePath != "" {
		if err := os.Remove(tokenResult.FilePath); err != nil {
			r.logger.Warn("failed to delete token file", "path", tokenResult.FilePath, "error", err)
		}
	}

	// 10. Present the bearer envelope so subsequent calls on the shared
	// client authenticate as the newly registered node.
	r.client.SetAuthToken(bearer)

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
		// Request-shape errors: the same body will fail the same way.
		if errors.Is(err, api.ErrConflict) || errors.Is(err, api.ErrBadRequest) ||
			errors.Is(err, api.ErrUnprocessable) {
			return nil, err
		}

		// Check timeout.
		if r.clock.Now().Sub(start) >= r.cfg.MaxRetryDuration {
			return nil, fmt.Errorf("registration: retry timeout after %v: %w", r.cfg.MaxRetryDuration, err)
		}

		// Determine delay. Retry-After is server-controlled and unbounded, and
		// the deadline above is only checked between attempts — so cap the wait
		// at what is left of the budget, or a single "Retry-After: 86400" would
		// park registration for a day that MaxRetryDuration never interrupts.
		var delay time.Duration
		if action == api.RespectServer {
			var apiErr *api.APIError
			if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
				delay = apiErr.RetryAfter
			} else {
				delay = currentInterval
			}
			if remaining := r.cfg.MaxRetryDuration - r.clock.Now().Sub(start); delay > remaining {
				delay = remaining
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

// newNonce returns a fresh random UUIDv4 in canonical 8-4-4-4-12 hex form,
// used for server-side replay protection on POST /v1/register.
func newNonce() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", fmt.Errorf("registration: generate nonce: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// jitter adds random jitter (plus or minus fraction) to a duration.
func jitter(d time.Duration, fraction float64) time.Duration {
	jit := float64(d) * fraction
	delta := (rand.Float64()*2 - 1) * jit
	return time.Duration(float64(d) + delta)
}
