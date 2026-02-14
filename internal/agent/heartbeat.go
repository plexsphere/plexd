// Package agent implements agent-level runtime services.
package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// DefaultHeartbeatInterval is the default heartbeat interval.
const DefaultHeartbeatInterval = 30 * time.Second

// HeartbeatConfig holds the configuration for the heartbeat service.
type HeartbeatConfig struct {
	// Interval is the heartbeat send interval.
	// Default: 30s
	Interval time.Duration

	// NodeID is the node identifier (required).
	NodeID string
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *HeartbeatConfig) ApplyDefaults() {
	if c.Interval == 0 {
		c.Interval = DefaultHeartbeatInterval
	}
}

// Validate checks that required fields are set.
func (c *HeartbeatConfig) Validate() error {
	if c.NodeID == "" {
		return errors.New("agent: heartbeat config: NodeID is required")
	}
	return nil
}

// HeartbeatClient sends heartbeat requests to the control plane.
type HeartbeatClient interface {
	Heartbeat(ctx context.Context, nodeID string, req api.HeartbeatRequest) (*api.HeartbeatResponse, error)
}

// ReconcileTrigger triggers an immediate reconciliation.
type ReconcileTrigger interface {
	TriggerReconcile()
}

// HeartbeatService sends periodic heartbeats to the control plane and
// dispatches directive flags from the response.
type HeartbeatService struct {
	cfg           HeartbeatConfig
	client        HeartbeatClient
	reconciler    ReconcileTrigger
	onAuthFailure func()
	onRotateKeys  func()
	buildRequest  func() api.HeartbeatRequest
	logger        *slog.Logger
}

// NewHeartbeatService creates a new HeartbeatService with the given
// configuration and client. The config is validated; defaults are applied
// for any zero-valued optional fields.
func NewHeartbeatService(cfg HeartbeatConfig, client HeartbeatClient, logger *slog.Logger) *HeartbeatService {
	cfg.ApplyDefaults()
	return &HeartbeatService{
		cfg:    cfg,
		client: client,
		logger: logger.With("component", "heartbeat"),
	}
}

// SetReconcileTrigger sets the reconcile trigger invoked when the control
// plane requests reconciliation.
func (s *HeartbeatService) SetReconcileTrigger(rt ReconcileTrigger) {
	s.reconciler = rt
}

// SetOnAuthFailure sets a callback invoked when a heartbeat fails with a
// 401 Unauthorized error.
func (s *HeartbeatService) SetOnAuthFailure(fn func()) {
	s.onAuthFailure = fn
}

// SetOnRotateKeys sets a callback invoked when the control plane signals
// that keys should be rotated.
func (s *HeartbeatService) SetOnRotateKeys(fn func()) {
	s.onRotateKeys = fn
}

// SetBuildRequest sets a custom heartbeat request builder. If not set,
// the service sends a zero-valued HeartbeatRequest.
func (s *HeartbeatService) SetBuildRequest(fn func() api.HeartbeatRequest) {
	s.buildRequest = fn
}

// Run starts the heartbeat loop. It sends one heartbeat immediately and
// then continues at the configured interval until ctx is cancelled.
// Run always returns nil.
func (s *HeartbeatService) Run(ctx context.Context) error {
	s.sendHeartbeat(ctx)

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.sendHeartbeat(ctx)
		}
	}
}

func (s *HeartbeatService) sendHeartbeat(ctx context.Context) {
	var req api.HeartbeatRequest
	if s.buildRequest != nil {
		req = s.buildRequest()
	}

	resp, err := s.client.Heartbeat(ctx, s.cfg.NodeID, req)
	if err != nil {
		if errors.Is(err, api.ErrUnauthorized) {
			s.logger.ErrorContext(ctx, "agent: heartbeat: unauthorized")
			if s.onAuthFailure != nil {
				s.onAuthFailure()
			}
			return
		}
		s.logger.ErrorContext(ctx, "agent: heartbeat: send failed", "error", err)
		return
	}

	if resp.Reconcile && s.reconciler != nil {
		s.reconciler.TriggerReconcile()
	}
	if resp.RotateKeys && s.onRotateKeys != nil {
		s.onRotateKeys()
	}
}
