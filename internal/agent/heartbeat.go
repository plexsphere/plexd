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

// CredentialRefusedThreshold is the number of consecutive heartbeats the
// control plane must answer 401, with no accepted heartbeat between them,
// before the heartbeat service parks.
const CredentialRefusedThreshold = 3

// MaxCredentialProbeInterval caps the delay between two heartbeats while the
// heartbeat service is parked.
const MaxCredentialProbeInterval = time.Hour

// HeartbeatConfig holds the configuration for the heartbeat service.
type HeartbeatConfig struct {
	// Interval is the heartbeat send interval.
	// Default: 30s
	Interval time.Duration `yaml:"interval"`

	// NodeID is the node identifier (required).
	NodeID string `yaml:"node_id"`
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
//
// The heartbeat also decides whether the control plane still accepts the
// node's credential. After CredentialRefusedThreshold consecutive heartbeats
// answered 401 the service parks: it reports the refusal through the callback
// set by SetOnCredentialRefused, and from then on sends a heartbeat only as a
// probe, first after twice the interval and then at a delay that doubles on
// every probe that fails, up to MaxCredentialProbeInterval. The first accepted
// probe unparks it and the interval applies again.
//
// DECISION: any heartbeat 401 counts, whatever its problem code, and a 401 on
// another route does not. The control plane answers nsk_invalid for a removed
// Node and nsk_revoked for a revoked credential, and an older one sends no
// code at all; keeping the decision in the heartbeat gives it one owner. Any
// other failure leaves the count unchanged, since it says nothing about the
// credential, and only an accepted heartbeat resets it.
type HeartbeatService struct {
	cfg                 HeartbeatConfig
	client              HeartbeatClient
	reconciler          ReconcileTrigger
	onCredentialRefused func(refused bool)
	onRotateKeys        func()
	buildRequest        func() api.HeartbeatRequest
	logger              *slog.Logger

	// refusals counts the heartbeats answered 401 since the last accepted one.
	// parked is set once refusals reaches CredentialRefusedThreshold, and
	// probeDelay is then the wait before the next probe. Only the Run
	// goroutine reads and writes them, so they take no lock.
	refusals   int
	parked     bool
	probeDelay time.Duration
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

// SetOnCredentialRefused sets a callback invoked with true when the service
// parks on a credential the control plane keeps refusing, and with false when
// a probe is accepted again. It is called once per transition, on the Run
// goroutine, before the transition is logged.
func (s *HeartbeatService) SetOnCredentialRefused(fn func(refused bool)) {
	s.onCredentialRefused = fn
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

// Run starts the heartbeat loop. It sends one heartbeat immediately and then
// waits nextDelay after every send, until ctx is cancelled. Run always returns
// nil.
func (s *HeartbeatService) Run(ctx context.Context) error {
	s.sendHeartbeat(ctx)

	timer := time.NewTimer(s.nextDelay())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			s.sendHeartbeat(ctx)
			timer.Reset(s.nextDelay())
		}
	}
}

// nextDelay returns how long Run waits before the next heartbeat: the probe
// delay while parked, the configured interval otherwise.
func (s *HeartbeatService) nextDelay() time.Duration {
	if s.parked {
		return s.probeDelay
	}
	return s.cfg.Interval
}

func (s *HeartbeatService) sendHeartbeat(ctx context.Context) {
	var req api.HeartbeatRequest
	if s.buildRequest != nil {
		req = s.buildRequest()
	}

	sentAt := time.Now().UTC()
	resp, err := s.client.Heartbeat(ctx, s.cfg.NodeID, req)
	if err != nil {
		if errors.Is(err, api.ErrUnauthorized) {
			s.credentialRefused(ctx, err)
			return
		}
		if s.parked {
			s.backOffProbe()
		}
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "clock_skew" {
			s.logger.ErrorContext(ctx, "agent: heartbeat: rejected for clock skew, synchronize the system clock via NTP", "error", err)
			return
		}
		s.logger.ErrorContext(ctx, "agent: heartbeat: send failed", "error", err)
		return
	}

	s.logger.DebugContext(ctx, "agent: heartbeat: accepted", "accepted_at", resp.AcceptedAt, "sent_at", sentAt)

	if s.parked {
		s.parked = false
		s.probeDelay = 0
		if s.onCredentialRefused != nil {
			s.onCredentialRefused(false)
		}
		s.logger.InfoContext(ctx, "agent: heartbeat: node credential accepted again, control-plane calls resumed")
	}
	s.refusals = 0

	if resp.Reconcile && s.reconciler != nil {
		s.reconciler.TriggerReconcile()
	}
	if resp.RotateKeys && s.onRotateKeys != nil {
		s.onRotateKeys()
	}
}

// credentialRefused counts a heartbeat the control plane answered 401. Below
// the threshold it warns. At the threshold it parks, reports the refusal and
// logs the cause once, with the way to enrol again. While parked it only backs
// the next probe off.
func (s *HeartbeatService) credentialRefused(ctx context.Context, err error) {
	s.refusals++
	switch {
	case s.parked:
		s.backOffProbe()
		s.logger.DebugContext(ctx, "agent: heartbeat: probe refused", "error", err, "next_probe", s.probeDelay)
	case s.refusals < CredentialRefusedThreshold:
		s.logger.WarnContext(ctx, "agent: heartbeat: credential refused",
			"error", err,
			"consecutive", s.refusals,
			"threshold", CredentialRefusedThreshold,
		)
	default:
		s.parked = true
		s.probeDelay = min(2*s.cfg.Interval, MaxCredentialProbeInterval)
		if s.onCredentialRefused != nil {
			s.onCredentialRefused(true)
		}
		var code string
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			code = apiErr.Code
		}
		s.logger.ErrorContext(ctx, "agent: heartbeat: node credential refused, the Node was removed from the control plane or its credential revoked; control-plane calls suspended",
			"node_id", s.cfg.NodeID,
			"code", code,
			"consecutive", s.refusals,
			"next_probe", s.probeDelay,
			"enrol_again", "run 'plexd deregister', provide a fresh bootstrap token, and restart plexd",
		)
	}
}

// backOffProbe doubles the delay before the next probe, up to
// MaxCredentialProbeInterval.
func (s *HeartbeatService) backOffProbe() {
	s.probeDelay = min(2*s.probeDelay, MaxCredentialProbeInterval)
}
