package nat

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// CandidateReporter abstracts the control plane's endpoint candidates API.
// *api.ControlPlane satisfies it.
type CandidateReporter interface {
	ReportEndpointCandidates(ctx context.Context, nodeID string, req api.EndpointCandidatesRequest) (*api.EndpointCandidatesResponse, error)
}

// CandidatePublisher reports the node's local endpoint candidates to the
// control plane on its own loop. It is independent of STUN discovery: a node
// whose STUN servers are unreachable still has LAN addresses a peer on the
// same network can dial, and a failed initial discovery ends the Discoverer
// for good.
type CandidatePublisher struct {
	gather func() ([]string, int, error)
	cfg    Config
	logger *slog.Logger
	// now is the clock behind reported_at and the stale_after arithmetic. Tests
	// replace it before Run starts.
	now func() time.Time

	// The fields below are owned by the Run loop and never read concurrently.

	// notServed is set while the control plane answers that it does not serve
	// the operation, so that state is logged once on entry and once on exit
	// rather than on every cycle.
	notServed bool
	// accepted is set once a report succeeded. It tells the first accepted set
	// apart from an unchanged one when both are empty.
	accepted bool
	// lastAccepted is the most recent set the control plane accepted.
	lastAccepted []string
}

// NewCandidatePublisher creates a CandidatePublisher. gather returns the
// candidates to report and how many were dropped past the cap; cfg supplies
// RefreshInterval and MinReportInterval.
func NewCandidatePublisher(gather func() ([]string, int, error), cfg Config, logger *slog.Logger) *CandidatePublisher {
	return &CandidatePublisher{
		gather: gather,
		cfg:    cfg,
		logger: logger.With("component", "nat"),
		now:    time.Now,
	}
}

// Run reports the candidates at once and then once per cycle until ctx is
// done, when it returns nil. After an accepted report the next one follows
// the control plane's stale_after deadline as the Discoverer's does; after
// any failure, a failed interface read included, it follows RefreshInterval.
// No answer ends the loop: a control plane that does not serve the operation
// yet is asked again every cycle, so an upgrade is picked up without a
// restart.
func (p *CandidatePublisher) Run(ctx context.Context, reporter CandidateReporter, nodeID string) error {
	p.logger.Info("nat: endpoint candidates: started")

	timer := time.NewTimer(p.cycle(ctx, reporter, nodeID))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			timer.Reset(p.cycle(ctx, reporter, nodeID))
		}
	}
}

// cycle gathers and reports the candidates once and returns the wait before
// the next cycle.
func (p *CandidatePublisher) cycle(ctx context.Context, reporter CandidateReporter, nodeID string) time.Duration {
	candidates, truncated, err := p.gather()
	if err != nil {
		p.logger.Warn("nat: endpoint candidates: read interfaces failed", "error", err)
		return p.cfg.RefreshInterval
	}
	// An empty set is still sent: it withdraws the candidates reported
	// before. It goes out as an empty array, since the contract refuses null.
	if candidates == nil {
		candidates = []string{}
	}

	resp, err := reporter.ReportEndpointCandidates(ctx, nodeID, api.EndpointCandidatesRequest{
		Candidates: candidates,
		ReportedAt: p.now().UTC(),
	})
	if err != nil {
		p.logFailure(ctx, err)
		return p.cfg.RefreshInterval
	}

	// A nil response with a nil error carries no deadline, which reportDelay
	// reads as RefreshInterval.
	var staleAfter time.Time
	if resp != nil {
		staleAfter = resp.StaleAfter
	}

	if p.notServed {
		p.logger.Info("nat: endpoint candidates: control plane accepts endpoint candidates")
		p.notServed = false
	}
	if !p.accepted || !slices.Equal(candidates, p.lastAccepted) {
		p.logger.Info("nat: endpoint candidates: published", "candidates", candidates, "truncated", truncated)
	}
	p.accepted = true
	p.lastAccepted = slices.Clone(candidates)
	p.logger.Debug("nat: endpoint candidates: accepted", "count", len(candidates), "stale_after", staleAfter)

	return p.nextDelay(staleAfter)
}

// logFailure logs a failed report at the level its cause deserves. An error
// that arrives once ctx is done is the shutdown itself and is not logged.
// A control plane that does not serve the operation is logged once, at Info,
// since it is the expected state until the control plane ships the
// operation. Every other failure is a Warn on every cycle: none of them says
// the operation is missing, and each may clear on a later cycle, a peer
// rejection once the control plane registers the node and a clock skew once
// NTP corrects the clock.
func (p *CandidatePublisher) logFailure(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case api.IsEndpointCandidatesNotServed(err):
		if !p.notServed {
			p.logger.Info("nat: endpoint candidates: control plane does not accept endpoint candidates, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			p.notServed = true
		}
	case isAPIErr && (apiErr.Code == "endpoint_peer_not_found" || apiErr.Code == "endpoint_peer_gone"):
		p.logger.Warn("nat: endpoint candidates: rejected, this node is not registered as a peer", "code", apiErr.Code)
	case isAPIErr && apiErr.Code == "endpoint_clock_skew":
		p.logger.Warn("nat: endpoint candidates: rejected for clock skew", "error", err)
	default:
		p.logger.Warn("nat: endpoint candidates: send failed", "error", err)
	}
}

// nextDelay is reportDelay at the publisher's clock. A deadline that shortens
// the cadence below RefreshInterval is logged, for the reason
// Discoverer.nextDelay gives: it is the control plane, not the operator,
// setting the request rate.
func (p *CandidatePublisher) nextDelay(staleAfter time.Time) time.Duration {
	delay := reportDelay(p.cfg, staleAfter, p.now())
	if delay < p.cfg.RefreshInterval {
		p.logger.Warn("nat: endpoint candidates: control plane deadline shortens the report cadence",
			"delay", delay,
			"refresh_interval", p.cfg.RefreshInterval,
			"min_report_interval", p.cfg.MinReportInterval,
			"stale_after", staleAfter,
		)
	}
	return delay
}
