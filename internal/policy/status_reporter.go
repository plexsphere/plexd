package policy

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// StatusClient sends policy status reports. *api.ControlPlane satisfies it.
type StatusClient interface {
	ReportPolicyStatus(ctx context.Context, nodeID string, req api.PolicyStatusRequest) (*api.PolicyStatusResponse, error)
}

// defaultStatusInterval is agent.DefaultHeartbeatInterval. internal/policy
// cannot import internal/agent, which depends on it.
const defaultStatusInterval = 30 * time.Second

// StatusReporter sends the Enforcer's record to
// PUT /v1/nodes/{node_id}/policy-status: what the node enforces, the ruleset
// it applied, the one its latest apply failed on and why, and the drop
// counters of its default deny. The control plane derives the node's policy
// status from it and logs every change in what the node enforces.
//
// It sends when the Enforcer signals a change of the enforcement, the applied
// block or the rejection. On each tick of the interval it sends only when no
// report of the current state was accepted yet, which is the case after a
// failed send, or when the drop counters moved since the last accepted one,
// so a quiet node sends nothing (the author chose this on 2026-11-13).
//
// DECISION: the reporter sends from a goroutine of its own, one report at a
// time, never from inside the dispatch handler, so a slow control plane never
// delays a reconcile cycle. This follows bridge.RelayStatusReporter.
//
// DECISION: nothing is sent before the Enforcer's first Sync, because until
// then plexd has seen no pull and could only report the startup baseline,
// which is no ruleset of the control plane's. Nothing is sent at shutdown
// either: the contract defines no such report, and the control plane keeps
// the last one.
type StatusReporter struct {
	interval time.Duration
	nodeID   string
	client   StatusClient
	enforcer *Enforcer
	logger   *slog.Logger

	// The fields below are owned by the Run loop and never read concurrently.

	// stopped is set once the control plane answered that it has no route
	// for the report. The contract asks the agent to stop reporting until it
	// restarts.
	stopped bool
	// notProvisioned is set while the control plane answers that it serves
	// the route without its recording service, so that state is logged once
	// on entry and once on exit.
	notProvisioned bool
	// accepted is the request the control plane accepted last, nil before
	// the first.
	accepted *api.PolicyStatusRequest
}

// NewStatusReporter creates a StatusReporter that reports what enforcer
// records for nodeID through client. A non-positive interval becomes 30 s,
// the value of agent.DefaultHeartbeatInterval: the contract asks for an
// unchanged report at most once per heartbeat interval.
func NewStatusReporter(interval time.Duration, nodeID string, client StatusClient, enforcer *Enforcer, logger *slog.Logger) *StatusReporter {
	if interval <= 0 {
		interval = defaultStatusInterval
	}
	return &StatusReporter{
		interval: interval,
		nodeID:   nodeID,
		client:   client,
		enforcer: enforcer,
		logger:   logger.With("component", "policy"),
	}
}

// Run sends a report on every change the Enforcer signals and checks on every
// tick of the interval whether one is due, until ctx is done. It then returns
// nil without a last report.
func (r *StatusReporter) Run(ctx context.Context) error {
	r.logger.Info("policy status: reporter started", "interval", r.interval)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.enforcer.Changed():
			r.report(ctx, true)
			// The interval restarts after a send on a change, so the tick
			// that follows does not check again at once.
			ticker.Reset(r.interval)
		case <-ticker.C:
			// A change signalled beside the tick is spent here: this send
			// reads the latest state, and left pending, the signal would
			// send it again at once.
			force := false
			select {
			case <-r.enforcer.Changed():
				force = true
			default:
			}
			r.report(ctx, force)
		}
	}
}

// report builds the report from the Enforcer's current record and sends it
// when force is set or it differs from the one accepted last. It does nothing
// before the Enforcer's first Sync and after the control plane answered that
// it has no route.
func (r *StatusReporter) report(ctx context.Context, force bool) {
	if r.stopped {
		return
	}
	st := r.enforcer.Status()
	if !st.Synced {
		return
	}
	packets, bytes, counted := r.enforcer.DropCounts()
	req := buildPolicyStatusRequest(st, packets, bytes, counted)
	if !force && r.accepted != nil && reflect.DeepEqual(*r.accepted, req) {
		return
	}

	resp, err := r.client.ReportPolicyStatus(ctx, r.nodeID, req)
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notProvisioned {
		r.logger.Info("policy status: control plane accepts policy status reports")
		r.notProvisioned = false
	}
	attrs := []any{
		"enforcement", req.Enforcement,
		"status", resp.Status,
		"applied_fingerprint", appliedFingerprint(req),
		"rejected_fingerprint", rejectedFingerprint(req),
	}
	if r.accepted == nil || !sameReportedRequest(*r.accepted, req) {
		r.logger.Info("policy status: reported", attrs...)
	} else {
		r.logger.Debug("policy status: reported", attrs...)
	}
	r.accepted = &req
}

// logSendError logs a failed send at the level its cause deserves. An error
// that arrives once ctx is done is the shutdown itself and is not logged. A
// refused credential is logged at Debug, since the heartbeat names the cause
// once when it parks the agent. A control plane without the route is logged
// once, at Info, and ends the reporting until plexd restarts, as the contract
// asks. One that serves the route without its recording service is logged
// once at Info and asked again every interval. policy_status_node_gone is a
// Warn on every send, and so is every other failure: the next tick sends
// again.
func (r *StatusReporter) logSendError(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case errors.Is(err, api.ErrCredentialRefused):
		r.logger.Debug("policy status: send failed", "error", err)
	case api.IsPolicyStatusNotServed(err):
		r.logger.Info("policy status: control plane does not accept policy status reports, not reporting until restart",
			"status", apiErr.StatusCode,
			"code", apiErr.Code,
		)
		r.stopped = true
	case api.IsPolicyStatusNotProvisioned(err):
		if !r.notProvisioned {
			r.logger.Info("policy status: control plane has not provisioned policy status reports, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			r.notProvisioned = true
		}
	case isAPIErr && apiErr.Code == "policy_status_node_gone":
		r.logger.Warn("policy status: rejected, this node was removed", "code", apiErr.Code)
	default:
		r.logger.Warn("policy status: send failed", "error", err)
	}
}

// buildPolicyStatusRequest turns the Enforcer's record into a report. It sets
// the enforcement; with a pull applied, applied: {revisions: []} for a pull
// with policy: null, and the block's fingerprint and revisions for a block
// with a fingerprint, while a block without one cannot be echoed and leaves
// applied out; with a rejection, its fingerprint, revisions and reason; and
// with counted drops, the counters, each capped at math.MaxInt64, the
// contract's ceiling.
func buildPolicyStatusRequest(s Status, packets, bytes uint64, counted bool) api.PolicyStatusRequest {
	req := api.PolicyStatusRequest{Enforcement: s.Enforcement}
	if s.HasApplied {
		switch {
		case s.Applied == nil:
			req.Applied = &api.PolicyStatusApplied{Revisions: []api.PolicyRevisionRef{}}
		case s.Applied.Fingerprint != "":
			req.Applied = &api.PolicyStatusApplied{
				Fingerprint: s.Applied.Fingerprint,
				Revisions:   revisionsOrEmpty(s.Applied.Revisions),
			}
		}
	}
	if s.Rejected != nil {
		req.Rejected = &api.PolicyStatusRejected{
			Fingerprint: s.Rejected.Fingerprint,
			Revisions:   revisionsOrEmpty(s.Rejected.Revisions),
			Reason:      s.Reason,
		}
	}
	if counted {
		req.Drops = &api.PolicyStatusDrops{Packets: capInt64(packets), Bytes: capInt64(bytes)}
	}
	return req
}

// revisionsOrEmpty returns a copy of revs, an empty list for none: the
// contract refuses null, and a block from a control plane before
// plexsphere/plexsphere#1059 names no revisions.
func revisionsOrEmpty(revs []api.PolicyRevisionRef) []api.PolicyRevisionRef {
	if len(revs) == 0 {
		return []api.PolicyRevisionRef{}
	}
	return slices.Clone(revs)
}

// capInt64 returns n, or math.MaxInt64 when n is larger.
func capInt64(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

// sameReportedRequest reports whether a and b state the same policy, ignoring
// the drop counters: the difference between a report the control plane logs
// as a transition and one that only refreshes the counters.
func sameReportedRequest(a, b api.PolicyStatusRequest) bool {
	a.Drops, b.Drops = nil, nil
	return reflect.DeepEqual(a, b)
}

func appliedFingerprint(req api.PolicyStatusRequest) string {
	if req.Applied == nil {
		return ""
	}
	return req.Applied.Fingerprint
}

func rejectedFingerprint(req api.PolicyStatusRequest) string {
	if req.Rejected == nil {
		return ""
	}
	return req.Rejected.Fingerprint
}
