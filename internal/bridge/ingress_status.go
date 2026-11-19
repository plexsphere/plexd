package bridge

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// IngressStatusClient sends ingress status reports. *api.ControlPlane
// satisfies it.
type IngressStatusClient interface {
	ReportIngressStatus(ctx context.Context, nodeID string, req api.IngressStatusRequest) (*api.IngressStatusResponse, error)
}

// IngressRuleReportSource is the part of *IngressManager the reporter reads.
type IngressRuleReportSource interface {
	RuleReports() []IngressRuleReport
	ReportChanged() <-chan struct{}
}

// ingressStatusChangeGap is the shortest time between two on-change sends.
const ingressStatusChangeGap = 5 * time.Second

// IngressStatusReporter sends to PUT /v1/nodes/{node_id}/ingress-status whether
// the bridge's local configuration serves public ingress, enabled or
// opted_out when bridge.ingress_enabled is false, and on an enabled bridge
// one entry per ingress rule as the ingress manager reports it: its listener,
// its certificate, how its last unit ended and the last dial to each of its
// targets. It sends once when it starts, again when the entries change, and
// once per interval. The control plane keeps the latest state per node and
// refuses ingress rule creates and updates on a bridge whose report reads
// opted_out; each report replaces the rule entries of the one before.
//
// DECISION: the reporter sends at once when it starts, without waiting for a
// pull. The state comes from the local configuration and is known before the
// first pull, unlike the relay's, which only the relay handler knows. plexd
// reads its configuration once per start, so the send after each start covers
// every change of the setting. That send carries no entries, because no pull
// is applied yet; the first Apply signals a change, and the entries follow at
// once.
//
// DECISION: a change sends only when its entries differ from those of the
// last accepted report, the dial ages of the rule entries and of their target
// entries ignored, and at most once per ingressStatusChangeGap; a change
// inside the gap is sent when the gap ends, with the entries as they are
// then. Dial outcomes follow public connections, so without the bound a
// target that alternates between failing and answering would cost one
// request per flip. An on-change send restarts the interval, as the relay
// status reporter's does. A moving dial age alone, of a rule or of a target,
// sends nothing; the tick carries it.
//
// DECISION: a failed send is never retried within its tick. The last
// accepted report stays what it was, so the next tick, or the next change,
// sends the state and the entries as they are then, at most one interval
// later. An opt-out whose first send fails reaches the control plane at most
// one interval late, and the bridge opens no public listener the whole time.
//
// DECISION: nothing is sent at shutdown. The control plane keeps the state and
// never ages it, and a stopped bridge keeps the state its configuration gives
// it, so there is nothing to withdraw; its rule entries read stale once its
// reports stop.
//
// DECISION: the report never gates serving. A bridge serves as the pull says
// while the report fails or the control plane does not serve the operation, as
// the contract, plexsphere/plexsphere docs/reference/api/plexd-agent-contract.md,
// requires. The reporter only reads the ingress manager; nothing it learns
// reaches the manager or the reconcile handler.
type IngressStatusReporter struct {
	interval time.Duration
	nodeID   string
	client   IngressStatusClient
	state    string                  // one of the api.IngressState* constants
	rules    IngressRuleReportSource // nil on an opted-out bridge
	logger   *slog.Logger

	// now is the clock dial ages and the change gap are measured on;
	// time.Now outside tests.
	now func() time.Time

	// The fields below are owned by the Run loop and never read concurrently.

	// notServed is set while the control plane answers that it does not serve
	// ingress status reports, so that state is logged once on entry and once
	// on exit rather than on every send.
	notServed bool
	// reported tells whether the control plane accepted a report yet, and
	// accepted holds the entries of the last report it accepted.
	reported bool
	accepted []api.IngressStatusRule
	// truncated is set while the manager reports more rules than a report
	// carries, so the Warn is logged once on entering that state.
	truncated bool
	// lastChange is when the last on-change send went out; zero before one.
	lastChange time.Time
}

// NewIngressStatusReporter creates an IngressStatusReporter that reports for
// nodeID through client the state optedOut gives, opted_out when it is true
// and enabled otherwise, and on an enabled bridge the rule entries rules
// reports. rules is nil on an opted-out bridge; a caller passes an untyped
// nil, since a nil *IngressManager in the interface does not compare equal to
// nil. A non-positive interval becomes 30 s, the value of
// agent.DefaultHeartbeatInterval, because the report's cadence is the
// heartbeat interval.
func NewIngressStatusReporter(interval time.Duration, nodeID string, client IngressStatusClient, optedOut bool, rules IngressRuleReportSource, logger *slog.Logger) *IngressStatusReporter {
	if interval <= 0 {
		interval = defaultRelayStatusInterval
	}
	state := api.IngressStateEnabled
	if optedOut {
		state = api.IngressStateOptedOut
	}
	return &IngressStatusReporter{
		interval: interval,
		nodeID:   nodeID,
		client:   client,
		state:    state,
		rules:    rules,
		logger:   logger.With("component", "bridge"),
		now:      time.Now,
	}
}

// Run sends the report at once, on every change of the rule entries, bounded
// by ingressStatusChangeGap, and on every tick of the interval until ctx is
// done, and returns nil without a last send. No answer ends the loop: a
// control plane that does not serve the operation yet is asked again every
// interval, so an upgrade is picked up without a restart.
func (r *IngressStatusReporter) Run(ctx context.Context) error {
	r.logger.Info("ingress status: reporter started", "interval", r.interval, "state", r.state)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	var changed <-chan struct{}
	if r.rules != nil {
		changed = r.rules.ReportChanged()
	}
	// gap is armed while a change waits for the end of the change gap.
	var gap *time.Timer
	var gapEnd <-chan time.Time
	disarm := func() {
		if gap != nil {
			gap.Stop()
			gap, gapEnd = nil, nil
		}
	}
	defer disarm()

	r.reportOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
			if gapEnd != nil {
				// The armed timer sends the entries as they are when it fires.
				continue
			}
			if wait := r.lastChange.Add(ingressStatusChangeGap).Sub(r.now()); !r.lastChange.IsZero() && wait > 0 {
				if req := r.build(); !r.sameAsAccepted(req) {
					gap = time.NewTimer(wait)
					gapEnd = gap.C
				}
				continue
			}
			if r.reportChange(ctx) {
				ticker.Reset(r.interval)
			}
		case <-gapEnd:
			gap, gapEnd = nil, nil
			if r.reportChange(ctx) {
				ticker.Reset(r.interval)
			}
		case <-ticker.C:
			// This send reads the latest entries, so a change signal pending
			// beside the tick, and a change waiting for the gap, are spent
			// here.
			select {
			case <-changed:
			default:
			}
			disarm()
			r.reportOnce(ctx)
		}
	}
}

// reportChange sends the report when its entries differ from those of the
// last accepted report, and reports whether it sent.
func (r *IngressStatusReporter) reportChange(ctx context.Context) bool {
	req := r.build()
	if r.sameAsAccepted(req) {
		return false
	}
	r.lastChange = r.now()
	r.send(ctx, req)
	return true
}

// build returns the report as it is now, and logs the Warn about the rules a
// report cannot carry once on entering that state.
func (r *IngressStatusReporter) build() api.IngressStatusRequest {
	var reports []IngressRuleReport
	if r.rules != nil && r.state == api.IngressStateEnabled {
		reports = r.rules.RuleReports()
	}
	switch {
	case len(reports) <= api.MaxIngressStatusRules:
		r.truncated = false
	case !r.truncated:
		r.logger.Warn("ingress status: more rules than a report carries, reporting the first 1024", "rules", len(reports))
		r.truncated = true
	}
	return buildIngressStatusRequest(r.state, reports, r.now())
}

// sameAsAccepted reports whether req carries the entries of the last accepted
// report, the dial ages of the rules and of their targets ignored.
func (r *IngressStatusReporter) sameAsAccepted(req api.IngressStatusRequest) bool {
	return r.reported && slices.EqualFunc(req.Rules, r.accepted, func(a, b api.IngressStatusRule) bool {
		a.DialAgeSeconds, b.DialAgeSeconds = nil, nil
		a.Targets, b.Targets = targetsWithoutAges(a.Targets), targetsWithoutAges(b.Targets)
		return reflect.DeepEqual(a, b)
	})
}

// targetsWithoutAges returns a copy of targets without their dial ages, nil
// for no entry.
func targetsWithoutAges(targets []api.IngressStatusTarget) []api.IngressStatusTarget {
	if len(targets) == 0 {
		return nil
	}
	out := slices.Clone(targets)
	for i := range out {
		out[i].DialAgeSeconds = nil
	}
	return out
}

// buildIngressStatusRequest turns the state and the rule reports into the
// report body at now. It returns the state alone for opted_out and for no
// reports, and otherwise maps the first api.MaxIngressStatusRules reports in
// order, each with its target entries in order. The DialAgeSeconds of a rule
// entry and of a target entry is set by one rule (see dialAgeSeconds).
func buildIngressStatusRequest(state string, reports []IngressRuleReport, now time.Time) api.IngressStatusRequest {
	req := api.IngressStatusRequest{State: state}
	if state == api.IngressStateOptedOut || len(reports) == 0 {
		return req
	}
	reports = reports[:min(len(reports), api.MaxIngressStatusRules)]
	req.Rules = make([]api.IngressStatusRule, len(reports))
	for i, rep := range reports {
		entry := api.IngressStatusRule{
			ID:                rep.RuleID,
			Listener:          rep.Listener,
			ListenerReason:    rep.ListenerReason,
			Certificate:       rep.Certificate,
			CertificateReason: rep.CertificateReason,
			Dial:              rep.Dial,
			DialReason:        rep.DialReason,
			DialAgeSeconds:    dialAgeSeconds(rep.Dial, rep.DialAt, now),
		}
		if len(rep.Targets) > 0 {
			entry.Targets = make([]api.IngressStatusTarget, len(rep.Targets))
			for j, t := range rep.Targets {
				entry.Targets[j] = api.IngressStatusTarget{
					NodeID:         t.NodeID,
					Port:           t.Port,
					Dial:           t.Dial,
					DialReason:     t.DialReason,
					DialAgeSeconds: dialAgeSeconds(t.Dial, t.DialAt, now),
				}
			}
		}
		req.Rules[i] = entry
	}
	return req
}

// dialAgeSeconds returns the dial_age_seconds of a dial whose outcome is dial
// and whose time is at, in a report sent at now. It is nil unless dial is
// succeeded or failed, and otherwise now minus at in whole seconds, floored,
// clamped to 0 when at postdates now and to
// api.MaxIngressStatusDialAgeSeconds above it.
func dialAgeSeconds(dial string, at, now time.Time) *int64 {
	if dial != api.IngressDialSucceeded && dial != api.IngressDialFailed {
		return nil
	}
	// Integer division floors here because the clamped age is not negative.
	secs := int64(max(now.Sub(at), 0) / time.Second)
	secs = min(secs, api.MaxIngressStatusDialAgeSeconds)
	return &secs
}

// reportOnce sends the report as it is now once.
func (r *IngressStatusReporter) reportOnce(ctx context.Context) {
	r.send(ctx, r.build())
}

// send sends req once and, when the control plane accepts it, keeps its
// entries as the last accepted ones.
func (r *IngressStatusReporter) send(ctx context.Context, req api.IngressStatusRequest) {
	resp, err := r.client.ReportIngressStatus(ctx, r.nodeID, req)
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notServed {
		r.logger.Info("ingress status: control plane accepts ingress status reports")
		r.notServed = false
	}
	if !r.reported {
		r.logger.Info("ingress status: reported", "state", r.state, "rules", len(req.Rules))
		r.reported = true
	}
	r.accepted = req.Rules
	r.logger.Debug("ingress status: accepted", "state", r.state, "rules", len(req.Rules), "accepted_at", resp.AcceptedAt)
}

// logSendError logs a failed send at the level its cause deserves. An error
// that arrives once ctx is done is the shutdown itself and is not logged. A
// refused credential is logged at Debug, since the heartbeat names the cause
// once when it parks the agent. A control plane that does not serve the
// operation is logged once, at Info, on the way in: it is the expected state
// until the control plane ships the operation. ingress_status_node_gone is a
// Warn on every send, since the node was removed and every send will say so.
// Every other failure, 400 malformed_ingress_status and a timed-out send
// included, is a Warn on every send.
func (r *IngressStatusReporter) logSendError(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case errors.Is(err, api.ErrCredentialRefused):
		r.logger.Debug("ingress status: send failed", "error", err)
	case api.IsIngressStatusNotServed(err):
		if !r.notServed {
			r.logger.Info("ingress status: control plane does not accept ingress status reports, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			r.notServed = true
		}
	case isAPIErr && apiErr.Code == "ingress_status_node_gone":
		r.logger.Warn("ingress status: rejected, this node was removed", "code", apiErr.Code)
	default:
		r.logger.Warn("ingress status: send failed", "error", err)
	}
}
