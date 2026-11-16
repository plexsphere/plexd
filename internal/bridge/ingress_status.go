package bridge

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// IngressStatusClient sends ingress status reports. *api.ControlPlane
// satisfies it.
type IngressStatusClient interface {
	ReportIngressStatus(ctx context.Context, nodeID string, req api.IngressStatusRequest) (*api.IngressStatusResponse, error)
}

// IngressStatusReporter sends whether the bridge's local configuration serves
// public ingress to PUT /v1/nodes/{node_id}/ingress-status: enabled, or
// opted_out when bridge.ingress_enabled is false. It sends once when it starts
// and again once per interval. The control plane keeps the latest report per
// node and refuses ingress rule creates and updates on a bridge whose report
// reads opted_out.
//
// DECISION: the reporter sends at once when it starts, without waiting for a
// pull. The state comes from the local configuration and is known before the
// first pull, unlike the relay's, which only the relay handler knows. plexd
// reads its configuration once per start, so the send after each start covers
// every change of the setting.
//
// DECISION: a failed send is never retried within its tick. The body never
// changes, so the next tick sends the same report, at most one interval later.
// An opt-out whose first send fails reaches the control plane at most one
// interval late, and the bridge opens no public listener the whole time.
//
// DECISION: nothing is sent at shutdown. The control plane keeps the report and
// never ages it, and a stopped bridge keeps the state its configuration gives
// it, so there is nothing to withdraw.
//
// DECISION: the report never gates serving. A bridge serves as the pull says
// while the report fails or the control plane does not serve the operation, as
// the contract, plexsphere/plexsphere docs/reference/api/plexd-agent-contract.md,
// requires. Nothing the reporter learns reaches the ingress manager or the
// reconcile handler.
type IngressStatusReporter struct {
	interval time.Duration
	nodeID   string
	client   IngressStatusClient
	state    string // one of the api.IngressState* constants
	logger   *slog.Logger

	// The fields below are owned by the Run loop and never read concurrently.

	// notServed is set while the control plane answers that it does not serve
	// ingress status reports, so that state is logged once on entry and once
	// on exit rather than on every send.
	notServed bool
	// reported tells whether the control plane accepted a report yet.
	reported bool
}

// NewIngressStatusReporter creates an IngressStatusReporter that reports for
// nodeID through client the state optedOut gives: opted_out when it is true,
// enabled otherwise. A non-positive interval becomes 30 s, the value of
// agent.DefaultHeartbeatInterval, because the report's cadence is the
// heartbeat interval.
func NewIngressStatusReporter(interval time.Duration, nodeID string, client IngressStatusClient, optedOut bool, logger *slog.Logger) *IngressStatusReporter {
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
		logger:   logger.With("component", "bridge"),
	}
}

// Run sends the state at once and then on every tick of the interval until ctx
// is done, and returns nil without a last send. No answer ends the
// loop: a control plane that does not serve the operation yet is asked again
// every interval, so an upgrade is picked up without a restart.
func (r *IngressStatusReporter) Run(ctx context.Context) error {
	r.logger.Info("ingress status: reporter started", "interval", r.interval, "state", r.state)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.reportOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.reportOnce(ctx)
		}
	}
}

// reportOnce sends the state once.
func (r *IngressStatusReporter) reportOnce(ctx context.Context) {
	resp, err := r.client.ReportIngressStatus(ctx, r.nodeID, api.IngressStatusRequest{State: r.state})
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notServed {
		r.logger.Info("ingress status: control plane accepts ingress status reports")
		r.notServed = false
	}
	if !r.reported {
		r.logger.Info("ingress status: reported", "state", r.state)
		r.reported = true
	}
	r.logger.Debug("ingress status: accepted", "state", r.state, "accepted_at", resp.AcceptedAt)
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
