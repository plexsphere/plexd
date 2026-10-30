package bridge

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// RelayStatus is the relay's state as plexd reports it.
type RelayStatus struct {
	State      string    // one of the api.RelayState* constants
	ListenPort int       // running and bind_failed; 0 otherwise
	BoundAt    time.Time // running; zero otherwise
}

// equal reports whether s and o are the same status. BoundAt is compared with
// time.Time.Equal, so the same instant in another Location is equal.
func (s RelayStatus) equal(o RelayStatus) bool {
	return s.State == o.State && s.ListenPort == o.ListenPort && s.BoundAt.Equal(o.BoundAt)
}

// RelayStatusTracker holds the latest RelayStatus and signals each change.
// RelayReconcileHandler sets it and the RelayStatusReporter reads it. It is
// safe for concurrent use.
type RelayStatusTracker struct {
	mu      sync.Mutex
	status  RelayStatus
	known   bool
	changed chan struct{} // capacity 1
}

// NewRelayStatusTracker returns a tracker that holds no status yet.
func NewRelayStatusTracker() *RelayStatusTracker {
	return &RelayStatusTracker{changed: make(chan struct{}, 1)}
}

// Set stores s. When no status was held, or s differs from the held one, it
// signals Changed without blocking: a full channel already carries the signal.
// Several Set calls before the reader wakes collapse into one signal, and the
// reader then sees the latest status.
func (t *RelayStatusTracker) Set(s RelayStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := !t.known || !t.status.equal(s)
	t.status = s
	t.known = true
	if !changed {
		return
	}
	select {
	case t.changed <- struct{}{}:
	default:
	}
}

// Get returns the held status and whether one was ever set.
func (t *RelayStatusTracker) Get() (RelayStatus, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.known
}

// Changed returns the channel Set signals a change on.
func (t *RelayStatusTracker) Changed() <-chan struct{} {
	return t.changed
}

// RelayStatusClient sends relay status reports. *api.ControlPlane satisfies it.
type RelayStatusClient interface {
	ReportRelayStatus(ctx context.Context, nodeID string, req api.RelayStatusRequest) (*api.RelayStatusResponse, error)
}

// relayStatusShutdownTimeout bounds the stopped report sent at shutdown.
const relayStatusShutdownTimeout = 5 * time.Second

// defaultRelayStatusInterval is agent.DefaultHeartbeatInterval. internal/bridge
// cannot import it, because internal/agent already depends on internal/bridge.
const defaultRelayStatusInterval = 30 * time.Second

// RelayStatusReporter sends the relay's state, as RelayReconcileHandler records
// it on a RelayStatusTracker, to PUT /v1/nodes/{node_id}/relay-status: when it
// changes, again once per interval, and a last stopped when plexd shuts down.
// The control plane takes a relay whose report in force is not running on its
// configured port out of the bridge candidates, and keeps a report in force
// only while it is repeated within three heartbeat intervals.
//
// DECISION: the reporter sends from a goroutine of its own, never from inside
// the reconcile handler, so a slow control plane never delays a reconcile
// cycle. This follows the DECISION on agent.HandshakeReporter.
//
// DECISION: a failed send is never retried within its tick. The control plane
// anchors bound_seconds on its own receive time, so the next send builds a
// fresh body with fresh seconds instead. A lost on-change report reaches the
// control plane at the next tick, at most one interval later.
//
// DECISION: nothing is sent before the handler first ran. Until then plexd does
// not know the relay's state, and a stopped report at start, followed a moment
// later by running from the first reconcile, could land in a control plane
// sweep and move the relayed pairs away and back on every start. A bridge whose
// first pull carries no drift never runs the handler and sends nothing, which
// is harmless: the control plane reads the report only for an enabled relay,
// and enabling one is bridge drift.
//
// DECISION (per the author): the reporter sends one last stopped report when
// plexd shuts down, so a bridge stopped for good gives up its pairs within
// about 15 s instead of waiting about 100 s for its heartbeat to read stale.
// The accepted cost is that every restart and self-upgrade of a bridge moves
// its pairs away and back, and in a Domain with one bridge the pairs lose their
// fallback_endpoint until the restarted agent reports running.
type RelayStatusReporter struct {
	interval time.Duration
	nodeID   string
	client   RelayStatusClient
	status   *RelayStatusTracker
	logger   *slog.Logger

	// Seams, replaced by tests before Run starts. now is the clock
	// bound_seconds is measured on; outside tests both it and the relay's
	// bind instant come from time.Now, so the difference uses the monotonic
	// clock and a stepped wall clock does not move it. shutdownTimeout bounds
	// the stopped report sent at shutdown.
	now             func() time.Time
	shutdownTimeout time.Duration

	// The fields below are owned by the Run loop and never read concurrently.

	// notServed is set while the control plane answers that it does not serve
	// relay status reports, so that state is logged once on entry and once on
	// exit rather than on every send.
	notServed bool
	// lastReported is the most recent status the control plane accepted, and
	// reported tells whether there is one.
	lastReported RelayStatus
	reported     bool
}

// NewRelayStatusReporter creates a RelayStatusReporter that reports the status
// tracker holds for nodeID through client. A non-positive interval becomes 30
// s, the value of agent.DefaultHeartbeatInterval, because the report's cadence
// is the heartbeat interval.
func NewRelayStatusReporter(interval time.Duration, nodeID string, client RelayStatusClient, status *RelayStatusTracker, logger *slog.Logger) *RelayStatusReporter {
	if interval <= 0 {
		interval = defaultRelayStatusInterval
	}
	return &RelayStatusReporter{
		interval:        interval,
		nodeID:          nodeID,
		client:          client,
		status:          status,
		logger:          logger.With("component", "bridge"),
		now:             time.Now,
		shutdownTimeout: relayStatusShutdownTimeout,
	}
}

// Run sends the status on every change and on every tick of the interval until
// ctx is done. It then sends the shutdown report and returns nil. No answer
// ends the loop and none touches the relay: a control plane that does not
// serve the operation yet is asked again every interval, so an upgrade is
// picked up without a restart.
func (r *RelayStatusReporter) Run(ctx context.Context) error {
	r.logger.Info("relay status: reporter started", "interval", r.interval)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.reportShutdown(ctx)
			return nil
		case <-r.status.Changed():
			r.reportOnce(ctx)
			// The interval restarts after an on-change send, so an unchanged
			// state goes out once per interval and never twice in quick
			// succession after a change.
			ticker.Reset(r.interval)
		case <-ticker.C:
			// This send reads the latest status, so a change signal pending
			// beside the tick is spent here. Left pending, it would make the
			// next iteration send the same status again at once.
			select {
			case <-r.status.Changed():
			default:
			}
			r.reportOnce(ctx)
		}
	}
}

// reportOnce sends the held status once. It does nothing while no status is
// known, that is before the relay handler first ran.
func (r *RelayStatusReporter) reportOnce(ctx context.Context) {
	s, ok := r.status.Get()
	if !ok {
		return
	}
	req := buildRelayStatusRequest(s, r.now())

	resp, err := r.client.ReportRelayStatus(ctx, r.nodeID, req)
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notServed {
		r.logger.Info("relay status: control plane accepts relay status reports")
		r.notServed = false
	}
	if !r.reported || !r.lastReported.equal(s) {
		attrs := []any{"state", req.State}
		if req.ListenPort != 0 {
			attrs = append(attrs, "listen_port", req.ListenPort)
		}
		if req.BoundSeconds != nil {
			attrs = append(attrs, "bound_seconds", *req.BoundSeconds)
		}
		r.logger.Info("relay status: reported", attrs...)
	}
	r.reported = true
	r.lastReported = s
	r.logger.Debug("relay status: accepted", "state", req.State, "accepted_at", resp.AcceptedAt)
}

// logSendError logs a failed send at the level its cause deserves. An error
// that arrives once ctx is done is the shutdown itself and is not logged. A
// refused credential is logged at Debug, since the heartbeat names the cause
// once when it parks the agent. A control plane that does not serve the
// operation is logged once, at Info, on the way in: it is the expected state
// until the control plane ships the operation. relay_status_node_gone is a
// Warn on every send, since the node was removed and every send will say so.
// Every other failure, 400 malformed_relay_status and invalid_relay_status
// included, is a Warn on every send.
func (r *RelayStatusReporter) logSendError(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case errors.Is(err, api.ErrCredentialRefused):
		r.logger.Debug("relay status: send failed", "error", err)
	case api.IsRelayStatusNotServed(err):
		if !r.notServed {
			r.logger.Info("relay status: control plane does not accept relay status reports, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			r.notServed = true
		}
	case isAPIErr && apiErr.Code == "relay_status_node_gone":
		r.logger.Warn("relay status: rejected, this node was removed", "code", apiErr.Code)
	default:
		r.logger.Warn("relay status: send failed", "error", err)
	}
}

// reportShutdown sends stopped once ctx is done, under a context of its own
// that ctx's cancellation does not reach and shutdownTimeout bounds. It sends
// nothing while no status is known, as Run does not either, or while the
// control plane does not serve the operation. The report can reach the control
// plane before the shutdown sequence closes the relay socket, which only moves
// the pairs off a relay that is about to stop.
func (r *RelayStatusReporter) reportShutdown(ctx context.Context) {
	if _, ok := r.status.Get(); !ok || r.notServed {
		return
	}

	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.shutdownTimeout)
	defer cancel()
	if _, err := r.client.ReportRelayStatus(sendCtx, r.nodeID, api.RelayStatusRequest{State: api.RelayStateStopped}); err != nil {
		r.logger.Warn("relay status: shutdown report failed", "error", err)
		return
	}
	r.logger.Info("relay status: reported stopped at shutdown")
}

// buildRelayStatusRequest turns s into the report body at now. State is
// copied, ListenPort is set for running and bind_failed, and BoundSeconds for
// running only, as the contract requires and forbids them. BoundSeconds is
// now minus BoundAt in whole seconds, floored, clamped to 0 when BoundAt
// postdates now and to api.MaxRelayStatusBoundSeconds above it.
func buildRelayStatusRequest(s RelayStatus, now time.Time) api.RelayStatusRequest {
	req := api.RelayStatusRequest{State: s.State}
	switch s.State {
	case api.RelayStateRunning:
		req.ListenPort = s.ListenPort
		// Integer division floors here because the clamped age is not
		// negative.
		secs := int64(max(now.Sub(s.BoundAt), 0) / time.Second)
		secs = min(secs, api.MaxRelayStatusBoundSeconds)
		req.BoundSeconds = &secs
	case api.RelayStateBindFailed:
		req.ListenPort = s.ListenPort
	}
	return req
}
