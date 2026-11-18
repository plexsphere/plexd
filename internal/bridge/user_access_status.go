package bridge

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// UserAccessProviderReport is what the bridge says about one user access
// provider in a user access status report. It carries no slug, interface or
// error text: those stay in the bridge's log and its local status.
type UserAccessProviderReport struct {
	ProviderID string
	Kind       string // the provider's kind as pulled, one of api.UserAccessKind* or one this plexd does not know
	Health     string // api.UserAccessHealth*
	Reason     string // a UserAccessReason* while Health is down; empty while it is up
	// PublicKey is the public half of a wireguard provider's interface key,
	// in standard base64, while the provider is up; empty otherwise.
	PublicKey string
	// ConnectedDevices counts a wireguard provider's devices whose latest
	// handshake is at most 180 s old, while the provider is up; 0 otherwise.
	ConnectedDevices int
}

// UserAccessStatusClient sends user access status reports. *api.ControlPlane
// satisfies it.
type UserAccessStatusClient interface {
	ReportUserAccessStatus(ctx context.Context, nodeID string, req api.UserAccessStatusRequest) (*api.UserAccessStatusResponse, error)
}

// UserAccessProviderReportSource is the part of *UserAccessManager the
// reporter reads.
type UserAccessProviderReportSource interface {
	ProviderReports() []UserAccessProviderReport
	ReportChanged() <-chan struct{}
}

// userAccessStatusChangeGap is the shortest time between two on-change sends.
const userAccessStatusChangeGap = 5 * time.Second

// maxUserAccessConnectedDevices is the contract's ceiling on connected_devices,
// the most devices a wireguard provider admits.
const maxUserAccessConnectedDevices = 1024

// UserAccessStatusReporter sends to PUT /v1/nodes/{node_id}/user-access-status
// whether the bridge's local configuration serves user access, enabled or
// opted_out when bridge.user_access_enabled is false, and on an enabled bridge
// one entry per user access provider as the user access manager reports it:
// whether it is up, why not, and for a wireguard provider that is up the
// public key of its interface and how many devices reach it. It sends once
// when it starts, again when the entries change, and once per interval. The
// control plane keeps the latest state per node and refuses provider writes
// and device admissions on a bridge whose report reads opted_out; each report
// replaces the provider entries of the one before.
//
// DECISION: the reporter sends at once when it starts, without waiting for a
// pull. The state comes from the local configuration and is known before the
// first pull. plexd reads its configuration once per start, so the send after
// each start covers every change of the setting. That send carries no
// entries, because no pull is applied yet; the first Apply signals a change,
// and the entries follow at once.
//
// DECISION: a change sends only when its entries differ from those of the
// last accepted report in an id, a health, a reason or a public key, and at
// most once per userAccessStatusChangeGap; a change inside the gap is sent
// when the gap ends, with the entries as they are then. connected_devices
// follows the devices' handshakes, so it is left out of the comparison, as
// the contract asks: a moving count alone sends nothing, and the tick carries
// it. An on-change send restarts the interval, as the ingress status
// reporter's does.
//
// DECISION: a failed send is never retried within its tick. The last
// accepted report stays what it was, so the next tick, or the next change,
// sends the state and the entries as they are then, at most one interval
// later. An opt-out whose first send fails reaches the control plane at most
// one interval late, and the bridge serves no provider the whole time.
//
// DECISION: nothing is sent at shutdown. The control plane keeps the state and
// never ages it, and a stopped bridge keeps the state its configuration gives
// it, so there is nothing to withdraw; its provider entries read stale once
// its reports stop.
//
// DECISION: the report never gates serving. A bridge serves as the pull says
// while the report fails or the control plane does not serve the operation, as
// the contract, plexsphere/plexsphere docs/reference/api/plexd-agent-contract.md,
// requires. The reporter only reads the user access manager; nothing it learns
// reaches the manager or the reconcile handler.
type UserAccessStatusReporter struct {
	interval  time.Duration
	nodeID    string
	client    UserAccessStatusClient
	state     string                         // one of the api.UserAccessState* constants
	providers UserAccessProviderReportSource // nil on an opted-out bridge
	logger    *slog.Logger

	// now is the clock the change gap is measured on; time.Now outside tests.
	now func() time.Time

	// The fields below are owned by the Run loop and never read concurrently.

	// notServed is set while the control plane answers that it does not serve
	// user access status reports, so that state is logged once on entry and
	// once on exit rather than on every send.
	notServed bool
	// reported tells whether the control plane accepted a report yet, and
	// accepted holds the entries of the last report it accepted.
	reported bool
	accepted []api.UserAccessStatusProvider
	// truncated is set while the manager reports more providers than a report
	// carries, so the Warn is logged once on entering that state.
	truncated bool
	// lastChange is when the last on-change send went out; zero before one.
	lastChange time.Time
}

// NewUserAccessStatusReporter creates a UserAccessStatusReporter that reports
// for nodeID through client the state optedOut gives, opted_out when it is
// true and enabled otherwise, and on an enabled bridge the provider entries
// providers reports. providers is nil on an opted-out bridge; a caller passes
// an untyped nil, since a nil *UserAccessManager in the interface does not
// compare equal to nil. A non-positive interval becomes 30 s, the value of
// agent.DefaultHeartbeatInterval, because the report's cadence is the
// heartbeat interval.
func NewUserAccessStatusReporter(interval time.Duration, nodeID string, client UserAccessStatusClient, optedOut bool, providers UserAccessProviderReportSource, logger *slog.Logger) *UserAccessStatusReporter {
	if interval <= 0 {
		interval = defaultRelayStatusInterval
	}
	state := api.UserAccessStateEnabled
	if optedOut {
		state = api.UserAccessStateOptedOut
	}
	return &UserAccessStatusReporter{
		interval:  interval,
		nodeID:    nodeID,
		client:    client,
		state:     state,
		providers: providers,
		logger:    logger.With("component", "bridge"),
		now:       time.Now,
	}
}

// Run sends the report at once, on every change of the provider entries,
// bounded by userAccessStatusChangeGap, and on every tick of the interval
// until ctx is done, and returns nil without a last send. No answer ends the
// loop: a control plane that does not serve the operation yet is asked again
// every interval, so an upgrade is picked up without a restart.
func (r *UserAccessStatusReporter) Run(ctx context.Context) error {
	r.logger.Info("user access status: reporter started", "interval", r.interval, "state", r.state)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	var changed <-chan struct{}
	if r.providers != nil {
		changed = r.providers.ReportChanged()
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
			if wait := r.lastChange.Add(userAccessStatusChangeGap).Sub(r.now()); !r.lastChange.IsZero() && wait > 0 {
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
func (r *UserAccessStatusReporter) reportChange(ctx context.Context) bool {
	req := r.build()
	if r.sameAsAccepted(req) {
		return false
	}
	r.lastChange = r.now()
	r.send(ctx, req)
	return true
}

// build returns the report as it is now, and logs the Warn about the
// providers a report cannot carry once on entering that state.
func (r *UserAccessStatusReporter) build() api.UserAccessStatusRequest {
	var reports []UserAccessProviderReport
	if r.providers != nil && r.state == api.UserAccessStateEnabled {
		reports = r.providers.ProviderReports()
	}
	switch {
	case len(reports) <= api.MaxUserAccessStatusProviders:
		r.truncated = false
	case !r.truncated:
		r.logger.Warn("user access status: more providers than a report carries, reporting the first 256", "providers", len(reports))
		r.truncated = true
	}
	return buildUserAccessStatusRequest(r.state, reports)
}

// sameAsAccepted reports whether req carries the entries of the last accepted
// report, connected_devices ignored.
func (r *UserAccessStatusReporter) sameAsAccepted(req api.UserAccessStatusRequest) bool {
	return r.reported && slices.EqualFunc(req.Providers, r.accepted, func(a, b api.UserAccessStatusProvider) bool {
		return a.ID == b.ID && a.Health == b.Health && a.Reason == b.Reason && a.PublicKey == b.PublicKey
	})
}

// buildUserAccessStatusRequest turns the state and the provider reports into
// the report body. It returns the state alone for opted_out and for no
// reports, and otherwise maps the first api.MaxUserAccessStatusProviders
// reports in order. An entry carries Reason exactly when it is down, and
// PublicKey and ConnectedDevices exactly when it is a wireguard provider that
// is up; ConnectedDevices is clamped to the contract's 1024 and sent when it
// is 0. A vendor provider that is up carries neither: its network manages its
// own keys and devices.
func buildUserAccessStatusRequest(state string, reports []UserAccessProviderReport) api.UserAccessStatusRequest {
	req := api.UserAccessStatusRequest{State: state}
	if state == api.UserAccessStateOptedOut || len(reports) == 0 {
		return req
	}
	reports = reports[:min(len(reports), api.MaxUserAccessStatusProviders)]
	req.Providers = make([]api.UserAccessStatusProvider, len(reports))
	for i, rep := range reports {
		entry := api.UserAccessStatusProvider{ID: rep.ProviderID, Health: rep.Health}
		switch {
		case rep.Health == api.UserAccessHealthDown:
			entry.Reason = rep.Reason
		case rep.Kind == api.UserAccessKindWireGuard:
			connected := min(max(rep.ConnectedDevices, 0), maxUserAccessConnectedDevices)
			entry.PublicKey = rep.PublicKey
			entry.ConnectedDevices = &connected
		}
		req.Providers[i] = entry
	}
	return req
}

// reportOnce sends the report as it is now once.
func (r *UserAccessStatusReporter) reportOnce(ctx context.Context) {
	r.send(ctx, r.build())
}

// send sends req once and, when the control plane accepts it, keeps its
// entries as the last accepted ones.
func (r *UserAccessStatusReporter) send(ctx context.Context, req api.UserAccessStatusRequest) {
	resp, err := r.client.ReportUserAccessStatus(ctx, r.nodeID, req)
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notServed {
		r.logger.Info("user access status: control plane accepts user access status reports")
		r.notServed = false
	}
	if !r.reported {
		r.logger.Info("user access status: reported", "state", r.state, "providers", len(req.Providers))
		r.reported = true
	}
	r.accepted = req.Providers
	r.logger.Debug("user access status: accepted", "state", r.state, "providers", len(req.Providers), "accepted_at", resp.AcceptedAt)
}

// logSendError logs a failed send at the level its cause deserves. An error
// that arrives once ctx is done is the shutdown itself and is not logged. A
// refused credential is logged at Debug, since the heartbeat names the cause
// once when it parks the agent. A control plane that does not serve the
// operation is logged once, at Info, on the way in: it is the expected state
// until the control plane ships the operation. user_access_status_node_gone
// is a Warn on every send, since the node was removed and every send will say
// so. Every other failure, 400 malformed_user_access_status and a timed-out
// send included, is a Warn on every send.
func (r *UserAccessStatusReporter) logSendError(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case errors.Is(err, api.ErrCredentialRefused):
		r.logger.Debug("user access status: send failed", "error", err)
	case api.IsUserAccessStatusNotServed(err):
		if !r.notServed {
			r.logger.Info("user access status: control plane does not accept user access status reports, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			r.notServed = true
		}
	case isAPIErr && apiErr.Code == "user_access_status_node_gone":
		r.logger.Warn("user access status: rejected, this node was removed", "code", apiErr.Code)
	default:
		r.logger.Warn("user access status: send failed", "error", err)
	}
}
