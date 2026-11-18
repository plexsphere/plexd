package bridge

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// SiteToSiteTunnelReport is what the bridge says about one site-to-site
// tunnel in a site-to-site status report. It carries no slug, interface or
// error text: those stay in the bridge's log and its local status.
type SiteToSiteTunnelReport struct {
	TunnelID string
	Kind     string // the tunnel's kind as pulled, one of api.SiteToSiteKind* or one this plexd does not know
	Health   string // api.SiteToSiteHealth*
	Reason   string // a SiteToSiteReason* while Health is down; empty while it is up
	// PublicKey is the public half of a wireguard tunnel's interface key, in
	// standard base64, while the tunnel is up; empty otherwise.
	PublicKey string
	// Established tells whether the remote site answers while the tunnel is
	// up: for a wireguard tunnel its latest handshake with the remote peer
	// is at most 180 s old, for an ipsec or openvpn tunnel the provider says
	// so. It is false while the tunnel is down.
	Established bool
}

// SiteToSiteStatusClient sends site-to-site status reports. *api.ControlPlane
// satisfies it.
type SiteToSiteStatusClient interface {
	ReportSiteToSiteStatus(ctx context.Context, nodeID string, req api.SiteToSiteStatusRequest) (*api.SiteToSiteStatusResponse, error)
}

// SiteToSiteTunnelReportSource is the part of *SiteToSiteManager the reporter
// reads.
type SiteToSiteTunnelReportSource interface {
	TunnelReports() []SiteToSiteTunnelReport
	ReportChanged() <-chan struct{}
}

// siteToSiteStatusChangeGap is the shortest time between two on-change sends.
const siteToSiteStatusChangeGap = 5 * time.Second

// SiteToSiteStatusReporter sends to PUT /v1/nodes/{node_id}/site-to-site-status
// whether the bridge's local configuration serves site-to-site tunnels,
// enabled or opted_out when bridge.site_to_site_enabled is false, and on an
// enabled bridge one entry per tunnel as the site-to-site manager reports it:
// whether it is up, why not, whether its remote site answers, and for a
// wireguard tunnel that is up the public key of its interface. It sends once
// when it starts, again when the entries change, and once per interval. The
// control plane keeps the latest state per node and refuses tunnel creates
// and updates on a bridge whose report reads opted_out; each report replaces
// the tunnel entries of the one before.
//
// DECISION: the reporter sends at once when it starts, without waiting for a
// pull. The state comes from the local configuration and is known before the
// first pull. plexd reads its configuration once per start, so the send after
// each start covers every change of the setting. That send carries no
// entries, because no pull is applied yet; the first Apply signals a change,
// and the entries follow at once.
//
// DECISION: a change sends only when its entries differ from those of the
// last accepted report in an id, a health, a reason, a public key or
// established, and at most once per siteToSiteStatusChangeGap; a change inside
// the gap is sent when the gap ends, with the entries as they are then.
// established follows whether the remote site answers, and the manager raises
// no signal when it alone moves: the next signal, or the next tick, finds it
// changed and sends it, at most one interval late. An on-change send restarts
// the interval, as the ingress status reporter's does.
//
// DECISION: a failed send is never retried within its tick. The last
// accepted report stays what it was, so the next tick, or the next change,
// sends the state and the entries as they are then, at most one interval
// later. An opt-out whose first send fails reaches the control plane at most
// one interval late, and the bridge serves no tunnel the whole time.
//
// DECISION: nothing is sent at shutdown. The control plane keeps the state and
// never ages it, and a stopped bridge keeps the state its configuration gives
// it, so there is nothing to withdraw; its tunnel entries age once its reports
// stop.
//
// DECISION: the report never gates serving. A bridge serves as the pull says
// while the report fails or the control plane does not serve the operation, as
// the contract, plexsphere/plexsphere docs/reference/api/plexd-agent-contract.md,
// requires. The reporter only reads the site-to-site manager; nothing it
// learns reaches the manager or the reconcile handlers.
type SiteToSiteStatusReporter struct {
	interval time.Duration
	nodeID   string
	client   SiteToSiteStatusClient
	state    string                       // one of the api.SiteToSiteState* constants
	tunnels  SiteToSiteTunnelReportSource // nil on an opted-out bridge
	logger   *slog.Logger

	// now is the clock the change gap is measured on; time.Now outside tests.
	now func() time.Time

	// The fields below are owned by the Run loop and never read concurrently.

	// notServed is set while the control plane answers that it does not serve
	// site-to-site status reports, so that state is logged once on entry and
	// once on exit rather than on every send.
	notServed bool
	// reported tells whether the control plane accepted a report yet, and
	// accepted holds the entries of the last report it accepted.
	reported bool
	accepted []api.SiteToSiteStatusTunnel
	// truncated is set while the manager reports more tunnels than a report
	// carries, so the Warn is logged once on entering that state.
	truncated bool
	// lastChange is when the last on-change send went out; zero before one.
	lastChange time.Time
}

// NewSiteToSiteStatusReporter creates a SiteToSiteStatusReporter that reports
// for nodeID through client the state optedOut gives, opted_out when it is
// true and enabled otherwise, and on an enabled bridge the tunnel entries
// tunnels reports. tunnels is nil on an opted-out bridge; a caller passes an
// untyped nil, since a nil *SiteToSiteManager in the interface does not
// compare equal to nil. A non-positive interval becomes 30 s, the value of
// agent.DefaultHeartbeatInterval, because the report's cadence is the
// heartbeat interval.
func NewSiteToSiteStatusReporter(interval time.Duration, nodeID string, client SiteToSiteStatusClient, optedOut bool, tunnels SiteToSiteTunnelReportSource, logger *slog.Logger) *SiteToSiteStatusReporter {
	if interval <= 0 {
		interval = defaultRelayStatusInterval
	}
	state := api.SiteToSiteStateEnabled
	if optedOut {
		state = api.SiteToSiteStateOptedOut
	}
	return &SiteToSiteStatusReporter{
		interval: interval,
		nodeID:   nodeID,
		client:   client,
		state:    state,
		tunnels:  tunnels,
		logger:   logger.With("component", "bridge"),
		now:      time.Now,
	}
}

// Run sends the report at once, on every change of the tunnel entries,
// bounded by siteToSiteStatusChangeGap, and on every tick of the interval
// until ctx is done, and returns nil without a last send. No answer ends the
// loop: a control plane that does not serve the operation yet is asked again
// every interval, so an upgrade is picked up without a restart.
func (r *SiteToSiteStatusReporter) Run(ctx context.Context) error {
	r.logger.Info("site-to-site status: reporter started", "interval", r.interval, "state", r.state)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	var changed <-chan struct{}
	if r.tunnels != nil {
		changed = r.tunnels.ReportChanged()
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
			if wait := r.lastChange.Add(siteToSiteStatusChangeGap).Sub(r.now()); !r.lastChange.IsZero() && wait > 0 {
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
func (r *SiteToSiteStatusReporter) reportChange(ctx context.Context) bool {
	req := r.build()
	if r.sameAsAccepted(req) {
		return false
	}
	r.lastChange = r.now()
	r.send(ctx, req)
	return true
}

// build returns the report as it is now, and logs the Warn about the tunnels
// a report cannot carry once on entering that state.
func (r *SiteToSiteStatusReporter) build() api.SiteToSiteStatusRequest {
	var reports []SiteToSiteTunnelReport
	if r.tunnels != nil && r.state == api.SiteToSiteStateEnabled {
		reports = r.tunnels.TunnelReports()
	}
	switch {
	case len(reports) <= api.MaxSiteToSiteStatusTunnels:
		r.truncated = false
	case !r.truncated:
		r.logger.Warn("site-to-site status: more tunnels than a report carries, reporting the first 256", "tunnels", len(reports))
		r.truncated = true
	}
	return buildSiteToSiteStatusRequest(r.state, reports)
}

// sameAsAccepted reports whether req carries the entries of the last accepted
// report: the same ids, health, reasons, public keys and established values,
// in the same order.
func (r *SiteToSiteStatusReporter) sameAsAccepted(req api.SiteToSiteStatusRequest) bool {
	return r.reported && slices.EqualFunc(req.Tunnels, r.accepted, func(a, b api.SiteToSiteStatusTunnel) bool {
		return a.ID == b.ID && a.Health == b.Health && a.Reason == b.Reason && a.PublicKey == b.PublicKey &&
			sameEstablished(a.Established, b.Established)
	})
}

// sameEstablished reports whether two established members say the same:
// both absent, or both present with the same value.
func sameEstablished(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// buildSiteToSiteStatusRequest turns the state and the tunnel reports into the
// report body. It returns the state alone for opted_out and for no reports,
// and otherwise maps the first api.MaxSiteToSiteStatusTunnels reports in
// order. An entry carries Reason exactly when it is down, Established exactly
// when it is up, false included, and PublicKey exactly when it is a wireguard
// tunnel that is up. An ipsec or openvpn tunnel that is up carries no public
// key: its daemon authenticates with the tunnel's Secret.
func buildSiteToSiteStatusRequest(state string, reports []SiteToSiteTunnelReport) api.SiteToSiteStatusRequest {
	req := api.SiteToSiteStatusRequest{State: state}
	if state == api.SiteToSiteStateOptedOut || len(reports) == 0 {
		return req
	}
	reports = reports[:min(len(reports), api.MaxSiteToSiteStatusTunnels)]
	req.Tunnels = make([]api.SiteToSiteStatusTunnel, len(reports))
	for i, rep := range reports {
		entry := api.SiteToSiteStatusTunnel{ID: rep.TunnelID, Health: rep.Health}
		if rep.Health == api.SiteToSiteHealthDown {
			entry.Reason = rep.Reason
		} else {
			established := rep.Established
			entry.Established = &established
			if isWireGuardTunnelKind(rep.Kind) {
				entry.PublicKey = rep.PublicKey
			}
		}
		req.Tunnels[i] = entry
	}
	return req
}

// isWireGuardTunnelKind reports whether kind is the wireguard kind of a
// site-to-site tunnel, the one kind whose report entry carries the public key
// of the bridge's interface.
func isWireGuardTunnelKind(kind string) bool {
	return kind == api.SiteToSiteKindWireGuard
}

// reportOnce sends the report as it is now once.
func (r *SiteToSiteStatusReporter) reportOnce(ctx context.Context) {
	r.send(ctx, r.build())
}

// send sends req once and, when the control plane accepts it, keeps its
// entries as the last accepted ones.
func (r *SiteToSiteStatusReporter) send(ctx context.Context, req api.SiteToSiteStatusRequest) {
	resp, err := r.client.ReportSiteToSiteStatus(ctx, r.nodeID, req)
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notServed {
		r.logger.Info("site-to-site status: control plane accepts site-to-site status reports")
		r.notServed = false
	}
	if !r.reported {
		r.logger.Info("site-to-site status: reported", "state", r.state, "tunnels", len(req.Tunnels))
		r.reported = true
	}
	r.accepted = req.Tunnels
	r.logger.Debug("site-to-site status: accepted", "state", r.state, "tunnels", len(req.Tunnels), "accepted_at", resp.AcceptedAt)
}

// logSendError logs a failed send at the level its cause deserves. An error
// that arrives once ctx is done is the shutdown itself and is not logged. A
// refused credential is logged at Debug, since the heartbeat names the cause
// once when it parks the agent. A control plane that does not serve the
// operation is logged once, at Info, on the way in: it is the expected state
// until the control plane ships the operation. site_to_site_status_node_gone
// is a Warn on every send, since the node was removed and every send will say
// so. Every other failure, 400 malformed_site_to_site_status and a timed-out
// send included, is a Warn on every send.
func (r *SiteToSiteStatusReporter) logSendError(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case errors.Is(err, api.ErrCredentialRefused):
		r.logger.Debug("site-to-site status: send failed", "error", err)
	case api.IsSiteToSiteStatusNotServed(err):
		if !r.notServed {
			r.logger.Info("site-to-site status: control plane does not accept site-to-site status reports, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			r.notServed = true
		}
	case isAPIErr && apiErr.Code == "site_to_site_status_node_gone":
		r.logger.Warn("site-to-site status: rejected, this node was removed", "code", apiErr.Code)
	default:
		r.logger.Warn("site-to-site status: send failed", "error", err)
	}
}
