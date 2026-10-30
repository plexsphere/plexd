package agent

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// HandshakeReportClient sends handshake reports to the control plane.
type HandshakeReportClient interface {
	ReportHandshakes(ctx context.Context, nodeID string, req api.HandshakeReportRequest) (*api.HandshakeReportResponse, error)
}

// MeshPeerStatsSource reads the runtime state of every mesh peer from the
// WireGuard device, keyed by the peer's node ID.
type MeshPeerStatsSource interface {
	MeshPeerStats() ([]wireguard.MeshPeerStat, error)
}

// uuidRE matches the textual UUID form the contract's peer_node_id requires.
// The control plane refuses the whole report with 400
// malformed_handshake_report for a single id that does not parse as a UUID, so
// buildHandshakeReport leaves such an entry out instead of sending it.
var uuidRE = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// nilUUID is the all-zero UUID. It matches uuidRE, but the contract requires a
// non-zero peer_node_id and refuses the whole report for one.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// HandshakeReporter posts, once per interval, the age of the latest completed
// WireGuard handshake with each mesh peer and the endpoint WireGuard used for
// it to POST /v1/nodes/{node_id}/handshakes. The control plane derives each
// mesh edge's status, mode, handshake age and endpoint from these reports.
//
// DECISION: the reporter runs its own loop at the heartbeat interval rather
// than riding on HeartbeatService.sendHeartbeat. The contract asks for one
// report per heartbeat interval, and a slow report inside the heartbeat would
// delay the liveness signal the control plane times the node out on.
//
// DECISION: a failed report is never retried within its tick. The control
// plane anchors every age on its own receive time, so a replayed body would
// make each handshake look newer than it was; the next tick builds a fresh body
// with a fresh observed_at and fresh ages instead.
type HandshakeReporter struct {
	interval time.Duration
	nodeID   string
	client   HandshakeReportClient
	source   MeshPeerStatsSource
	logger   *slog.Logger

	// now reads the wall clock observed_at is stamped with. It is time.Now
	// outside tests, which replace it to pin observed_at and the ages.
	now func() time.Time

	// notServed is set while the control plane answers that it does not serve
	// handshake reports, so the condition is logged once on the way in and
	// once on the way out rather than on every tick. Only the Run goroutine
	// reads and writes it.
	notServed bool
}

// NewHandshakeReporter creates a HandshakeReporter that reports for nodeID
// through client, reading the device through source. A non-positive interval
// becomes DefaultHeartbeatInterval, the same fallback the heartbeat applies,
// because the report's cadence is defined as the heartbeat interval.
func NewHandshakeReporter(interval time.Duration, nodeID string, client HandshakeReportClient, source MeshPeerStatsSource, logger *slog.Logger) *HandshakeReporter {
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	return &HandshakeReporter{
		interval: interval,
		nodeID:   nodeID,
		client:   client,
		source:   source,
		logger:   logger.With("component", "handshake-report"),
		now:      time.Now,
	}
}

// Run reports on every tick of the interval until ctx is cancelled. Unlike the
// heartbeat it sends nothing at start: the WireGuard interface has only just
// come up, so no handshake can have completed yet and the first report would
// carry nothing. Run always returns nil.
func (r *HandshakeReporter) Run(ctx context.Context) error {
	r.logger.InfoContext(ctx, "agent: handshake report: started", "interval", r.interval)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.reportOnce(ctx)
		}
	}
}

// reportOnce reads the device, builds one report and sends it once. A report
// is sent on every tick, an empty one included: an empty peers array is a
// valid report that records nothing, and it is what keeps the not-served and
// recovery transitions observable on a node with no handshakes.
func (r *HandshakeReporter) reportOnce(ctx context.Context) {
	stats, err := r.source.MeshPeerStats()
	if err != nil {
		r.logger.WarnContext(ctx, "agent: handshake report: read peer stats failed", "error", err)
		return
	}

	// observed_at is read after the device so that, on a clock that does not
	// step, no handshake the read saw postdates it and no age comes out
	// negative.
	observedAt := r.now().UTC()
	req, skipped, truncated := buildHandshakeReport(observedAt, stats)
	if skipped > 0 {
		r.logger.DebugContext(ctx, "agent: handshake report: skipped peers", "count", skipped)
	}
	if truncated > 0 {
		r.logger.WarnContext(ctx, "agent: handshake report: more peers than the contract allows, reporting the most recent",
			"peers", len(req.Peers)+truncated,
			"max", api.MaxHandshakeReportPeers,
		)
	}

	resp, err := r.client.ReportHandshakes(ctx, r.nodeID, req)
	if err != nil {
		r.logSendError(ctx, err)
		return
	}

	if r.notServed {
		r.logger.InfoContext(ctx, "agent: handshake report: control plane accepts handshake reports")
		r.notServed = false
	}
	r.logger.DebugContext(ctx, "agent: handshake report: accepted",
		"sent", len(req.Peers),
		"recorded", resp.Recorded,
		"ignored", resp.Ignored,
		"accepted_at", resp.AcceptedAt,
	)
}

// logSendError classifies a failed send. A cancelled ctx is shutdown, not a
// failure, and is not logged. A control plane that does not serve the operation
// (a 404 from one older than it, or 501 handshakes_not_provisioned) is logged
// at Info on the transition only, the way PlatformReporter treats an
// unprovisioned ingest: the reporter keeps sending on its interval and the
// condition clears by itself once the control plane is upgraded, so it is not
// worth a warning per tick. A clock skew refusal is logged at Error naming the
// fix, since it repeats on every tick until the operator acts. A refused
// credential is a send failure logged at Debug: the heartbeat names the cause
// once when it parks the agent, and every tick until a probe is accepted would
// repeat it as a Warn.
func (r *HandshakeReporter) logSendError(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}

	var apiErr *api.APIError
	isAPIErr := errors.As(err, &apiErr)
	switch {
	case errors.Is(err, api.ErrCredentialRefused):
		r.logger.DebugContext(ctx, "agent: handshake report: send failed", "error", err)
	case api.IsHandshakeReportNotServed(err):
		if !r.notServed {
			r.logger.InfoContext(ctx, "agent: handshake report: control plane does not accept handshake reports, retrying every interval",
				"status", apiErr.StatusCode,
				"code", apiErr.Code,
			)
			r.notServed = true
		}
	case isAPIErr && apiErr.Code == "handshake_clock_skew":
		r.logger.ErrorContext(ctx, "agent: handshake report: rejected for clock skew, synchronize the system clock via NTP", "error", err)
	default:
		r.logger.WarnContext(ctx, "agent: handshake report: send failed", "error", err)
	}
}

// buildHandshakeReport turns the device's mesh peer state into the report body
// stamped observedAt. req.Peers is never nil, because the contract refuses a
// null peers array.
//
// A peer with no completed handshake is left out without counting it, as the
// contract asks. A peer is left out and counted in skipped when its NodeID is
// not a non-zero UUID or its endpoint is invalid, has port 0 or an unspecified
// address: the control plane refuses the whole report for any one such entry,
// so sending it would take every edge in the report down with it.
//
// The endpoint is unmapped and its zone stripped before it is rendered. An
// IPv4-mapped IPv6 address would never match any of the peer's plain IPv4
// relays the control plane compares against to tell a direct link from a
// relayed one, and a zoned one is refused for the whole report. Stripping the
// zone is preferred over leaving the peer out, which would make a working
// link-local edge read never_reported.
//
// The age is observedAt minus the handshake, floored to whole seconds, clamped
// to 0 when the handshake postdates observedAt (a wall clock stepped back) and
// to math.MaxInt32, the contract's int32 ceiling, above it. A NodeID that
// repeats keeps the entry with the smaller age; the contract refuses a repeated
// peer_node_id and the newer handshake is the truer one. The entries are
// sorted by age and then PeerNodeID, and beyond api.MaxHandshakeReportPeers the
// oldest are cut and counted in truncated, since the freshest handshakes are
// the ones that keep edges from reading stale.
func buildHandshakeReport(observedAt time.Time, stats []wireguard.MeshPeerStat) (req api.HandshakeReportRequest, skipped, truncated int) {
	req.ObservedAt = observedAt
	req.Peers = make([]api.HandshakeReportPeer, 0, len(stats))

	// seen maps a NodeID to its entry's index in req.Peers, for the dedup.
	seen := make(map[string]int, len(stats))
	for _, s := range stats {
		if s.LastHandshake.IsZero() {
			continue
		}
		if !uuidRE.MatchString(s.NodeID) || s.NodeID == nilUUID {
			skipped++
			continue
		}
		endpoint, ok := wireEndpoint(s.Endpoint)
		if !ok {
			skipped++
			continue
		}

		peer := api.HandshakeReportPeer{
			PeerNodeID:              s.NodeID,
			LastHandshakeAgeSeconds: handshakeAgeSeconds(observedAt, s.LastHandshake),
			Endpoint:                endpoint,
		}
		if i, dup := seen[s.NodeID]; dup {
			if peer.LastHandshakeAgeSeconds < req.Peers[i].LastHandshakeAgeSeconds {
				req.Peers[i] = peer
			}
			continue
		}
		seen[s.NodeID] = len(req.Peers)
		req.Peers = append(req.Peers, peer)
	}

	slices.SortFunc(req.Peers, func(a, b api.HandshakeReportPeer) int {
		return cmp.Or(
			cmp.Compare(a.LastHandshakeAgeSeconds, b.LastHandshakeAgeSeconds),
			strings.Compare(a.PeerNodeID, b.PeerNodeID),
		)
	})
	if n := len(req.Peers); n > api.MaxHandshakeReportPeers {
		truncated = n - api.MaxHandshakeReportPeers
		req.Peers = req.Peers[:api.MaxHandshakeReportPeers]
	}

	return req, skipped, truncated
}

// wireEndpoint renders ep in the form the contract accepts, reporting false
// when no such form exists: an invalid endpoint, port 0, or an address that is
// unspecified once unmapped (::ffff:0.0.0.0 unmaps to 0.0.0.0, which the
// control plane refuses).
func wireEndpoint(ep netip.AddrPort) (string, bool) {
	if !ep.IsValid() || ep.Port() == 0 {
		return "", false
	}
	addr := ep.Addr().Unmap().WithZone("")
	if addr.IsUnspecified() {
		return "", false
	}
	return netip.AddrPortFrom(addr, ep.Port()).String(), true
}

// handshakeAgeSeconds returns the whole seconds from last to observedAt,
// clamped to the contract's 0..math.MaxInt32.
func handshakeAgeSeconds(observedAt, last time.Time) int32 {
	age := observedAt.Sub(last)
	if age < 0 {
		return 0
	}
	// Integer division floors here because age is not negative.
	secs := int64(age / time.Second)
	if secs > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(secs)
}
