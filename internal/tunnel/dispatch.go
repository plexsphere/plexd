package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// sessionStartedReportTimeout bounds a single session_started report. The
// dispatch context is the reconciler's own, which carries no deadline, so
// without an explicit bound the only limit on a stalled control plane is the API
// client's request timeout — long enough that one unanswered post would freeze
// the reconciler's single goroutine for the rest of the cycle.
//
// It has to stay above api.DefaultConnectTimeout, because it covers the TCP
// connect, the TLS handshake, the request and the response, while that constant
// is what the same client grants the connect phase on its own. A bound at or
// below it would make the report the one call that deterministically fails on a
// high-latency link or during a control-plane failover, while every other call
// to the same control plane still succeeds.
const sessionStartedReportTimeout = 15 * time.Second

// Dispatcher consumes the sessions block of the reconciliation pull and holds
// the node's mediated-access listeners level with it. The block is desired
// state, not a delivery queue like the executions block: an entry stands for as
// long as the session is valid, and its disappearance is the teardown signal.
// Revocation and hard expiry both reach the node as that same absence — there is
// no revocation callback to answer and no terminal status to report.
//
// Provisioning is tcp-kind only. An ssh or k8s entry is decoded and settled as
// unsupported: one warning, no listener, no activity row.
//
// A Dispatcher is not safe for concurrent use. Handle is invoked only from the
// reconcile goroutine, one cycle at a time, so known and unreported need no
// mutex.
//
// The pass carries no dispatch budget, unlike the executions block's: it is
// bounded by the live sessions the manager caps at MaxSessions plus the length
// of the block, and its only network call is a single bounded activity post per
// session whose started row is still outstanding.
type Dispatcher struct {
	manager  *SessionManager
	reporter SessionActivityReporter
	logger   *slog.Logger

	// known is the set of session ids this dispatcher has already handled while
	// their entry stands in the block — provisioned, observed live, or
	// permanently settled (unsupported kind, mismatched target, missing or
	// lapsed expiry, tunneling disabled). A known id is a no-op on every later
	// pull until its entry drains, which is also the signal to forget it again,
	// so the map stays bounded by the size of the block.
	known map[string]struct{}

	// unreported maps the id of a provisioned session whose started row has not
	// reached the control plane to the address its listener holds. The row is
	// re-posted from that address on every later pull until it lands, rather
	// than the listener being rebuilt: the ephemeral port is the operator's only
	// route in, so giving it up would publish a different listener_endpoint per
	// attempt and pair each one with a spurious session_ended row. It drains on
	// the first delivered row, and otherwise with the entry itself.
	unreported map[string]string
}

// NewDispatcher creates a Dispatcher that provisions the pull's sessions block
// through manager and reports each started listener through reporter.
func NewDispatcher(manager *SessionManager, reporter SessionActivityReporter, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		manager:    manager,
		reporter:   reporter,
		logger:     logger.With("component", "tunnel"),
		known:      make(map[string]struct{}),
		unreported: make(map[string]string),
	}
}

// startedSession is one listener this pass provisioned, held until the report
// pass that follows the provisioning loop. reported is written by the goroutine
// posting that session's started row and read once every report has returned.
type startedSession struct {
	entry    api.NodeStateSession
	addr     string
	reported bool
}

// Handle reconciles the snapshot's sessions block: it first tears down every
// live session the block no longer carries, then provisions the entries it does
// not yet serve, in block order, and finally reports the listeners it brought
// up. Its signature matches reconcile.DispatchHandler.
func (d *Dispatcher) Handle(ctx context.Context, desired *api.NodeStateSnapshot) {
	// A block the control plane did not populate is not an empty block. Absence
	// is destructive here — it closes every live session — so a null block, or a
	// key a control-plane build predating the block never wrote, must not be read
	// as "this node has no sessions". The pull is left to say so explicitly.
	if desired.Sessions == nil {
		d.logger.Warn("state snapshot carries no sessions block; leaving live sessions alone")
		return
	}
	entries := *desired.Sessions

	// The id set of the whole block is collected before anything is torn down:
	// absence from the block is what drives teardown, so the set has to be
	// complete before the first close.
	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		// An entry without an id has no identity to provision, close, or audit
		// on — every such entry would collapse onto the same session slot. It is
		// dropped, and it stays out of the present set, which holds only ids a
		// teardown or a provision can act on.
		if entry.SessionID == "" {
			d.logger.Error("session entry carries no session_id; dropping",
				"kind", entry.Kind,
			)
			continue
		}
		present[entry.SessionID] = struct{}{}
	}

	// The live sessions are snapshotted once, ahead of both passes. Their capped
	// local expiry is the only discriminator the node has for why an entry left
	// the block, and it only settles one of the two cases: an entry that leaves
	// after its expiry lapsed is self-evidently a hard expiry.
	live := d.manager.ActiveSessions()

	// Each close blocks on the session's drain and on a bounded activity post, so
	// they run concurrently: closing serially would let a slow or unreachable
	// control plane stretch a mass teardown to MaxSessions times the per-report
	// bound, and this pass runs inline on the reconciler's single goroutine,
	// ahead of the diff and every reconcile handler.
	var wg sync.WaitGroup
	for id, expiresAt := range live {
		if _, ok := present[id]; ok {
			continue
		}
		// The node cannot tell a revocation from a block the control plane failed
		// to serve; only a lapsed local expiry is self-evident. Anything else is
		// reported as a local close rather than asserted as an operator action in
		// the audit trail.
		reason := reasonExpired
		if time.Now().Before(expiresAt) {
			reason = reasonDrained
		}
		wg.Add(1)
		go func(id, reason string) {
			defer wg.Done()
			d.manager.CloseSession(id, reason)
		}(id, reason)
	}
	wg.Wait()

	// Provisioning stays serial and in block order: it is local work, and the
	// capacity the manager caps at MaxSessions is handed out in the order the
	// block lists. Only the reports that follow it go out concurrently.
	var started []startedSession

	for _, entry := range entries {
		// Already dropped, with its error logged, in the collection pass above.
		if entry.SessionID == "" {
			continue
		}

		if _, settled := d.known[entry.SessionID]; settled {
			continue
		}

		// A live session is already provisioned, so re-observing it is not a
		// reason to set it up a second time. The teardown pass above keeps a
		// reported session live ⇒ known, so this is reachable only for one whose
		// started row is still outstanding — or, as defence in depth, if one
		// block carries the same id twice.
		if _, ok := live[entry.SessionID]; ok {
			if addr, outstanding := d.unreported[entry.SessionID]; outstanding {
				started = append(started, startedSession{entry: entry, addr: addr})
			} else {
				d.known[entry.SessionID] = struct{}{}
			}
			continue
		}

		// The session behind an outstanding row is gone — its capped expiry or
		// its idle window took it down while the entry still stood — so the
		// address it held is stale and the entry is provisioned afresh below.
		delete(d.unreported, entry.SessionID)

		// A missing expires_at decodes to the zero time, which is never after
		// now: folding it into the lapsed case below would silently discard the
		// entry instead of naming what is wrong with it.
		if entry.ExpiresAt.IsZero() {
			d.logger.Warn("session carries no expires_at; refusing to provision",
				"session_id", entry.SessionID,
				"kind", entry.Kind,
			)
			d.known[entry.SessionID] = struct{}{}
			continue
		}

		// Hard expiry is the control plane's drain to perform: the entry leaves
		// the block on its own, and until it does there is nothing to provision.
		if !entry.ExpiresAt.After(time.Now()) {
			d.logger.Info("session expired; waiting for the control plane to drain the entry",
				"session_id", entry.SessionID,
				"kind", entry.Kind,
				"expires_at", entry.ExpiresAt,
			)
			d.known[entry.SessionID] = struct{}{}
			continue
		}

		// ssh and k8s sessions are part of the contract but not of this agent's
		// mediation. They are settled rather than retried, so the warning is
		// emitted once per entry rather than once per pull.
		if entry.Kind == api.SessionKindSSH || entry.Kind == api.SessionKindK8s {
			d.logger.Warn("unsupported session kind; no listener provisioned",
				"session_id", entry.SessionID,
				"kind", entry.Kind,
			)
			d.known[entry.SessionID] = struct{}{}
			continue
		}

		// A kind outside the three the contract names is one a later control
		// plane started emitting: nothing is wrong with the entry's target, so
		// the operator is told about the kind rather than sent to inspect it.
		if entry.Kind != api.SessionKindTCP {
			d.logger.Warn("unrecognised session kind; no listener provisioned",
				"session_id", entry.SessionID,
				"kind", entry.Kind,
			)
			d.known[entry.SessionID] = struct{}{}
			continue
		}

		// What is left must be a tcp session carrying exactly its own target: a
		// tcp entry without a tcp target, or one with a second member set,
		// describes a session this build cannot place.
		if entry.Target.TCP == nil || entry.Target.SSH != nil || entry.Target.K8s != nil {
			d.logger.Warn("session target does not match kind",
				"session_id", entry.SessionID,
				"kind", entry.Kind,
			)
			d.known[entry.SessionID] = struct{}{}
			continue
		}

		addr, err := d.manager.CreateSession(ctx, entry)
		switch {
		case err == nil:
			// The entry is settled by the report pass below, not here: an entry
			// whose started row never lands stays unsettled so the next pull
			// rebuilds it.
			started = append(started, startedSession{entry: entry, addr: addr})

		case errors.Is(err, ErrTunnelingDisabled):
			// Configuration, not weather. Retrying it would warn once per pull
			// for the life of the process and never succeed.
			d.logger.Warn("tunneling is disabled; no listener provisioned",
				"session_id", entry.SessionID,
			)
			d.known[entry.SessionID] = struct{}{}

		default:
			// Capacity reached, an unusable target, a listener that would not
			// bind: the entry is left unsettled so the next pull retries it —
			// a freed session slot is all the common case needs.
			d.logger.Warn("session listener setup failed",
				"session_id", entry.SessionID,
				"error", err,
			)
		}
	}

	// The started rows go out concurrently and under an explicit bound, for the
	// same reason the teardown pass closes concurrently: each post blocks on the
	// control plane, and a failed one blocks again on the close's own ended row,
	// so posting them one after another would let a stalled control plane stretch
	// a single pull to MaxSessions times both bounds — on the reconciler's single
	// goroutine, with every other reconcile handler waiting behind it.
	var reportWg sync.WaitGroup
	for i := range started {
		reportWg.Add(1)
		go func(s *startedSession) {
			defer reportWg.Done()
			reportCtx, cancel := context.WithTimeout(ctx, sessionStartedReportTimeout)
			defer cancel()
			// The started row carries the ephemeral port that is the operator's
			// only route to the listener, so an undelivered row leaves a bound
			// listener nobody can reach until it lands. The listener is kept and
			// the entry left unsettled, so the next pull re-posts the same
			// endpoint; tearing it down instead would forfeit the port, and a
			// control plane too slow to answer within the bound would then see a
			// session_ended row and a fresh listener_endpoint on every pull for
			// the whole TTL of the entry. The capped expiry timer is what
			// reclaims a listener whose row never lands.
			if err := d.reporter.ReportSessionStarted(reportCtx, s.entry.SessionID, s.entry.Target.TCP.Host, s.entry.Target.TCP.Port, s.addr); err != nil {
				d.logger.Warn("session started report failed; keeping the listener for the next pull to re-post it",
					"session_id", s.entry.SessionID,
					"listener_endpoint", s.addr,
					"error", err,
				)
				return
			}
			s.reported = true
		}(&started[i])
	}
	reportWg.Wait()

	// Settling happens back on this goroutine, once every report has returned,
	// so known and unreported keep needing no mutex.
	for _, s := range started {
		if s.reported {
			delete(d.unreported, s.entry.SessionID)
			d.known[s.entry.SessionID] = struct{}{}
			continue
		}
		d.unreported[s.entry.SessionID] = s.addr
	}

	// An entry draining from the block is the garbage-collection signal: its
	// session has been torn down above and the id can only come back as a freshly
	// issued session. Pruning here bounds both maps by the size of the block.
	for id := range d.known {
		if _, ok := present[id]; !ok {
			delete(d.known, id)
		}
	}
	for id := range d.unreported {
		if _, ok := present[id]; !ok {
			delete(d.unreported, id)
		}
	}
}
