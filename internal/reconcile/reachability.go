package reconcile

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// ReachabilityObserver logs the control plane's reachability verdict about this
// node whenever it changes. The verdict is the one signal a node cannot derive
// for itself: an agent whose state pulls succeed while its heartbeats stop being
// admitted looks healthy in its own journal and reads as stale or unreachable to
// everyone else. One line at the moment the verdict changes puts that split
// where a node operator already looks.
//
// The block is a diagnostic projection, not desired state. The observer stores
// nothing beyond the last verdict it saw, and the snapshot store still never
// keeps the block.
//
// A ReachabilityObserver is not safe for concurrent use. Handle is invoked only
// from the reconcile goroutine, one cycle at a time, so its fields need no mutex.
type ReachabilityObserver struct {
	logger *slog.Logger

	// state is the last verdict this observer logged, and the empty string
	// before the first one. Every decision below is a comparison against it, so
	// an unchanged verdict costs no line however many pulls carry it.
	state string

	// malformedLogged records that the warning for an undecodable block has
	// already gone out. A block the control plane serves broken stays broken
	// across pulls, and at one line per reconcile interval that fills a journal
	// with the same fact. The next successful decode re-arms it.
	malformedLogged bool
}

// NewReachabilityObserver returns an observer that logs verdict changes through
// logger.
func NewReachabilityObserver(logger *slog.Logger) *ReachabilityObserver {
	return &ReachabilityObserver{logger: logger.With("component", "reachability")}
}

// Handle observes the snapshot's reachability block. Its signature matches
// DispatchHandler, so it runs on every successful pull, including the cycles the
// empty-diff short-circuit ends early.
func (o *ReachabilityObserver) Handle(_ context.Context, desired *api.NodeStateSnapshot) {
	// An absent block is not an observation. A control plane that populates the
	// key sends a verdict; one that does not is silent about this node, which is
	// different from saying its verdict is empty.
	if len(desired.Reachability) == 0 {
		return
	}

	// The decode is deliberately lenient and deliberately here rather than in
	// FetchState: a malformed diagnostic block must not abort the pull that
	// carries the peers, the policy, and the executions.
	var snapshot *api.ReachabilitySnapshot
	if err := json.Unmarshal(desired.Reachability, &snapshot); err != nil {
		if !o.malformedLogged {
			o.logger.Warn("reachability block malformed", "error", err)
			o.malformedLogged = true
		}
		return
	}
	o.malformedLogged = false

	// A literal null is the wire form of "block not populated" and decodes to a
	// nil pointer. Like an absent block, it says nothing about the verdict, so
	// the remembered one stands and a null pull between two identical verdicts
	// produces no duplicate line.
	if snapshot == nil {
		return
	}

	if snapshot.State == o.state {
		return
	}

	// The verdict is logged verbatim, whatever it is. A value outside the
	// documented set — a fifth verdict a later control plane introduces — is
	// exactly what this line exists to surface.
	attrs := []any{
		"state", snapshot.State,
		"previous", o.state,
		"changed_at", snapshot.ChangedAt,
	}
	if snapshot.LastHeartbeatAt != nil {
		attrs = append(attrs, "last_heartbeat_at", *snapshot.LastHeartbeatAt)
	}
	o.logger.Info("reachability verdict changed", attrs...)

	o.state = snapshot.State
}
