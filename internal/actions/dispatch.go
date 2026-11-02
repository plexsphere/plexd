package actions

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// dispatchBudget bounds the wall clock one dispatch pass may spend. Handle runs
// on the reconcile goroutine, ahead of peer, policy, and bridge convergence, and
// every entry it settles costs up to three sequential callbacks. Block size is
// the control plane's to choose and nothing caps it, so without a budget a
// degraded control plane pins the whole cycle open for the length of the block.
// Entries the pass does not reach are redelivered by the next pull, so an
// exhausted budget only defers work.
//
// The budget gates which entries the pass starts, not how long an entry it
// already started may take: a settlement handed what is left of the budget as
// its deadline would fail on that deadline rather than on the control plane,
// deferring the entry into the next pass to fail the same way. Each settlement
// therefore carries its own per-leg deadline, and an entry is started only while
// maxSettlementCost of the budget is left. That leaves a five-second window in
// which entries start and bounds the whole pass at the budget, instead of at the
// budget plus one entire settlement.
const dispatchBudget = 20 * time.Second

// maxSettlementCost is the most one entry can cost the pass: the rejection walk
// is the longest settlement at three legs of dispatchCallbackTimeout each. The
// claim handshake is two of those legs and the orphan report a single
// terminalReportTimeout, both shorter.
const maxSettlementCost = 3 * dispatchCallbackTimeout

// maxDeferrals bounds how many consecutive passes one entry may hold the head of
// the block. An orphan report the control plane does not take leaves its entry
// unsettled so the next pull retries it, but a report that keeps failing spends
// the budget on the same entries every pass and starves everything queued behind
// them until the block drains — which, for an execution held at started, is its
// whole expiry window. After this many passes the entry is settled locally and
// its execution left to server-side expiry: the outcome an undeliverable report
// ends at anyway, reached without burning a pass per cycle on the way.
const maxDeferrals = 5

// Dispatcher consumes the executions block of the reconciliation pull and turns
// each entry into an execution on the Executor. The block is a delivery queue,
// not desired state: an entry keeps reappearing on every pull until its
// execution reaches a terminal status through the callback, so suppressing the
// re-observations is the node's job.
//
// The one thing a re-observation can still carry is a cancel request, set on
// the entry of a run in flight. It is forwarded to the executor while the
// block's ids are collected, ahead of the settled check and of the budget: the
// run's id sits in handled, so the pass itself never reads that entry again,
// and a pass that spends its budget must not hold back a stop.
//
// A Dispatcher is not safe for concurrent use. Handle is invoked only from the
// reconcile goroutine, one cycle at a time, so handled needs no mutex.
type Dispatcher struct {
	executor *Executor
	nodeID   string
	logger   *slog.Logger

	// handled is the set of execution ids this dispatcher has already settled —
	// dispatched, rejected, expired, or reported lost. A settled id is a no-op
	// on every later pull until the entry drains from the block, which is also
	// the signal to forget it again. It is only ever a hint that an entry needs
	// no further work: the executor, not this set, is authoritative on whether a
	// run is still in flight. A cancel request is forwarded before this set is
	// consulted, because the run it stops is one whose id the set holds.
	handled map[string]struct{}

	// deferrals counts, per execution id, the passes on which the orphan report
	// this dispatcher owed was left undelivered. It caps that retry at
	// maxDeferrals so a single unsettleable entry cannot hold the head of the
	// block for the life of it. It is pruned alongside handled when the entry
	// drains.
	deferrals map[string]int

	// cancelled is the set of execution ids whose cancel request this
	// dispatcher forwarded to a run the executor held. The block repeats the
	// request on every pull until the run's terminal report drains the entry,
	// so the set is what forwards and logs it once. It is pruned alongside
	// handled when the entry drains.
	cancelled map[string]struct{}
}

// NewDispatcher creates a Dispatcher that dispatches the pull's executions
// block through executor on behalf of nodeID.
func NewDispatcher(executor *Executor, nodeID string, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		executor:  executor,
		nodeID:    nodeID,
		logger:    logger.With("component", "actions"),
		handled:   make(map[string]struct{}),
		deferrals: make(map[string]int),
		cancelled: make(map[string]struct{}),
	}
}

// Handle dispatches every entry of the snapshot's executions block, in block
// order. Its signature matches reconcile.DispatchHandler.
func (d *Dispatcher) Handle(ctx context.Context, desired *api.NodeStateSnapshot) {
	// The id set of the whole block is collected before anything is dispatched:
	// the pass below can stop early on its budget, and an entry it never reached
	// must not be mistaken for one the control plane has drained.
	present := make(map[string]struct{}, len(desired.Executions))
	for _, entry := range desired.Executions {
		present[entry.ExecutionID] = struct{}{}
		// A cancel is forwarded here rather than in the pass below, which skips
		// the settled id of a run in flight and can stop on its budget before
		// it reaches the entry. An entry without an id has nothing to cancel
		// and is dropped by the pass.
		if entry.ExecutionID != "" && entry.CancelRequestedAt != nil {
			d.forwardCancel(entry)
		}
	}

	deadline := time.Now().Add(dispatchBudget)

	for _, entry := range desired.Executions {
		// An entry without an id has no callback route and no identity to
		// deduplicate, cancel, or audit on — every such entry would collapse
		// onto the same active and handled slot. It is dropped, never run.
		if entry.ExecutionID == "" {
			d.logger.Error("execution entry carries no execution_id; dropping",
				"action", entry.Action,
			)
			continue
		}

		if _, settled := d.handled[entry.ExecutionID]; settled {
			continue
		}

		// The executor holds the authoritative run state. An id pruned from
		// handled while the block transiently omitted it is still in flight
		// here, and must be neither reported lost nor dispatched a second time.
		if d.executor.IsActive(entry.ExecutionID) {
			d.handled[entry.ExecutionID] = struct{}{}
			continue
		}

		if ctx.Err() != nil || time.Until(deadline) < maxSettlementCost {
			d.logger.Warn("dispatch budget exhausted; the remaining entries wait for the next pull",
				"execution_id", entry.ExecutionID,
				"budget", dispatchBudget,
			)
			break
		}

		// A missing expires_at decodes to the zero time, which is never after
		// now: folding it into the lapsed case below would silently discard
		// every dispatch the control plane ever queues.
		if entry.ExpiresAt.IsZero() {
			d.logger.Warn("execution carries no expires_at; refusing to dispatch",
				"execution_id", entry.ExecutionID,
				"action", entry.Action,
			)
			d.handled[entry.ExecutionID] = struct{}{}
			continue
		}

		// Expiry is the control plane's move: timeout is a server-side status a
		// node never reports, so a lapsed entry is dropped without a callback.
		// The clock is sampled per entry rather than once per pass: a pass can
		// spend most of its budget before reaching this entry, and a stale now
		// would wave through an execution the control plane has already timed
		// out — buying it a full claim handshake and a terminal callback that is
		// answered execution_already_terminal.
		if !entry.ExpiresAt.After(time.Now()) {
			d.logger.Info("execution expired; leaving the timeout to the control plane",
				"execution_id", entry.ExecutionID,
				"action", entry.Action,
				"expires_at", entry.ExpiresAt,
			)
			d.handled[entry.ExecutionID] = struct{}{}
			continue
		}

		switch entry.Status {
		case api.ExecutionStatusPending, api.ExecutionStatusAck:
			// The control plane ends a waiting target itself when its
			// Execution is cancelled, so it never serves one with a request. An
			// entry that carries one anyway is not started, with actions
			// disabled too, and gets no callback: a claim or a rejection walk
			// on it would be answered execution_already_terminal.
			if entry.CancelRequestedAt != nil {
				d.logger.Warn("execution entry carries a cancel request but never started; not starting it",
					"execution_id", entry.ExecutionID,
					"action", entry.Action,
					"status", entry.Status,
				)
				d.handled[entry.ExecutionID] = struct{}{}
				continue
			}

			// The disabled gate sits inside the status roster: an entry whose
			// status this build does not know must not be driven through a
			// rejection walk, which would guess a transition path from a state
			// the node cannot place.
			if !d.executor.cfg.IsEnabled() {
				// The walk settles the execution, so it gets the cycle context
				// rather than the budget: legs issued on a near-spent budget
				// fail on the deadline instead of on the control plane, which
				// only defers the entry into the next pass to fail the same way.
				if err := d.executor.reject(ctx, d.nodeID, entry, "actions_disabled"); err != nil {
					continue
				}
				d.handled[entry.ExecutionID] = struct{}{}
				continue
			}

			// A deferral is local backpressure, not a failure of the execution:
			// the block redelivers the entry, so leaving it unsettled retries it
			// on the next cycle instead of burning it. The run itself outlives
			// the pass, so it gets the cycle context rather than the budget.
			if err := d.executor.Execute(ctx, d.nodeID, entry); errors.Is(err, ErrDispatchDeferred) {
				continue
			}
			d.handled[entry.ExecutionID] = struct{}{}

		case api.ExecutionStatusStarted:
			// The control plane holds the execution at started but this agent
			// keeps no run state across a restart. Actions are not idempotent,
			// so the run is reported lost rather than repeated. The report is
			// the execution's only transition out of started and outlives the
			// pass, so — like the run above — it gets the cycle context rather
			// than the budget. An undelivered report leaves the entry unsettled:
			// marking it handled anyway would drop the report for the life of
			// the process and strand the execution at started until it expires.
			// That retry is capped, because an entry left unsettled is retried
			// at the head of the block on every pull: past maxDeferrals passes
			// the report is abandoned rather than allowed to spend the budget
			// ahead of the entries queued behind it.
			if err := d.executor.FailOrphan(ctx, d.nodeID, entry.ExecutionID); err != nil {
				d.deferrals[entry.ExecutionID]++
				if d.deferrals[entry.ExecutionID] < maxDeferrals {
					continue
				}
				d.logger.Error("orphan report undelivered across repeated pulls; leaving the execution to server-side expiry",
					"execution_id", entry.ExecutionID,
					"passes", d.deferrals[entry.ExecutionID],
				)
			}
			d.handled[entry.ExecutionID] = struct{}{}

		default:
			d.logger.Warn("unexpected execution status in the pull block",
				"execution_id", entry.ExecutionID,
				"action", entry.Action,
				"status", entry.Status,
			)
			d.handled[entry.ExecutionID] = struct{}{}
		}
	}

	// An entry draining from the block is the garbage-collection signal: the
	// control plane has settled it, so it can never be re-observed under the
	// same id. Pruning here bounds the map by the size of the block.
	for id := range d.handled {
		if _, ok := present[id]; !ok {
			delete(d.handled, id)
		}
	}
	for id := range d.deferrals {
		if _, ok := present[id]; !ok {
			delete(d.deferrals, id)
		}
	}
	for id := range d.cancelled {
		if _, ok := present[id]; !ok {
			delete(d.cancelled, id)
		}
	}
}

// forwardCancel hands the cancel request entry carries to the executor, once
// per id. It sends no callback: the run reports cancelled through its own
// terminal report once its context ends, or its real outcome when it finished
// first. A request for a run the executor does not hold is left to the pass,
// which reports a started entry lost, as after a restart, and never starts a
// waiting one.
func (d *Dispatcher) forwardCancel(entry api.NodeStateExecution) {
	if _, forwarded := d.cancelled[entry.ExecutionID]; forwarded {
		return
	}
	if !d.executor.Cancel(entry.ExecutionID) {
		return
	}
	d.cancelled[entry.ExecutionID] = struct{}{}
	// The stopped run leaves the executor as soon as its report is sent,
	// which can be before the pass reaches the entry. Settling the id here
	// keeps the pass from reading that run as lost to a restart when a block
	// that briefly omitted the entry has pruned it from handled.
	d.handled[entry.ExecutionID] = struct{}{}
	d.logger.Info("cancel requested; stopping the run",
		"execution_id", entry.ExecutionID,
		"action", entry.Action,
		"cancel_requested_at", *entry.CancelRequestedAt,
	)
}
