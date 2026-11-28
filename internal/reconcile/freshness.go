package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// maxStateAgeSeconds is the longest maximum age the reconciler applies, ten
// years: a larger value is read as ten years, so no limit overflows a
// time.Duration.
const maxStateAgeSeconds = 315_360_000

// stateAgeFloorIntervals is how many reconcile intervals the applied maximum
// age is at least: under the floor a healthy node would withdraw its state
// between two pulls.
const stateAgeFloorIntervals = 3

// SetMaxAgeSeconds sets the maximum age of the desired state in whole seconds,
// counted from the last successful pull. A value below 1 clears the limit. It
// logs state freshness limit set when the applied value (see MaxAge) changed,
// state freshness limit removed when a limit is cleared, and state freshness
// limit below three reconcile intervals when the floor raises the value, once
// per value.
//
// It is for the reconcile goroutine, or for the caller before Run.
func (r *Reconciler) SetMaxAgeSeconds(v int64) {
	if v < 1 {
		v = 0
	}
	if v == r.maxAgeSeconds {
		return
	}
	before := r.MaxAge()
	r.maxAgeSeconds = v
	if v == 0 {
		r.logger.Info("state freshness limit removed", "component", "reconcile")
		return
	}
	applied := r.MaxAge()
	if cappedStateAge(v) < applied {
		r.logger.Warn("state freshness limit below three reconcile intervals",
			"component", "reconcile",
			"max_age_seconds", v,
			"applied", applied,
		)
	}
	if applied != before {
		r.logger.Info("state freshness limit set",
			"component", "reconcile",
			"max_age", applied,
		)
	}
}

// MaxAgeSeconds returns the maximum age as the control plane set it, in
// seconds, before the floor and the cap; 0 for none. The state store records
// this value.
//
// It is for the reconcile goroutine, or for the caller before Run.
func (r *Reconciler) MaxAgeSeconds() int64 {
	return r.maxAgeSeconds
}

// MaxAge returns the maximum age the reconciler applies: the limit read as at
// most ten years and raised to at least three reconcile intervals; 0 for
// none.
//
// It is for the reconcile goroutine, or for the caller before Run.
func (r *Reconciler) MaxAge() time.Duration {
	if r.maxAgeSeconds < 1 {
		return 0
	}
	return max(cappedStateAge(r.maxAgeSeconds), stateAgeFloorIntervals*r.cfg.Interval)
}

// cappedStateAge converts v seconds into a duration of at most ten years.
func cappedStateAge(v int64) time.Duration {
	return time.Duration(min(v, maxStateAgeSeconds)) * time.Second
}

// takeFreshness applies the state_freshness block of a successful pull:
//   - An absent block or a null changes nothing and logs nothing: the
//     reconciler keeps the limit it holds.
//   - A block json.Unmarshal refuses, such as a string or a fractional
//     max_age_seconds, changes nothing and logs state freshness block
//     malformed at Warn, once until a block decodes again.
//   - A block without max_age_seconds, or with null, clears the limit.
//   - A max_age_seconds below 1 changes nothing and logs state freshness
//     limit out of range at Warn, once per run of the same raw value.
//   - Any other value becomes the limit (see SetMaxAgeSeconds).
func (r *Reconciler) takeFreshness(raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var block *api.NodeStateFreshness
	if err := json.Unmarshal(raw, &block); err != nil {
		if !r.freshnessMalformed {
			r.logger.Warn("state freshness block malformed",
				"component", "reconcile",
				"error", err,
			)
			r.freshnessMalformed = true
		}
		return
	}
	// A literal null decodes to a nil block: like an absent key, it says
	// nothing about the limit.
	if block == nil {
		return
	}
	r.freshnessMalformed = false

	if block.MaxAgeSeconds == nil {
		r.freshnessOutOfRange = false
		r.SetMaxAgeSeconds(0)
		return
	}
	v := *block.MaxAgeSeconds
	if v < 1 {
		if !r.freshnessOutOfRange || v != r.freshnessOutOfRangeRaw {
			r.logger.Warn("state freshness limit out of range",
				"component", "reconcile",
				"max_age_seconds", v,
			)
			r.freshnessOutOfRange, r.freshnessOutOfRangeRaw = true, v
		}
		return
	}
	r.freshnessOutOfRange = false
	r.SetMaxAgeSeconds(v)
}

// Restore applies a stored desired state before the first pull, as a pull's
// apply without the pull: it counts as a pull age old for the maximum age,
// diffs stored against the current snapshot and, on drift, invokes the
// reconcile handlers. It runs no dispatch handler, because those mean "a pull
// succeeded" and would log the absent blocks of a pull that never happened.
//
// stored becomes the snapshot whether or not a handler failed. The snapshot
// before a restore is empty, so keeping it would leave a later pull unable to
// remove a restored peer the control plane has dropped. A failure sets
// reapply instead (see runCycle), so the next successful pull writes every
// peer it lists again. A negative age counts as 0, and a nil stored does
// nothing.
//
// Restore returns whether a handler failed and logs stored state applied. It
// is called once, before Run, from the goroutine that then calls Run.
func (r *Reconciler) Restore(ctx context.Context, stored *api.NodeStateSnapshot, age time.Duration) bool {
	if stored == nil {
		return false
	}
	age = max(age, 0)
	r.lastPull = r.now().Add(-age)

	current := r.snapshot.Get()
	diff := ComputeDiff(stored, &current)
	failed := false
	if !diff.IsEmpty() {
		failed = r.invokeHandlers(ctx, stored, diff)
	}
	r.snapshot.Update(stored)
	if failed {
		r.reapply = true
	}
	r.logger.Info("stored state applied",
		"component", "reconcile",
		"drift", diff.Summary(),
		"age", age,
		"handler_failed", failed,
	)
	return failed
}

// reapplyPeers appends to diff.PeersToAdd every peer of peers the diff lists
// neither as an add nor as an update, so a cycle that reapplies writes every
// pulled peer again.
func reapplyPeers(diff *StateDiff, peers []api.SnapshotPeer) {
	listed := make(map[string]struct{}, len(diff.PeersToAdd)+len(diff.PeersToUpdate))
	for _, p := range diff.PeersToAdd {
		listed[p.NodeID] = struct{}{}
	}
	for _, p := range diff.PeersToUpdate {
		listed[p.NodeID] = struct{}{}
	}
	for _, p := range peers {
		if _, ok := listed[p.NodeID]; !ok {
			diff.PeersToAdd = append(diff.PeersToAdd, p)
		}
	}
}

// WithdrawHandler withdraws state the reconcile handlers do not own, such as
// the policy, which lives on the dispatch seam, when the desired state passes
// its maximum age (see RegisterWithdrawHandler).
type WithdrawHandler func(ctx context.Context) error

// RegisterWithdrawHandler adds a handler the reconciler calls when the
// desired state passes its maximum age. Handlers are called in registration
// order, before the reconcile handlers get the withdrawn snapshot.
// RegisterWithdrawHandler must be called before Run; it is not safe for
// concurrent use.
func (r *Reconciler) RegisterWithdrawHandler(handler WithdrawHandler) {
	r.withdrawHandlers = append(r.withdrawHandlers, handler)
}

// pendingWithdrawal is a withdrawal a handler failed on: the withdrawn
// snapshot and its diff against the snapshot the reconciler still holds.
type pendingWithdrawal struct {
	snapshot *api.NodeStateSnapshot
	diff     StateDiff
}

// expiryIn returns how long from now the desired state passes its maximum
// age, and whether there is such a time: a limit applies, a pull or a
// restore happened, and the state is not withdrawn already.
func (r *Reconciler) expiryIn() (time.Duration, bool) {
	maxAge := r.MaxAge()
	if maxAge <= 0 || r.lastPull.IsZero() || r.withdrawn {
		return 0, false
	}
	return r.lastPull.Add(maxAge).Sub(r.now()), true
}

// withdraw withdraws the desired state once its last successful pull is
// older than the maximum age. It calls the withdraw handlers in order, then
// hands the reconcile handlers the withdrawn snapshot: no peers, no shared
// subnets, no policy, the bridge block withdrawnBridge leaves, and the state
// and reports blocks as they are, since a nil state makes the node API clear
// its cache. When nothing failed it records the withdrawn snapshot, so the
// next successful pull adds every peer again; otherwise the withdrawal is
// pending and retried on every later cycle whose fetch fails. The expiry
// timer stays disarmed until a fetch succeeds.
func (r *Reconciler) withdraw(ctx context.Context) {
	r.logger.Warn("desired state passed its maximum age, withdrawing",
		"component", "reconcile",
		"age", r.now().Sub(r.lastPull),
		"max_age", r.MaxAge(),
	)
	r.withdrawn = true

	current := r.snapshot.Get()
	withdrawn := &api.NodeStateSnapshot{
		Bridge:  withdrawnBridge(current.Bridge),
		State:   current.State,
		Reports: current.Reports,
	}
	failed := r.applyWithdrawal(ctx, &pendingWithdrawal{
		snapshot: withdrawn,
		diff:     ComputeDiff(withdrawn, &current),
	})
	r.logger.Info("desired state withdrawn",
		"component", "reconcile",
		"handler_failed", failed,
	)
}

// applyWithdrawal calls the withdraw handlers and, on drift, the reconcile
// handlers with p. It records p's snapshot when nothing failed and keeps p
// pending otherwise, and returns whether a handler failed.
func (r *Reconciler) applyWithdrawal(ctx context.Context, p *pendingWithdrawal) bool {
	failed := false
	for i, handler := range r.withdrawHandlers {
		if err := r.safeWithdraw(ctx, handler); err != nil {
			r.logger.Error("withdraw handler failed",
				"component", "reconcile",
				"handler_index", i,
				"error", err,
			)
			failed = true
		}
	}
	if !p.diff.IsEmpty() && r.invokeHandlers(ctx, p.snapshot, p.diff) {
		failed = true
	}
	if failed {
		r.pending = p
		return true
	}
	r.snapshot.Update(p.snapshot)
	r.pending = nil
	return false
}

// retryWithdrawal applies a pending withdrawal again, on a cycle whose fetch
// failed.
func (r *Reconciler) retryWithdrawal(ctx context.Context) {
	if r.pending == nil || ctx.Err() != nil {
		return
	}
	failed := r.applyWithdrawal(ctx, r.pending)
	r.logger.Debug("withdrawal retried",
		"component", "reconcile",
		"handler_failed", failed,
	)
}

// safeWithdraw calls a withdraw handler with panic recovery.
func (r *Reconciler) safeWithdraw(ctx context.Context, handler WithdrawHandler) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("withdraw handler panicked: %v\n%s", v, debug.Stack())
		}
	}()
	return handler(ctx)
}

// withdrawnBridge returns the bridge block of a withdrawn state: no relay and
// no ingress, and the user access and site-to-site blocks with Enabled false
// and their providers and tunnels kept. The managers keep the key file of
// every provider and tunnel a block lists whatever Enabled says and delete
// the others, so a nil child would delete every bridge key. A nil block
// stays nil.
func withdrawnBridge(b *api.BridgeSnapshot) *api.BridgeSnapshot {
	if b == nil {
		return nil
	}
	w := &api.BridgeSnapshot{
		UserAccess: copyUserAccess(b.UserAccess),
		SiteToSite: copySiteToSite(b.SiteToSite),
	}
	if w.UserAccess != nil {
		w.UserAccess.Enabled = false
	}
	if w.SiteToSite != nil {
		w.SiteToSite.Enabled = false
	}
	return w
}
