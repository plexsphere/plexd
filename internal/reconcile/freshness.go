package reconcile

import (
	"context"
	"encoding/json"
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
