package bridge

// forwardingPair is one EnableForwarding request: the mesh-side and
// access-side interface names as the caller passed them.
type forwardingPair [2]string

// forwardingLedger remembers which pairs currently hold which forwarding
// knobs, and what each knob held before plexd touched it, so that a knob is
// restored only when its last holder lets go.
//
// Linux needs none of this: its knob is a per-interface sysctl and every
// manager writes its own. The other two platforms share theirs. macOS has a
// single global forwarding sysctl, and on Windows the access adapter's
// forwarding flag is claimed by the bridge manager and the user-access manager
// alike, so tearing one down would otherwise switch forwarding off under the
// other.
//
// V is the saved state; each platform picks its own. The ledger carries no
// lock: every caller already holds its controller's mutex.
type forwardingLedger[V any] struct {
	holders map[string]map[forwardingPair]struct{}
	saved   map[string]V
}

// newForwardingLedger returns an empty ledger.
func newForwardingLedger[V any]() *forwardingLedger[V] {
	return &forwardingLedger[V]{
		holders: make(map[string]map[forwardingPair]struct{}),
		saved:   make(map[string]V),
	}
}

// held reports whether any pair currently holds knob.
func (l *forwardingLedger[V]) held(knob string) bool {
	return len(l.holders[knob]) > 0
}

// acquire records pair as a holder of knob. before is kept only when pair is
// the knob's first holder, so neither a later holder nor the same pair
// acquiring twice overwrites the state the first one found.
func (l *forwardingLedger[V]) acquire(knob string, pair forwardingPair, before V) {
	holders, ok := l.holders[knob]
	if !ok {
		holders = make(map[forwardingPair]struct{})
		l.holders[knob] = holders
		l.saved[knob] = before
	}
	holders[pair] = struct{}{}
}

// release drops pair from knob. When no holder remains it returns the saved
// state and true and forgets the knob, which is the caller's cue to restore
// what it found. While other holders remain it returns the zero value and
// false and keeps the saved state for them; a pair that never held knob
// changes nothing.
func (l *forwardingLedger[V]) release(knob string, pair forwardingPair) (V, bool) {
	var zero V

	holders, ok := l.holders[knob]
	if !ok {
		return zero, false
	}
	if _, ok := holders[pair]; !ok {
		return zero, false
	}

	delete(holders, pair)
	if len(holders) > 0 {
		return zero, false
	}

	before := l.saved[knob]
	delete(l.holders, knob)
	delete(l.saved, knob)
	return before, true
}
