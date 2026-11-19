package bridge

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The bounds of a rule's targets. The control plane's contract fixes both,
// and no rule member sets them.
const (
	// maxIngressTargets is the most targets a rule holds; a rule with more
	// is invalid_rule with the Detail targets.
	maxIngressTargets = 8
	// ingressTargetHoldOut is how long a target whose dial failed is passed
	// over, counted from that dial.
	ingressTargetHoldOut = 30 * time.Second
)

// ingressBalancer spreads the units of one rule over the rule's targets by
// round robin. A unit is what the bridge forwards to one target: a connection
// for a rule that forwards bytes, a request for a rule with conditions, a
// client flow for a udp rule. The balancer holds the round-robin position,
// the hold-outs and the dial records of the rule; Apply carries it over while
// the rule's targets stay equal, so a changed list starts with every target
// in and every dial none. It is concurrent-safe via mu and never takes the
// manager's mu.
type ingressBalancer struct {
	mu      sync.Mutex
	targets []balancedTarget // in the order of the rule's targets
	last    int              // index of the last pick; -1 before the first
	unit    dialRecord       // how the rule's last unit ended
}

// balancedTarget is one target of a balancer. target and addr never change
// once newIngressBalancer returns, so they are read without mu; mu guards
// outUntil and dial.
type balancedTarget struct {
	target   api.IngressTarget
	addr     string    // net.JoinHostPort(Address, strconv.Itoa(Port))
	outUntil time.Time // zero while the target is in
	dial     dialRecord
}

// newIngressBalancer returns the balancer of a rule with targets, every
// target in and every dial none.
func newIngressBalancer(targets []api.IngressTarget) *ingressBalancer {
	b := &ingressBalancer{targets: make([]balancedTarget, len(targets)), last: -1}
	for i, t := range targets {
		b.targets[i] = balancedTarget{target: t, addr: net.JoinHostPort(t.Address, strconv.Itoa(t.Port))}
	}
	return b
}

// pick returns the target a unit dials next, tried holding a bit per target
// index the unit dialled already. It walks the targets from the one after the
// last pick, wrapping, and returns the first untried target that is in at
// now; when no untried target is in, it returns the first untried one in the
// same order, since a rule whose targets are all out dials them as if all
// were in. ok is false when the unit tried every target. Every pick becomes
// the last pick, so concurrent units spread over the targets, and a unit
// starts after the target the unit before it went to.
func (b *ingressBalancer) pick(tried uint8, now time.Time) (idx int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	first := -1
	for k := 1; k <= len(b.targets); k++ {
		i := (b.last + k) % len(b.targets)
		if tried&(1<<i) != 0 {
			continue
		}
		if !now.Before(b.targets[i].outUntil) {
			b.last = i
			return i, true
		}
		if first < 0 {
			first = i
		}
	}
	if first < 0 {
		return -1, false
	}
	b.last = first
	return first, true
}

// dialled stores the outcome of a dial to the target idx at now, reason
// naming a failed one. A failure takes the target out until
// ingressTargetHoldOut after now, also when it was out already. A success
// brings the target in and makes the rule's unit succeeded at now: a target
// that answers serves the unit. It reports whether the outcome or the reason
// of the target's record changed, or on a success that of the unit; a record
// without a dial before it counts as changed.
func (b *ingressBalancer) dialled(idx int, failed bool, reason string, now time.Time) (changed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := &b.targets[idx]
	changed = t.dial.changedTo(failed, reason)
	t.dial = dialRecord{failed: failed, reason: reason, at: now}
	if failed {
		t.outUntil = now.Add(ingressTargetHoldOut)
		return changed
	}
	t.outUntil = time.Time{}
	if b.unit.changedTo(false, "") {
		changed = true
	}
	b.unit = dialRecord{at: now}
	return changed
}

// unitFailed makes the rule's unit failed with reason at at: no target took
// it. It reports whether the unit's outcome or reason changed.
func (b *ingressBalancer) unitFailed(reason string, at time.Time) (changed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	changed = b.unit.changedTo(true, reason)
	b.unit = dialRecord{failed: true, reason: reason, at: at}
	return changed
}

// otherIn reports whether a target other than idx is in at now.
func (b *ingressBalancer) otherIn(idx int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.targets {
		if i != idx && !now.Before(b.targets[i].outUntil) {
			return true
		}
	}
	return false
}

// balances reports whether b is the balancer of targets: the same targets in
// the same order. It reads only the members that never change, so it takes
// no lock.
func (b *ingressBalancer) balances(targets []api.IngressTarget) bool {
	if len(b.targets) != len(targets) {
		return false
	}
	for i := range targets {
		if b.targets[i].target != targets[i] {
			return false
		}
	}
	return true
}

// index returns the first target whose address is addr, or -1.
func (b *ingressBalancer) index(addr string) int {
	for i := range b.targets {
		if b.targets[i].addr == addr {
			return i
		}
	}
	return -1
}

// snapshot returns the record of the rule's last unit and the record of the
// last dial to each target, in the order of the targets.
func (b *ingressBalancer) snapshot() (unit dialRecord, targets []dialRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	targets = make([]dialRecord, len(b.targets))
	for i := range b.targets {
		targets[i] = b.targets[i].dial
	}
	return b.unit, targets
}

// changedTo reports whether a record of failed and reason differs from rec in
// its outcome or its reason. A record without a dial differs from every one.
func (rec dialRecord) changedTo(failed bool, reason string) bool {
	return rec.at.IsZero() || rec.failed != failed || rec.reason != reason
}
