package bridge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// IngressDialPolicy tells whether the node's compiled policy blocks a dial to
// target.
type IngressDialPolicy interface {
	// DialDenied reports whether the compiled policy blocks a dial of
	// protocol, tcp or udp, to target.
	DialDenied(protocol string, target netip.AddrPort) bool
}

// The reasons of a failed dial in an ingress status report, in the order they
// are checked: the first that applies names the dial.
const (
	// IngressDialReasonPolicyDenied: the node's compiled policy blocks the
	// dial, as the dial policy answers after the dial failed.
	IngressDialReasonPolicyDenied = "policy_denied"
	// IngressDialReasonTimeout: the dial did not complete within
	// bridge.ingress_dial_timeout.
	IngressDialReasonTimeout = "timeout"
	// IngressDialReasonRefused: the target's host answered that nothing
	// listens on the port.
	IngressDialReasonRefused = "refused"
	// IngressDialReasonUnreachable: no route reaches the target's host or
	// network.
	IngressDialReasonUnreachable = "unreachable"
	// IngressDialReasonOther: any other failure.
	IngressDialReasonOther = "other"
)

// dialRecord is the outcome of the last dial to one of a rule's targets, or
// of the rule's last unit. A zero at means no dial yet.
type dialRecord struct {
	failed bool
	reason string // one of the IngressDialReason* constants; empty unless failed
	at     time.Time
}

// SetDialPolicy sets the policy that names a failed dial policy_denied. It is
// called before Setup and never afterwards; without one, no dial reads
// policy_denied.
//
// The policy only names the reason of a dial that already failed: the bridge
// dials every target as before, and the kernel stays the only place that
// enforces.
func (m *IngressManager) SetDialPolicy(p IngressDialPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialPolicy = p
}

// dialTarget dials addr, a target of route, under the route's context within
// bridge.ingress_dial_timeout, through the test seam when one is set.
func (m *IngressManager) dialTarget(route *ingressRoute, addr string) (net.Conn, error) {
	if m.dial != nil {
		return m.dial(route.ctx, "tcp", addr)
	}
	dialer := net.Dialer{Timeout: m.dialTimeout}
	return dialer.DialContext(route.ctx, "tcp", addr)
}

// recordDial records the outcome of a dial to the target idx of route, err
// being the dial's error, on the route's balancer, and returns the reason of
// a failed dial and whether the record changed (see ingressBalancer.dialled).
// A changed record signals ReportChanged. It records nothing, so a failed
// dial takes no target out, and returns "" and false once the route's context
// is done: the rule changed or was removed, or the manager was torn down,
// which cancels the parent of every route's context, and err is
// context.Canceled or belongs to a route the rule no longer has. It does the
// same for an idx outside the route's targets, which index returns for an
// address the rule does not name. It never takes mu.
func (m *IngressManager) recordDial(route *ingressRoute, idx int, err error) (reason string, changed bool) {
	reason, changed = m.storeDial(route, idx, err)
	if changed {
		m.signalReport()
	}
	return reason, changed
}

// recordUnitFailed records that no target of route took a unit, reason being
// the reason recordDial gave the last target the unit dialled, and signals
// ReportChanged when the rule's unit changed its outcome or reason. It
// records nothing for an empty reason, which recordDial gives a dial it did
// not record, and once the route's context is done. It never takes mu.
func (m *IngressManager) recordUnitFailed(route *ingressRoute, reason string) {
	if m.storeUnitFailed(route, reason) {
		m.signalReport()
	}
}

// recordLastDial records err, a failed dial after which the unit has no
// target left to dial, as recordDial does, then the unit failed with the
// dial's reason, as recordUnitFailed does, and signals ReportChanged once,
// after both, when either changed. A reader the signal wakes reads how the
// unit ended, and no later signal of the same unit is left for it.
func (m *IngressManager) recordLastDial(route *ingressRoute, idx int, err error) (reason string, changed bool) {
	reason, changed = m.storeDial(route, idx, err)
	if m.storeUnitFailed(route, reason) || changed {
		m.signalReport()
	}
	return reason, changed
}

// storeDial is recordDial without the signal.
func (m *IngressManager) storeDial(route *ingressRoute, idx int, err error) (reason string, changed bool) {
	if route.ctx.Err() != nil || idx < 0 || idx >= len(route.lb.targets) {
		return "", false
	}
	if err != nil {
		// Named before the balancer's lock: the policy asks the kernel for a
		// route and the Enforcer for its rules.
		reason = m.dialReason(route.rule.Protocol, route.lb.targets[idx].addr, err)
	}
	// A route cancelled since the check records on its balancer, which the
	// rule's next route shares only when it names the same targets.
	return reason, route.lb.dialled(idx, err != nil, reason, m.now())
}

// storeUnitFailed is recordUnitFailed without the signal; it reports whether
// the unit changed.
func (m *IngressManager) storeUnitFailed(route *ingressRoute, reason string) bool {
	if reason == "" || route.ctx.Err() != nil {
		return false
	}
	return route.lb.unitFailed(reason, m.now())
}

// dialUnit returns a connection to a target of route for one unit, a client
// connection of a rule without conditions. It dials each target the route's
// balancer picks, within bridge.ingress_dial_timeout each, records the dial
// and logs a failed one, and returns the first connection; it stops without a
// further dial once the route's context is done. When no target takes the
// unit, the last dial also records the unit failed with its reason (see
// recordLastDial), and dialUnit returns that dial's error as an
// *ingressDialError.
func (m *IngressManager) dialUnit(route *ingressRoute) (net.Conn, error) {
	every := 1<<len(route.lb.targets) - 1 // tried, once the unit dialled every target
	var tried uint8
	var dialErr *ingressDialError
	for idx, ok := route.lb.pick(tried, m.now()); ok; idx, ok = route.lb.pick(tried, m.now()) {
		tried |= 1 << idx
		addr := route.lb.targets[idx].addr
		conn, err := m.dialTarget(route, addr)
		if err == nil {
			m.recordDial(route, idx, nil)
			return conn, nil
		}
		var reason string
		if int(tried) == every {
			reason, _ = m.recordLastDial(route, idx, err)
		} else {
			reason, _ = m.recordDial(route, idx, err)
		}
		m.logDialFailed(route, addr, reason, err)
		dialErr = &ingressDialError{reason: reason, err: err}
		if route.ctx.Err() != nil {
			break
		}
	}
	return nil, dialErr
}

// dialReason names a failed dial of protocol, tcp or udp, to target:
// policy_denied when the dial policy blocks it, and otherwise what
// classifyDialError makes of err.
func (m *IngressManager) dialReason(protocol, target string, err error) string {
	if m.dialPolicy != nil {
		if addr, perr := netip.ParseAddrPort(target); perr == nil && m.dialPolicy.DialDenied(protocol, addr) {
			return IngressDialReasonPolicyDenied
		}
	}
	return classifyDialError(err)
}

// classifyDialError names a dial error, the first that applies: timeout for a
// deadline, a net.Error that timed out or an errno of dialErrnoTimeout;
// refused for an errno of dialErrnoRefused; unreachable for an errno of
// dialErrnoUnreachable; other otherwise.
func classifyDialError(err error) string {
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout(),
		isAnyErrno(err, dialErrnoTimeout):
		return IngressDialReasonTimeout
	case isAnyErrno(err, dialErrnoRefused):
		return IngressDialReasonRefused
	case isAnyErrno(err, dialErrnoUnreachable):
		return IngressDialReasonUnreachable
	default:
		return IngressDialReasonOther
	}
}

// isAnyErrno reports whether err is one of errnos.
func isAnyErrno(err error, errnos []error) bool {
	for _, errno := range errnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}
