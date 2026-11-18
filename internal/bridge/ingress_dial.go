package bridge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/plexsphere/plexd/internal/api"
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

// dialRecord is the outcome of the last dial a client connection caused to a
// rule's target.
type dialRecord struct {
	target string // the route's target at the dial
	failed bool
	reason string // one of the IngressDialReason* constants; empty unless failed
	at     time.Time
}

// ingressTarget returns the address the bridge dials for a rule.
func ingressTarget(r api.IngressRule) string {
	return net.JoinHostPort(r.TargetAddress, strconv.Itoa(r.TargetPort))
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

// dialTarget dials route's target under the route's context, through the test
// seam when one is set.
func (m *IngressManager) dialTarget(route *ingressRoute) (net.Conn, error) {
	if m.dial != nil {
		return m.dial(route.ctx, "tcp", route.target)
	}
	dialer := net.Dialer{Timeout: m.dialTimeout}
	return dialer.DialContext(route.ctx, "tcp", route.target)
}

// recordDial records the outcome of a dial to route's target, err being the
// dial's error, and returns the reason of a failed dial and whether the record
// changed: it is new, or its target, outcome or reason differs from the one
// before. A changed record signals ReportChanged. It records nothing and
// returns "" and false once the route's context is done: the rule changed or
// was removed, or the manager was torn down, and err is context.Canceled or
// belongs to a target the rule no longer names.
func (m *IngressManager) recordDial(route *ingressRoute, err error) (reason string, changed bool) {
	if route.ctx.Err() != nil {
		return "", false
	}
	rec := dialRecord{target: route.target}
	if err != nil {
		// Named outside mu: the policy asks the kernel for a route and the
		// Enforcer for its rules.
		rec.failed, rec.reason = true, m.dialReason(route.rule.Protocol, route.target, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Apply, renewRoutesLocked and Teardown cancel a route under mu, so a
	// route that is live here is still the rule's.
	if route.ctx.Err() != nil || !m.active {
		return "", false
	}
	rec.at = m.now()
	old, ok := m.dials[route.rule.ID]
	m.dials[route.rule.ID] = rec
	changed = !ok || old.target != rec.target || old.failed != rec.failed || old.reason != rec.reason
	if changed {
		m.signalReport()
	}
	return rec.reason, changed
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
