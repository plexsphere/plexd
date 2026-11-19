package bridge

import (
	"container/list"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// The lifetime and the limits of the flows of a udp rule.
const (
	// ingressUDPUnansweredTimeout closes a flow the target never answered
	// after this long without a datagram in either direction, as Linux
	// conntrack's nf_conntrack_udp_timeout does.
	ingressUDPUnansweredTimeout = 30 * time.Second
	// ingressUDPAnsweredTimeout closes a flow the target answered after this
	// long without a datagram in either direction: conntrack's
	// nf_conntrack_udp_timeout_stream, and the floor RFC 4787 REQ-5 sets for
	// a NAT mapping.
	ingressUDPAnsweredTimeout = 120 * time.Second
	// ingressUDPBufSize is the read buffer of a udp rule's socket and of each
	// of its flows, the largest UDP payload.
	ingressUDPBufSize = 65535
	// ingressUDPFullWarnInterval bounds the Warn of a full flow table to one
	// line per socket and interval.
	ingressUDPFullWarnInterval = time.Minute
)

// The reasons a udp flow is closed.
const (
	udpFlowReasonIdle           = "idle"
	udpFlowReasonEvicted        = "evicted"
	udpFlowReasonRouteCancelled = "route_cancelled"
	udpFlowReasonReadFailed     = "read_failed"
	udpFlowReasonListenerClosed = "listener_closed"
)

// udpFlowConn is the part of *net.UDPConn a flow uses; a test injects one.
type udpFlowConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// udpIngressListener is the one UDP socket of a udp rule's listen port, the
// route its datagrams go by, and the flows of its clients.
type udpIngressListener struct {
	port  int
	conn  *net.UDPConn
	route atomic.Pointer[ingressRoute]
	done  chan struct{} // closed when the read loop and every flow loop ended

	// epoch is when the listener was made, with its monotonic reading. The
	// lastActive of each flow counts from it.
	epoch time.Time

	// replies counts the reply loops of the flows. Only the read loop adds
	// to it and waits for it.
	replies sync.WaitGroup

	// mu guards flows, order, evicted and warnedAt, and the elem, closed and
	// reason of each flow.
	mu       sync.Mutex
	flows    map[netip.AddrPort]*udpFlow // the open flows, by client address
	order    *list.List                  // the open flows, the most recently active first
	evicted  int                         // the flows evicted since the last Warn
	warnedAt time.Time                   // when the last Warn was logged
}

// udpFlow carries the datagrams of one client address and port: it owns one
// socket toward the target, so the target tells the clients of a rule apart
// by the bridge's source port, and its replies return to the client the flow
// belongs to.
type udpFlow struct {
	client netip.AddrPort
	route  *ingressRoute
	target netip.AddrPort // the rule's first target, unmapped
	conn   udpFlowConn

	// lastActive is the time of the last datagram in either direction, in
	// nanoseconds since the listener's epoch. The reply loop's deadline is
	// the epoch plus lastActive plus the timeout, which keeps the epoch's
	// monotonic reading, so a step of the wall clock does not move it.
	// answered is set by the first datagram of the target.
	lastActive atomic.Int64
	answered   atomic.Bool

	// sent and failed are the outcome of the last send, which only the read
	// loop touches.
	sent, failed bool

	// stop unregisters the flow's context.AfterFunc. It is set before the
	// flow can be closed.
	stop func() bool

	// Guarded by the listener's mu.
	elem   *list.Element // the flow in order; nil once closed
	closed bool
	reason string // why the flow was closed
}

// newUDPIngressListener returns the listener of port on conn without a route
// or a flow.
func newUDPIngressListener(port int, conn *net.UDPConn) *udpIngressListener {
	return &udpIngressListener{
		port:  port,
		conn:  conn,
		done:  make(chan struct{}),
		epoch: time.Now(),
		flows: make(map[netip.AddrPort]*udpFlow),
		order: list.New(),
	}
}

// closeUDPListener closes l's socket, which ends its read loop and then every
// flow.
func closeUDPListener(l *udpIngressListener) {
	// A close error leaves nothing to undo: the read loop ends on the next
	// read either way.
	_ = l.conn.Close()
}

// serveUDP reads the datagrams of l's socket into one buffer until the socket
// is closed and forwards each, zero-length ones included, on the flow of its
// unmapped source. A read error other than net.ErrClosed is logged at Debug
// and the loop continues. Once the socket is closed it closes every flow,
// waits for their reply loops, and closes l.done.
func (m *IngressManager) serveUDP(l *udpIngressListener) {
	defer close(l.done)

	buf := make([]byte, ingressUDPBufSize)
	for {
		n, src, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			m.logger.Debug("ingress udp read failed", "component", "bridge", "listen_port", l.port, "error", err)
			continue
		}
		m.forwardUDP(l, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), buf[:n])
	}

	l.mu.Lock()
	open := make([]*udpFlow, 0, l.order.Len())
	for e := l.order.Front(); e != nil; e = e.Next() {
		open = append(open, e.Value.(*udpFlow))
	}
	for _, f := range open {
		l.detachLocked(f, udpFlowReasonListenerClosed)
	}
	l.mu.Unlock()
	for _, f := range open {
		_ = f.conn.Close()
	}
	l.replies.Wait()
}

// forwardUDP sends b, a datagram of the client src, to the target on src's
// flow, and opens the flow first when src has none. A failed send drops the
// datagram and leaves the flow open.
//
// The flow's first send, and every later send that ends differently from the
// one before it, is a dial of the rule's first target: recordDial records it,
// a failed one also fails the rule's unit, and a failed one that changed the
// target's record logs "bridge: ingress: dial target failed". Every
// other failed send logs "ingress datagram not forwarded" at Debug, so a
// client that keeps sending into a blocked rule writes one Error line, not one
// per datagram. A send that fails with net.ErrClosed is no dial: the flow was
// closed between the lookup and the send, by a cancelled route or a failed
// read, and the target was never asked.
func (m *IngressManager) forwardUDP(l *udpIngressListener, src netip.AddrPort, b []byte) {
	now := time.Now()
	f, stale := l.lookup(src, now)
	if stale != nil {
		_ = stale.conn.Close()
	}
	if f == nil {
		if f = m.openUDPFlow(l, src, now); f == nil {
			return
		}
	}

	_, err := f.conn.WriteToUDPAddrPort(b, f.target)
	if errors.Is(err, net.ErrClosed) {
		m.logDatagramNotForwarded(l, src, err)
		return
	}
	var reason string
	var changed bool
	if !f.sent || f.failed != (err != nil) {
		f.sent, f.failed = true, err != nil
		if err != nil {
			reason, changed = m.recordLastDial(f.route, 0, err)
		} else {
			reason, changed = m.recordDial(f.route, 0, nil)
		}
	}
	if err != nil {
		m.logSendFailed(l, f.route, src, err, reason, changed)
	}
}

// lookup returns the open flow of src, moved to the front of order with
// lastActive set to now, or nil when src has none. Set under mu, lastActive
// keeps the reply loop from closing the flow as idle before the caller's send.
// A flow whose route is cancelled counts as absent: the rule changed or was
// removed. It is detached with the reason route_cancelled and returned as
// stale, for the caller to close its socket.
func (l *udpIngressListener) lookup(src netip.AddrPort, now time.Time) (f, stale *udpFlow) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f = l.flows[src]
	if f == nil {
		return nil, nil
	}
	if f.route.ctx.Err() != nil {
		l.detachLocked(f, udpFlowReasonRouteCancelled)
		return nil, f
	}
	l.order.MoveToFront(f.elem)
	f.lastActive.Store(int64(now.Sub(l.epoch)))
	return f, nil
}

// openUDPFlow opens the flow of src to the first target of the route l holds
// now, registers its close for when the route is cancelled, and starts its
// reply loop. At maxUDPFlows it first closes the least recently active flow.
// It returns nil, and the datagram is dropped, when the route is cancelled,
// which Apply does before it stores the next one, or when the flow's socket
// does not open; a socket that does not open is recorded as a failed dial of
// that target and fails the rule's unit.
func (m *IngressManager) openUDPFlow(l *udpIngressListener, src netip.AddrPort, now time.Time) *udpFlow {
	route := l.route.Load()
	if route.ctx.Err() != nil {
		return nil
	}
	m.evictUDPFlow(l, route, now)

	open := m.openUDP
	if open == nil {
		open = openUDPFlowConn
	}
	target, err := netip.ParseAddrPort(route.lb.targets[0].addr)
	var conn udpFlowConn
	if err == nil {
		target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
		conn, err = open(target)
	}
	if err != nil {
		reason, changed := m.recordLastDial(route, 0, err)
		m.logSendFailed(l, route, src, err, reason, changed)
		return nil
	}

	f := &udpFlow{client: src, route: route, target: target, conn: conn}
	f.lastActive.Store(int64(now.Sub(l.epoch)))
	m.connCount.Add(1)
	l.replies.Add(1)
	l.mu.Lock()
	f.elem = l.order.PushFront(f)
	l.flows[src] = f
	// Registered under mu, so the callback, which takes mu, finds the flow
	// in flows and order.
	f.stop = context.AfterFunc(route.ctx, func() { l.closeFlow(f, udpFlowReasonRouteCancelled) })
	l.mu.Unlock()

	// Logged before the reply loop starts, which logs the flow's close.
	m.logger.Debug("ingress udp flow opened",
		"component", "bridge",
		"rule_id", route.rule.ID,
		"listen_port", l.port,
		"remote", src.String(),
	)
	go m.udpReplyLoop(l, f)
	return f
}

// evictUDPFlow closes the flow at the back of order with the reason evicted
// when l holds maxUDPFlows flows, and counts it. The Warn that the table is
// full is logged at most once per ingressUDPFullWarnInterval, with the flows
// evicted since the last one.
func (m *IngressManager) evictUDPFlow(l *udpIngressListener, route *ingressRoute, now time.Time) {
	l.mu.Lock()
	if l.order.Len() == 0 || l.order.Len() < m.maxUDPFlows {
		l.mu.Unlock()
		return
	}
	victim := l.order.Back().Value.(*udpFlow)
	l.detachLocked(victim, udpFlowReasonEvicted)
	l.evicted++
	evicted := l.evicted
	warn := l.warnedAt.IsZero() || now.Sub(l.warnedAt) >= ingressUDPFullWarnInterval
	if warn {
		l.warnedAt, l.evicted = now, 0
	}
	l.mu.Unlock()

	_ = victim.conn.Close()
	if warn {
		m.logger.Warn("ingress udp flow table full, closing the least recently active flow",
			"component", "bridge",
			"rule_id", route.rule.ID,
			"slug", route.rule.Slug,
			"listen_port", l.port,
			"max_flows", m.maxUDPFlows,
			"evicted", evicted,
		)
	}
}

// udpReplyLoop writes the target's datagrams on f to its client until f is
// closed, and then finishes the flow (see endUDPFlow).
//
// It reads with a deadline of lastActive plus the flow's timeout,
// udpAnsweredTimeout once the target answered and udpUnansweredTimeout
// before. When the deadline passes and no datagram in either direction moved
// lastActive since the loop read it, the timeout has passed since lastActive
// and the flow is closed with the reason idle; otherwise the loop reads on. A
// datagram whose unmapped source is not the target is dropped and changes
// nothing. A failed write to the client is logged at Debug and leaves the flow
// open. net.ErrClosed ends the loop, and any other read error closes the flow
// with the reason read_failed, so no error can spin the loop.
func (m *IngressManager) udpReplyLoop(l *udpIngressListener, f *udpFlow) {
	defer m.endUDPFlow(l, f)

	buf := make([]byte, ingressUDPBufSize)
	for {
		at := f.lastActive.Load()
		timeout := m.udpUnansweredTimeout
		if f.answered.Load() {
			timeout = m.udpAnsweredTimeout
		}
		var n int
		var src netip.AddrPort
		err := f.conn.SetReadDeadline(l.epoch.Add(time.Duration(at) + timeout))
		if err == nil {
			n, src, err = f.conn.ReadFromUDPAddrPort(buf)
		}
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded):
			if l.closeIdle(f, at) {
				return
			}
			continue
		case errors.Is(err, net.ErrClosed):
			return
		default:
			l.closeFlow(f, udpFlowReasonReadFailed)
			return
		}

		if netip.AddrPortFrom(src.Addr().Unmap(), src.Port()) != f.target {
			continue
		}
		f.answered.Store(true)
		f.lastActive.Store(int64(time.Since(l.epoch)))
		if _, err := l.conn.WriteToUDPAddrPort(buf[:n], f.client); err != nil {
			m.logger.Debug("ingress udp reply not forwarded",
				"component", "bridge",
				"listen_port", l.port,
				"remote", f.client.String(),
				"error", err,
			)
		}
	}
}

// endUDPFlow finishes f once its reply loop ended, which happens exactly once
// and only after f was closed: it stops the flow's AfterFunc, subtracts it
// from connCount, logs the reason it was closed for, and releases the read
// loop's wait. The line is Debug, as "ingress connection closed" is: a public
// port draws scanners.
func (m *IngressManager) endUDPFlow(l *udpIngressListener, f *udpFlow) {
	f.stop()
	l.mu.Lock()
	reason := f.reason
	l.mu.Unlock()
	m.connCount.Add(-1)
	m.logger.Debug("ingress udp flow closed",
		"component", "bridge",
		"listen_port", l.port,
		"remote", f.client.String(),
		"reason", reason,
	)
	l.replies.Done()
}

// detachLocked marks f closed for reason and removes it from flows and order.
// It reports false, and changes nothing, when f was closed already, so a flow
// is closed once. On true the caller closes f's socket, which ends its reply
// loop. The caller holds l.mu.
func (l *udpIngressListener) detachLocked(f *udpFlow, reason string) bool {
	if f.closed {
		return false
	}
	f.closed, f.reason = true, reason
	delete(l.flows, f.client)
	l.order.Remove(f.elem)
	f.elem = nil
	return true
}

// closeFlow closes f for reason unless it was closed already.
func (l *udpIngressListener) closeFlow(f *udpFlow, reason string) {
	l.mu.Lock()
	detached := l.detachLocked(f, reason)
	l.mu.Unlock()
	if detached {
		_ = f.conn.Close()
	}
}

// closeIdle reports whether the reply loop of f ends at an expired deadline:
// when f was closed already, or when lastActive is still at, the value the
// loop based the deadline on, and closeIdle closed f with the reason idle. It
// decides under mu, where the read loop refreshes lastActive of a flow it
// found, so a flow the read loop is about to send on is never closed as idle.
func (l *udpIngressListener) closeIdle(f *udpFlow, at int64) bool {
	l.mu.Lock()
	if f.closed {
		l.mu.Unlock()
		return true
	}
	idle := f.lastActive.Load() == at
	if idle {
		l.detachLocked(f, udpFlowReasonIdle)
	}
	l.mu.Unlock()
	if idle {
		_ = f.conn.Close()
	}
	return idle
}

// logSendFailed logs err, a send to route's first target for the client src
// that failed or a flow socket that did not open, as recordDial left it: at
// Error when it changed the target's dial record, and otherwise at Debug.
func (m *IngressManager) logSendFailed(l *udpIngressListener, route *ingressRoute, src netip.AddrPort, err error, reason string, changed bool) {
	if !changed {
		m.logDatagramNotForwarded(l, src, err)
		return
	}
	m.logger.Error("bridge: ingress: dial target failed",
		"component", "bridge",
		"rule_id", route.rule.ID,
		"slug", route.rule.Slug,
		"protocol", route.rule.Protocol,
		"target", route.lb.targets[0].addr,
		"reason", reason,
		"error", err,
	)
}

// logDatagramNotForwarded logs a datagram of src that did not reach the
// target.
func (m *IngressManager) logDatagramNotForwarded(l *udpIngressListener, src netip.AddrPort, err error) {
	m.logger.Debug("ingress datagram not forwarded",
		"component", "bridge",
		"listen_port", l.port,
		"remote", src.String(),
		"error", err,
	)
}

// openUDPFlowConn opens the socket of a flow to target. The socket is
// unconnected, so a send reports only what the send itself fails with and not
// an ICMP error a datagram before it caused. It is bound to the source
// address the kernel's route to target selects, so it is not reachable
// through the bridge's public addresses: a probe socket connected to target,
// which sends nothing, picks the address and is closed.
func openUDPFlowConn(target netip.AddrPort) (udpFlowConn, error) {
	probe, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return nil, err
	}
	local := probe.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = probe.Close()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local.Addr().Unmap(), 0)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
