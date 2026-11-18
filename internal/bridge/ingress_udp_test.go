package bridge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// udpIngressRule returns a udp rule to 127.0.0.1 on targetPort.
func udpIngressRule(slug string, port, targetPort int) api.IngressRule {
	r := ingressRule(slug, port, "", targetPort)
	r.Protocol = api.IngressProtocolUDP
	return r
}

// udpDatagram is one datagram a udpBackend received.
type udpDatagram struct {
	payload []byte
	from    netip.AddrPort
}

// udpBackend is a UDP socket on 127.0.0.1 the tests route to. It records
// every datagram it receives and, unless it is silent, echoes each.
type udpBackend struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  []udpDatagram
}

// startUDPBackend binds a backend on 127.0.0.1:0 that echoes when echo is set,
// until the test ends.
func startUDPBackend(t *testing.T, echo bool) *udpBackend {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	b := &udpBackend{conn: conn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, ingressUDPBufSize)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				continue
			}
			b.mu.Lock()
			b.got = append(b.got, udpDatagram{payload: bytes.Clone(buf[:n]), from: from})
			b.mu.Unlock()
			if echo {
				_, _ = conn.WriteToUDPAddrPort(buf[:n], from)
			}
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return b
}

func (b *udpBackend) port() int {
	return int(b.conn.LocalAddr().(*net.UDPAddr).AddrPort().Port())
}

// received waits up to 2 s for the backend to hold n datagrams and returns
// every datagram it holds.
func (b *udpBackend) received(t *testing.T, n int) []udpDatagram {
	t.Helper()
	var got []udpDatagram
	waitForCondition(t, 2*time.Second, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		got = slices.Clone(b.got)
		return len(got) >= n
	})
	return got
}

// udpClient returns a UDP socket connected to addr that is closed when the
// test ends.
func udpClient(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// clientAddr returns the address a client sends from.
func clientAddr(c *net.UDPConn) netip.AddrPort {
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// sendUDP writes msg on c.
func sendUDP(t *testing.T, c *net.UDPConn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("send %q: %v", msg, err)
	}
}

// requireUDPEcho sends msg on c and reads it back within 2 s.
func requireUDPEcho(t *testing.T, c *net.UDPConn, msg string) {
	t.Helper()
	sendUDP(t, c, msg)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, ingressUDPBufSize)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read echo of %q: %v", msg, err)
	}
	if got := string(buf[:n]); got != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// requireNoDatagram fails when a datagram arrives on c within d.
func requireNoDatagram(t *testing.T, c *net.UDPConn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, ingressUDPBufSize)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("read %q, want no datagram", buf[:n])
	}
}

// waitForLogLine waits up to 2 s for a log line that carries every needle.
func waitForLogLine(t *testing.T, logs *relayLog, needles ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for logLines(logs, needles...) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no log line with %q within 2s:\n%s", needles, logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// flowClosed returns the needles of the "ingress udp flow closed" line of
// client.
func flowClosed(client netip.AddrPort) []string {
	return []string{`msg="ingress udp flow closed"`, "remote=" + client.String()}
}

// udpFlows returns the clients of the open flows of port, the most recently
// active first.
func udpFlows(mgr *IngressManager, port int) []netip.AddrPort {
	mgr.mu.Lock()
	l := mgr.udp[port]
	mgr.mu.Unlock()
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []netip.AddrPort
	for e := l.order.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value.(*udpFlow).client)
	}
	return out
}

// udpFlowOf returns the open flow of client on port, or nil.
func udpFlowOf(mgr *IngressManager, port int, client netip.AddrPort) *udpFlow {
	mgr.mu.Lock()
	l := mgr.udp[port]
	mgr.mu.Unlock()
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flows[client]
}

// connectionCount returns IngressStatus().ConnectionCount.
func connectionCount(t *testing.T, mgr *IngressManager) int {
	t.Helper()
	s := mgr.IngressStatus()
	if s == nil {
		t.Fatal("IngressStatus = nil, want the status of an active manager")
	}
	return s.ConnectionCount
}

// newUDPFixture returns a set-up manager on a loopback controller.
func newUDPFixture(t *testing.T) (*ingressFixture, *loopbackIngressController) {
	t.Helper()
	ctrl := newLoopbackIngressController(t)
	return newIngressFixture(t, ctrl), ctrl
}

// ---------------------------------------------------------------------------
// Sockets and Apply
// ---------------------------------------------------------------------------

func TestIngressUDP_TCPAndUDPShareAPortNumber(t *testing.T) {
	fx, ctrl := newUDPFixture(t)
	block := rulesBlock(ingressRule("ssh", 7022, "", 9022), udpIngressRule("game", 7022, 9053))

	for _, step := range []string{"first Apply", "second Apply of the same block"} {
		if err := fx.mgr.Apply(t.Context(), block); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		listens := ctrl.ingressCallsFor("Listen")
		if len(listens) != 1 || listens[0].Args[0] != ":7022" || listens[0].Args[1].(*tls.Config) != nil {
			t.Errorf("%s: Listen calls = %+v, want one Listen(\":7022\", nil)", step, listens)
		}
		if got := ctrl.listenUDPAddrs(); !slices.Equal(got, []string{":7022"}) {
			t.Errorf("%s: ListenUDP addresses = %v, want [:7022]", step, got)
		}
		for _, slug := range []string{"ssh", "game"} {
			if st := stateOf(t, fx.mgr, slug); !st.Served || st.Reason != "" {
				t.Errorf("%s: rule %s = %+v, want served", step, slug, st)
			}
		}
	}
	if ctrl.addr(7022) == "" || ctrl.udpAddr(7022) == "" {
		t.Errorf("addresses of 7022: tcp %q, udp %q, want both bound", ctrl.addr(7022), ctrl.udpAddr(7022))
	}
}

func TestIngressUDP_ListenFailureIsRetried(t *testing.T) {
	fx, ctrl := newUDPFixture(t)
	ctrl.failListenUDP(7053, syscall.EADDRINUSE)
	block := rulesBlock(udpIngressRule("dns", 7053, 9053), ingressRule("dns-tcp", 7053, "", 9053))

	err := fx.mgr.Apply(t.Context(), block)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want an error that wraps EADDRINUSE", err)
	}
	if !strings.Contains(err.Error(), "bridge: ingress: listen on udp :7053: ") {
		t.Errorf("Apply = %q, want it to contain %q", err, "bridge: ingress: listen on udp :7053: ")
	}
	if st := stateOf(t, fx.mgr, "dns"); st.Served || st.Reason != IngressReasonListenFailed {
		t.Errorf("udp rule = %+v, want %q", st, IngressReasonListenFailed)
	}
	if st := stateOf(t, fx.mgr, "dns-tcp"); !st.Served || st.Reason != "" {
		t.Errorf("tcp rule on 7053 = %+v, want served", st)
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: listen failed"`, "listen_port=7053", "protocol=udp"); got != 1 {
		t.Errorf("%d 'listen failed' lines with protocol=udp for 7053, want 1:\n%s", got, fx.logs.String())
	}

	ctrl.failListenUDP(7053, nil)
	if err := fx.mgr.Apply(t.Context(), block); err != nil {
		t.Fatalf("Apply after the failure was lifted: %v", err)
	}
	if got := ctrl.listenUDPAddrs(); !slices.Equal(got, []string{":7053", ":7053"}) {
		t.Errorf("ListenUDP addresses = %v, want a second call for :7053", got)
	}
	for _, slug := range []string{"dns", "dns-tcp"} {
		if st := stateOf(t, fx.mgr, slug); !st.Served || st.Reason != "" {
			t.Errorf("rule %s = %+v, want served", slug, st)
		}
	}
	if got := len(ctrl.ingressCallsFor("Listen")); got != 1 {
		t.Errorf("Listen calls = %d, want 1: the TCP port stayed bound", got)
	}
}

func TestIngressUDP_ListenPermissionHint(t *testing.T) {
	fx, ctrl := newUDPFixture(t)
	ctrl.failListenUDP(53, &net.OpError{Op: "listen", Net: "udp", Err: fs.ErrPermission})

	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("dns", 53, 9053))); err == nil {
		t.Fatal("Apply = nil, want the listen error")
	}
	if got := logLines(fx.logs, `msg="bridge: ingress: listen failed"`, "listen_port=53 ", "protocol=udp",
		`hint="ports below 1024 need CAP_NET_BIND_SERVICE"`); got != 1 {
		t.Errorf("%d 'listen failed' lines with protocol=udp and the hint, want 1:\n%s", got, fx.logs.String())
	}
}

func TestIngressUDP_RemovedRuleClosesSocketAndFlows(t *testing.T) {
	backend := startUDPBackend(t, true)

	t.Run("removed rule", func(t *testing.T) {
		fx, ctrl := newUDPFixture(t)
		rule := udpIngressRule("dns", 7053, backend.port())
		keep := ingressRule("ssh", 7022, "", 9022)
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule, keep)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		client := udpClient(t, ctrl.udpAddr(7053))
		requireUDPEcho(t, client, "before")
		if got := connectionCount(t, fx.mgr); got != 1 {
			t.Fatalf("ConnectionCount with one flow = %d, want 1", got)
		}

		if err := fx.mgr.Apply(t.Context(), rulesBlock(keep)); err != nil {
			t.Fatalf("Apply without the rule: %v", err)
		}
		sendUDP(t, client, "after")
		requireNoDatagram(t, client, 100*time.Millisecond)
		if got := connectionCount(t, fx.mgr); got != 0 {
			t.Errorf("ConnectionCount after the rule was removed = %d, want 0", got)
		}
		if got := logLines(fx.logs, `msg="ingress listener closed"`, "listen_port=7053", "protocol=udp"); got != 1 {
			t.Errorf("%d 'ingress listener closed' lines with protocol=udp for 7053, want 1:\n%s", got, fx.logs.String())
		}
		if got := logLines(fx.logs, flowClosed(clientAddr(client))...); got != 1 {
			t.Errorf("%d 'ingress udp flow closed' lines for the client, want 1:\n%s", got, fx.logs.String())
		}
		if got := logLines(fx.logs, `msg="ingress listener closed"`, "listen_port=7022"); got != 0 {
			t.Errorf("%d 'ingress listener closed' lines for the kept tcp rule, want 0:\n%s", got, fx.logs.String())
		}
	})

	t.Run("zero block", func(t *testing.T) {
		fx, ctrl := newUDPFixture(t)
		if err := fx.mgr.Apply(t.Context(), rulesBlock(
			udpIngressRule("dns", 7053, backend.port()),
			udpIngressRule("game", 7054, backend.port()),
		)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		var clients []*net.UDPConn
		for _, port := range []int{7053, 7054} {
			c := udpClient(t, ctrl.udpAddr(port))
			requireUDPEcho(t, c, "before")
			clients = append(clients, c)
		}

		if err := fx.mgr.Apply(t.Context(), api.IngressConfig{}); err != nil {
			t.Fatalf("Apply of the zero block: %v", err)
		}
		for i, port := range []string{"7053", "7054"} {
			if got := logLines(fx.logs, `msg="ingress listener closed"`, "listen_port="+port, "protocol=udp"); got != 1 {
				t.Errorf("%d 'ingress listener closed' lines with protocol=udp for %s, want 1:\n%s", got, port, fx.logs.String())
			}
			sendUDP(t, clients[i], "after")
			requireNoDatagram(t, clients[i], 100*time.Millisecond)
		}
		fx.mgr.mu.Lock()
		open := len(fx.mgr.udp)
		fx.mgr.mu.Unlock()
		if open != 0 {
			t.Errorf("%d UDP sockets after the zero block, want none", open)
		}
		if got := connectionCount(t, fx.mgr); got != 0 {
			t.Errorf("ConnectionCount after the zero block = %d, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

func TestIngressUDP_ForwardsBothWays(t *testing.T) {
	backend := startUDPBackend(t, true)
	fx, ctrl := newUDPFixture(t)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("echo", 7053, backend.port()))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	a := udpClient(t, ctrl.udpAddr(7053))
	b := udpClient(t, ctrl.udpAddr(7053))
	requireUDPEcho(t, a, "from a")
	requireUDPEcho(t, b, "from b")

	got := backend.received(t, 2)
	if len(got) != 2 || string(got[0].payload) != "from a" || string(got[1].payload) != "from b" {
		t.Fatalf("backend received %+v, want the payloads of a and b", got)
	}
	if got[0].from.Port() == got[1].from.Port() {
		t.Errorf("the backend saw both clients from port %d, want two source ports", got[0].from.Port())
	}
	if got := connectionCount(t, fx.mgr); got != 2 {
		t.Errorf("ConnectionCount = %d, want 2", got)
	}
}

func TestIngressUDP_EmptyDatagram(t *testing.T) {
	backend := startUDPBackend(t, false)
	fx, ctrl := newUDPFixture(t)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("echo", 7053, backend.port()))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	client := udpClient(t, ctrl.udpAddr(7053))
	sendUDP(t, client, "")
	got := backend.received(t, 1)
	if len(got) != 1 || len(got[0].payload) != 0 {
		t.Fatalf("backend received %+v, want one zero-length datagram", got)
	}
	if flows := udpFlows(fx.mgr, 7053); !slices.Equal(flows, []netip.AddrPort{clientAddr(client)}) {
		t.Errorf("flows = %v, want the client's", flows)
	}
	if got := connectionCount(t, fx.mgr); got != 1 {
		t.Errorf("ConnectionCount = %d, want 1", got)
	}
	if got := logLines(fx.logs, "level=DEBUG", `msg="ingress udp flow opened"`, "rule_id=id-echo", "listen_port=7053", "remote="+clientAddr(client).String()); got != 1 {
		t.Errorf("%d 'ingress udp flow opened' lines, want 1:\n%s", got, fx.logs.String())
	}
}

func TestIngressUDP_UnchangedRuleKeepsFlows(t *testing.T) {
	backend := startUDPBackend(t, true)
	fx, ctrl := newUDPFixture(t)
	block := rulesBlock(udpIngressRule("echo", 7053, backend.port()))
	if err := fx.mgr.Apply(t.Context(), block); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	client := udpClient(t, ctrl.udpAddr(7053))
	requireUDPEcho(t, client, "one")

	if err := fx.mgr.Apply(t.Context(), block); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	requireUDPEcho(t, client, "two")

	got := backend.received(t, 2)
	if got[0].from != got[1].from {
		t.Errorf("the backend saw the client from %v and then %v, want one source port", got[0].from, got[1].from)
	}
	if got := logLines(fx.logs, `msg="ingress udp flow closed"`); got != 0 {
		t.Errorf("%d 'ingress udp flow closed' lines, want 0:\n%s", got, fx.logs.String())
	}
}

func TestIngressUDP_ChangedTargetOpensNewFlows(t *testing.T) {
	old := startUDPBackend(t, true)
	next := startUDPBackend(t, true)
	fx, ctrl := newUDPFixture(t)
	rule := udpIngressRule("echo", 7053, old.port())
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	client := udpClient(t, ctrl.udpAddr(7053))
	requireUDPEcho(t, client, "one")

	rule.TargetPort = next.port()
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply with another target_port: %v", err)
	}
	requireUDPEcho(t, client, "two")

	if got := next.received(t, 1); len(got) != 1 || string(got[0].payload) != "two" {
		t.Errorf("new backend received %+v, want the client's next datagram", got)
	}
	if got := old.received(t, 1); len(got) != 1 {
		t.Errorf("old backend received %+v, want only the first datagram", got)
	}
	waitForLogLine(t, fx.logs, append(flowClosed(clientAddr(client)), "reason=route_cancelled")...)
	if got := logLines(fx.logs, `msg="ingress udp flow closed"`); got != 1 {
		t.Errorf("%d 'ingress udp flow closed' lines, want only the old flow's:\n%s", got, fx.logs.String())
	}
}

func TestIngressUDP_IdleFlowIsClosed(t *testing.T) {
	backend := startUDPBackend(t, false)
	fx, ctrl := newUDPFixture(t)
	fx.mgr.udpUnansweredTimeout = 50 * time.Millisecond
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("quiet", 7053, backend.port()))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	client := udpClient(t, ctrl.udpAddr(7053))
	sendUDP(t, client, "one")
	first := backend.received(t, 1)[0].from

	waitForLogLine(t, fx.logs, append(flowClosed(clientAddr(client)), "reason=idle")...)
	if got := connectionCount(t, fx.mgr); got != 0 {
		t.Errorf("ConnectionCount after the idle close = %d, want 0", got)
	}

	// Hold the closed flow's port, so the kernel cannot hand it to the next
	// flow by chance.
	if hold, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(first)); err == nil {
		t.Cleanup(func() { _ = hold.Close() })
	}
	sendUDP(t, client, "two")
	if second := backend.received(t, 2)[1].from; second.Port() == first.Port() {
		t.Errorf("the client's next datagram arrived from port %d again, want a new flow", second.Port())
	}
}

func TestIngressUDP_AnsweredFlowLivesLonger(t *testing.T) {
	backend := startUDPBackend(t, true)
	fx, ctrl := newUDPFixture(t)
	fx.mgr.udpUnansweredTimeout = 50 * time.Millisecond
	fx.mgr.udpAnsweredTimeout = 500 * time.Millisecond
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("echo", 7053, backend.port()))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	client := udpClient(t, ctrl.udpAddr(7053))
	closed := flowClosed(clientAddr(client))

	start := time.Now()
	requireUDPEcho(t, client, "one")
	time.Sleep(150 * time.Millisecond)
	if got := logLines(fx.logs, closed...); got != 0 || connectionCount(t, fx.mgr) != 1 {
		t.Fatalf("150ms after the reply: %d 'flow closed' lines and ConnectionCount %d, want the flow open:\n%s",
			got, connectionCount(t, fx.mgr), fx.logs.String())
	}

	waitForLogLine(t, fx.logs, append(closed, "reason=idle")...)
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("the answered flow closed %v after its last datagram, want 500ms or more", elapsed)
	}
}

func TestIngressUDP_FlowBoundEvictsLeastRecentlyActive(t *testing.T) {
	const warn = `msg="ingress udp flow table full, closing the least recently active flow"`
	backend := startUDPBackend(t, true)
	fx, ctrl := newUDPFixture(t)
	fx.mgr.maxUDPFlows = 2
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("echo", 7053, backend.port()))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	addr := ctrl.udpAddr(7053)
	a, b, c, d := udpClient(t, addr), udpClient(t, addr), udpClient(t, addr), udpClient(t, addr)

	requireUDPEcho(t, a, "a1")
	requireUDPEcho(t, b, "b1")
	requireUDPEcho(t, a, "a2")
	requireUDPEcho(t, c, "c1")

	waitForLogLine(t, fx.logs, append(flowClosed(clientAddr(b)), "reason=evicted")...)
	if got := udpFlows(fx.mgr, 7053); !slices.Equal(got, []netip.AddrPort{clientAddr(c), clientAddr(a)}) {
		t.Errorf("open flows = %v, want c's and a's", got)
	}
	for name, cl := range map[string]*net.UDPConn{"a": a, "c": c} {
		if got := logLines(fx.logs, flowClosed(clientAddr(cl))...); got != 0 {
			t.Errorf("%d 'flow closed' lines for %s, want 0:\n%s", got, name, fx.logs.String())
		}
	}
	if got := connectionCount(t, fx.mgr); got != 2 {
		t.Errorf("ConnectionCount = %d, want 2", got)
	}
	if got := logLines(fx.logs, "level=WARN", warn, "rule_id=id-echo", "slug=echo", "listen_port=7053", "max_flows=2", "evicted=1"); got != 1 {
		t.Errorf("%d table-full Warn lines, want 1:\n%s", got, fx.logs.String())
	}

	// A fourth client evicts a's flow within the interval.
	requireUDPEcho(t, d, "d1")
	waitForLogLine(t, fx.logs, append(flowClosed(clientAddr(a)), "reason=evicted")...)
	if got := logLines(fx.logs, warn); got != 1 {
		t.Errorf("%d table-full Warn lines after a second eviction, want still 1:\n%s", got, fx.logs.String())
	}
}

func TestIngressUDP_DropsDatagramsNotFromTheTarget(t *testing.T) {
	backend := startUDPBackend(t, false)
	fx, ctrl := newUDPFixture(t)
	// An answered flow would outlive the test; an unanswered one closes as
	// idle soon after the stray datagram.
	fx.mgr.udpUnansweredTimeout = 300 * time.Millisecond
	fx.mgr.udpAnsweredTimeout = time.Minute
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("quiet", 7053, backend.port()))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	client := udpClient(t, ctrl.udpAddr(7053))
	sendUDP(t, client, "hello")
	backend.received(t, 1)
	f := udpFlowOf(fx.mgr, 7053, clientAddr(client))
	if f == nil {
		t.Fatal("no flow for the client")
	}

	third := udpClient(t, f.conn.(*net.UDPConn).LocalAddr().String())
	sendUDP(t, third, "stray")

	waitForLogLine(t, fx.logs, append(flowClosed(clientAddr(client)), "reason=idle")...)
	if f.answered.Load() {
		t.Error("the flow reads answered after a datagram from a third socket")
	}
	requireNoDatagram(t, client, 100*time.Millisecond)
}

func TestIngressUDP_ReplyLoopErrors(t *testing.T) {
	fx, ctrl := newUDPFixture(t)
	conn := newScriptedFlowConn()
	opener := &scriptedFlowOpener{steps: []openStep{{conn: conn}}}
	fx.mgr.openUDP = opener.open
	if err := fx.mgr.Apply(t.Context(), rulesBlock(udpIngressRule("dns", 7053, 9053))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	target := netip.MustParseAddrPort("127.0.0.1:9053")
	client := udpClient(t, ctrl.udpAddr(7053))
	closed := flowClosed(clientAddr(client))
	sendUDP(t, client, "query")
	waitForCondition(t, 2*time.Second, func() bool { return len(conn.sent()) == 1 })

	// No platform sends a 65535-byte payload as one IPv4 datagram, so the
	// write to the client fails.
	conn.read(t, scriptedRead{payload: make([]byte, ingressUDPBufSize), from: target})
	waitForLogLine(t, fx.logs, "level=DEBUG", `msg="ingress udp reply not forwarded"`, "listen_port=7053", "remote="+clientAddr(client).String(), "error=")
	if got := logLines(fx.logs, closed...); got != 0 {
		t.Errorf("%d 'flow closed' lines after a failed write to the client, want 0:\n%s", got, fx.logs.String())
	}
	if got := connectionCount(t, fx.mgr); got != 1 {
		t.Errorf("ConnectionCount after a failed write to the client = %d, want 1", got)
	}

	conn.read(t, scriptedRead{err: errors.New("scripted: read failed")})
	waitForLogLine(t, fx.logs, append(closed, "reason=read_failed")...)
	if got := connectionCount(t, fx.mgr); got != 0 {
		t.Errorf("ConnectionCount after a failed read = %d, want 0", got)
	}
	if !conn.isClosed() {
		t.Error("the flow's socket is open after a failed read")
	}
}

// ---------------------------------------------------------------------------
// Dial record
// ---------------------------------------------------------------------------

// sendErr is the error a send that failed with errno returns.
func sendErr(errno error) error {
	return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", errno)}
}

// newScriptedUDPFixture returns a set-up manager on a settable clock whose
// flow sockets come from opener, with policy as its dial policy unless it is
// nil, serving a udp rule on 7053 to 127.0.0.1:9053, and the rule's id. The
// signal of the Apply is drained.
func newScriptedUDPFixture(t *testing.T, opener *scriptedFlowOpener, policy *fakeDialPolicy) (*ingressFixture, *loopbackIngressController, string) {
	t.Helper()
	ctrl := newLoopbackIngressController(t)
	fx := buildIngressFixture(t, ctrl, ingressTestConfig(true))
	fx.mgr.openUDP = opener.open
	fx.mgr.now = (&relayClock{now: relayStart}).Now
	if policy != nil {
		fx.mgr.SetDialPolicy(policy)
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(udpIngressRule("dns", 7053, 9053), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	drain(fx.mgr.ReportChanged())
	return fx, ctrl, id
}

// waitForDial waits up to 2 s for the report of id to read dial and returns
// it.
func waitForDial(t *testing.T, mgr *IngressManager, id, dial string) IngressRuleReport {
	t.Helper()
	var r IngressRuleReport
	waitForCondition(t, 2*time.Second, func() bool {
		r = reportFor(t, mgr.RuleReports(), id)
		return r.Dial == dial
	})
	return r
}

func TestIngressUDP_SendOutcomeIsTheDial(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:9053")
	report := func(id, dial, reason string) IngressRuleReport {
		return IngressRuleReport{
			RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
			Dial: dial, DialReason: reason, DialAt: relayStart,
		}
	}

	t.Run("a send returning nil records succeeded", func(t *testing.T) {
		conn := newScriptedFlowConn(nil)
		fx, ctrl, id := newScriptedUDPFixture(t, &scriptedFlowOpener{steps: []openStep{{conn: conn}}}, &fakeDialPolicy{})
		sendUDP(t, udpClient(t, ctrl.udpAddr(7053)), "query")
		if got, want := waitForDial(t, fx.mgr, id, api.IngressDialSucceeded), report(id, api.IngressDialSucceeded, ""); got != want {
			t.Errorf("report = %+v, want %+v", got, want)
		}
		if sent := conn.sent(); len(sent) != 1 || string(sent[0].payload) != "query" || sent[0].to != target {
			t.Errorf("sent = %+v, want the query to %v", sent, target)
		}
	})

	t.Run("EPERM with a policy that denies", func(t *testing.T) {
		eperm := sendErr(syscall.EPERM)
		conn := newScriptedFlowConn(eperm, eperm, eperm)
		policy := &fakeDialPolicy{denied: true}
		fx, ctrl, id := newScriptedUDPFixture(t, &scriptedFlowOpener{steps: []openStep{{conn: conn}}}, policy)
		client := udpClient(t, ctrl.udpAddr(7053))
		for _, msg := range []string{"one", "two", "three"} {
			sendUDP(t, client, msg)
		}
		// The second and the third send fail as the first did, so they are
		// no dial and log at Debug.
		notForwarded := []string{"level=DEBUG", `msg="ingress datagram not forwarded"`, "listen_port=7053", "remote=" + clientAddr(client).String(), "error="}
		waitForCondition(t, 2*time.Second, func() bool { return logLines(fx.logs, notForwarded...) == 2 })

		if got, want := waitForDial(t, fx.mgr, id, api.IngressDialFailed), report(id, api.IngressDialFailed, IngressDialReasonPolicyDenied); got != want {
			t.Errorf("report = %+v, want %+v", got, want)
		}
		if got, want := policy.askedWith(), []dialQuestion{{protocol: "udp", target: target}}; !slices.Equal(got, want) {
			t.Errorf("the dial policy was asked %+v, want %+v", got, want)
		}
		if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "component=bridge", "rule_id="+id,
			"slug=dns", "protocol=udp", "target=127.0.0.1:9053", "reason=policy_denied", "error="); got != 1 {
			t.Errorf("%d 'dial target failed' lines for three datagrams, want 1:\n%s", got, fx.logs.String())
		}
		if got := logLines(fx.logs, `msg="bridge: ingress: dial target failed"`); got != 1 {
			t.Errorf("%d 'dial target failed' lines in all, want 1:\n%s", got, fx.logs.String())
		}
	})

	for _, tc := range []struct {
		name   string
		policy *fakeDialPolicy
		err    error
		reason string
	}{
		{"EPERM with a policy that admits", &fakeDialPolicy{}, sendErr(syscall.EPERM), IngressDialReasonOther},
		{"EPERM without a policy", nil, sendErr(syscall.EPERM), IngressDialReasonOther},
		{"ENETUNREACH", &fakeDialPolicy{}, sendErr(errNetUnreachable), IngressDialReasonUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newScriptedFlowConn(tc.err)
			fx, ctrl, id := newScriptedUDPFixture(t, &scriptedFlowOpener{steps: []openStep{{conn: conn}}}, tc.policy)
			sendUDP(t, udpClient(t, ctrl.udpAddr(7053)), "query")
			if got, want := waitForDial(t, fx.mgr, id, api.IngressDialFailed), report(id, api.IngressDialFailed, tc.reason); got != want {
				t.Errorf("report = %+v, want %+v", got, want)
			}
			if tc.policy != nil {
				if got, want := tc.policy.askedWith(), []dialQuestion{{protocol: "udp", target: target}}; !slices.Equal(got, want) {
					t.Errorf("the dial policy was asked %+v, want %+v", got, want)
				}
			}
			waitForLogLine(t, fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "protocol=udp", "reason="+tc.reason)
		})
	}

	t.Run("a nil send after a failed one records succeeded", func(t *testing.T) {
		conn := newScriptedFlowConn(sendErr(syscall.EPERM), nil)
		fx, ctrl, id := newScriptedUDPFixture(t, &scriptedFlowOpener{steps: []openStep{{conn: conn}}}, &fakeDialPolicy{})
		changed := fx.mgr.ReportChanged()
		client := udpClient(t, ctrl.udpAddr(7053))

		sendUDP(t, client, "one")
		requireSignal(t, changed, "a failed send")
		if got, want := reportFor(t, fx.mgr.RuleReports(), id), report(id, api.IngressDialFailed, IngressDialReasonOther); got != want {
			t.Errorf("after a failed send: report = %+v, want %+v", got, want)
		}

		sendUDP(t, client, "two")
		requireSignal(t, changed, "a send that succeeded after a failed one")
		if got, want := reportFor(t, fx.mgr.RuleReports(), id), report(id, api.IngressDialSucceeded, ""); got != want {
			t.Errorf("after a send that succeeded: report = %+v, want %+v", got, want)
		}
	})

	t.Run("openUDP fails with ENETUNREACH", func(t *testing.T) {
		conn := newScriptedFlowConn()
		openErr := &net.OpError{Op: "dial", Net: "udp", Err: os.NewSyscallError("connect", errNetUnreachable)}
		opener := &scriptedFlowOpener{steps: []openStep{{err: openErr}, {conn: conn}}}
		fx, ctrl, id := newScriptedUDPFixture(t, opener, &fakeDialPolicy{})
		client := udpClient(t, ctrl.udpAddr(7053))

		sendUDP(t, client, "one")
		if got, want := waitForDial(t, fx.mgr, id, api.IngressDialFailed), report(id, api.IngressDialFailed, IngressDialReasonUnreachable); got != want {
			t.Errorf("after a socket that did not open: report = %+v, want %+v", got, want)
		}
		if got := connectionCount(t, fx.mgr); got != 0 {
			t.Errorf("ConnectionCount after a socket that did not open = %d, want 0", got)
		}
		if flows := udpFlows(fx.mgr, 7053); len(flows) != 0 {
			t.Errorf("flows = %v, want none", flows)
		}
		if got := logLines(fx.logs, `msg="ingress udp flow opened"`); got != 0 {
			t.Errorf("%d 'ingress udp flow opened' lines, want 0:\n%s", got, fx.logs.String())
		}

		sendUDP(t, client, "two")
		if got, want := waitForDial(t, fx.mgr, id, api.IngressDialSucceeded), report(id, api.IngressDialSucceeded, ""); got != want {
			t.Errorf("after the next datagram: report = %+v, want %+v", got, want)
		}
		if got := opener.opened(); !slices.Equal(got, []netip.AddrPort{target, target}) {
			t.Errorf("opened = %v, want two opens to %v", got, target)
		}
		if sent := conn.sent(); len(sent) != 1 || string(sent[0].payload) != "two" {
			t.Errorf("sent = %+v, want the second datagram", sent)
		}
		if got := connectionCount(t, fx.mgr); got != 1 {
			t.Errorf("ConnectionCount after the next datagram = %d, want 1", got)
		}
	})
}
