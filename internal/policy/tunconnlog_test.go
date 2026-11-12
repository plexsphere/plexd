//go:build linux || darwin

package policy

import (
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"
)

// tunConnLogChain is the chain the connection-log checks install. It is not
// the traffic checks' chain, so a chain one test leaves behind never filters
// the other's traffic.
const tunConnLogChain = "plexd-logtest"

// tunTestLogger returns the logger a platform's harness hands its controller.
// It keeps what the controller logs and prints it when the test fails, so the
// CI log of a failed check also shows a Warn the controller logged, such as
// connection logging that could not start.
func tunTestLogger(t *testing.T) *slog.Logger {
	logs := &syncBuffer{}
	t.Cleanup(func() {
		logs.mu.Lock()
		defer logs.mu.Unlock()
		if t.Failed() && logs.buf.Len() > 0 {
			t.Logf("the controller logged:\n%s", logs.buf.String())
		}
	})
	return slog.New(slog.NewTextHandler(logs, nil))
}

// tunConnSink records the connections a controller reports, in order. It is
// safe for concurrent use: a backend reports from a goroutine of its own.
type tunConnSink struct {
	mu     sync.Mutex
	events []ConnEvent
	lost   int
	// changed gets a value after each event, so a waiter scans again.
	changed chan struct{}
}

func newTunConnSink() *tunConnSink {
	return &tunConnSink{changed: make(chan struct{}, 1)}
}

func (s *tunConnSink) Event(ev ConnEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *tunConnSink) Lost(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lost += n
}

// mark returns how many events the sink holds. A check takes it before it
// sends anything and looks only at the events recorded from it on.
func (s *tunConnSink) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// since returns the events recorded from index from on, and how many records
// the backend reported lost so far.
func (s *tunConnSink) since(from int) (events []ConnEvent, lost int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events[from:]), s.lost
}

// waitFor waits up to wait until done accepts the events recorded from index
// from on, and reports whether it did.
func (s *tunConnSink) waitFor(from int, wait time.Duration, done func([]ConnEvent) bool) bool {
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	for {
		if events, _ := s.since(from); done(events) {
			return true
		}
		select {
		case <-s.changed:
		case <-timeout.C:
			return false
		}
	}
}

// expectEvents waits up to tunAnswerWait for as many events as want holds,
// then tunSilenceWait for any more. It fails the test unless the events
// recorded from index from on are want, in order, and nothing else.
func (s *tunConnSink) expectEvents(t *testing.T, from int, what string, want ...ConnEvent) {
	t.Helper()
	s.waitFor(from, tunAnswerWait, func(events []ConnEvent) bool { return len(events) >= len(want) })
	time.Sleep(tunSilenceWait)
	if got, lost := s.since(from); !slices.Equal(got, want) {
		t.Errorf("%s: reported %+v, want %+v (records the backend lost: %d)", what, got, want, lost)
	}
}

// runTunConnLogChecks proves with traffic through h's device that the
// controller reports the connections its logged rules admit, under their
// tags, and nothing else. N's address must already be on the device. Like
// runTunTrafficChecks, the checks first wait until it can be bound and check
// that the host answers through the device at all. They then hand the
// controller a sink that records what it reports and install the ruleset the
// Enforcer hands it for these rules on the device, logged rules first:
//
//	r0 tcp P → N port 7001  LogTag "7/0"
//	r1 udp P → N port 7002  LogTag "7/1"
//	r2 tcp N → P port 7006  LogTag "7/2"
//	r3 tcp P → N port 7003
//	r4 the default deny
//
// Every check sends from a source port of its own, so a report of one
// check's connection never satisfies another. The checks end with
// DeleteChain, so a platform's test can look at what the controller leaves
// behind once it returns. Their cleanup closes the device before it deletes
// the chain, and deletes it only when a check stopped the test before that
// DeleteChain ran.
func runTunConnLogChecks(t *testing.T, h tunHarness) {
	reporter, ok := h.ctrl.(ConnReporter)
	if !ok {
		t.Fatalf("%T does not implement ConnReporter, so it reports no connection", h.ctrl)
	}
	sink := newTunConnSink()
	reporter.SetConnSink(sink)

	h.waitForNodeAddr(t)

	reader := startTunReader(t, h.dev, h.offset)
	chainMade := false
	t.Cleanup(func() {
		// The device goes first: closing it ends the reader, and the
		// interface is gone before its filters are.
		close(reader.stop)
		if err := h.dev.Close(); err != nil {
			t.Errorf("close the test device: %v", err)
		}
		<-reader.done
		if !chainMade {
			return
		}
		if err := h.run(func() error { return h.ctrl.DeleteChain(tunConnLogChain) }); err != nil {
			t.Errorf("cleanup DeleteChain() error = %v", err)
		}
	})
	// A device reports link events on a channel nothing else reads, and
	// one that fills up stalls the device's own listener.
	go func() {
		for range h.dev.Events() {
		}
	}()

	h.listenTCP(t, 7001)
	h.listenTCP(t, 7003)
	h.echoUDP(t, 7002)

	t.Log("control: without plexd's filters N answers a SYN from P")
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 41000, 7001, 1))
	if _, ok := reader.nextPacket(tunAnswerWait, fromNodeTCP(7001, 41000, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK)); !ok {
		t.Fatal("the host answers nothing through the test device without plexd's filters")
	}

	// Set before the call, so a chain EnsureChain left half made goes too.
	chainMade = true
	if err := h.run(func() error { return h.ctrl.EnsureChain(tunConnLogChain) }); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	peer, node := tunPeerAddr.String()+"/32", tunNodeAddr.String()+"/32"
	rules := []FirewallRule{
		{Interface: h.iface, SrcIP: peer, DstIP: node, Port: 7001, Protocol: "tcp", Action: "allow", LogTag: "7/0"},
		{Interface: h.iface, SrcIP: peer, DstIP: node, Port: 7002, Protocol: "udp", Action: "allow", LogTag: "7/1"},
		{Interface: h.iface, SrcIP: node, DstIP: peer, Port: 7006, Protocol: "tcp", Action: "allow", LogTag: "7/2"},
		{Interface: h.iface, SrcIP: peer, DstIP: node, Port: 7003, Protocol: "tcp", Action: "allow"},
		{Interface: h.iface, Action: "deny"},
	}
	if err := h.run(func() error { return h.ctrl.ApplyRules(tunConnLogChain, rules) }); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	t.Log("r0 lets P open a connection to N:7001 and reports it once")
	from := sink.mark()
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 41001, 7001, 1))
	reader.expectPacket(t, tunAnswerWait, "SYN-ACK from N:7001 to P:41001",
		fromNodeTCP(7001, 41001, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK))
	sink.expectEvents(t, from, "P's connection to N:7001",
		ConnEvent{Tag: "7/0", Dir: ConnIn, Src: tunPeerAddr, Dst: tunNodeAddr, Protocol: protoTCP, SrcPort: 41001, DstPort: 7001})

	t.Log("r3 lets P open a connection to N:7003 and, untagged, reports nothing")
	from = sink.mark()
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 41002, 7003, 1))
	reader.expectPacket(t, tunAnswerWait, "SYN-ACK from N:7003 to P:41002",
		fromNodeTCP(7003, 41002, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK))
	sink.expectEvents(t, from, "P's connection to N:7003")

	t.Log("r1 lets P's datagram reach N:7002, and reports it")
	udpEvent := ConnEvent{
		Tag: "7/1", Dir: ConnIn, Src: tunPeerAddr, Dst: tunNodeAddr, Protocol: protoUDP, SrcPort: 41003, DstPort: 7002,
	}
	from = sink.mark()
	h.inject(t, buildIPv4UDP(tunPeerAddr, tunNodeAddr, 41003, 7002, []byte("plexd 7002")))
	reader.expectPacket(t, tunAnswerWait, "UDP echo from N:7002 to P:41003",
		fromNodeUDP(7002, 41003, []byte("plexd 7002")))
	sink.expectEvents(t, from, "P's first datagram to N:7002", udpEvent)

	var again []ConnEvent
	if tunUDPLogsEveryPacket {
		t.Log("a second datagram on the same ports is reported as well: this backend reports every UDP datagram")
		again = []ConnEvent{udpEvent}
	} else {
		t.Log("a second datagram on the same ports belongs to the flow already reported, and is not reported")
	}
	from = sink.mark()
	h.inject(t, buildIPv4UDP(tunPeerAddr, tunNodeAddr, 41003, 7002, []byte("plexd 7002 again")))
	reader.expectPacket(t, tunAnswerWait, "second UDP echo from N:7002 to P:41003",
		fromNodeUDP(7002, 41003, []byte("plexd 7002 again")))
	sink.expectEvents(t, from, "P's second datagram to N:7002", again...)

	t.Log("r2 lets N open a connection to P:7006, and reports it under r2's tag alone")
	// N's kernel picks the source port, and a SYN it sends again may be
	// reported again.
	nodeDial := func(ev ConnEvent) bool {
		return ev.Tag == "7/2" && ev.Dir == ConnOut && ev.Src == tunNodeAddr && ev.Dst == tunPeerAddr &&
			ev.Protocol == protoTCP && ev.SrcPort != 0 && ev.DstPort == 7006
	}
	notNodeDial := func(ev ConnEvent) bool { return !nodeDial(ev) }
	from = sink.mark()
	stop := h.dialPeer(7006)
	reader.expectPacket(t, tunAnswerWait, "SYN from N to P:7006", fromNodeTCP(0, 7006, tcpFlagSYN|tcpFlagACK, tcpFlagSYN))
	if !sink.waitFor(from, tunAnswerWait, func(events []ConnEvent) bool { return slices.ContainsFunc(events, nodeDial) }) {
		t.Errorf("N's connection to P:7006: no report under tag 7/2 within %s", tunAnswerWait)
	}
	stop()
	if got, lost := sink.since(from); slices.ContainsFunc(got, notNodeDial) {
		t.Errorf("N's connection to P:7006: reported %+v, want only reports of N's connection under tag 7/2 (records the backend lost: %d)",
			got, lost)
	}

	t.Log("with r0's tag gone, r0 still lets P open a connection to N:7001 and reports nothing")
	rules[0].LogTag = ""
	from = sink.mark()
	if err := h.run(func() error { return h.ctrl.ApplyRules(tunConnLogChain, rules) }); err != nil {
		t.Fatalf("ApplyRules() without r0's tag error = %v, want nil", err)
	}
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 41004, 7001, 1))
	reader.expectPacket(t, tunAnswerWait, "SYN-ACK from N:7001 to P:41004",
		fromNodeTCP(7001, 41004, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK))
	// The filter engine delivers its events after the connection, so a
	// report of N's connection to P:7006 may still arrive here.
	if sink.waitFor(from, tunSilenceWait, func(events []ConnEvent) bool { return slices.ContainsFunc(events, notNodeDial) }) {
		got, lost := sink.since(from)
		t.Errorf("P's connection to N:7001 without r0's tag: reported %+v, "+
			"want nothing but a late report of N's connection to P:7006 (records the backend lost: %d)", got, lost)
	}

	t.Log("DeleteChain removes the rules and ends the connection log")
	if err := h.run(func() error { return h.ctrl.DeleteChain(tunConnLogChain) }); err != nil {
		t.Errorf("DeleteChain() error = %v, want nil", err)
		return
	}
	chainMade = false
}
