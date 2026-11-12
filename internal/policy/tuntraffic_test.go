//go:build linux || darwin || windows

package policy

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// The traffic tests put node N's address on a TUN device the test owns and
// play peer P behind it: what the test writes into the device arrives at N
// from P, and what N sends to P comes out of the device for the test to read.
// No other test uses this prefix.
var (
	tunNodeAddr = netip.MustParseAddr("10.255.247.1")
	tunPeerAddr = netip.MustParseAddr("10.255.247.2")
)

const (
	tunTestMTU      = 1420
	tunTrafficChain = "plexd-test"

	// tunAnswerWait bounds the wait for a packet a check expects, and
	// tunSilenceWait is how long a check watches for a packet that must
	// not come.
	tunAnswerWait  = 3 * time.Second
	tunSilenceWait = 2 * time.Second
)

// tunHarness is what a platform's traffic test hands runTunTrafficChecks.
type tunHarness struct {
	ctrl   FirewallController
	dev    tun.Device
	offset int    // room the device needs in front of each packet
	iface  string // the device's interface name, which the rules carry
	// do runs fn where N's sockets and the controller's calls belong:
	// inside N's network namespace on Linux. nil runs fn in place.
	do func(fn func() error) error
}

func (h tunHarness) run(fn func() error) error {
	if h.do == nil {
		return fn()
	}
	return h.do(fn)
}

// inject writes one packet into the device, so it arrives at N from P.
func (h tunHarness) inject(t *testing.T, pkt []byte) {
	t.Helper()
	buf := make([]byte, h.offset+len(pkt))
	copy(buf[h.offset:], pkt)
	if _, err := h.dev.Write([][]byte{buf}, h.offset); err != nil {
		t.Fatalf("write into the test device: %v", err)
	}
}

// waitForNodeAddr waits up to 10 s until a socket can bind N's address. A
// host may hold a fresh address back for a moment after it is assigned.
func (h tunHarness) waitForNodeAddr(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := h.run(func() error {
			c, err := net.ListenPacket("udp4", netip.AddrPortFrom(tunNodeAddr, 0).String())
			if err != nil {
				return err
			}
			return c.Close()
		})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no socket could bind %s within 10 s: %v", tunNodeAddr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// listenTCP opens a TCP listener on N's address. Nothing accepts: the host
// answers a SYN for a listening port on its own.
func (h tunHarness) listenTCP(t *testing.T, port uint16) {
	t.Helper()
	var ln net.Listener
	if err := h.run(func() error {
		var err error
		ln, err = net.Listen("tcp4", netip.AddrPortFrom(tunNodeAddr, port).String())
		return err
	}); err != nil {
		t.Fatalf("listen on %s:%d: %v", tunNodeAddr, port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
}

// echoUDP sends every datagram N receives on port back to its sender.
func (h tunHarness) echoUDP(t *testing.T, port uint16) {
	t.Helper()
	var pc net.PacketConn
	if err := h.run(func() error {
		var err error
		pc, err = net.ListenPacket("udp4", netip.AddrPortFrom(tunNodeAddr, port).String())
		return err
	}); err != nil {
		t.Fatalf("listen on udp %s:%d: %v", tunNodeAddr, port, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})
}

// sendToPeer sends one datagram from N to P's port. A drop may surface as the
// error it returns.
func (h tunHarness) sendToPeer(port uint16, payload []byte) error {
	return h.run(func() error {
		c, err := net.DialUDP("udp4",
			net.UDPAddrFromAddrPort(netip.AddrPortFrom(tunNodeAddr, 0)),
			net.UDPAddrFromAddrPort(netip.AddrPortFrom(tunPeerAddr, port)))
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write(payload)
		return err
	})
}

// dialPeer starts a TCP connection from N to P's port in the background.
// Nothing behind the device answers it, and a drop may end it with an error,
// which nothing looks at. The returned function ends the attempt.
func (h tunHarness) dialPeer(port uint16) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.run(func() error {
			d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(tunNodeAddr, 0))}
			c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(tunPeerAddr, port).String())
			if err != nil {
				return err
			}
			return c.Close()
		})
	}()
	return func() {
		cancel()
		<-done
	}
}

// tunReader hands over, parsed, every IPv4 packet the host writes into the
// device. It ignores every other packet.
type tunReader struct {
	packets chan tunPacket
	stop    chan struct{} // closed before the test closes the device
	done    chan struct{} // closed when the reader has returned
}

func startTunReader(t *testing.T, dev tun.Device, offset int) *tunReader {
	r := &tunReader{
		packets: make(chan tunPacket, 256),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go r.run(t, dev, offset)
	return r
}

func (r *tunReader) run(t *testing.T, dev tun.Device, offset int) {
	defer close(r.done)
	bufs := make([][]byte, dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, offset+65535)
	}
	sizes := make([]int, len(bufs))
	for {
		n, err := dev.Read(bufs, sizes, offset)
		for i := range n {
			// The device reuses its buffers, and a parsed payload shares
			// the memory it was parsed from.
			p, perr := parseIPv4(bytes.Clone(bufs[i][offset : offset+sizes[i]]))
			if perr != nil {
				continue
			}
			select {
			case r.packets <- p:
			case <-r.stop:
				return
			}
		}
		if err != nil {
			select {
			case <-r.stop:
			default:
				t.Errorf("read from the test device: %v", err)
			}
			return
		}
	}
}

// nextPacket waits up to wait for a packet from the device that match
// accepts, skipping every other one.
func (r *tunReader) nextPacket(wait time.Duration, match func(tunPacket) bool) (tunPacket, bool) {
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	for {
		select {
		case p, ok := <-r.packets:
			if !ok {
				return tunPacket{}, false
			}
			if match(p) {
				return p, true
			}
		case <-timeout.C:
			return tunPacket{}, false
		}
	}
}

// expectPacket fails the test unless a packet that match accepts comes from
// the device within wait. It skips every other packet.
func (r *tunReader) expectPacket(t *testing.T, wait time.Duration, what string, match func(tunPacket) bool) {
	t.Helper()
	if _, ok := r.nextPacket(wait, match); !ok {
		t.Errorf("no %s came out of the device within %s", what, wait)
	}
}

// expectNoPacket fails the test if a packet that match accepts comes from
// the device within wait. It skips every other packet.
func (r *tunReader) expectNoPacket(t *testing.T, wait time.Duration, what string, match func(tunPacket) bool) {
	t.Helper()
	if p, ok := r.nextPacket(wait, match); ok {
		t.Errorf("%s came out of the device (%v), want none within %s", what, p, wait)
	}
}

// fromNodeTCP matches a TCP segment from N's srcPort to P's dstPort whose
// flags, masked by mask, equal want.
func fromNodeTCP(srcPort, dstPort uint16, mask, want uint8) func(tunPacket) bool {
	return func(p tunPacket) bool {
		return p.proto == protoTCP && p.src == tunNodeAddr && p.dst == tunPeerAddr &&
			(srcPort == 0 || p.srcPort == srcPort) && p.dstPort == dstPort &&
			p.tcpFlags&mask == want
	}
}

// fromNodeUDP matches a UDP datagram from N to P's dstPort that carries
// payload, from N's srcPort unless that is 0.
func fromNodeUDP(srcPort, dstPort uint16, payload []byte) func(tunPacket) bool {
	return func(p tunPacket) bool {
		return p.proto == protoUDP && p.src == tunNodeAddr && p.dst == tunPeerAddr &&
			(srcPort == 0 || p.srcPort == srcPort) && p.dstPort == dstPort &&
			bytes.Equal(p.payload, payload)
	}
}

// runTunTrafficChecks proves with traffic through h's device that the
// controller filters both directions: what P sends to N and what N sends to
// P. N's address must already be on the device. The checks first wait until
// it can be bound and check that the host answers through the device at all.
// They then install the ruleset the engine builds for these rules on the
// device:
//
//	r0 tcp  P → N port 7001
//	r1 udp  P → N port 7002
//	r2 icmp P → N
//	r3 udp  N → P port 7005
//	r4 tcp  N → P port 7006
//	r5 the default deny
//
// Every injected packet has a source port or ICMP id of its own, so an answer
// to one check never satisfies another. When the test ends, the device is
// closed before the chain is deleted.
func runTunTrafficChecks(t *testing.T, h tunHarness) {
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
		if err := h.run(func() error { return h.ctrl.DeleteChain(tunTrafficChain) }); err != nil {
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
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 40000, 7001, 1))
	if _, ok := reader.nextPacket(tunAnswerWait, fromNodeTCP(7001, 40000, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK)); !ok {
		t.Fatal("the host answers nothing through the test device without plexd's filters")
	}

	// Set before the call, so a chain EnsureChain left half made goes too.
	chainMade = true
	if err := h.run(func() error { return h.ctrl.EnsureChain(tunTrafficChain) }); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	peer, node := tunPeerAddr.String()+"/32", tunNodeAddr.String()+"/32"
	rules := []FirewallRule{
		{Interface: h.iface, SrcIP: peer, DstIP: node, Port: 7001, Protocol: "tcp", Action: "allow"},
		{Interface: h.iface, SrcIP: peer, DstIP: node, Port: 7002, Protocol: "udp", Action: "allow"},
		{Interface: h.iface, SrcIP: peer, DstIP: node, Protocol: "icmp", Action: "allow"},
		{Interface: h.iface, SrcIP: node, DstIP: peer, Port: 7005, Protocol: "udp", Action: "allow"},
		{Interface: h.iface, SrcIP: node, DstIP: peer, Port: 7006, Protocol: "tcp", Action: "allow"},
		{Interface: h.iface, Action: "deny"},
	}
	if err := h.run(func() error { return h.ctrl.ApplyRules(tunTrafficChain, rules) }); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	t.Log("r0 lets P open a connection to N:7001, and N's SYN-ACK leaves")
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 40001, 7001, 1))
	reader.expectPacket(t, tunAnswerWait, "SYN-ACK from N:7001 to P:40001",
		fromNodeTCP(7001, 40001, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK))

	t.Log("no rule lets P open a connection to N:7003, where N listens; a RST is accepted")
	h.inject(t, buildIPv4TCPSyn(tunPeerAddr, tunNodeAddr, 40002, 7003, 1))
	reader.expectNoPacket(t, tunSilenceWait, "a SYN-ACK from N:7003 to P:40002",
		fromNodeTCP(7003, 40002, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK))

	t.Log("r1 lets P's datagram reach N:7002, and N's echo leaves")
	h.inject(t, buildIPv4UDP(tunPeerAddr, tunNodeAddr, 40003, 7002, []byte("plexd 7002")))
	reader.expectPacket(t, tunAnswerWait, "UDP echo from N:7002 to P:40003",
		fromNodeUDP(7002, 40003, []byte("plexd 7002")))

	t.Log("r2 lets P's echo request reach N, and N's echo reply leaves")
	h.inject(t, buildIPv4EchoRequest(tunPeerAddr, tunNodeAddr, 0x7178, 1, []byte("plexd ping")))
	reader.expectPacket(t, tunAnswerWait, "ICMP echo reply from N to P with id 0x7178 and sequence 1",
		func(p tunPacket) bool {
			return p.proto == protoICMP && p.src == tunNodeAddr && p.dst == tunPeerAddr &&
				p.icmpType == icmpEchoReply && p.icmpID == 0x7178 && p.icmpSeq == 1
		})

	t.Log("r3 lets N send a datagram to P:7005")
	if err := h.sendToPeer(7005, []byte("plexd 7005")); err != nil {
		t.Errorf("send from N to P:7005: %v", err)
	}
	reader.expectPacket(t, tunAnswerWait, "datagram from N to P:7005", fromNodeUDP(0, 7005, []byte("plexd 7005")))

	t.Log("no rule lets N send a datagram to P:7007; a send error is accepted")
	_ = h.sendToPeer(7007, []byte("plexd 7007"))
	reader.expectNoPacket(t, tunSilenceWait, "a datagram from N to P:7007", fromNodeUDP(0, 7007, []byte("plexd 7007")))

	t.Log("r4 lets N open a connection to P:7006")
	stop := h.dialPeer(7006)
	reader.expectPacket(t, tunAnswerWait, "SYN from N to P:7006", fromNodeTCP(0, 7006, tcpFlagSYN|tcpFlagACK, tcpFlagSYN))
	stop()

	t.Log("no rule lets N open a connection to P:7008; a dial error is accepted")
	stop = h.dialPeer(7008)
	reader.expectNoPacket(t, tunSilenceWait, "a SYN from N to P:7008", fromNodeTCP(0, 7008, tcpFlagSYN|tcpFlagACK, tcpFlagSYN))
	stop()

	t.Logf("no rule names it, but N's relay probe to P:%d leaves", RelayProbePort)
	if err := h.sendToPeer(RelayProbePort, []byte("plexd probe")); err != nil {
		t.Errorf("send from N to P:%d: %v", RelayProbePort, err)
	}
	reader.expectPacket(t, tunAnswerWait, "relay probe from N to P:"+strconv.Itoa(RelayProbePort),
		fromNodeUDP(0, RelayProbePort, []byte("plexd probe")))
}
