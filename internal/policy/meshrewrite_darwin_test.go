//go:build darwin

package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// The devices of TestPFController_RealMeshSourceRewrite and the far ends the
// test plays behind them. M is the mesh interface, with mesh node N behind
// it. P is a user access provider's interface, with device D behind it. T is
// a site-to-site tunnel's link, which carries the mesh address as a /32, as
// plexd up's tunnel controller assigns it, with site host S behind it. No
// other test uses these prefixes.
var (
	rewriteMeshAddr = netip.MustParseAddr("10.255.245.1") // M's address, the bridge's mesh address
	rewriteNode     = netip.MustParseAddr("10.255.245.2") // N
	rewriteDevice   = netip.MustParseAddr("10.255.246.2") // D
	rewriteSite     = netip.MustParseAddr("10.255.244.2") // S
)

// rewriteNodePort is the port of N the far ends send to.
const rewriteNodePort = 7001

// rewriteUTUN is a utun the test owns, addressed and routed the way the
// controllers do it, with a reader for what the host writes into it.
type rewriteUTUN struct {
	tunHarness
	reader *tunReader
}

// newRewriteUTUN creates a utun that carries cidr and routes route over it,
// with the commands DarwinController and DarwinRouteController run:
// ifconfig <utun> inet <cidr> <address> alias, route -n add -inet <route>
// -interface <utun>, ifconfig <utun> up. The device is closed when the test
// ends, which takes its address and route with it.
func newRewriteUTUN(t *testing.T, cidr, route string) *rewriteUTUN {
	t.Helper()

	// "utun" asks for the next free unit.
	dev, err := tun.CreateTUN("utun", tunTestMTU)
	if err != nil {
		t.Fatalf("create a utun: %v", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		t.Fatalf("name of the utun: %v", err)
	}

	// wireguard-go's utun writes the address family in front of each packet,
	// so a buffer needs room for it.
	reader := startTunReader(t, dev, 4)
	t.Cleanup(func() {
		close(reader.stop)
		if err := dev.Close(); err != nil {
			t.Errorf("close %s: %v", name, err)
		}
		<-reader.done
	})
	// A device reports link events on a channel nothing else reads, and one
	// that fills up stalls the device's own listener.
	go func() {
		for range dev.Events() {
		}
	}()

	prefix := netip.MustParsePrefix(cidr)
	runRewriteTool(t, "/sbin/ifconfig", name, "inet", prefix.String(), prefix.Addr().String(), "alias")
	runRewriteTool(t, "/sbin/route", "-n", "add", "-inet", route, "-interface", name)
	runRewriteTool(t, "/sbin/ifconfig", name, "up")

	return &rewriteUTUN{tunHarness: tunHarness{dev: dev, offset: 4, iface: name}, reader: reader}
}

// runRewriteTool runs one host command and stops the test when it fails.
func runRewriteTool(t *testing.T, name string, args ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := execCommand(ctx, nil, name, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// buildIPv4TCPSynAck returns a TCP SYN-ACK without options that acknowledges
// ack.
func buildIPv4TCPSynAck(src, dst netip.Addr, srcPort, dstPort uint16, seq, ack uint32) []byte {
	seg := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], ack)
	seg[12] = tcpHeaderLen / 4 << 4 // data offset
	seg[13] = tcpFlagSYN | tcpFlagACK
	binary.BigEndian.PutUint16(seg[14:], 65535) // window
	binary.BigEndian.PutUint16(seg[16:], transportChecksum(src, dst, protoTCP, seg))
	return buildIPv4(src, dst, protoTCP, seg)
}

// udpTo matches a UDP datagram to dst's port that carries payload.
func udpTo(dst netip.Addr, port uint16, payload []byte) func(tunPacket) bool {
	return func(p tunPacket) bool {
		return p.proto == protoUDP && p.dst == dst && p.dstPort == port && bytes.Equal(p.payload, payload)
	}
}

// tcpTo matches a TCP segment to dst's port whose flags, masked by mask, equal
// want.
func tcpTo(dst netip.Addr, port uint16, mask, want uint8) func(tunPacket) bool {
	return func(p tunPacket) bool {
		return p.proto == protoTCP && p.dst == dst && p.dstPort == port && p.tcpFlags&mask == want
	}
}

// TestPFController_RealMeshSourceRewrite proves the pf lines of a mesh source
// rewrite with packets through utuns the test owns: what a provider's
// interface or a tunnel's link forwards into the mesh leaves the mesh
// interface with the bridge's mesh address as its source, its reply finds the
// way back, the bridge's own traffic still meets the default deny, a mesh
// node reaches the far end only under a rule and keeps its source, and the
// far end's reply to it keeps the far end's. The fake-based tests pin which
// lines the controller renders; this is the only test that proves pf
// translates and filters them as plexd needs.
//
// It runs the checks once with P and D and once with T and S. A packet
// enters a device when the test writes it into the device and leaves when
// the test reads it from the device. Every check uses ports of its own, so
// none meets a pf state an earlier check left.
//
// CI runs it in the privileged macOS step, which fails unless it passed.
func TestPFController_RealMeshSourceRewrite(t *testing.T) {
	// Gated like TestPFController_Real: sudo go test ./... on a developer's
	// Mac should not enable pf and load an anchor unasked.
	if os.Getenv("PLEXD_TEST_REAL_PF") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PF=1 to load a real pf anchor")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating a utun, forwarding and loading a pf anchor need root; run with sudo")
	}

	// macOS has one IPv4 forwarding knob for the whole host.
	before := strings.TrimSpace(runRewriteTool(t, "/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := execCommand(ctx, nil, "/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding="+before); err != nil {
			t.Errorf("restore net.inet.ip.forwarding to %s: %v\n%s", before, err, out)
		}
	})
	runRewriteTool(t, "/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1")

	// Registered before any device, so it runs after every device is closed:
	// the interfaces are gone before their lines are.
	ctrl := NewPFController(tunTestLogger(t))
	chainMade := false
	t.Cleanup(func() {
		if err := ctrl.ResetMeshSourceRewrite(); err != nil {
			t.Errorf("cleanup ResetMeshSourceRewrite() error = %v", err)
		}
		if !chainMade {
			return
		}
		if err := ctrl.DeleteChain(tunTrafficChain); err != nil {
			t.Errorf("cleanup DeleteChain() error = %v", err)
		}
	})

	mesh := newRewriteUTUN(t, "10.255.245.1/24", "10.255.245.0/24")
	waitForAddr(t, rewriteMeshAddr)

	// Set before the call, so a chain EnsureChain left half made goes too.
	chainMade = true
	if err := ctrl.EnsureChain(tunTrafficChain); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}

	t.Run("provider", func(t *testing.T) {
		provider := newRewriteUTUN(t, "10.255.246.1/24", "10.255.246.0/24")
		runMeshRewriteChecks(t, ctrl, mesh, provider, rewriteDevice, 41000)
	})
	t.Run("tunnel", func(t *testing.T) {
		tunnel := newRewriteUTUN(t, "10.255.245.1/32", "10.255.244.0/24")
		runMeshRewriteChecks(t, ctrl, mesh, tunnel, rewriteSite, 42000)
	})
}

// waitForAddr waits up to 10 s until a socket can bind addr. A host may hold
// a fresh address back for a moment after it is assigned.
func waitForAddr(t *testing.T, addr netip.Addr) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.ListenPacket("udp4", netip.AddrPortFrom(addr, 0).String())
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no socket could bind %s within 10 s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// runMeshRewriteChecks runs the checks for one shape: src is the provider's
// interface or the tunnel's link, far the host behind it, and the ports of
// the far end start above base. The chain on mesh holds the default deny
// alone until the fifth check adds its rules.
func runMeshRewriteChecks(t *testing.T, ctrl *PFController, mesh, src *rewriteUTUN, far netip.Addr, base uint16) {
	deny := FirewallRule{Interface: mesh.iface, Action: "deny"}
	if err := ctrl.ApplyRules(tunTrafficChain, []FirewallRule{deny}); err != nil {
		t.Fatalf("ApplyRules(the default deny) error = %v, want nil", err)
	}
	if err := ctrl.AddMeshSourceRewrite(src.iface, mesh.iface); err != nil {
		t.Fatalf("AddMeshSourceRewrite(%q, %q) error = %v, want nil", src.iface, mesh.iface, err)
	}
	rewritten := true
	t.Cleanup(func() {
		if !rewritten {
			return
		}
		if err := ctrl.RemoveMeshSourceRewrite(src.iface, mesh.iface); err != nil {
			t.Errorf("cleanup RemoveMeshSourceRewrite() error = %v", err)
		}
	})

	t.Logf("1. a datagram from %s to N:%d enters %s and leaves %s from the bridge's mesh address", far, rewriteNodePort, src.iface, mesh.iface)
	payload := []byte("plexd rewrite 1")
	src.inject(t, buildIPv4UDP(far, rewriteNode, base+1, rewriteNodePort, payload))
	out, ok := mesh.reader.nextPacket(tunAnswerWait, udpTo(rewriteNode, rewriteNodePort, payload))
	if !ok {
		t.Fatalf("no datagram to N:%d left %s within %s", rewriteNodePort, mesh.iface, tunAnswerWait)
	}
	if out.src != rewriteMeshAddr {
		t.Errorf("the datagram left %s from %s:%d, want the source %s", mesh.iface, out.src, out.srcPort, rewriteMeshAddr)
	}

	t.Logf("2. N's reply to %s:%d enters %s and leaves %s to %s:%d from N", out.src, out.srcPort, mesh.iface, src.iface, far, base+1)
	reply := []byte("plexd rewrite 2")
	mesh.inject(t, buildIPv4UDP(rewriteNode, out.src, rewriteNodePort, out.srcPort, reply))
	back, ok := src.reader.nextPacket(tunAnswerWait, udpTo(far, base+1, reply))
	if !ok {
		t.Errorf("no reply to %s:%d left %s within %s", far, base+1, src.iface, tunAnswerWait)
	} else if back.src != rewriteNode || back.srcPort != rewriteNodePort {
		t.Errorf("the reply left %s from %s:%d, want N:%d", src.iface, back.src, back.srcPort, rewriteNodePort)
	}

	t.Logf("3. the bridge's own datagram from %s to N meets the default deny", rewriteMeshAddr)
	droppedPackets, _, err := ctrl.DropCounts(tunTrafficChain)
	if err != nil {
		t.Fatalf("DropCounts() error = %v, want nil", err)
	}
	own := []byte("plexd rewrite 3")
	// A drop may surface as the error of the dial or the write.
	if c, err := net.DialUDP("udp4",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(rewriteMeshAddr, 0)),
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(rewriteNode, base+3))); err == nil {
		_, _ = c.Write(own)
		_ = c.Close()
	}
	mesh.reader.expectNoPacket(t, tunSilenceWait, "the bridge's own datagram to N", udpTo(rewriteNode, base+3, own))
	gotPackets, _, err := ctrl.DropCounts(tunTrafficChain)
	if err != nil {
		t.Fatalf("DropCounts() error = %v, want nil", err)
	}
	if gotPackets <= droppedPackets {
		t.Errorf("DropCounts() went from %d to %d packets, want more", droppedPackets, gotPackets)
	}

	t.Logf("4. under the default deny alone, N's datagram to %s does not leave %s", far, src.iface)
	toFar := buildIPv4UDP(rewriteNode, far, base+4, base+5, []byte("plexd rewrite 4"))
	mesh.inject(t, toFar)
	src.reader.expectNoPacket(t, tunSilenceWait, "N's datagram to the far end", udpTo(far, base+5, []byte("plexd rewrite 4")))

	t.Logf("5. a rule lets N's datagram to %s through with N's source, and the far end's reply keeps its own", far)
	node, farHost := rewriteNode.String()+"/32", far.String()+"/32"
	rules := []FirewallRule{
		{Interface: mesh.iface, SrcIP: node, DstIP: farHost, Protocol: "udp", Action: "allow"},
		{Interface: mesh.iface, SrcIP: node, DstIP: farHost, Protocol: "tcp", Action: "allow"},
		deny,
	}
	if err := ctrl.ApplyRules(tunTrafficChain, rules); err != nil {
		t.Fatalf("ApplyRules(the allow rules) error = %v, want nil", err)
	}
	mesh.inject(t, toFar)
	got, ok := src.reader.nextPacket(tunAnswerWait, udpTo(far, base+5, []byte("plexd rewrite 4")))
	if !ok {
		t.Errorf("N's datagram to %s:%d did not leave %s within %s", far, base+5, src.iface, tunAnswerWait)
	} else if got.src != rewriteNode {
		t.Errorf("N's datagram left %s from %s, want N", src.iface, got.src)
	}
	farReply := []byte("plexd rewrite 5")
	src.inject(t, buildIPv4UDP(far, rewriteNode, base+5, base+4, farReply))
	got, ok = mesh.reader.nextPacket(tunAnswerWait, udpTo(rewriteNode, base+4, farReply))
	if !ok {
		t.Errorf("the far end's reply to N:%d did not leave %s within %s", base+4, mesh.iface, tunAnswerWait)
	} else if got.src != far {
		t.Errorf("the far end's reply left %s from %s, want %s, not the bridge's mesh address", mesh.iface, got.src, far)
	}

	t.Logf("6. the same holds for N's SYN to %s and its SYN-ACK", far)
	mesh.inject(t, buildIPv4TCPSyn(rewriteNode, far, base+6, base+7, 1))
	got, ok = src.reader.nextPacket(tunAnswerWait, tcpTo(far, base+7, tcpFlagSYN|tcpFlagACK, tcpFlagSYN))
	if !ok {
		t.Errorf("N's SYN to %s:%d did not leave %s within %s", far, base+7, src.iface, tunAnswerWait)
	} else if got.src != rewriteNode {
		t.Errorf("N's SYN left %s from %s, want N", src.iface, got.src)
	}
	src.inject(t, buildIPv4TCPSynAck(far, rewriteNode, base+7, base+6, 5000, 2))
	got, ok = mesh.reader.nextPacket(tunAnswerWait, tcpTo(rewriteNode, base+6, tcpFlagSYN|tcpFlagACK, tcpFlagSYN|tcpFlagACK))
	if !ok {
		t.Errorf("the far end's SYN-ACK to N:%d did not leave %s within %s", base+6, mesh.iface, tunAnswerWait)
	} else if got.src != far {
		t.Errorf("the far end's SYN-ACK left %s from %s, want %s, not the bridge's mesh address", mesh.iface, got.src, far)
	}

	t.Logf("7. without the rewrite, a new datagram from %s leaves %s with its own source", far, mesh.iface)
	if err := ctrl.RemoveMeshSourceRewrite(src.iface, mesh.iface); err != nil {
		t.Fatalf("RemoveMeshSourceRewrite() error = %v, want nil", err)
	}
	rewritten = false
	plain := []byte("plexd rewrite 7")
	src.inject(t, buildIPv4UDP(far, rewriteNode, base+8, rewriteNodePort, plain))
	got, ok = mesh.reader.nextPacket(tunAnswerWait, udpTo(rewriteNode, rewriteNodePort, plain))
	if !ok {
		t.Errorf("the datagram to N:%d did not leave %s within %s", rewriteNodePort, mesh.iface, tunAnswerWait)
	} else if got.src != far {
		t.Errorf("the datagram left %s from %s, want %s", mesh.iface, got.src, far)
	}

	t.Log("8. a reset on a controller that holds nothing removes the lines another one loaded")
	if err := ctrl.AddMeshSourceRewrite(src.iface, mesh.iface); err != nil {
		t.Fatalf("AddMeshSourceRewrite() again error = %v, want nil", err)
	}
	rewritten = true
	if lines := anchorRewriteLines(t, "nat"); len(lines) == 0 {
		t.Fatal("pfctl -s nat shows no plexd-mesh-rewrite line after AddMeshSourceRewrite")
	}
	if err := NewPFController(tunTestLogger(t)).ResetMeshSourceRewrite(); err != nil {
		t.Fatalf("ResetMeshSourceRewrite() on a second controller error = %v, want nil", err)
	}
	for _, what := range []string{"nat", "rules"} {
		if lines := anchorRewriteLines(t, what); len(lines) != 0 {
			t.Errorf("pfctl -a %s -s %s still shows %q", pfAnchor, what, lines)
		}
	}
}

// anchorRewriteLines returns the lines of pfctl -a com.apple/plexd -s what
// that carry the rewrite's tag.
func anchorRewriteLines(t *testing.T, what string) []string {
	t.Helper()

	out := runRewriteTool(t, pfctlPath, "-a", pfAnchor, "-s", what)
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, pfMeshRewriteTag) {
			lines = append(lines, line)
		}
	}
	return lines
}
