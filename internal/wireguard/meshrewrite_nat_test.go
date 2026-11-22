package wireguard

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// The addresses and interfaces of the rewrite's tests: the bridge's mesh
// interface carries 10.255.241.1, a provider's interface the pool
// 10.255.242.0/24 and a tunnel's interface none. N is a mesh node, D and D2
// devices behind the provider, S a host of the tunnel's site.
var (
	rwMeshAddr = netip.MustParseAddr("10.255.241.1")
	rwNodeN    = netip.MustParseAddr("10.255.241.2")
	rwPoolAddr = netip.MustParseAddr("10.255.242.1")
	rwDeviceD  = netip.MustParseAddr("10.255.242.2")
	rwDeviceD2 = netip.MustParseAddr("10.255.242.3")
	rwSiteS    = netip.MustParseAddr("10.255.240.2")

	rwPoolPrefix = netip.MustParsePrefix("10.255.242.1/24")
)

const (
	rwMesh   = "plexd0"
	rwAccess = "wg-ua-a0a0a0e1"
	rwTunnel = "wg-s2s-a0a0a0e1"
)

// rwStart is the fake clock's time when a rule test starts.
var rwStart = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Packets
// ---------------------------------------------------------------------------

// pktOpt changes an IPv4 header field of a test packet before its header
// checksum is computed.
type pktOpt func(h []byte)

func withTTL(ttl uint8) pktOpt { return func(h []byte) { h[8] = ttl } }

func withDF() pktOpt { return func(h []byte) { h[6] |= 0x40 } }

func withIPID(id uint16) pktOpt { return func(h []byte) { binary.BigEndian.PutUint16(h[4:6], id) } }

// ipPacket returns an IPv4 packet from src to dst with a TTL of 64, the IP
// identification 0x0214 and a valid header checksum, after opts.
func ipPacket(src, dst netip.Addr, proto uint8, payload []byte, opts ...pktOpt) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], 0x0214)
	b[8] = 64
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[20:], payload)
	for _, opt := range opts {
		opt(b)
	}
	refreshHeaderSum(b)
	return b
}

// refreshHeaderSum recomputes the IPv4 header checksum of b.
func refreshHeaderSum(b []byte) {
	hl := int(b[0]&0x0f) * 4
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], ^inetSum(b[:hl]))
}

// inetSum is the 16-bit one's complement sum of the concatenated parts, the
// tests' own RFC 1071 arithmetic.
func inetSum(parts ...[]byte) uint16 {
	all := bytes.Join(parts, nil)
	var s uint32
	for i := 0; i < len(all); i += 2 {
		w := uint32(all[i]) << 8
		if i+1 < len(all) {
			w |= uint32(all[i+1])
		}
		s += w
	}
	for s > 0xffff {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

// pseudoHeader is the TCP and UDP pseudo header of a segment of length n.
func pseudoHeader(src, dst netip.Addr, proto uint8, n int) []byte {
	s, d := src.As4(), dst.As4()
	b := append(s[:], d[:]...)
	return append(b, 0, proto, byte(n>>8), byte(n))
}

// udpPacket returns a UDP datagram with a valid checksum.
func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte, opts ...pktOpt) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	sum := ^inetSum(pseudoHeader(src, dst, protoUDP, len(u)), u)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], sum)
	return ipPacket(src, dst, protoUDP, u, opts...)
}

// udpPacketNoSum returns a UDP datagram that carries no checksum.
func udpPacketNoSum(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	b := udpPacket(src, dst, sport, dport, payload)
	b[26], b[27] = 0, 0
	return b
}

// TCP flags of the test segments.
const (
	tcpSYN = 0x02
	tcpACK = 0x10
	tcpFIN = 0x01
)

// tcpPacket returns a TCP segment without options or payload.
func tcpPacket(src, dst netip.Addr, sport, dport uint16, flags uint8, opts ...pktOpt) []byte {
	s := make([]byte, 20)
	binary.BigEndian.PutUint16(s[0:2], sport)
	binary.BigEndian.PutUint16(s[2:4], dport)
	binary.BigEndian.PutUint32(s[4:8], 0x01020304)
	if flags&tcpACK != 0 {
		binary.BigEndian.PutUint32(s[8:12], 0x0a0b0c0d)
	}
	s[12] = 5 << 4
	s[13] = flags
	binary.BigEndian.PutUint16(s[14:16], 65535)
	binary.BigEndian.PutUint16(s[16:18], ^inetSum(pseudoHeader(src, dst, protoTCP, len(s)), s))
	return ipPacket(src, dst, protoTCP, s, opts...)
}

// echoPacket returns an ICMP echo request (icmpEchoRequest) or reply
// (icmpEchoReply) with id and seq.
func echoPacket(src, dst netip.Addr, typ uint8, id, seq uint16, opts ...pktOpt) []byte {
	m := make([]byte, 8+16)
	m[0] = typ
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	copy(m[8:], "plexd echo bytes")
	binary.BigEndian.PutUint16(m[2:4], ^inetSum(m))
	return ipPacket(src, dst, protoICMP, m, opts...)
}

// icmpMessage returns an ICMP message of typ and code with the rest of its
// header zero and body after it.
func icmpMessage(src, dst netip.Addr, typ, code uint8, body []byte, opts ...pktOpt) []byte {
	m := make([]byte, 8+len(body))
	m[0], m[1] = typ, code
	copy(m[8:], body)
	binary.BigEndian.PutUint16(m[2:4], ^inetSum(m))
	return ipPacket(src, dst, protoICMP, m, opts...)
}

// portUnreachable returns the ICMP port unreachable from src to dst that
// quotes quoted's header and the first 8 bytes after it.
func portUnreachable(src, dst netip.Addr, quoted []byte, opts ...pktOpt) []byte {
	hl := int(quoted[0]&0x0f) * 4
	return icmpMessage(src, dst, icmpUnreachable, 3, quoted[:hl+8], opts...)
}

// fragments splits the IPv4 packet b after at bytes of its payload, a multiple
// of 8, into a first fragment with MF and a later one.
func fragments(b []byte, at int) (first, later []byte) {
	hl := int(b[0]&0x0f) * 4
	first = append(append([]byte(nil), b[:hl]...), b[hl:hl+at]...)
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	binary.BigEndian.PutUint16(first[6:8], binary.BigEndian.Uint16(b[6:8])|0x2000)
	refreshHeaderSum(first)

	later = append(append([]byte(nil), b[:hl]...), b[hl+at:]...)
	binary.BigEndian.PutUint16(later[2:4], uint16(len(later)))
	binary.BigEndian.PutUint16(later[6:8], binary.BigEndian.Uint16(b[6:8])&0x4000|uint16(at/8))
	refreshHeaderSum(later)
	return first, later
}

// reassemble joins a first and a later fragment back into one packet.
func reassemble(first, later []byte) []byte {
	hl := int(first[0]&0x0f) * 4
	b := append(append([]byte(nil), first...), later[hl:]...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:8], 0)
	refreshHeaderSum(b)
	return b
}

func pktSrc(b []byte) netip.Addr   { return netip.AddrFrom4([4]byte(b[12:16])) }
func pktDst(b []byte) netip.Addr   { return netip.AddrFrom4([4]byte(b[16:20])) }
func pktTTL(b []byte) uint8        { return b[8] }
func pktProto(b []byte) uint8      { return b[9] }
func pktHL(b []byte) int           { return int(b[0]&0x0f) * 4 }
func pktSport(b []byte) uint16     { return binary.BigEndian.Uint16(b[pktHL(b):]) }
func pktDport(b []byte) uint16     { return binary.BigEndian.Uint16(b[pktHL(b)+2:]) }
func pktEchoID(b []byte) uint16    { return binary.BigEndian.Uint16(b[pktHL(b)+4:]) }
func pktICMPType(b []byte) uint8   { return b[pktHL(b)] }
func pktICMPCode(b []byte) uint8   { return b[pktHL(b)+1] }
func pktQuoted(b []byte) []byte    { return b[pktHL(b)+8:] }
func pktPayload(b []byte) []byte   { return b[pktHL(b):] }
func udpSum(b []byte) uint16       { return binary.BigEndian.Uint16(b[pktHL(b)+6:]) }
func headerSumOK(b []byte) bool    { return inetSum(b[:pktHL(b)]) == 0xffff }
func icmpSumOK(b []byte) bool      { return inetSum(pktPayload(b)) == 0xffff }
func quotedSumOK(q []byte) bool    { return inetSum(q[:pktHL(q)]) == 0xffff }
func pktMeshPort(port uint16) bool { return port >= meshPortFirst && port <= meshPortLast }

// transportSumOK reports whether the TCP, UDP or ICMP checksum of the whole
// packet b sums to 0xffff. A UDP checksum of 0 is none and fails.
func transportSumOK(b []byte) bool {
	p := pktPayload(b)
	switch pktProto(b) {
	case protoTCP, protoUDP:
		return inetSum(pseudoHeader(pktSrc(b), pktDst(b), pktProto(b), len(p)), p) == 0xffff
	case protoICMP:
		return inetSum(p) == 0xffff
	}
	return false
}

// ---------------------------------------------------------------------------
// The rules under test
// ---------------------------------------------------------------------------

// fakeNATDevice is a device the rules send packets to; only its MTU matters.
type fakeNATDevice struct {
	name string
	mtu  int
}

func (d *fakeNATDevice) MTU() (int, error) { return d.mtu, nil }

func (d *fakeNATDevice) String() string { return d.name }

// natTest is a meshNAT with the provider's rewrite from rwAccess and the
// tunnel's from rwTunnel into rwMesh, on a fake clock.
type natTest struct {
	n                    *meshNAT
	clock                *fakeClock
	mesh, access, tunnel *fakeNATDevice
}

func newNATTest(t *testing.T) *natTest {
	t.Helper()
	clock := &fakeClock{now: rwStart}
	nt := &natTest{
		n:      newMeshNAT(clock.Now),
		clock:  clock,
		mesh:   &fakeNATDevice{name: rwMesh, mtu: 1420},
		access: &fakeNATDevice{name: rwAccess, mtu: 1420},
		tunnel: &fakeNATDevice{name: rwTunnel, mtu: 1420},
	}
	nt.n.register(rwMesh, nt.mesh)
	nt.n.register(rwAccess, nt.access)
	nt.n.register(rwTunnel, nt.tunnel)
	if o := nt.n.addRewrite(rwAccess, rwMesh, rwMeshAddr, []netip.Prefix{rwPoolPrefix}); o != addAdded {
		t.Fatalf("addRewrite(%s) = %d, want added", rwAccess, o)
	}
	if o := nt.n.addRewrite(rwTunnel, rwMesh, rwMeshAddr, nil); o != addAdded {
		t.Fatalf("addRewrite(%s) = %d, want added", rwTunnel, o)
	}
	return nt
}

func (nt *natTest) advance(d time.Duration) { nt.clock.Set(nt.clock.Now().Add(d)) }

// decide runs pkt through the rules for the device iface and fails if they
// changed the caller's bytes.
func (nt *natTest) decide(t *testing.T, iface string, pkt []byte) natResult {
	t.Helper()
	before := bytes.Clone(pkt)
	res := nt.n.decide(iface, pkt)
	if !bytes.Equal(pkt, before) {
		t.Fatalf("decide(%s) changed the packet it was handed", iface)
	}
	return res
}

func (nt *natTest) fromAccess(t *testing.T, pkt []byte) natResult {
	t.Helper()
	return nt.decide(t, rwAccess, pkt)
}

func (nt *natTest) fromTunnel(t *testing.T, pkt []byte) natResult {
	t.Helper()
	return nt.decide(t, rwTunnel, pkt)
}

func (nt *natTest) fromMesh(t *testing.T, pkt []byte) natResult {
	t.Helper()
	return nt.decide(t, rwMesh, pkt)
}

// queued fails unless res queues a packet for to, and returns it.
func queued(t *testing.T, res natResult, to *fakeNATDevice) []byte {
	t.Helper()
	if res.action != natQueue {
		t.Fatalf("action = %d, want the packet queued for %s", res.action, to.name)
	}
	if res.to != natDevice(to) {
		t.Fatalf("queued for %v, want %s", res.to, to.name)
	}
	if !headerSumOK(res.out) {
		t.Errorf("translated packet's IPv4 header checksum does not sum to 0xffff")
	}
	return res.out
}

// passes fails unless res hands the packet to the host.
func passes(t *testing.T, res natResult, what string) {
	t.Helper()
	if res.action != natPass {
		t.Errorf("%s: action = %d, want it handed to the host unchanged", what, res.action)
	}
	if res.out != nil || res.icmp != nil {
		t.Errorf("%s: the rules produced a packet for one they hand to the host", what)
	}
}

// dropped fails unless res drops the packet.
func dropped(t *testing.T, res natResult, what string) {
	t.Helper()
	if res.action != natDrop {
		t.Errorf("%s: action = %d, want it dropped", what, res.action)
	}
}

// translateUDP sends a datagram from far:farPort to N:7001 through iface and
// returns the mesh port it left with.
func (nt *natTest) translateUDP(t *testing.T, iface string, far netip.Addr, farPort uint16) uint16 {
	t.Helper()
	out := queued(t, nt.decide(t, iface, udpPacket(far, rwNodeN, farPort, 7001, []byte("query"))), nt.mesh)
	if pktSrc(out) != rwMeshAddr || !pktMeshPort(pktSport(out)) {
		t.Fatalf("translated datagram from %s:%d, want %s and a mesh port", pktSrc(out), pktSport(out), rwMeshAddr)
	}
	return pktSport(out)
}

// testPackets returns a valid packet of every kind the rules read, from D to N
// and from N to D's mesh port, for the sweeps over packet prefixes.
func testPackets(meshPort uint16) map[string][]byte {
	translated := udpPacket(rwMeshAddr, rwNodeN, meshPort, 7001, []byte("query"))
	answer := udpPacket(rwNodeN, rwDeviceD, 7001, 5555, []byte("answer"))
	return map[string][]byte{
		"udp from D":          udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query")),
		"tcp from D":          tcpPacket(rwDeviceD, rwNodeN, 5556, 7001, tcpSYN),
		"echo from D":         echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1),
		"icmp error from D":   portUnreachable(rwDeviceD, rwNodeN, answer),
		"udp from N":          udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, []byte("answer")),
		"tcp from N":          tcpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, tcpSYN|tcpACK),
		"echo reply from N":   echoPacket(rwNodeN, rwMeshAddr, icmpEchoReply, meshPort, 1),
		"icmp error from N":   portUnreachable(rwNodeN, rwMeshAddr, translated),
		"icmp error, options": portUnreachable(rwNodeN, rwMeshAddr, withOptions(translated)),
	}
}

// withOptions returns b with 4 bytes of IP options (a NOP and an end of
// options list) after its header.
func withOptions(b []byte) []byte {
	out := append(append(append([]byte(nil), b[:20]...), 1, 0, 0, 0), b[20:]...)
	out[0] = 0x46
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	refreshHeaderSum(out)
	return out
}

func TestMeshRewriteRules_A1_NoPacketPasses(t *testing.T) {
	nt := newNATTest(t)
	ipv4TooShort := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	binary.BigEndian.PutUint16(ipv4TooShort[2:4], uint16(len(ipv4TooShort)+1))
	refreshHeaderSum(ipv4TooShort)
	badHL := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	badHL[0] = 0x44
	ipv6 := make([]byte, 48)
	ipv6[0] = 0x60
	ipv6[6] = protoUDP

	for name, pkt := range map[string][]byte{
		"zero length":               {},
		"ipv6":                      ipv6,
		"total length beyond bytes": ipv4TooShort,
		"header length below 20":    badHL,
	} {
		passes(t, nt.fromAccess(t, pkt), name+" from D")
		passes(t, nt.fromMesh(t, pkt), name+" from N")
	}
	if len(nt.n.flows) != 0 {
		t.Errorf("%d flows after packets the rules cannot read, want none", len(nt.n.flows))
	}
}

// Every prefix of every valid packet, with its total length as sent and with
// the total length cut to the prefix, goes through the rules of a source and
// of the mesh interface without a panic, while flows exist that the packets
// would match.
func TestMeshRewriteRules_A1_PrefixesDoNotPanic(t *testing.T) {
	nt := newNATTest(t)
	meshPort := nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
	queued(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, []byte("answer"))), nt.access)

	for name, pkt := range testPackets(meshPort) {
		for n := 0; n <= len(pkt); n++ {
			for _, cut := range []bool{false, true} {
				prefix := bytes.Clone(pkt[:n])
				if cut && n >= 20 {
					binary.BigEndian.PutUint16(prefix[2:4], uint16(n))
					refreshHeaderSum(prefix)
				}
				for _, iface := range []string{rwAccess, rwMesh} {
					func() {
						defer func() {
							if r := recover(); r != nil {
								t.Fatalf("%s, %d of %d bytes (total length cut %t) on %s: panic %v", name, n, len(pkt), cut, iface, r)
							}
						}()
						nt.decide(t, iface, prefix)
						nt.n.observe(iface, prefix)
					}()
				}
			}
		}
	}
}

func TestMeshRewriteRules_A2_ToTheHostPasses(t *testing.T) {
	nt := newNATTest(t)
	for _, dst := range []netip.Addr{
		rwMeshAddr,
		rwPoolAddr,
		netip.MustParseAddr("10.255.242.77"),
		netip.MustParseAddr("10.255.242.255"),
		netip.MustParseAddr("224.0.0.251"),
		netip.MustParseAddr("255.255.255.255"),
	} {
		pkt := udpPacket(rwDeviceD, dst, 5555, 5353, []byte("query"))
		passes(t, nt.fromAccess(t, pkt), "datagram from D to "+dst.String())
	}
	// The tunnel's interface carries no prefix, so only the mesh address,
	// multicast and broadcast are the host's.
	for _, dst := range []string{"10.255.241.1", "224.0.0.251", "255.255.255.255"} {
		pkt := udpPacket(rwSiteS, netip.MustParseAddr(dst), 5555, 5353, []byte("query"))
		passes(t, nt.fromTunnel(t, pkt), "datagram from S to "+dst)
	}
	if len(nt.n.flows) != 0 {
		t.Errorf("%d flows after packets for the host, want none", len(nt.n.flows))
	}
}

func TestMeshRewriteRules_A3_RepliesToHostFlowsPass(t *testing.T) {
	nt := newNATTest(t)

	// What a mesh node opened toward the site, which Windows forwarded out
	// of the tunnel's interface.
	for name, pkt := range map[string][]byte{
		"udp":  udpPacket(rwNodeN, rwSiteS, 5000, 7002, []byte("query")),
		"tcp":  tcpPacket(rwNodeN, rwSiteS, 5001, 7002, tcpSYN),
		"echo": echoPacket(rwNodeN, rwSiteS, icmpEchoRequest, 77, 1),
	} {
		if ok, _ := nt.n.observe(rwTunnel, pkt); !ok {
			t.Fatalf("observe(%s) = false, want the host's packet to pass", name)
		}
	}

	passes(t, nt.fromTunnel(t, udpPacket(rwSiteS, rwNodeN, 7002, 5000, []byte("answer"))), "S's answer")
	passes(t, nt.fromTunnel(t, tcpPacket(rwSiteS, rwNodeN, 7002, 5001, tcpSYN|tcpACK)), "S's SYN-ACK")
	passes(t, nt.fromTunnel(t, echoPacket(rwSiteS, rwNodeN, icmpEchoReply, 77, 1)), "S's echo reply")
	passes(t, nt.fromTunnel(t, portUnreachable(rwSiteS, rwNodeN, udpPacket(rwNodeN, rwSiteS, 5000, 7002, []byte("query")))),
		"S's port unreachable about N's datagram")

	// Both fragments of a fragmented answer are the host's.
	first, later := fragments(udpPacket(rwSiteS, rwNodeN, 7002, 5000, make([]byte, 56), withIPID(0x0a0a)), 32)
	passes(t, nt.fromTunnel(t, first), "first fragment of S's answer")
	passes(t, nt.fromTunnel(t, later), "later fragment of S's answer")

	// A datagram from another port is one S opens itself.
	out := queued(t, nt.fromTunnel(t, udpPacket(rwSiteS, rwNodeN, 7003, 5000, []byte("query"))), nt.mesh)
	if pktSrc(out) != rwMeshAddr {
		t.Errorf("S's datagram from another port left from %s, want %s", pktSrc(out), rwMeshAddr)
	}

	// The answered UDP host flow lives 120 s after its last packet, after
	// which S's next datagram is taken as opened by S.
	nt.advance(121 * time.Second)
	out = queued(t, nt.fromTunnel(t, udpPacket(rwSiteS, rwNodeN, 7002, 5000, []byte("late"))), nt.mesh)
	if pktSrc(out) != rwMeshAddr {
		t.Errorf("S's datagram after the host flow expired left from %s, want %s", pktSrc(out), rwMeshAddr)
	}
}

func TestMeshRewriteRules_A4B3_ICMPErrorsOfTranslatedFlows(t *testing.T) {
	nt := newNATTest(t)
	sent := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	translated := queued(t, nt.fromAccess(t, sent), nt.mesh)
	meshPort := pktSport(translated)

	// B3: N's port unreachable about the datagram as N read it.
	out := queued(t, nt.fromMesh(t, portUnreachable(rwNodeN, rwMeshAddr, translated)), nt.access)
	q := pktQuoted(out)
	if pktSrc(out) != rwNodeN || pktDst(out) != rwDeviceD {
		t.Errorf("B3: outer %s -> %s, want %s -> %s", pktSrc(out), pktDst(out), rwNodeN, rwDeviceD)
	}
	if pktSrc(q) != rwDeviceD || pktSport(q) != 5555 || pktDst(q) != rwNodeN || pktDport(q) != 7001 {
		t.Errorf("B3: quoted %s:%d -> %s:%d, want %s:5555 -> %s:7001", pktSrc(q), pktSport(q), pktDst(q), pktDport(q), rwDeviceD, rwNodeN)
	}
	if !icmpSumOK(out) || !quotedSumOK(q) {
		t.Errorf("B3: ICMP checksum ok = %t, quoted header checksum ok = %t, want both", icmpSumOK(out), quotedSumOK(q))
	}
	// The quoted UDP checksum is left as the datagram N read carried it.
	if got, want := binary.BigEndian.Uint16(q[26:28]), udpSum(translated); got != want {
		t.Errorf("B3: quoted UDP checksum = %#04x, want it left at %#04x", got, want)
	}

	// A4: D's port unreachable about N's answer as D read it.
	answer := queued(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, []byte("answer"))), nt.access)
	out = queued(t, nt.fromAccess(t, portUnreachable(rwDeviceD, rwNodeN, answer)), nt.mesh)
	q = pktQuoted(out)
	if pktSrc(out) != rwMeshAddr || pktDst(out) != rwNodeN {
		t.Errorf("A4: outer %s -> %s, want %s -> %s", pktSrc(out), pktDst(out), rwMeshAddr, rwNodeN)
	}
	if pktSrc(q) != rwNodeN || pktSport(q) != 7001 || pktDst(q) != rwMeshAddr || pktDport(q) != meshPort {
		t.Errorf("A4: quoted %s:%d -> %s:%d, want %s:7001 -> %s:%d", pktSrc(q), pktSport(q), pktDst(q), pktDport(q), rwNodeN, rwMeshAddr, meshPort)
	}
	if !icmpSumOK(out) || !quotedSumOK(q) {
		t.Errorf("A4: ICMP checksum ok = %t, quoted header checksum ok = %t, want both", icmpSumOK(out), quotedSumOK(q))
	}

	// The same for an echo: N's error about the request, D's about the
	// reply.
	request := queued(t, nt.fromAccess(t, echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1)), nt.mesh)
	out = queued(t, nt.fromMesh(t, portUnreachable(rwNodeN, rwMeshAddr, request)), nt.access)
	if q := pktQuoted(out); pktSrc(q) != rwDeviceD || pktEchoID(q) != 0x1234 || !icmpSumOK(out) || !quotedSumOK(q) {
		t.Errorf("B3 echo: quoted source %s id %#x, sums %t %t, want %s id 0x1234 and valid sums", pktSrc(q), pktEchoID(q), icmpSumOK(out), quotedSumOK(q), rwDeviceD)
	}
	reply := queued(t, nt.fromMesh(t, echoPacket(rwNodeN, rwMeshAddr, icmpEchoReply, pktEchoID(request), 1)), nt.access)
	out = queued(t, nt.fromAccess(t, portUnreachable(rwDeviceD, rwNodeN, reply)), nt.mesh)
	if q := pktQuoted(out); pktDst(q) != rwMeshAddr || pktEchoID(q) != pktEchoID(request) || !icmpSumOK(out) || !quotedSumOK(q) {
		t.Errorf("A4 echo: quoted destination %s id %#x, want %s id %#x and valid sums", pktDst(q), pktEchoID(q), rwMeshAddr, pktEchoID(request))
	}

	// An error about a packet of no flow is the host's on the mesh side and
	// unsupported from a far end.
	passes(t, nt.fromMesh(t, portUnreachable(rwNodeN, rwMeshAddr, udpPacket(rwMeshAddr, rwNodeN, 40000, 7001, nil))), "N's error about no flow")
	dropped(t, nt.fromAccess(t, portUnreachable(rwDeviceD, rwNodeN, udpPacket(rwNodeN, rwDeviceD, 7001, 9, nil))), "D's error about no flow")
	if got := nt.n.dropCount(dropUnsupportedProtocol); got != 1 {
		t.Errorf("unsupported_protocol drops = %d, want 1", got)
	}
}

func TestMeshRewriteRules_A5B2_Fragments(t *testing.T) {
	nt := newNATTest(t)
	sent := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, bytes.Repeat([]byte("D"), 56), withIPID(0x0b0b))
	first, later := fragments(sent, 32)

	outFirst := queued(t, nt.fromAccess(t, first), nt.mesh)
	outLater := queued(t, nt.fromAccess(t, later), nt.mesh)
	for name, out := range map[string][]byte{"first": outFirst, "later": outLater} {
		if pktSrc(out) != rwMeshAddr {
			t.Errorf("%s fragment from D left from %s, want %s", name, pktSrc(out), rwMeshAddr)
		}
	}
	whole := reassemble(outFirst, outLater)
	meshPort := pktSport(whole)
	if !pktMeshPort(meshPort) || !transportSumOK(whole) {
		t.Errorf("reassembled datagram: source port %d, UDP checksum ok = %t, want a mesh port and a valid checksum", meshPort, transportSumOK(whole))
	}

	answer := udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, bytes.Repeat([]byte("N"), 56), withIPID(0x0c0c))
	first, later = fragments(answer, 32)
	outFirst = queued(t, nt.fromMesh(t, first), nt.access)
	outLater = queued(t, nt.fromMesh(t, later), nt.access)
	for name, out := range map[string][]byte{"first": outFirst, "later": outLater} {
		if pktDst(out) != rwDeviceD {
			t.Errorf("%s fragment of N's answer went to %s, want %s", name, pktDst(out), rwDeviceD)
		}
	}
	if whole := reassemble(outFirst, outLater); pktDport(whole) != 5555 || !transportSumOK(whole) {
		t.Errorf("reassembled answer: destination port %d, UDP checksum ok = %t, want 5555 and a valid checksum", pktDport(whole), transportSumOK(whole))
	}

	// A later fragment whose first fragment left no record.
	_, orphan := fragments(udpPacket(rwDeviceD, rwNodeN, 5555, 7001, make([]byte, 56), withIPID(0x0d0d)), 32)
	dropped(t, nt.fromAccess(t, orphan), "later fragment without a record")
	if got := nt.n.dropCount(dropFragment); got != 1 {
		t.Errorf("fragment drops = %d, want 1", got)
	}
	// On the mesh side it is the host's.
	_, orphan = fragments(udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, make([]byte, 56), withIPID(0x0e0e)), 32)
	passes(t, nt.fromMesh(t, orphan), "N's later fragment without a record")

	// A record lives 30 s after its last fragment.
	nt.advance(fragmentRecordLifetime)
	_, later = fragments(sent, 32)
	dropped(t, nt.fromAccess(t, later), "later fragment 30 s after the record's last use")
}

func TestMeshRewriteRules_A6_UnsupportedProtocolsDrop(t *testing.T) {
	nt := newNATTest(t)
	dropped(t, nt.fromAccess(t, ipPacket(rwDeviceD, rwNodeN, 47, make([]byte, 24))), "GRE")
	dropped(t, nt.fromAccess(t, icmpMessage(rwDeviceD, rwNodeN, 13, 0, make([]byte, 12))), "ICMP timestamp request")
	dropped(t, nt.fromAccess(t, echoPacket(rwDeviceD, rwNodeN, icmpEchoReply, 9, 1)), "echo reply that answers nothing")
	if got := nt.n.dropCount(dropUnsupportedProtocol); got != 3 {
		t.Errorf("unsupported_protocol drops = %d, want 3", got)
	}
	if len(nt.n.flows) != 0 {
		t.Errorf("%d flows, want none", len(nt.n.flows))
	}
}

// cutShort returns packets from src to dst whose IPv4 header length and
// total length fit their bytes but whose TCP, UDP or ICMP header does not.
func cutShort(src, dst netip.Addr) map[string][]byte {
	tinyFragment, _ := fragments(tcpPacket(src, dst, 5556, 7001, tcpSYN), 8)
	return map[string][]byte{
		"udp header of 3 bytes":              ipPacket(src, dst, protoUDP, []byte{0x15, 0xb3, 0x1b}),
		"tcp header of 8 bytes with ttl 1":   ipPacket(src, dst, protoTCP, tcpPacket(src, dst, 5556, 7001, tcpSYN)[20:28], withTTL(1)),
		"echo request of 4 bytes":            ipPacket(src, dst, protoICMP, echoPacket(src, dst, icmpEchoRequest, 9, 1)[20:24]),
		"first fragment with 8 bytes of tcp": tinyFragment,
		"echo request of 4 bytes with ttl 0": ipPacket(src, dst, protoICMP, echoPacket(src, dst, icmpEchoRequest, 9, 1)[20:24], withTTL(0)),
	}
}

// A far end's packet whose TCP, UDP or ICMP header is cut short is no TCP,
// UDP or ICMP echo request the rewrite carries: row A6 drops it before row A7
// looks at its TTL, so Windows never forwards it with the far end's own
// source. Row A2 still hands the host what is for the host, and a mesh peer's
// such packet is the host's (row B4).
func TestMeshRewriteRules_A6_CutShortHeadersDrop(t *testing.T) {
	nt := newNATTest(t)
	fromD := cutShort(rwDeviceD, rwNodeN)
	for name, pkt := range fromD {
		res := nt.fromAccess(t, pkt)
		dropped(t, res, name+" from D")
		if res.out != nil || res.icmp != nil {
			t.Errorf("%s from D: the rules produced a packet for one they drop", name)
		}
	}
	if got := nt.n.dropCount(dropUnsupportedProtocol); got != uint64(len(fromD)) {
		t.Errorf("unsupported_protocol drops = %d, want %d", got, len(fromD))
	}
	if got := nt.n.dropCount(dropTTL); got != 0 {
		t.Errorf("ttl drops = %d, want none", got)
	}

	for name, pkt := range cutShort(rwDeviceD, rwMeshAddr) {
		passes(t, nt.fromAccess(t, pkt), name+" from D to the mesh address")
	}
	for name, pkt := range cutShort(rwNodeN, rwMeshAddr) {
		passes(t, nt.fromMesh(t, pkt), name+" from N")
	}
	if len(nt.n.flows) != 0 || len(nt.n.frags) != 0 {
		t.Errorf("%d flows and %d fragment records, want none", len(nt.n.flows), len(nt.n.frags))
	}
}

func TestMeshRewriteRules_A7_TTLExpires(t *testing.T) {
	for _, ttl := range []uint8{1, 0} {
		t.Run(fmt.Sprintf("ttl %d", ttl), func(t *testing.T) {
			nt := newNATTest(t)
			sent := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query payload"), withTTL(ttl))
			res := nt.fromAccess(t, sent)
			dropped(t, res, "datagram")
			if got := nt.n.dropCount(dropTTL); got != 1 {
				t.Errorf("ttl drops = %d, want 1", got)
			}
			if res.icmp == nil || res.icmpTo != natDevice(nt.access) {
				t.Fatalf("ICMP error = %x for %v, want one for %s", res.icmp, res.icmpTo, rwAccess)
			}
			e := res.icmp
			if pktSrc(e) != rwMeshAddr || pktDst(e) != rwDeviceD || pktICMPType(e) != 11 || pktICMPCode(e) != 0 {
				t.Errorf("ICMP %s -> %s type %d code %d, want %s -> %s type 11 code 0", pktSrc(e), pktDst(e), pktICMPType(e), pktICMPCode(e), rwMeshAddr, rwDeviceD)
			}
			if want := sent[:28]; !bytes.Equal(pktQuoted(e), want) {
				t.Errorf("quoted = %x, want the header and first 8 bytes %x", pktQuoted(e), want)
			}
			if !headerSumOK(e) || !icmpSumOK(e) {
				t.Errorf("ICMP error checksums ok = %t, %t, want both", headerSumOK(e), icmpSumOK(e))
			}
		})
	}
}

func TestMeshRewriteRules_A8_OversizeDrops(t *testing.T) {
	nt := newNATTest(t)
	nt.mesh.mtu = 1280

	sent := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, make([]byte, 1400-28), withDF())
	res := nt.fromAccess(t, sent)
	dropped(t, res, "1400-byte datagram with DF")
	if res.icmp == nil || res.icmpTo != natDevice(nt.access) {
		t.Fatalf("ICMP error = %x for %v, want one for %s", res.icmp, res.icmpTo, rwAccess)
	}
	e := res.icmp
	if pktSrc(e) != rwMeshAddr || pktDst(e) != rwDeviceD || pktICMPType(e) != 3 || pktICMPCode(e) != 4 {
		t.Errorf("ICMP %s -> %s type %d code %d, want %s -> %s type 3 code 4", pktSrc(e), pktDst(e), pktICMPType(e), pktICMPCode(e), rwMeshAddr, rwDeviceD)
	}
	if mtu := binary.BigEndian.Uint16(e[26:28]); mtu != 1280 {
		t.Errorf("next-hop MTU = %d, want 1280", mtu)
	}
	if !headerSumOK(e) || !icmpSumOK(e) {
		t.Errorf("ICMP error checksums ok = %t, %t, want both", headerSumOK(e), icmpSumOK(e))
	}

	res = nt.fromAccess(t, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, make([]byte, 1400-28)))
	dropped(t, res, "1400-byte datagram without DF")
	if res.icmp != nil {
		t.Errorf("ICMP error %x for a datagram without DF, want none", res.icmp)
	}
	if got := nt.n.dropCount(dropOversize); got != 1 {
		t.Errorf("oversize drops = %d, want 1", got)
	}

	queued(t, nt.fromAccess(t, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, make([]byte, 1280-28), withDF())), nt.mesh)
}

func TestMeshRewriteRules_A9_Translates(t *testing.T) {
	nt := newNATTest(t)
	for _, tc := range []struct {
		name   string
		pkt    []byte
		port   func([]byte) uint16
		header int // the transport header's length, after which the payload starts
	}{
		{"udp", udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"), withTTL(50)), pktSport, 8},
		{"tcp", tcpPacket(rwDeviceD, rwNodeN, 5556, 7001, tcpSYN, withTTL(50)), pktSport, 20},
		{"echo", echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1, withTTL(50)), pktEchoID, 8},
	} {
		out := queued(t, nt.fromAccess(t, tc.pkt), nt.mesh)
		if pktSrc(out) != rwMeshAddr || pktDst(out) != rwNodeN {
			t.Errorf("%s: %s -> %s, want %s -> %s", tc.name, pktSrc(out), pktDst(out), rwMeshAddr, rwNodeN)
		}
		if !pktMeshPort(tc.port(out)) {
			t.Errorf("%s: mesh port or id %d, want one from %d to %d", tc.name, tc.port(out), meshPortFirst, meshPortLast)
		}
		if pktTTL(out) != 49 {
			t.Errorf("%s: TTL = %d, want 49", tc.name, pktTTL(out))
		}
		if !transportSumOK(out) {
			t.Errorf("%s: transport checksum does not sum to 0xffff", tc.name)
		}
		if !bytes.Equal(out[pktHL(out)+tc.header:], tc.pkt[pktHL(tc.pkt)+tc.header:]) {
			t.Errorf("%s: payload changed", tc.name)
		}
	}

	out := queued(t, nt.fromAccess(t, udpPacketNoSum(rwDeviceD, rwNodeN, 5557, 7001, []byte("query"))), nt.mesh)
	if udpSum(out) != 0 {
		t.Errorf("UDP checksum = %#04x, want a checksum of 0 left at 0", udpSum(out))
	}

	// A second packet of a flow keeps its mesh port.
	first := nt.translateUDP(t, rwAccess, rwDeviceD, 6000)
	if again := nt.translateUDP(t, rwAccess, rwDeviceD, 6000); again != first {
		t.Errorf("second datagram of a flow left from port %d, want %d", again, first)
	}
}

func TestMeshRewriteRules_MeshPortsPerFarEnd(t *testing.T) {
	nt := newNATTest(t)
	portD := nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
	portD2 := nt.translateUDP(t, rwAccess, rwDeviceD2, 5555)
	if portD == portD2 {
		t.Fatalf("both far ends left with mesh port %d, want two", portD)
	}
	span := uint32(meshPortLast-meshPortFirst) + 1
	if want := meshPortFirst + uint16(farEndHash(rwDeviceD, 5555)%span); portD != want {
		t.Errorf("D's mesh port = %d, want %d where the search from the hash of its address and port starts", portD, want)
	}
	for _, tc := range []struct {
		port uint16
		want netip.Addr
	}{{portD, rwDeviceD}, {portD2, rwDeviceD2}} {
		out := queued(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, tc.port, []byte("answer"))), nt.access)
		if pktDst(out) != tc.want || pktDport(out) != 5555 {
			t.Errorf("answer to mesh port %d went to %s:%d, want %s:5555", tc.port, pktDst(out), pktDport(out), tc.want)
		}
	}
}

func TestMeshRewriteRules_B1_TranslatesReplies(t *testing.T) {
	nt := newNATTest(t)
	udpPort := nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
	tcpOut := queued(t, nt.fromAccess(t, tcpPacket(rwDeviceD, rwNodeN, 5556, 7001, tcpSYN)), nt.mesh)
	echoOut := queued(t, nt.fromAccess(t, echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1)), nt.mesh)

	for _, tc := range []struct {
		name     string
		pkt      []byte
		wantPort uint16
		port     func([]byte) uint16
	}{
		{"udp", udpPacket(rwNodeN, rwMeshAddr, 7001, udpPort, []byte("answer"), withTTL(50)), 5555, pktDport},
		{"tcp", tcpPacket(rwNodeN, rwMeshAddr, 7001, pktSport(tcpOut), tcpSYN|tcpACK, withTTL(50)), 5556, pktDport},
		{"echo", echoPacket(rwNodeN, rwMeshAddr, icmpEchoReply, pktEchoID(echoOut), 1, withTTL(50)), 0x1234, pktEchoID},
	} {
		out := queued(t, nt.fromMesh(t, tc.pkt), nt.access)
		if pktSrc(out) != rwNodeN || pktDst(out) != rwDeviceD || tc.port(out) != tc.wantPort {
			t.Errorf("%s: %s -> %s port %d, want %s -> %s port %d", tc.name, pktSrc(out), pktDst(out), tc.port(out), rwNodeN, rwDeviceD, tc.wantPort)
		}
		if pktTTL(out) != 49 || !transportSumOK(out) {
			t.Errorf("%s: TTL %d, transport checksum ok = %t, want 49 and a valid checksum", tc.name, pktTTL(out), transportSumOK(out))
		}
	}

	dropped(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, udpPort, nil, withTTL(1))), "N's answer with TTL 1")
	if got := nt.n.dropCount(dropTTL); got != 1 {
		t.Errorf("ttl drops = %d, want 1", got)
	}

	nt.access.mtu = 1280
	res := nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, udpPort, make([]byte, 1400-28), withDF()))
	dropped(t, res, "N's 1400-byte answer with DF")
	if res.icmp == nil || res.icmpTo != natDevice(nt.mesh) {
		t.Fatalf("ICMP error = %x for %v, want one for %s", res.icmp, res.icmpTo, rwMesh)
	}
	if e := res.icmp; pktSrc(e) != rwMeshAddr || pktDst(e) != rwNodeN || pktICMPType(e) != 3 || pktICMPCode(e) != 4 || binary.BigEndian.Uint16(e[26:28]) != 1280 {
		t.Errorf("ICMP %s -> %s type %d code %d MTU %d, want %s -> %s type 3 code 4 MTU 1280", pktSrc(e), pktDst(e), pktICMPType(e), pktICMPCode(e), binary.BigEndian.Uint16(e[26:28]), rwMeshAddr, rwNodeN)
	}
	dropped(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, udpPort, make([]byte, 1400-28))), "N's 1400-byte answer without DF")
	if got := nt.n.dropCount(dropOversize); got != 1 {
		t.Errorf("oversize drops = %d, want 1", got)
	}
}

func TestMeshRewriteRules_B4_OtherPacketsPass(t *testing.T) {
	nt := newNATTest(t)
	nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
	passes(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, 40000, []byte("x"))), "N's datagram to a port no flow holds")
	passes(t, nt.fromMesh(t, udpPacket(rwNodeN, rwSiteS, 5000, 7002, []byte("x"))), "N's datagram to a site address")
	passes(t, nt.fromMesh(t, echoPacket(rwNodeN, rwMeshAddr, icmpEchoRequest, 40000, 1)), "N's echo request to the mesh address")
	passes(t, nt.fromMesh(t, tcpPacket(rwNodeN, rwMeshAddr, 7001, 22, tcpSYN)), "N's SYN to the host")
}

func TestMeshRewriteRules_Lifetimes(t *testing.T) {
	answerUDP := func(port uint16) []byte { return udpPacket(rwNodeN, rwMeshAddr, 7001, port, []byte("answer")) }
	answerTCP := func(port uint16) []byte { return tcpPacket(rwNodeN, rwMeshAddr, 7001, port, tcpACK) }
	openTCP := func(t *testing.T, nt *natTest, answered bool) uint16 {
		t.Helper()
		port := pktSport(queued(t, nt.fromAccess(t, tcpPacket(rwDeviceD, rwNodeN, 5556, 7001, tcpSYN)), nt.mesh))
		if answered {
			queued(t, nt.fromMesh(t, tcpPacket(rwNodeN, rwMeshAddr, 7001, port, tcpSYN|tcpACK)), nt.access)
		}
		return port
	}

	for _, tc := range []struct {
		name  string
		open  func(*testing.T, *natTest) uint16
		reply func(uint16) []byte
		after time.Duration
		alive bool
	}{
		{"unanswered udp at 29 s", func(t *testing.T, nt *natTest) uint16 { return nt.translateUDP(t, rwAccess, rwDeviceD, 5555) }, answerUDP, 29 * time.Second, true},
		{"unanswered udp at 31 s", func(t *testing.T, nt *natTest) uint16 { return nt.translateUDP(t, rwAccess, rwDeviceD, 5555) }, answerUDP, 31 * time.Second, false},
		{"answered udp at 119 s", func(t *testing.T, nt *natTest) uint16 {
			p := nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
			queued(t, nt.fromMesh(t, answerUDP(p)), nt.access)
			return p
		}, answerUDP, 119 * time.Second, true},
		{"answered udp at 121 s", func(t *testing.T, nt *natTest) uint16 {
			p := nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
			queued(t, nt.fromMesh(t, answerUDP(p)), nt.access)
			return p
		}, answerUDP, 121 * time.Second, false},
		{"one-way tcp at 119 s", func(t *testing.T, nt *natTest) uint16 { return openTCP(t, nt, false) }, answerTCP, 119 * time.Second, true},
		{"one-way tcp at 121 s", func(t *testing.T, nt *natTest) uint16 { return openTCP(t, nt, false) }, answerTCP, 121 * time.Second, false},
		{"two-way tcp at 431999 s", func(t *testing.T, nt *natTest) uint16 { return openTCP(t, nt, true) }, answerTCP, 431999 * time.Second, true},
		{"two-way tcp at 432001 s", func(t *testing.T, nt *natTest) uint16 { return openTCP(t, nt, true) }, answerTCP, 432001 * time.Second, false},
		{"tcp after FIN at 121 s", func(t *testing.T, nt *natTest) uint16 {
			p := openTCP(t, nt, true)
			queued(t, nt.fromAccess(t, tcpPacket(rwDeviceD, rwNodeN, 5556, 7001, tcpFIN|tcpACK)), nt.mesh)
			return p
		}, answerTCP, 121 * time.Second, false},
		{"echo at 29 s", func(t *testing.T, nt *natTest) uint16 {
			return pktEchoID(queued(t, nt.fromAccess(t, echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1)), nt.mesh))
		}, func(id uint16) []byte { return echoPacket(rwNodeN, rwMeshAddr, icmpEchoReply, id, 1) }, 29 * time.Second, true},
		{"echo at 31 s", func(t *testing.T, nt *natTest) uint16 {
			return pktEchoID(queued(t, nt.fromAccess(t, echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1)), nt.mesh))
		}, func(id uint16) []byte { return echoPacket(rwNodeN, rwMeshAddr, icmpEchoReply, id, 1) }, 31 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nt := newNATTest(t)
			port := tc.open(t, nt)
			nt.advance(tc.after)
			res := nt.fromMesh(t, tc.reply(port))
			if tc.alive {
				queued(t, res, nt.access)
			} else {
				passes(t, res, "reply after the flow expired")
			}
		})
	}
}

// Packet handling removes expired entries at most every 30 s; between two
// sweeps only a lookup does.
func TestMeshRewriteRules_SweepsEvery30s(t *testing.T) {
	nt := newNATTest(t)
	nt.translateUDP(t, rwAccess, rwDeviceD, 5001) // A, swept at the first packet
	nt.advance(20 * time.Second)
	nt.translateUDP(t, rwAccess, rwDeviceD, 5002) // B

	other := udpPacket(rwNodeN, rwSiteS, 5000, 7002, nil)
	nt.advance(15 * time.Second) // A expired 5 s ago, the last sweep was 35 s ago
	passes(t, nt.fromMesh(t, other), "unrelated packet")
	if got := len(nt.n.flows); got != 1 {
		t.Fatalf("%d flows after the sweep, want B alone", got)
	}

	nt.advance(20 * time.Second) // B expired 5 s ago, the last sweep was 20 s ago
	passes(t, nt.fromMesh(t, other), "unrelated packet")
	if got := len(nt.n.flows); got != 1 {
		t.Errorf("%d flows 20 s after the last sweep, want the expired B still held", got)
	}
	nt.advance(10 * time.Second)
	passes(t, nt.fromMesh(t, other), "unrelated packet")
	if got := len(nt.n.flows); got != 0 {
		t.Errorf("%d flows 30 s after the last sweep, want none", got)
	}
}

func TestMeshRewriteRules_TableFull(t *testing.T) {
	t.Run("flow limit", func(t *testing.T) {
		nt := newNATTest(t)
		nt.n.maxFlows = 4
		for port := uint16(5001); port <= 5004; port++ {
			nt.translateUDP(t, rwAccess, rwDeviceD, port)
		}
		dropped(t, nt.fromAccess(t, udpPacket(rwDeviceD, rwNodeN, 5005, 7001, nil)), "fifth flow")
		if got := nt.n.dropCount(dropTableFull); got != 1 {
			t.Errorf("table_full drops = %d, want 1", got)
		}
		for port := uint16(5001); port <= 5004; port++ {
			nt.translateUDP(t, rwAccess, rwDeviceD, port)
		}
	})

	t.Run("two mesh ports", func(t *testing.T) {
		nt := newNATTest(t)
		nt.n.portFirst, nt.n.portLast = 40000, 40001
		nt.translateUDP(t, rwAccess, rwDeviceD, 6001)
		nt.translateUDP(t, rwAccess, rwDeviceD, 6002)
		dropped(t, nt.fromAccess(t, udpPacket(rwDeviceD, rwNodeN, 6003, 7001, nil)), "third flow to N:7001")
		if got := nt.n.dropCount(dropTableFull); got != 1 {
			t.Errorf("table_full drops = %d, want 1", got)
		}
		out := queued(t, nt.fromAccess(t, udpPacket(rwDeviceD, rwNodeN, 6003, 7002, nil)), nt.mesh)
		if p := pktSport(out); p != 40000 && p != 40001 {
			t.Errorf("flow to N:7002 left from port %d, want 40000 or 40001", p)
		}
	})

	t.Run("host flow limit", func(t *testing.T) {
		nt := newNATTest(t)
		nt.n.maxHostFlows = 2
		for port := uint16(5001); port <= 5002; port++ {
			if ok, _ := nt.n.observe(rwTunnel, udpPacket(rwNodeN, rwSiteS, port, 7002, nil)); !ok {
				t.Fatalf("observe of host flow %d = false, want true", port)
			}
		}
		ok, reports := nt.n.observe(rwTunnel, udpPacket(rwNodeN, rwSiteS, 5003, 7002, nil))
		if ok {
			t.Error("observe of a third host flow = true, want it dropped")
		}
		if len(reports) != 1 || reports[0] != (dropReport{reason: dropTableFull, count: 1}) {
			t.Errorf("reports = %v, want one table_full of 1", reports)
		}
		if ok, _ := nt.n.observe(rwTunnel, udpPacket(rwNodeN, rwSiteS, 5001, 7002, nil)); !ok {
			t.Error("observe of an existing host flow = false, want true")
		}
	})
}

func TestMeshRewriteRules_ICMPErrorsPerSecond(t *testing.T) {
	nt := newNATTest(t)
	expiring := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, nil, withTTL(1))
	sent := 0
	for range 101 {
		if res := nt.fromAccess(t, expiring); res.icmp != nil {
			sent++
		}
		nt.advance(9 * time.Millisecond)
	}
	if sent != 100 {
		t.Errorf("sent %d ICMP errors within one second, want 100", sent)
	}
	if got := nt.n.dropCount(dropTTL); got != 101 {
		t.Errorf("ttl drops = %d, want 101", got)
	}
	nt.advance(100 * time.Millisecond)
	if res := nt.fromAccess(t, expiring); res.icmp == nil {
		t.Error("no ICMP error in the next second")
	}

	// None about an ICMP error, translated or unsupported, or a later
	// fragment, with a record or without.
	meshPort := nt.translateUDP(t, rwAccess, rwDeviceD, 6000)
	answer := queued(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, nil)), nt.access)
	first, _ := fragments(udpPacket(rwDeviceD, rwNodeN, 6001, 7001, make([]byte, 56), withIPID(7)), 32)
	queued(t, nt.fromAccess(t, first), nt.mesh)
	_, laterTTL := fragments(udpPacket(rwDeviceD, rwNodeN, 6001, 7001, make([]byte, 56), withIPID(7), withTTL(1)), 32)
	_, orphan := fragments(udpPacket(rwDeviceD, rwNodeN, 6001, 7001, make([]byte, 56), withIPID(8), withTTL(1)), 32)
	for name, pkt := range map[string][]byte{
		"ICMP error about a translated flow": portUnreachable(rwDeviceD, rwNodeN, answer, withTTL(1)),
		"unsupported ICMP error":             icmpMessage(rwDeviceD, rwNodeN, icmpUnreachable, 1, make([]byte, 28), withTTL(1)),
		"later fragment with a record":       laterTTL,
		"later fragment without a record":    orphan,
	} {
		if res := nt.fromAccess(t, pkt); res.icmp != nil {
			t.Errorf("%s with TTL 1: ICMP error %x, want none", name, res.icmp)
		}
	}
	res := natResult{}
	if p, ok := parseIPv4(portUnreachable(rwDeviceD, rwNodeN, answer)); ok {
		nt.n.sendICMPError(&res, rwAccess, rwMeshAddr, p, icmpTimeExceeded, 0, 0, nt.clock.Now())
	}
	if res.icmp != nil {
		t.Errorf("sendICMPError about an ICMP error built %x, want nothing", res.icmp)
	}
}

func TestMeshRewriteRules_DropReports(t *testing.T) {
	nt := newNATTest(t)
	expiring := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, nil, withTTL(1))
	gre := ipPacket(rwDeviceD, rwNodeN, 47, make([]byte, 24))

	if got := nt.fromAccess(t, expiring).reports; len(got) != 1 || got[0] != (dropReport{dropTTL, 1}) {
		t.Errorf("first ttl drop reports %v, want ttl 1", got)
	}
	if got := nt.fromAccess(t, gre).reports; len(got) != 1 || got[0] != (dropReport{dropUnsupportedProtocol, 1}) {
		t.Errorf("first unsupported drop reports %v, want unsupported_protocol 1", got)
	}
	for range 3 {
		nt.advance(10 * time.Second)
		if got := nt.fromAccess(t, expiring).reports; len(got) != 0 {
			t.Errorf("ttl drop within 60 s reports %v, want nothing", got)
		}
	}
	nt.advance(30 * time.Second)
	if got := nt.fromAccess(t, expiring).reports; len(got) != 1 || got[0] != (dropReport{dropTTL, 4}) {
		t.Errorf("ttl drop 60 s after the last report reports %v, want ttl 4", got)
	}

	// A count that waits is reported by the next packet 60 s after the last
	// report, whatever becomes of that packet.
	nt.advance(10 * time.Second)
	if got := nt.fromAccess(t, expiring).reports; len(got) != 0 {
		t.Errorf("ttl drop 10 s after a report reports %v, want nothing", got)
	}
	nt.advance(50 * time.Second)
	if got := nt.fromMesh(t, udpPacket(rwNodeN, rwSiteS, 5000, 7002, nil)).reports; len(got) != 1 || got[0] != (dropReport{dropTTL, 1}) {
		t.Errorf("packet 60 s after the last report reports %v, want the waiting ttl 1", got)
	}

	if got := nt.n.dropped(dropQueueFull); len(got) != 1 || got[0] != (dropReport{dropQueueFull, 1}) {
		t.Errorf("first queue_full reports %v, want queue_full 1", got)
	}
	if got := nt.n.dropped(dropQueueFull); len(got) != 0 {
		t.Errorf("second queue_full reports %v, want nothing", got)
	}
}

func TestMeshRewriteRules_DropReasonNames(t *testing.T) {
	want := []string{"queue_full", "fragment", "unsupported_protocol", "ttl", "oversize", "table_full"}
	for i, w := range want {
		if got := dropReason(i).String(); got != w {
			t.Errorf("dropReason(%d) = %q, want %q", i, got, w)
		}
	}
}

func TestMeshRewriteRules_Rewrites(t *testing.T) {
	nt := newNATTest(t)
	meshPort := nt.translateUDP(t, rwAccess, rwDeviceD, 5555)

	for _, tc := range []struct {
		from, mesh string
		want       addOutcome
	}{
		{rwAccess, rwMesh, addPresent},
		{"wg-ua-unknown", rwMesh, addNoSource},
		{rwAccess, "plexd9", addNoMesh},
		{"wg-ua-unknown", "plexd9", addNoMesh},
	} {
		if got := nt.n.checkRewrite(tc.from, tc.mesh); got != tc.want {
			t.Errorf("checkRewrite(%s, %s) = %d, want %d", tc.from, tc.mesh, got, tc.want)
		}
	}
	if o := nt.n.addRewrite(rwAccess, rwTunnel, rwSiteS, nil); o != addPresent {
		t.Errorf("second addRewrite = %d, want present", o)
	}
	if got := nt.n.rewrites[rwAccess]; got.mesh != rwMesh || got.meshAddr != rwMeshAddr {
		t.Errorf("rewrite after a second add = %+v, want it unchanged", got)
	}
	if o := nt.n.addRewrite("wg-ua-unknown", rwMesh, rwMeshAddr, nil); o != addNoSource {
		t.Errorf("addRewrite of an unknown source = %d, want no source", o)
	}
	if o := nt.n.addRewrite(rwAccess, "plexd9", rwMeshAddr, nil); o != addNoMesh {
		t.Errorf("addRewrite into an unknown mesh = %d, want no mesh", o)
	}
	if !nt.n.involved(rwAccess) || !nt.n.involved(rwMesh) {
		t.Error("involved = false for an interface of a rewrite")
	}

	if mesh, ok := nt.n.removeRewrite(rwAccess); !ok || mesh != rwMesh {
		t.Errorf("removeRewrite = %q, %t, want %q, true", mesh, ok, rwMesh)
	}
	if _, ok := nt.n.removeRewrite(rwAccess); ok {
		t.Error("second removeRewrite = true, want false")
	}
	if nt.n.involved(rwAccess) {
		t.Error("involved = true after the rewrite was removed")
	}
	passes(t, nt.fromMesh(t, udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, nil)), "answer to a forgotten flow")
	passes(t, nt.fromAccess(t, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, nil)), "datagram from D without a rewrite")

	// Closing the mesh device forgets every rewrite into it; a device of
	// another registration leaves it alone.
	nt.n.unregister(rwMesh, &fakeNATDevice{name: rwMesh})
	if !nt.n.involved(rwTunnel) {
		t.Fatal("unregister of another device under the mesh name removed the tunnel's rewrite")
	}
	nt.n.unregister(rwMesh, nt.mesh)
	if nt.n.involved(rwTunnel) || nt.n.involved(rwMesh) || nt.n.known(rwMesh) {
		t.Error("the mesh device's rewrites outlived it")
	}

	nt = newNATTest(t)
	nt.translateUDP(t, rwAccess, rwDeviceD, 5555)
	nt.n.resetRewrites()
	if len(nt.n.rewrites) != 0 || len(nt.n.flows) != 0 || len(nt.n.meshPorts) != 0 || len(nt.n.meshUse) != 0 {
		t.Errorf("after resetRewrites: %d rewrites, %d flows, %d ports, %d mesh uses, want none",
			len(nt.n.rewrites), len(nt.n.flows), len(nt.n.meshPorts), len(nt.n.meshUse))
	}
}

// RFC 1624's worked example: a header checksum of 0xdd2f with a word that
// changes from 0x5555 to 0x3285 becomes 0x0000 by equation 3.
func TestMeshRewriteRules_ChecksumUpdateRFC1624(t *testing.T) {
	sum := []byte{0xdd, 0x2f}
	updateChecksum(sum, 0x5555, 0x3285)
	if got := binary.BigEndian.Uint16(sum); got != 0x0000 {
		t.Errorf("updated checksum = %#04x, want 0x0000", got)
	}
}
