package policy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

// Header lengths, protocol numbers, TCP flags and ICMP types of the IPv4
// packets the traffic tests write into a test device and read back from it.
const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20
	udpHeaderLen  = 8
	icmpHeaderLen = 8

	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10

	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// tunPacket is an IPv4 packet reduced to the fields the traffic checks look
// at. The ports belong to TCP and UDP, the flags to TCP, and the ICMP id and
// sequence to an echo request or reply.
type tunPacket struct {
	proto    uint8
	src, dst netip.Addr
	srcPort  uint16
	dstPort  uint16
	tcpFlags uint8
	icmpType uint8
	icmpID   uint16
	icmpSeq  uint16
	payload  []byte
}

func (p tunPacket) equal(q tunPacket) bool {
	return p.proto == q.proto && p.src == q.src && p.dst == q.dst &&
		p.srcPort == q.srcPort && p.dstPort == q.dstPort && p.tcpFlags == q.tcpFlags &&
		p.icmpType == q.icmpType && p.icmpID == q.icmpID && p.icmpSeq == q.icmpSeq &&
		bytes.Equal(p.payload, q.payload)
}

func (p tunPacket) String() string {
	switch p.proto {
	case protoTCP:
		return fmt.Sprintf("tcp %s:%d > %s:%d flags %#02x payload %q", p.src, p.srcPort, p.dst, p.dstPort, p.tcpFlags, p.payload)
	case protoUDP:
		return fmt.Sprintf("udp %s:%d > %s:%d payload %q", p.src, p.srcPort, p.dst, p.dstPort, p.payload)
	case protoICMP:
		return fmt.Sprintf("icmp %s > %s type %d id %d seq %d payload %q", p.src, p.dst, p.icmpType, p.icmpID, p.icmpSeq, p.payload)
	}
	return fmt.Sprintf("protocol %d %s > %s", p.proto, p.src, p.dst)
}

// onesComplementSum adds b, read as big-endian 16-bit words, to initial in
// one's complement arithmetic (RFC 1071) and returns the folded sum. A
// trailing odd byte is the high byte of a last word padded with zero. A
// checksum field holds the complement of this sum, so the sum over data that
// carries a valid checksum is 0xffff.
func onesComplementSum(b []byte, initial uint32) uint16 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

// pseudoHeader returns the IPv4 pseudo-header that a TCP or UDP checksum
// covers ahead of the segment.
func pseudoHeader(src, dst netip.Addr, proto uint8, segmentLen int) []byte {
	ph := make([]byte, 12)
	s, d := src.As4(), dst.As4()
	copy(ph[0:4], s[:])
	copy(ph[4:8], d[:])
	ph[9] = proto
	binary.BigEndian.PutUint16(ph[10:], uint16(segmentLen))
	return ph
}

// transportChecksum returns the checksum of a TCP or UDP segment whose own
// checksum field is still zero.
func transportChecksum(src, dst netip.Addr, proto uint8, segment []byte) uint16 {
	ph := onesComplementSum(pseudoHeader(src, dst, proto, len(segment)), 0)
	return ^onesComplementSum(segment, uint32(ph))
}

// buildIPv4 wraps a transport segment, whose checksum is already set, in an
// IPv4 header with a valid header checksum.
func buildIPv4(src, dst netip.Addr, proto uint8, segment []byte) []byte {
	pkt := make([]byte, ipv4HeaderLen+len(segment))
	pkt[0] = 4<<4 | ipv4HeaderLen/4
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], 0x7178) // identification
	binary.BigEndian.PutUint16(pkt[6:], 0x4000) // don't fragment
	pkt[8] = 64                                 // time to live
	pkt[9] = proto
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:], ^onesComplementSum(pkt[:ipv4HeaderLen], 0))
	copy(pkt[ipv4HeaderLen:], segment)
	return pkt
}

// buildIPv4TCPSyn returns a TCP SYN without options.
func buildIPv4TCPSyn(src, dst netip.Addr, srcPort, dstPort uint16, seq uint32) []byte {
	seg := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint32(seg[4:], seq)
	seg[12] = tcpHeaderLen / 4 << 4 // data offset
	seg[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(seg[14:], 65535) // window
	binary.BigEndian.PutUint16(seg[16:], transportChecksum(src, dst, protoTCP, seg))
	return buildIPv4(src, dst, protoTCP, seg)
}

// buildIPv4UDP returns a UDP datagram that carries payload.
func buildIPv4UDP(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	seg := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)))
	copy(seg[udpHeaderLen:], payload)
	sum := transportChecksum(src, dst, protoUDP, seg)
	if sum == 0 {
		// A zero UDP checksum means none was computed (RFC 768).
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[6:], sum)
	return buildIPv4(src, dst, protoUDP, seg)
}

// buildIPv4EchoRequest returns an ICMP echo request that carries payload.
func buildIPv4EchoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	msg := make([]byte, icmpHeaderLen+len(payload))
	msg[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[icmpHeaderLen:], payload)
	binary.BigEndian.PutUint16(msg[2:], ^onesComplementSum(msg, 0))
	return buildIPv4(src, dst, protoICMP, msg)
}

// parseIPv4 parses an IPv4 packet. It does not check the checksums. The
// payload shares b's memory.
func parseIPv4(b []byte) (tunPacket, error) {
	if len(b) < ipv4HeaderLen {
		return tunPacket{}, fmt.Errorf("%d bytes, shorter than an IPv4 header", len(b))
	}
	if v := b[0] >> 4; v != 4 {
		return tunPacket{}, fmt.Errorf("IP version %d, want 4", v)
	}
	hdrLen := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if hdrLen < ipv4HeaderLen || total < hdrLen || total > len(b) {
		return tunPacket{}, fmt.Errorf("header length %d and total length %d do not fit %d bytes", hdrLen, total, len(b))
	}

	p := tunPacket{
		proto: b[9],
		src:   netip.AddrFrom4([4]byte(b[12:16])),
		dst:   netip.AddrFrom4([4]byte(b[16:20])),
	}
	seg := b[hdrLen:total]
	switch p.proto {
	case protoTCP:
		if len(seg) < tcpHeaderLen {
			return tunPacket{}, fmt.Errorf("tcp segment of %d bytes, shorter than its header", len(seg))
		}
		off := int(seg[12]>>4) * 4
		if off < tcpHeaderLen || off > len(seg) {
			return tunPacket{}, fmt.Errorf("tcp data offset %d does not fit %d bytes", off, len(seg))
		}
		p.srcPort = binary.BigEndian.Uint16(seg[0:])
		p.dstPort = binary.BigEndian.Uint16(seg[2:])
		p.tcpFlags = seg[13]
		p.payload = seg[off:]
	case protoUDP:
		if len(seg) < udpHeaderLen {
			return tunPacket{}, fmt.Errorf("udp datagram of %d bytes, shorter than its header", len(seg))
		}
		n := int(binary.BigEndian.Uint16(seg[4:]))
		if n < udpHeaderLen || n > len(seg) {
			return tunPacket{}, fmt.Errorf("udp length %d does not fit %d bytes", n, len(seg))
		}
		p.srcPort = binary.BigEndian.Uint16(seg[0:])
		p.dstPort = binary.BigEndian.Uint16(seg[2:])
		p.payload = seg[udpHeaderLen:n]
	case protoICMP:
		if len(seg) < icmpHeaderLen {
			return tunPacket{}, fmt.Errorf("icmp message of %d bytes, shorter than its header", len(seg))
		}
		p.icmpType = seg[0]
		if p.icmpType == icmpEchoRequest || p.icmpType == icmpEchoReply {
			p.icmpID = binary.BigEndian.Uint16(seg[4:])
			p.icmpSeq = binary.BigEndian.Uint16(seg[6:])
		}
		p.payload = seg[icmpHeaderLen:]
	default:
		p.payload = seg
	}
	return p, nil
}

// TestTunPacketRoundTrip checks the packet builders and the parser the
// traffic tests share. A packet with a wrong checksum would be dropped by the
// host before any filter saw it, and the test would read that as a drop.
func TestTunPacketRoundTrip(t *testing.T) {
	// Known sums: the example of RFC 1071 section 3, an odd trailing byte,
	// and the common worked example of an IPv4 header, its checksum 0xb861
	// filled in.
	for _, tc := range []struct {
		data []byte
		want uint16
	}{
		{[]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}, 0xddf2},
		{[]byte{0xab}, 0xab00},
		{[]byte{
			0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
			0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
		}, 0xffff},
	} {
		if got := onesComplementSum(tc.data, 0); got != tc.want {
			t.Errorf("onesComplementSum(% x) = %#04x, want %#04x", tc.data, got, tc.want)
		}
	}

	peer := netip.MustParseAddr("10.255.247.2")
	node := netip.MustParseAddr("10.255.247.1")
	// ipSum and l4Sum are the header and transport checksums of each packet,
	// computed outside this code with an independent RFC 1071 implementation
	// over the same bytes, so a builder and the sum check below cannot share a
	// mistake, such as a misplaced pseudo-header field. l4At is the offset of
	// the transport checksum field in the segment.
	for _, tc := range []struct {
		name         string
		pkt          []byte
		want         tunPacket
		ipSum, l4Sum uint16
		l4At         int
	}{
		{
			name:  "tcp syn",
			pkt:   buildIPv4TCPSyn(peer, node, 40000, 7001, 0x01020304),
			want:  tunPacket{proto: protoTCP, src: peer, dst: node, srcPort: 40000, dstPort: 7001, tcpFlags: tcpFlagSYN},
			ipSum: 0xc555, l4Sum: 0xf040, l4At: 16,
		},
		{
			name:  "udp",
			pkt:   buildIPv4UDP(peer, node, 40003, 7002, []byte("plexd")),
			want:  tunPacket{proto: protoUDP, src: peer, dst: node, srcPort: 40003, dstPort: 7002, payload: []byte("plexd")},
			ipSum: 0xc551, l4Sum: 0x0a4f, l4At: 6,
		},
		{
			name:  "icmp echo request",
			pkt:   buildIPv4EchoRequest(peer, node, 0x7178, 3, []byte("ping")),
			want:  tunPacket{proto: protoICMP, src: peer, dst: node, icmpType: icmpEchoRequest, icmpID: 0x7178, icmpSeq: 3, payload: []byte("ping")},
			ipSum: 0xc562, l4Sum: 0xa7b3, l4At: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := binary.BigEndian.Uint16(tc.pkt[10:]); got != tc.ipSum {
				t.Errorf("IPv4 header checksum = %#04x, want %#04x", got, tc.ipSum)
			}
			if got := binary.BigEndian.Uint16(tc.pkt[ipv4HeaderLen+tc.l4At:]); got != tc.l4Sum {
				t.Errorf("transport checksum = %#04x, want %#04x", got, tc.l4Sum)
			}
			if got := onesComplementSum(tc.pkt[:ipv4HeaderLen], 0); got != 0xffff {
				t.Errorf("the IPv4 header sums to %#04x, want 0xffff", got)
			}
			seg := tc.pkt[ipv4HeaderLen:]
			var initial uint32
			if tc.want.proto != protoICMP {
				// ICMP covers its message alone, TCP and UDP the
				// pseudo-header as well.
				initial = uint32(onesComplementSum(pseudoHeader(peer, node, tc.want.proto, len(seg)), 0))
			}
			if got := onesComplementSum(seg, initial); got != 0xffff {
				t.Errorf("the transport checksum sums to %#04x, want 0xffff", got)
			}

			got, err := parseIPv4(tc.pkt)
			if err != nil {
				t.Fatalf("parseIPv4() error = %v, want nil", err)
			}
			if !got.equal(tc.want) {
				t.Errorf("parseIPv4() = %v, want %v", got, tc.want)
			}

			for n := range len(tc.pkt) {
				if p, err := parseIPv4(tc.pkt[:n]); err == nil {
					t.Errorf("parseIPv4() of the first %d of %d bytes = %v, want an error", n, len(tc.pkt), p)
				}
			}
		})
	}

	ipv6 := make([]byte, 48)
	ipv6[0] = 6 << 4
	if p, err := parseIPv4(ipv6); err == nil {
		t.Errorf("parseIPv4() of an IPv6 header = %v, want an error", p)
	}
}
