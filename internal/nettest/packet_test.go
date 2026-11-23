package nettest

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// equal reports whether p and q hold the same fields and payload bytes. A nil
// payload equals an empty one.
func equal(p, q Packet) bool {
	return p.Proto == q.Proto && p.Src == q.Src && p.Dst == q.Dst &&
		p.SrcPort == q.SrcPort && p.DstPort == q.DstPort &&
		p.Seq == q.Seq && p.Ack == q.Ack && p.Flags == q.Flags &&
		bytes.Equal(p.Payload, q.Payload)
}

// TestOnesComplementSum checks the sum the builders and the round-trip tests
// rest on against known sums: the example of RFC 1071 section 3, an odd
// trailing byte, and the common worked example of an IPv4 header, its
// checksum 0xb861 filled in.
func TestOnesComplementSum(t *testing.T) {
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
}

// TestPacketRoundTrip builds a TCP segment and UDP datagrams, checks the
// IPv4 header and the transport checksum of each, and parses each back to
// the fields it was built from. A packet with a wrong checksum would be
// dropped by the kernel before any socket saw it, and a real test would read
// that as a drop.
func TestPacketRoundTrip(t *testing.T) {
	node := netip.MustParseAddr("10.98.0.1")
	peer := netip.MustParseAddr("10.98.0.2")
	meshSource := netip.MustParseAddr("10.98.0.3")
	lanHost := netip.MustParseAddr("192.0.2.2")

	// ipSum and l4Sum are the header and transport checksums of each packet,
	// computed outside this code with an independent RFC 1071 implementation
	// over the same bytes, so a builder and the sum check below cannot share a
	// mistake, such as a misplaced pseudo-header field. l4At is the offset of
	// the transport checksum field in the segment.
	for _, tc := range []struct {
		name         string
		pkt          []byte
		want         Packet
		ipSum, l4Sum uint16
		l4At         int
	}{
		{
			name: "tcp syn-ack",
			pkt: TCPSegment(netip.AddrPortFrom(meshSource, 40000), netip.AddrPortFrom(node, 7001),
				0x01020304, 0x0a0b0c0d, FlagSYN|FlagACK),
			want: Packet{
				Proto: ProtoTCP, Src: meshSource, Dst: node, SrcPort: 40000, DstPort: 7001,
				Seq: 0x01020304, Ack: 0x0a0b0c0d, Flags: FlagSYN | FlagACK,
			},
			ipSum: 0xb490, l4Sum: 0xc953, l4At: 16,
		},
		{
			name: "udp",
			pkt:  UDPDatagram(netip.AddrPortFrom(lanHost, 40001), netip.AddrPortFrom(node, 5353), []byte("plexd")),
			want: Packet{
				Proto: ProtoUDP, Src: lanHost, Dst: node, SrcPort: 40001, DstPort: 5353,
				Payload: []byte("plexd"),
			},
			ipSum: 0xfcee, l4Sum: 0x485f, l4At: 6,
		},
		{
			name: "udp without payload",
			pkt:  UDPDatagram(netip.AddrPortFrom(peer, 40002), netip.AddrPortFrom(node, 7911), nil),
			want: Packet{
				Proto: ProtoUDP, Src: peer, Dst: node, SrcPort: 40002, DstPort: 7911,
			},
			ipSum: 0xb492, l4Sum: 0x2fee, l4At: 6,
		},
		{
			// This payload makes the computed checksum zero, which a UDP
			// header cannot carry: zero means none was computed.
			name: "udp whose checksum computes to zero",
			pkt:  UDPDatagram(netip.AddrPortFrom(peer, 40003), netip.AddrPortFrom(node, 7911), []byte{0x2f, 0xe9}),
			want: Packet{
				Proto: ProtoUDP, Src: peer, Dst: node, SrcPort: 40003, DstPort: 7911,
				Payload: []byte{0x2f, 0xe9},
			},
			ipSum: 0xb490, l4Sum: 0xffff, l4At: 6,
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
			ph := onesComplementSum(pseudoHeader(tc.want.Src, tc.want.Dst, tc.want.Proto, len(seg)), 0)
			if got := onesComplementSum(seg, uint32(ph)); got != 0xffff {
				t.Errorf("the pseudo-header and the segment sum to %#04x, want 0xffff", got)
			}
			if got, want := binary.BigEndian.Uint16(tc.pkt[6:]), uint16(0x4000); got != want {
				t.Errorf("flags and fragment offset = %#04x, want %#04x, the don't-fragment bit alone", got, want)
			}
			if got := tc.pkt[8]; got != 64 {
				t.Errorf("TTL = %d, want 64", got)
			}

			got, ok := ParseIPv4(tc.pkt)
			if !ok {
				t.Fatalf("ParseIPv4() = false, want %v", tc.want)
			}
			if !equal(got, tc.want) {
				t.Errorf("ParseIPv4() = %v, want %v", got, tc.want)
			}

			for n := range len(tc.pkt) {
				if p, ok := ParseIPv4(tc.pkt[:n]); ok {
					t.Errorf("ParseIPv4() of the first %d of %d bytes = %v, want false", n, len(tc.pkt), p)
				}
			}
		})
	}
}

// TestParseIPv4Refuses checks that ParseIPv4 reports false for what is not a
// whole IPv4 TCP segment or UDP datagram.
func TestParseIPv4Refuses(t *testing.T) {
	src := netip.MustParseAddrPort("10.98.0.2:40000")
	dst := netip.MustParseAddrPort("10.98.0.1:7911")
	// with returns a UDP datagram from src to dst that change altered.
	with := func(change func(pkt []byte)) []byte {
		pkt := UDPDatagram(src, dst, []byte("plexd"))
		change(pkt)
		return pkt
	}
	ipv6 := make([]byte, 48)
	ipv6[0] = 6 << 4

	for _, tc := range []struct {
		name string
		pkt  []byte
	}{
		{"an empty buffer", nil},
		{"a buffer shorter than an IPv4 header", UDPDatagram(src, dst, nil)[:ipv4HeaderLen-1]},
		{"an IPv6 header", ipv6},
		{"a total length beyond the buffer", with(func(pkt []byte) {
			binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)+1))
		})},
		{"a header length below 20 bytes", with(func(pkt []byte) { pkt[0] = 4<<4 | 4 })},
		{"a header length beyond the total length", with(func(pkt []byte) { pkt[0] = 4<<4 | 15 })},
		{"a UDP length beyond the datagram", with(func(pkt []byte) {
			binary.BigEndian.PutUint16(pkt[ipv4HeaderLen+4:], uint16(len(pkt)-ipv4HeaderLen+1))
		})},
		{"a TCP data offset beyond the segment", func() []byte {
			pkt := TCPSegment(src, dst, 1, 0, FlagSYN)
			pkt[ipv4HeaderLen+12] = 6 << 4
			return pkt
		}()},
		{"a first fragment", with(func(pkt []byte) { binary.BigEndian.PutUint16(pkt[6:], 0x2000) })},
		{"a later fragment", with(func(pkt []byte) { binary.BigEndian.PutUint16(pkt[6:], 0x0001) })},
		{"ICMP", with(func(pkt []byte) { pkt[9] = 1 })},
	} {
		if p, ok := ParseIPv4(tc.pkt); ok {
			t.Errorf("ParseIPv4() of %s = %v, want false", tc.name, p)
		}
	}
}
