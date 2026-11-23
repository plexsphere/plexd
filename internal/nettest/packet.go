package nettest

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Protocol numbers and TCP flags of the packets the builders write and
// ParseIPv4 reads.
const (
	ProtoTCP = 6
	ProtoUDP = 17
	FlagSYN  = 0x02
	FlagACK  = 0x10
)

// Header lengths of the packets the builders write: none of them carries
// options.
const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20
	udpHeaderLen  = 8
)

// Packet is an IPv4 TCP segment or UDP datagram reduced to the fields the
// real tests look at.
type Packet struct {
	Proto            uint8
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack         uint32 // TCP only
	Flags            uint8  // TCP only
	Payload          []byte // the TCP payload or the UDP payload
}

// String formats p for a failure message.
func (p Packet) String() string {
	switch p.Proto {
	case ProtoTCP:
		return fmt.Sprintf("tcp %s:%d > %s:%d seq %d ack %d flags %#02x payload %q",
			p.Src, p.SrcPort, p.Dst, p.DstPort, p.Seq, p.Ack, p.Flags, p.Payload)
	case ProtoUDP:
		return fmt.Sprintf("udp %s:%d > %s:%d payload %q", p.Src, p.SrcPort, p.Dst, p.DstPort, p.Payload)
	}
	return fmt.Sprintf("protocol %d %s > %s", p.Proto, p.Src, p.Dst)
}

// TCPSegment returns an IPv4 packet from src to dst that carries a TCP
// header of 20 bytes without options and no payload: seq, ack, flags and a
// window of 65535. The IPv4 header sets the don't-fragment bit and a TTL of
// 64, and both checksums are valid. src and dst must hold IPv4 addresses.
func TCPSegment(src, dst netip.AddrPort, seq, ack uint32, flags uint8) []byte {
	seg := make([]byte, tcpHeaderLen)
	binary.BigEndian.PutUint16(seg[0:], src.Port())
	binary.BigEndian.PutUint16(seg[2:], dst.Port())
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], ack)
	seg[12] = tcpHeaderLen / 4 << 4 // data offset
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:], 65535) // window
	binary.BigEndian.PutUint16(seg[16:], transportChecksum(src.Addr(), dst.Addr(), ProtoTCP, seg))
	return buildIPv4(src.Addr(), dst.Addr(), ProtoTCP, seg)
}

// UDPDatagram returns an IPv4 packet from src to dst that carries a UDP
// datagram with payload. The IPv4 header sets the don't-fragment bit and a
// TTL of 64, and both checksums are valid. src and dst must hold IPv4
// addresses.
func UDPDatagram(src, dst netip.AddrPort, payload []byte) []byte {
	seg := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:], src.Port())
	binary.BigEndian.PutUint16(seg[2:], dst.Port())
	binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)))
	copy(seg[udpHeaderLen:], payload)
	sum := transportChecksum(src.Addr(), dst.Addr(), ProtoUDP, seg)
	if sum == 0 {
		// A zero UDP checksum means none was computed (RFC 768).
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[6:], sum)
	return buildIPv4(src.Addr(), dst.Addr(), ProtoUDP, seg)
}

// ParseIPv4 parses an IPv4 packet that carries a whole TCP segment or UDP
// datagram. It reports false for anything else: a buffer shorter than the
// headers, another IP version, a header, total, data offset or UDP length
// that does not fit the buffer, a fragment, or another protocol. It does not
// check the checksums. The payload shares b's memory.
func ParseIPv4(b []byte) (Packet, bool) {
	if len(b) < ipv4HeaderLen || b[0]>>4 != 4 {
		return Packet{}, false
	}
	hdrLen := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if hdrLen < ipv4HeaderLen || total < hdrLen || total > len(b) {
		return Packet{}, false
	}
	// The more-fragments bit and the fragment offset: a fragment holds part
	// of a segment, or none of its header.
	if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 {
		return Packet{}, false
	}

	p := Packet{
		Proto: b[9],
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
	}
	seg := b[hdrLen:total]
	switch p.Proto {
	case ProtoTCP:
		if len(seg) < tcpHeaderLen {
			return Packet{}, false
		}
		off := int(seg[12]>>4) * 4
		if off < tcpHeaderLen || off > len(seg) {
			return Packet{}, false
		}
		p.SrcPort = binary.BigEndian.Uint16(seg[0:])
		p.DstPort = binary.BigEndian.Uint16(seg[2:])
		p.Seq = binary.BigEndian.Uint32(seg[4:])
		p.Ack = binary.BigEndian.Uint32(seg[8:])
		p.Flags = seg[13]
		p.Payload = seg[off:]
	case ProtoUDP:
		if len(seg) < udpHeaderLen {
			return Packet{}, false
		}
		n := int(binary.BigEndian.Uint16(seg[4:]))
		if n < udpHeaderLen || n > len(seg) {
			return Packet{}, false
		}
		p.SrcPort = binary.BigEndian.Uint16(seg[0:])
		p.DstPort = binary.BigEndian.Uint16(seg[2:])
		p.Payload = seg[udpHeaderLen:n]
	default:
		return Packet{}, false
	}
	return p, true
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
// IPv4 header without options with a valid header checksum.
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
