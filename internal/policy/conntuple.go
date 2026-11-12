package policy

import (
	"encoding/binary"
	"net/netip"
)

// The IP protocol numbers the connection logging reads off a packet or a rule.
const (
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58
)

// parseIPTuple reads the addresses, the protocol and, for TCP and UDP, the
// ports of the IP packet that starts at b. The Linux and macOS readers hand it
// the packet their kernel copied with a log record.
//
// It reads an IPv4 header, honouring its header length, or the fixed IPv6
// header. Ports come from a TCP or UDP header that follows directly, and stay
// 0 for any other protocol, for a later IPv4 fragment, and for a transport
// header cut short. Under an IPv6 extension header proto is that header's
// next-header value and the ports are 0. ok is false for a version other than
// 4 or 6 and for a buffer shorter than the header it announces.
func parseIPTuple(b []byte) (src, dst netip.Addr, proto uint8, srcPort, dstPort uint16, ok bool) {
	if len(b) == 0 {
		return
	}

	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return
		}
		hdrLen := int(b[0]&0x0f) * 4
		if hdrLen < 20 || hdrLen > len(b) {
			return
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		proto = b[9]
		// Only the first fragment carries the transport header.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff == 0 {
			l4 = b[hdrLen:]
		}
	case 6:
		if len(b) < 40 {
			return
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		proto = b[6]
		l4 = b[40:]
	default:
		return
	}

	if (proto == ipProtoTCP || proto == ipProtoUDP) && len(l4) >= 4 {
		srcPort = binary.BigEndian.Uint16(l4[0:2])
		dstPort = binary.BigEndian.Uint16(l4[2:4])
	}
	return src, dst, proto, srcPort, dstPort, true
}
