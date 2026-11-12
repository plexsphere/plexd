package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ipv4Packet returns an IPv4 header of hdrLen bytes for proto, followed by
// payload. The checksum is left 0: parseIPTuple does not read it.
func ipv4Packet(src, dst netip.Addr, proto uint8, hdrLen int, payload []byte) []byte {
	b := make([]byte, hdrLen+len(payload))
	b[0] = 4<<4 | byte(hdrLen/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[hdrLen:], payload)
	return b
}

// ipv6Packet returns a fixed IPv6 header whose next header is next, followed
// by payload.
func ipv6Packet(src, dst netip.Addr, next uint8, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = next
	b[7] = 64
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], payload)
	return b
}

// ports returns the first four bytes of a TCP or UDP header.
func ports(src, dst uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], src)
	binary.BigEndian.PutUint16(b[2:4], dst)
	return b
}

func TestParseIPTuple(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("10.99.0.3"), netip.MustParseAddr("10.99.0.1")
	v6a, v6b := netip.MustParseAddr("fd00:99::3"), netip.MustParseAddr("fd00:99::1")

	tests := []struct {
		name             string
		pkt              []byte
		src, dst         netip.Addr
		proto            uint8
		srcPort, dstPort uint16
	}{
		{
			name:  "IPv4 TCP with IHL 6",
			pkt:   ipv4Packet(v4a, v4b, ipProtoTCP, 24, ports(41001, 7001)),
			src:   v4a,
			dst:   v4b,
			proto: ipProtoTCP, srcPort: 41001, dstPort: 7001,
		},
		{
			name:  "IPv6 UDP",
			pkt:   ipv6Packet(v6a, v6b, ipProtoUDP, ports(41003, 7002)),
			src:   v6a,
			dst:   v6b,
			proto: ipProtoUDP, srcPort: 41003, dstPort: 7002,
		},
		{
			name:  "IPv4 ICMP has no ports",
			pkt:   ipv4Packet(v4a, v4b, ipProtoICMP, 20, []byte{8, 0, 0, 0, 0x71, 0x78, 0, 1}),
			src:   v4a,
			dst:   v4b,
			proto: ipProtoICMP,
		},
		{
			name:  "IPv6 behind a hop-by-hop header names that header and no ports",
			pkt:   ipv6Packet(v6a, v6b, 0, ports(41003, 7002)),
			src:   v6a,
			dst:   v6b,
			proto: 0,
		},
		{
			name:  "a TCP header cut short leaves the ports 0",
			pkt:   ipv4Packet(v4a, v4b, ipProtoTCP, 20, []byte{0xa0}),
			src:   v4a,
			dst:   v4b,
			proto: ipProtoTCP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst, proto, sp, dp, ok := parseIPTuple(tt.pkt)
			if !ok {
				t.Fatal("parseIPTuple() ok = false, want true")
			}
			if src != tt.src || dst != tt.dst || proto != tt.proto || sp != tt.srcPort || dp != tt.dstPort {
				t.Errorf("parseIPTuple() = %v %v %d %d %d, want %v %v %d %d %d",
					src, dst, proto, sp, dp, tt.src, tt.dst, tt.proto, tt.srcPort, tt.dstPort)
			}
		})
	}
}

func TestParseIPTuple_LaterFragmentHasNoPorts(t *testing.T) {
	pkt := ipv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ipProtoUDP, 20, ports(1, 2))
	binary.BigEndian.PutUint16(pkt[6:8], 185) // fragment offset 185 × 8 bytes
	_, _, proto, sp, dp, ok := parseIPTuple(pkt)
	if !ok || proto != ipProtoUDP || sp != 0 || dp != 0 {
		t.Errorf("parseIPTuple() = proto %d ports %d %d ok %v, want udp, ports 0 0, ok", proto, sp, dp, ok)
	}
}

func TestParseIPTuple_Refuses(t *testing.T) {
	v4 := ipv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ipProtoTCP, 20, ports(1, 2))

	ihlPastBuffer := ipv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ipProtoTCP, 20, nil)
	ihlPastBuffer[0] = 4<<4 | 15 // 60 bytes announced, 20 present

	version5 := append([]byte(nil), v4...)
	version5[0] = 5<<4 | 5

	for name, pkt := range map[string][]byte{
		"empty slice":                    {},
		"nil":                            nil,
		"19-byte IPv4 header":            v4[:19],
		"version 5":                      version5,
		"IHL running past the buffer":    ihlPastBuffer,
		"IHL below the minimum":          append([]byte{4<<4 | 4}, v4[1:]...),
		"39-byte IPv6 header":            ipv6Packet(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), ipProtoTCP, nil)[:39],
		"version 0 with a full 40 bytes": make([]byte, 40),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, _, ok := parseIPTuple(pkt); ok {
				t.Error("parseIPTuple() ok = true, want false")
			}
		})
	}
}
