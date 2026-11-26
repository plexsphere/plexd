package wireguard

import (
	"encoding/binary"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// mssClampTUN lowers the MSS option of the IPv4 TCP SYN packets that pass
// the device it wraps, in both directions. With an MSS of 0 it passes every
// packet unread.
//
// It is the clamp of the macOS and Windows controllers, whose mesh interface
// is a wireguard-go device of this process, so every packet that crosses it
// passes through plexd. Linux runs the kernel path, the nftables table of
// mss_linux.go, and does not use the wrapper: a Linux tun can hand
// wireguard-go packets with a partial checksum, which covers only the pseudo
// header, and an incremental update would corrupt it.
// The file carries no build tag so its tests run on every runner.
//
// Every method but Read and Write is the wrapped device's, so wireguard-go
// sees the device's MTU, name, events and batch size, and Close closes it.
type mssClampTUN struct {
	tun.Device

	// mss is the value a larger MSS is lowered to, 0 for none. It is atomic
	// because the controller sets it while wireguard-go reads and writes.
	mss atomic.Uint32
}

// newMSSClampTUN returns a wrapper of dev that clamps nothing until setMSS
// is called. It is only called with a device the controller has already
// used, so it does not check for nil.
func newMSSClampTUN(dev tun.Device) *mssClampTUN {
	return &mssClampTUN{Device: dev}
}

// setMSS sets the value a larger MSS is lowered to. A value outside 1 to
// 65535 stores 0, which turns the clamp off: no MSS option can hold it.
func (w *mssClampTUN) setMSS(mss int) {
	if mss < 1 || mss > 65535 {
		mss = 0
	}
	w.mss.Store(uint32(mss))
}

// Read reads from the wrapped device and clamps each of the n packets it
// returned, also when it returned an error with them. It returns the wrapped
// call's n and error unchanged, so wireguard-go sees an os.ErrClosed as the
// device's.
func (w *mssClampTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := w.Device.Read(bufs, sizes, offset)
	// One load per call: a setMSS that lands meanwhile applies to the next
	// batch, not to half of this one.
	if mss := uint16(w.mss.Load()); mss != 0 {
		for i := range n {
			clampSYN(bufs[i][offset:offset+sizes[i]], mss)
		}
	}
	return n, err
}

// Write clamps each packet at buf[offset:] and writes the batch to the
// wrapped device with the same arguments, returning its result and error. A
// buffer no longer than offset holds no packet and is passed on unread.
func (w *mssClampTUN) Write(bufs [][]byte, offset int) (int, error) {
	if mss := uint16(w.mss.Load()); mss != 0 {
		for _, buf := range bufs {
			if len(buf) > offset {
				clampSYN(buf[offset:], mss)
			}
		}
	}
	return w.Device.Write(bufs, offset)
}

// clampSYN lowers the MSS option of pkt in place and reports whether it did.
//
// It changes only an unfragmented or first-fragment IPv4 TCP segment with
// SYN set and RST clear, a SYN or a SYN-ACK, whose MSS option of length 4
// holds a value above mss. A packet it cannot read up to that option, cut
// short or malformed, is left as it is. It runs for every packet that
// crosses the mesh interface, so it allocates nothing, and it never changes
// a packet's length.
func clampSYN(pkt []byte, mss uint16) bool {
	const (
		tcpHeaderLen = 20
		tcpFlagSYN   = 0x02

		optEnd    = 0
		optNOP    = 1
		optMSS    = 2
		optMSSLen = 4
	)

	if len(pkt) < ipv4HeaderLen || pkt[0]>>4 != 4 {
		return false
	}
	hl := int(pkt[0]&0x0f) * 4
	if hl < ipv4HeaderLen || hl > len(pkt) || pkt[9] != protoTCP {
		return false
	}
	// A later fragment carries no TCP header, only bytes of the segment.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return false
	}

	tcp := pkt[hl:]
	if len(tcp) < tcpHeaderLen {
		return false
	}
	if flags := tcp[13]; flags&tcpFlagSYN == 0 || flags&tcpFlagRST != 0 {
		return false
	}
	doff := int(tcp[12]>>4) * 4
	if doff < tcpHeaderLen || doff > len(tcp) {
		return false
	}

	for i := tcpHeaderLen; i < doff; {
		switch tcp[i] {
		case optEnd:
			return false
		case optNOP:
			i++
			continue
		}
		// Any other kind carries a length byte that counts the kind and
		// itself. One below 2 or past the header leaves no way to find the
		// next option.
		if i+1 >= doff {
			return false
		}
		n := int(tcp[i+1])
		if n < 2 || i+n > doff {
			return false
		}
		if tcp[i] == optMSS && n == optMSSLen {
			return lowerMSS(tcp, i+2, mss)
		}
		i += n
	}
	return false
}

// lowerMSS writes mss into the MSS value at tcp[at:at+2] when the value is
// above it, updates the TCP checksum at tcp[16:18] for the change (RFC 1624,
// equation 3) and reports whether it wrote.
//
// The checksum sums 16-bit words counted from the start of the segment: the
// pseudo header in front of it is 12 bytes, an even size. A NOP in front of
// the option puts the value at an odd offset, where its high byte is the low
// byte of one word and its low byte the high byte of the next, so both words
// are updated. The second word lies inside the header: the option ends at
// at+2, an odd offset, and the header length is a multiple of 4.
func lowerMSS(tcp []byte, at int, mss uint16) bool {
	if binary.BigEndian.Uint16(tcp[at:]) <= mss {
		return false
	}

	sum := tcp[16:18]
	if at%2 == 0 {
		old := binary.BigEndian.Uint16(tcp[at:])
		binary.BigEndian.PutUint16(tcp[at:], mss)
		updateChecksum(sum, old, mss)
		return true
	}

	first, second := at-1, at+1
	oldFirst := binary.BigEndian.Uint16(tcp[first:])
	oldSecond := binary.BigEndian.Uint16(tcp[second:])
	binary.BigEndian.PutUint16(tcp[at:], mss)
	updateChecksum(sum, oldFirst, binary.BigEndian.Uint16(tcp[first:]))
	updateChecksum(sum, oldSecond, binary.BigEndian.Uint16(tcp[second:]))
	return true
}
