package wireguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
)

// synLANMSS is the MSS a host on a 1500-byte LAN announces, synClampMSS the
// clamp of a node whose mesh MTU is 1372.
const (
	synLANMSS   = 1460
	synClampMSS = 1332
)

// TCP options of the test segments besides the MSS.
var (
	synNOP      = []byte{1}
	synWScale   = []byte{3, 3, 7}
	synSACKPerm = []byte{4, 2}
	synTS       = []byte{8, 10, 0, 0, 0x12, 0x34, 0, 0, 0, 0}
)

// synMSSOption returns a TCP MSS option that holds v.
func synMSSOption(v uint16) []byte {
	return []byte{2, 4, byte(v >> 8), byte(v)}
}

// synOptions joins TCP options into one list.
func synOptions(opts ...[]byte) []byte {
	return bytes.Join(opts, nil)
}

// synSegment returns an IPv4 TCP segment without payload from device D to
// node N with flags and the TCP options opts, padded with zeros (end of
// list) to a multiple of 4, and valid IP and TCP checksums. With ipOpts its
// IP header carries 4 bytes of options, a router alert, and is 24 bytes long.
func synSegment(flags uint8, ipOpts bool, opts []byte) []byte {
	hl := ipv4HeaderLen
	if ipOpts {
		hl += 4
	}
	optLen := (len(opts) + 3) &^ 3
	b := make([]byte, hl+20+optLen)

	b[0] = 0x40 | byte(hl/4)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], 0x0250)
	b[6] = 0x40 // DF
	b[8] = 64
	b[9] = protoTCP
	src, dst := rwDeviceD.As4(), rwNodeN.As4()
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	if ipOpts {
		copy(b[20:24], []byte{0x94, 0x04, 0, 0})
	}
	refreshHeaderSum(b)

	tcp := b[hl:]
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 0x01020304)
	if flags&tcpACK != 0 {
		binary.BigEndian.PutUint32(tcp[8:12], 0x0a0b0c0d)
	}
	tcp[12] = byte((20+optLen)/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:], opts)
	refreshTCPSum(b)
	return b
}

// tcpSumFromScratch computes the TCP checksum of the IPv4 packet b over its
// pseudo header and its whole segment, with the checksum field as zero.
func tcpSumFromScratch(b []byte) uint16 {
	seg := bytes.Clone(b[pktHL(b):])
	seg[16], seg[17] = 0, 0
	return ^inetSum(pseudoHeader(pktSrc(b), pktDst(b), protoTCP, len(seg)), seg)
}

// refreshTCPSum recomputes the TCP checksum of the IPv4 packet b.
func refreshTCPSum(b []byte) {
	binary.BigEndian.PutUint16(b[pktHL(b)+16:], tcpSumFromScratch(b))
}

// tcpSum returns the TCP checksum the IPv4 packet b carries.
func tcpSum(b []byte) uint16 {
	return binary.BigEndian.Uint16(b[pktHL(b)+16:])
}

// clampCase is a packet clampSYN is given and the packet it has to leave.
type clampCase struct {
	name    string
	in, out []byte
}

// clampLowered returns SYNs and SYN-ACKs with MSS 1460, each with the same
// segment at MSS 1332 built from scratch, which clampSYN has to turn them
// into at 1332.
func clampLowered() []clampCase {
	first := func(v uint16) []byte {
		return synOptions(synMSSOption(v), synSACKPerm, synTS, synNOP, synWScale)
	}
	// A NOP in front puts the value at an odd offset, 23.
	behindNOP := func(v uint16) []byte {
		return synOptions(synNOP, synMSSOption(v), synNOP, synWScale, synNOP, synNOP, synSACKPerm)
	}
	// The value at offset 38.
	behindOthers := func(v uint16) []byte {
		return synOptions(synSACKPerm, synTS, synNOP, synWScale, synMSSOption(v))
	}
	// The value at offset 25, odd without a NOP.
	behindWScale := func(v uint16) []byte {
		return synOptions(synWScale, synMSSOption(v))
	}
	// An MSS option of length 6 is skipped by its length, not read.
	behindLongMSS := func(v uint16) []byte {
		return synOptions([]byte{2, 6, 0x05, 0xb4, 0, 0}, synMSSOption(v))
	}

	var cases []clampCase
	add := func(name string, flags uint8, ipOpts bool, opts func(uint16) []byte) {
		cases = append(cases, clampCase{
			name: name,
			in:   synSegment(flags, ipOpts, opts(synLANMSS)),
			out:  synSegment(flags, ipOpts, opts(synClampMSS)),
		})
	}
	add("SYN, MSS first", tcpSYN, false, first)
	add("SYN-ACK, MSS first", tcpSYN|tcpACK, false, first)
	add("SYN, NOP in front", tcpSYN, false, behindNOP)
	add("SYN-ACK, NOP in front", tcpSYN|tcpACK, false, behindNOP)
	add("SYN behind IP options", tcpSYN, true, first)
	add("SYN-ACK behind IP options, NOP in front", tcpSYN|tcpACK, true, behindNOP)
	add("SYN, MSS behind other options", tcpSYN, false, behindOthers)
	add("SYN-ACK, MSS behind a window scale", tcpSYN|tcpACK, false, behindWScale)
	add("SYN, MSS behind an MSS option of length 6", tcpSYN, false, behindLongMSS)
	return cases
}

// clampLeft returns packets clampSYN has to leave as they are at 1332.
func clampLeft() []clampCase {
	syn := func() []byte {
		return synSegment(tcpSYN, false, synOptions(synMSSOption(synLANMSS), synSACKPerm, synTS, synNOP, synWScale))
	}

	udp := syn()
	udp[9] = protoUDP
	refreshHeaderSum(udp)

	later := syn()
	binary.BigEndian.PutUint16(later[6:8], 1) // offset 8 bytes, DF clear
	refreshHeaderSum(later)

	// The options of syn become payload behind a 20-byte header.
	inPayload := syn()
	inPayload[ipv4HeaderLen+12] = 5 << 4
	refreshTCPSum(inPayload)

	seg := syn()[ipv4HeaderLen:]
	ipv6 := make([]byte, 40, 40+len(seg))
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(seg)))
	ipv6[6] = protoTCP
	ipv6[7] = 64
	copy(ipv6[8:24], netip.MustParseAddr("fd00::2").AsSlice())
	copy(ipv6[24:40], netip.MustParseAddr("fd00::1").AsSlice())
	ipv6 = append(ipv6, seg...)

	return []clampCase{
		{name: "MSS equal to the clamp", in: synSegment(tcpSYN, false, synMSSOption(synClampMSS))},
		{name: "MSS below the clamp", in: synSegment(tcpSYN|tcpACK, false, synMSSOption(1200))},
		{name: "SYN without an MSS option", in: synSegment(tcpSYN, false, synOptions(synSACKPerm, synTS, synNOP, synWScale))},
		{name: "SYN without options", in: synSegment(tcpSYN, false, nil)},
		{name: "SYN with an MSS option of length 6 alone", in: synSegment(tcpSYN, false, []byte{2, 6, 0x05, 0xb4, 0, 0})},
		{name: "MSS behind the end of the option list", in: synSegment(tcpSYN, false, synOptions([]byte{0, 0, 0, 0}, synMSSOption(synLANMSS)))},
		{name: "MSS in the payload", in: inPayload},
		{name: "segment without SYN", in: synSegment(tcpACK, false, synMSSOption(synLANMSS))},
		{name: "SYN with RST", in: synSegment(tcpSYN|tcpFlagRST, false, synMSSOption(synLANMSS))},
		{name: "UDP packet", in: udp},
		{name: "IPv6 packet", in: ipv6},
		{name: "fragment with a non-zero offset", in: later},
	}
}

// clampMalformed returns packets clampSYN cannot read up to an MSS option.
// Each would carry MSS 1460 if it were whole.
func clampMalformed() []clampCase {
	full := synSegment(tcpSYN, false, synOptions(synMSSOption(synLANMSS), synSACKPerm, synTS, synNOP, synWScale))
	withIPOpts := synSegment(tcpSYN, true, synMSSOption(synLANMSS))
	mss := synMSSOption(synLANMSS)

	ihl4 := bytes.Clone(full)
	ihl4[0] = 0x44
	ihl15 := bytes.Clone(full)
	ihl15[0] = 0x4f
	doff4 := bytes.Clone(full)
	doff4[ipv4HeaderLen+12] = 4 << 4
	doff0 := bytes.Clone(full)
	doff0[ipv4HeaderLen+12] = 0
	// The header ends at 24, inside the MSS option at 22.
	mssPastHeader := synSegment(tcpSYN, false, synOptions(synNOP, synNOP, mss))
	mssPastHeader[ipv4HeaderLen+12] = 6 << 4

	return []clampCase{
		{name: "nil slice", in: nil},
		{name: "empty slice", in: []byte{}},
		{name: "cut inside the IP header", in: full[:12]},
		{name: "cut one byte short of the IP header", in: full[:19]},
		{name: "cut inside the IP options", in: withIPOpts[:22]},
		{name: "header length below 20", in: ihl4},
		{name: "header length past the packet", in: ihl15[:59]},
		{name: "cut inside the TCP header", in: full[:ipv4HeaderLen+10]},
		{name: "cut inside the options", in: full[:ipv4HeaderLen+22]},
		{name: "data offset 4", in: doff4},
		{name: "data offset 0", in: doff0},
		{name: "option with length 0", in: synSegment(tcpSYN, false, synOptions([]byte{8, 0}, mss))},
		{name: "option with length 1", in: synSegment(tcpSYN, false, synOptions([]byte{8, 1}, mss))},
		{name: "MSS option with length 0", in: synSegment(tcpSYN, false, []byte{2, 0, 0x05, 0xb4})},
		{name: "MSS option with length 1", in: synSegment(tcpSYN, false, []byte{2, 1, 0x05, 0xb4})},
		{name: "option longer than the header", in: synSegment(tcpSYN, false, synOptions(synNOP, synNOP, []byte{8, 10, 0, 0}))},
		{name: "length byte past the header", in: synSegment(tcpSYN, false, synOptions(synNOP, synNOP, synNOP, []byte{3}))},
		{name: "MSS option past the header", in: mssPastHeader},
	}
}

func TestClampSYN_Lowers(t *testing.T) {
	for _, tc := range clampLowered() {
		t.Run(tc.name, func(t *testing.T) {
			got := bytes.Clone(tc.in)
			if !clampSYN(got, synClampMSS) {
				t.Fatal("clampSYN = false, want true")
			}
			if want := tcpSumFromScratch(got); tcpSum(got) != want {
				t.Errorf("TCP checksum = %#04x, want %#04x as computed from scratch", tcpSum(got), want)
			}
			if !bytes.Equal(got, tc.out) {
				t.Errorf("packet =\n%x\nwant\n%x", got, tc.out)
			}
		})
	}
}

func TestClampSYN_LeavesUnchanged(t *testing.T) {
	for _, tc := range clampLeft() {
		t.Run(tc.name, func(t *testing.T) {
			got := bytes.Clone(tc.in)
			if clampSYN(got, synClampMSS) {
				t.Error("clampSYN = true, want false")
			}
			if !bytes.Equal(got, tc.in) {
				t.Errorf("packet =\n%x\nwant it unchanged\n%x", got, tc.in)
			}
		})
	}
}

func TestClampSYN_Malformed(t *testing.T) {
	for _, tc := range clampMalformed() {
		t.Run(tc.name, func(t *testing.T) {
			got := bytes.Clone(tc.in)
			if clampSYN(got, synClampMSS) {
				t.Error("clampSYN = true, want false")
			}
			if !bytes.Equal(got, tc.in) {
				t.Errorf("packet =\n%x\nwant it unchanged\n%x", got, tc.in)
			}
		})
	}
}

func TestClampSYN_AllocatesNothing(t *testing.T) {
	lowered := clampLowered()[2]
	pkt := bytes.Clone(lowered.in)
	allocs := testing.AllocsPerRun(100, func() {
		copy(pkt, lowered.in)
		clampSYN(pkt, synClampMSS)
	})
	if allocs != 0 {
		t.Errorf("clampSYN allocates %.0f times per packet, want 0", allocs)
	}
}

// FuzzClampSYN holds clampSYN to its contract on any packet and MSS: it
// never panics or changes a packet's length, leaves a packet it reports
// false for as it is, and changes in one it lowered only the two bytes of
// an MSS option's value, now mss, and the two of the TCP checksum, which
// stays valid when it was.
func FuzzClampSYN(f *testing.F) {
	for _, set := range [][]clampCase{clampLowered(), clampLeft(), clampMalformed()} {
		for _, tc := range set {
			f.Add(tc.in, uint16(synClampMSS))
		}
	}
	f.Add(clampLowered()[2].in, uint16(0))
	f.Add(clampLowered()[3].in, uint16(65535))

	f.Fuzz(func(t *testing.T, pkt []byte, mss uint16) {
		got := bytes.Clone(pkt)
		lowered := clampSYN(got, mss)
		if len(got) != len(pkt) {
			t.Fatalf("length = %d, want %d", len(got), len(pkt))
		}
		if !lowered {
			if !bytes.Equal(got, pkt) {
				t.Fatalf("clampSYN = false and changed\n%x\ninto\n%x", pkt, got)
			}
			return
		}
		checkLowered(t, pkt, got, mss)
	})
}

// checkLowered fails unless out differs from in only in the two bytes of the
// TCP checksum and in one or both bytes of the value of an MSS option, a
// kind 2 of length 4 in the TCP options, that was above mss and is now mss,
// and unless the checksum is still valid when it was.
func checkLowered(t *testing.T, in, out []byte, mss uint16) {
	t.Helper()

	hl := pktHL(in)
	sum := hl + 16
	var diff []int
	for i := range in {
		if in[i] != out[i] && i != sum && i != sum+1 {
			diff = append(diff, i)
		}
	}
	if len(diff) == 0 || diff[len(diff)-1]-diff[0] > 1 {
		t.Fatalf("clampSYN = true and changed bytes %v besides the checksum, want one or two adjacent bytes of an MSS value", diff)
	}

	// The value starts at the first changed byte, or one before it when only
	// its low byte changed.
	found := false
	for _, at := range []int{diff[0], diff[0] - 1} {
		if at-2 < hl+20 || at+2 > len(in) || diff[len(diff)-1] > at+1 {
			continue
		}
		if in[at-2] == 2 && in[at-1] == 4 &&
			binary.BigEndian.Uint16(in[at:]) > mss && binary.BigEndian.Uint16(out[at:]) == mss {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("clampSYN = true and changed bytes %v, want the value of an MSS option above %d set to it", diff, mss)
	}

	if transportSumOK(in) && !transportSumOK(out) {
		t.Fatalf("TCP checksum was valid and is not after clampSYN: %#04x, from scratch %#04x", tcpSum(out), tcpSumFromScratch(out))
	}
}

// batchTUN is a fakeTUN that reads and writes batches: Read fills the
// packets of batch into the buffers in one call and returns readErr with
// them, Write records each buffer whole and returns writeN and the
// fakeTUN's writeErr.
type batchTUN struct {
	*fakeTUN
	batch   [][]byte
	readErr error
	writeN  int
	got     [][]byte
}

func (b *batchTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, p := range b.batch {
		sizes[i] = copy(bufs[i][offset:], p)
	}
	return len(b.batch), b.readErr
}

func (b *batchTUN) Write(bufs [][]byte, _ int) (int, error) {
	for _, buf := range bufs {
		b.got = append(b.got, bytes.Clone(buf))
	}
	return b.writeN, b.writeErr
}

// clampBuffer returns a buffer of wireguard-go's shape: rwOffset bytes of
// headroom filled with 0xff, which no IPv4 packet starts with, then pkt,
// then room for a full packet.
func clampBuffer(pkt []byte) []byte {
	b := bytes.Repeat([]byte{0xff}, rwOffset+1500)
	copy(b[rwOffset:], pkt)
	return b
}

// newClampFake returns a fakeTUN whose Read hands out one queued packet
// without a sender goroutine, and a new wrapper of it.
func newClampFake(t *testing.T) (*fakeTUN, *mssClampTUN) {
	t.Helper()
	f := newFakeTUN()
	f.in = make(chan []byte, 1)
	w := newMSSClampTUN(f)
	t.Cleanup(func() { _ = w.Close() })
	return f, w
}

func TestMSSClampTUN_ReadClamps(t *testing.T) {
	f, w := newClampFake(t)
	w.setMSS(synClampMSS)
	tc := clampLowered()[0]
	f.in <- tc.in

	bufs := [][]byte{clampBuffer(nil)}
	sizes := make([]int, 1)
	n, err := w.Read(bufs, sizes, rwOffset)
	if n != 1 || err != nil {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}
	if got := bufs[0][rwOffset : rwOffset+sizes[0]]; !bytes.Equal(got, tc.out) {
		t.Errorf("read packet =\n%x\nwant\n%x", got, tc.out)
	}
}

func TestMSSClampTUN_ReadBatch(t *testing.T) {
	syn := clampLowered()[0]
	synAck := clampLowered()[3]
	ack := synSegment(tcpACK, false, synMSSOption(synLANMSS))
	// What the device reads is cut inside the options, and the buffer still
	// holds the rest of a whole SYN from an earlier read behind it: a clamp
	// that read past sizes[i] would find the option there.
	cut := syn.in[:ipv4HeaderLen+22]

	bufs := make([][]byte, 5)
	for i := range bufs {
		bufs[i] = clampBuffer(syn.in)
	}
	stale := bytes.Clone(bufs[4])
	readErr := errors.New("tun read failed")
	dev := &batchTUN{fakeTUN: newFakeTUN(), batch: [][]byte{syn.in, ack, synAck.in, cut}, readErr: readErr}
	w := newMSSClampTUN(dev)
	w.setMSS(synClampMSS)
	t.Cleanup(func() { _ = w.Close() })

	sizes := make([]int, len(bufs))
	n, err := w.Read(bufs, sizes, rwOffset)
	if n != 4 || err != readErr {
		t.Fatalf("Read = (%d, %v), want the device's (4, %v)", n, err, readErr)
	}

	for i, want := range [][]byte{syn.out, ack, synAck.out, cut} {
		if got := bufs[i][rwOffset : rwOffset+sizes[i]]; !bytes.Equal(got, want) {
			t.Errorf("packet %d =\n%x\nwant\n%x", i, got, want)
		}
	}
	if want := clampBuffer(syn.in); !bytes.Equal(bufs[3], want) {
		t.Errorf("buffer of the cut packet =\n%x\nwant it as the device left it\n%x", bufs[3], want)
	}
	if !bytes.Equal(bufs[4], stale) {
		t.Error("Read changed a buffer past the n packets the device returned")
	}
}

func TestMSSClampTUN_ReadClosed(t *testing.T) {
	f, w := newClampFake(t)
	w.setMSS(synClampMSS)
	_ = f.Close()

	pkt := clampLowered()[0].in
	bufs := [][]byte{clampBuffer(pkt)}
	sizes := make([]int, 1)
	n, err := w.Read(bufs, sizes, rwOffset)
	if n != 0 || err != os.ErrClosed {
		t.Errorf("Read = (%d, %v), want (0, os.ErrClosed) as the device returned it", n, err)
	}
	if want := clampBuffer(pkt); !bytes.Equal(bufs[0], want) {
		t.Error("Read changed a buffer the device returned no packet in")
	}
}

func TestMSSClampTUN_WriteClamps(t *testing.T) {
	f, w := newClampFake(t)
	w.setMSS(synClampMSS)
	writeErr := errors.New("tun write failed")
	f.writeErr = writeErr

	syn := clampLowered()[0]
	synAck := clampLowered()[3]
	ack := synSegment(tcpACK, false, synMSSOption(synLANMSS))
	headroom := bytes.Repeat([]byte{0xff}, rwOffset)
	bufs := [][]byte{
		append(bytes.Clone(headroom), syn.in...),
		bytes.Clone(headroom),
		append(bytes.Clone(headroom), synAck.in...),
		append(bytes.Clone(headroom), ack...),
	}

	n, err := w.Write(bufs, rwOffset)
	if n != len(bufs) || err != writeErr {
		t.Fatalf("Write = (%d, %v), want the device's (%d, %v)", n, err, len(bufs), writeErr)
	}
	if calls := f.writeCalls(); calls != 1 {
		t.Fatalf("device saw %d Write calls, want 1", calls)
	}
	got := f.written()
	want := [][]byte{syn.out, {}, synAck.out, ack}
	if len(got) != len(want) {
		t.Fatalf("device was handed %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("packet %d =\n%x\nwant\n%x", i, got[i], want[i])
		}
	}
	if !bytes.Equal(bufs[1], headroom) {
		t.Error("Write changed a buffer no longer than the offset")
	}
}

func TestMSSClampTUN_WriteResult(t *testing.T) {
	writeErr := errors.New("tun write failed")
	dev := &batchTUN{fakeTUN: newFakeTUN(), writeN: 1}
	dev.writeErr = writeErr
	w := newMSSClampTUN(dev)
	w.setMSS(synClampMSS)
	t.Cleanup(func() { _ = w.Close() })

	syn := clampLowered()[1]
	short := bytes.Repeat([]byte{0xff}, rwOffset-1)
	bufs := [][]byte{short, append(bytes.Repeat([]byte{0xff}, rwOffset), syn.in...)}

	n, err := w.Write(bufs, rwOffset)
	if n != 1 || err != writeErr {
		t.Fatalf("Write = (%d, %v), want the device's (1, %v)", n, err, writeErr)
	}
	if len(dev.got) != 2 {
		t.Fatalf("device was handed %d buffers, want 2", len(dev.got))
	}
	if !bytes.Equal(dev.got[0], short) {
		t.Error("Write changed a buffer shorter than the offset")
	}
	if got := dev.got[1][rwOffset:]; !bytes.Equal(got, syn.out) {
		t.Errorf("packet =\n%x\nwant\n%x", got, syn.out)
	}
}

func TestMSSClampTUN_Off(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []int
	}{
		{name: "new wrapper"},
		{name: "setMSS(0)", set: []int{synClampMSS, 0}},
		{name: "setMSS(-1)", set: []int{synClampMSS, -1}},
		{name: "setMSS(65536)", set: []int{synClampMSS, 65536}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, w := newClampFake(t)
			for _, mss := range tc.set {
				w.setMSS(mss)
			}
			if got := w.mss.Load(); got != 0 {
				t.Fatalf("mss = %d, want 0", got)
			}

			for _, c := range clampLowered() {
				f.in <- c.in
				bufs := [][]byte{clampBuffer(nil)}
				sizes := make([]int, 1)
				if n, err := w.Read(bufs, sizes, rwOffset); n != 1 || err != nil {
					t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
				}
				if got := bufs[0][rwOffset : rwOffset+sizes[0]]; !bytes.Equal(got, c.in) {
					t.Errorf("%s: Read changed the packet", c.name)
				}

				buf := clampBuffer(c.in)[:rwOffset+len(c.in)]
				if _, err := w.Write([][]byte{buf}, rwOffset); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if !bytes.Equal(buf[rwOffset:], c.in) {
					t.Errorf("%s: Write changed the packet", c.name)
				}
			}
			written := f.written()
			for i, c := range clampLowered() {
				if i >= len(written) || !bytes.Equal(written[i], c.in) {
					t.Errorf("%s: the device was not handed the packet unchanged", c.name)
				}
			}
		})
	}
}

func TestMSSClampTUN_SetMSS(t *testing.T) {
	for _, tc := range []struct {
		set  int
		want uint32
	}{
		{set: -1, want: 0},
		{set: 0, want: 0},
		{set: 1, want: 1},
		{set: synClampMSS, want: synClampMSS},
		{set: 65535, want: 65535},
		{set: 65536, want: 0},
	} {
		t.Run(fmt.Sprint(tc.set), func(t *testing.T) {
			w := newMSSClampTUN(newFakeTUN())
			w.setMSS(synLANMSS)
			w.setMSS(tc.set)
			if got := w.mss.Load(); got != tc.want {
				t.Errorf("mss after setMSS(%d) = %d, want %d", tc.set, got, tc.want)
			}
		})
	}
}

func TestMSSClampTUN_DelegatesTheRest(t *testing.T) {
	f := newFakeTUN()
	f.mtu = 1372
	w := newMSSClampTUN(f)

	if mtu, err := w.MTU(); mtu != 1372 || err != nil {
		t.Errorf("MTU() = (%d, %v), want the device's (1372, nil)", mtu, err)
	}
	if name, err := w.Name(); name != "fake0" || err != nil {
		t.Errorf("Name() = (%q, %v), want the device's (\"fake0\", nil)", name, err)
	}
	if w.Events() != f.Events() {
		t.Error("Events() is not the device's channel")
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	if f.closeCount() != 1 {
		t.Errorf("device saw %d Close calls, want 1", f.closeCount())
	}
}
