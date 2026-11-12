//go:build darwin

package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pflogTestSink records what a pflog reader reports.
type pflogTestSink struct {
	mu     sync.Mutex
	events []ConnEvent
	lost   []int
}

func (s *pflogTestSink) Event(ev ConnEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *pflogTestSink) Lost(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lost = append(s.lost, n)
}

func (s *pflogTestSink) snapshot() ([]ConnEvent, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events), slices.Clone(s.lost)
}

// pflogBytes returns a pflog record as XNU's pflog_packet writes it: the
// 64-byte pfloghdr with length 61, the size up to its padding, then packet.
func pflogBytes(ruleset string, action, dir uint8, subrulenr uint32, packet []byte) []byte {
	b := make([]byte, pflogHdrLen+len(packet))
	b[0] = 61
	b[1] = unix.AF_INET
	b[2] = action
	copy(b[4:20], "utun4")
	copy(b[20:36], ruleset)
	binary.BigEndian.PutUint32(b[36:40], 3)
	binary.BigEndian.PutUint32(b[40:44], subrulenr)
	b[60] = dir
	copy(b[pflogHdrLen:], packet)
	return b
}

// bpfFrame wraps one record in the 20-byte BPF header XNU writes for pflog0,
// padded to the BPF alignment.
func bpfFrame(data []byte) []byte {
	const hdrLen = 20
	b := make([]byte, (hdrLen+len(data)+bpfAlignment-1)&^(bpfAlignment-1))
	binary.NativeEndian.PutUint32(b[bpfOffCaplen:], uint32(len(data)))
	binary.NativeEndian.PutUint32(b[bpfOffCaplen+4:], uint32(len(data)))
	binary.NativeEndian.PutUint16(b[bpfOffHdrlen:], hdrLen)
	copy(b[hdrLen:], data)
	return b
}

// pflogRead is one result of a fake read: the bytes it fills in or its error.
type pflogRead struct {
	data []byte
	err  error
}

// pflogReads returns a read seam that hands out each of results in turn and
// then reports an empty read every millisecond, as the read timeout does. An
// error read returns -1, as unix.Read does.
func pflogReads(results ...pflogRead) func([]byte) (int, error) {
	i := 0
	return func(b []byte) (int, error) {
		if i < len(results) {
			r := results[i]
			i++
			if r.err != nil {
				return -1, r.err
			}
			return copy(b, r.data), nil
		}
		time.Sleep(time.Millisecond)
		return 0, nil
	}
}

// idlePflogReader returns a started reader that reads nothing, and whether its
// loop released its device.
func idlePflogReader() (*pflogReader, *atomic.Bool) {
	released := new(atomic.Bool)
	r := &pflogReader{
		sink:    &pflogTestSink{},
		logger:  testLogger(),
		tag:     func(uint32) (string, bool) { return "", false },
		local:   localAddrs{list: net.InterfaceAddrs, now: time.Now},
		read:    pflogReads(),
		drops:   func() (uint32, error) { return 0, nil },
		release: func() { released.Store(true) },
		buf:     make([]byte, 64),
	}
	r.start()
	return r, released
}

func TestParsePflogRecord(t *testing.T) {
	packet := ipv4Packet(connPeer, connNode, ipProtoTCP, 20, ports(41001, 7001))
	b := pflogBytes("plexd", pfActionPass, pfDirIn, 5, packet)

	rec, ok := parsePflogRecord(b)
	if !ok {
		t.Fatal("parsePflogRecord() ok = false, want true")
	}
	if rec.ruleset != "plexd" {
		t.Errorf("ruleset = %q, want %q", rec.ruleset, "plexd")
	}
	if rec.subrulenr != 5 {
		t.Errorf("subrulenr = %d, want 5", rec.subrulenr)
	}
	if rec.dir != 1 {
		t.Errorf("dir = %d, want 1", rec.dir)
	}
	if rec.action != pfActionPass {
		t.Errorf("action = %d, want %d", rec.action, pfActionPass)
	}
	// The length 61 rounds up to 64, where the packet starts.
	if len(rec.packet) != len(packet) || &rec.packet[0] != &b[64] {
		t.Fatalf("packet = %d bytes at another offset, want the %d bytes at offset 64", len(rec.packet), len(packet))
	}
	src, dst, proto, srcPort, dstPort, ok := parseIPTuple(rec.packet)
	if !ok || src != connPeer || dst != connNode || proto != ipProtoTCP || srcPort != 41001 || dstPort != 7001 {
		t.Errorf("parseIPTuple(packet) = %v %v %d %d %d %v, want %v %v 6 41001 7001 true", src, dst, proto, srcPort, dstPort, ok, connPeer, connNode)
	}

	// A ruleset name of all 16 bytes has no NUL to end it.
	const fullName = "plexd-0123456789"
	full := slices.Clone(b)
	copy(full[20:36], fullName)
	if rec, ok := parsePflogRecord(full); !ok || rec.ruleset != fullName {
		t.Errorf("ruleset of 16 bytes = %q, %v, want %q, true", rec.ruleset, ok, fullName)
	}

	long := slices.Clone(b)
	long[0] = 200
	inside := slices.Clone(b)
	inside[0] = 20
	for _, tt := range []struct {
		name string
		b    []byte
	}{
		{name: "63 bytes", b: b[:63]},
		{name: "length 200", b: long},
		{name: "length inside the header", b: inside},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := parsePflogRecord(tt.b); ok {
				t.Error("parsePflogRecord() ok = true, want false")
			}
		})
	}
}

// A read returns the records back to back, each padded to the BPF alignment.
// A record cut short ends the walk.
func TestBPFRecords(t *testing.T) {
	// 29 bytes of packet make a 93-byte record, which the alignment pads.
	first := pflogBytes("plexd", pfActionPass, pfDirIn, 1, ipv4Packet(connPeer, connNode, ipProtoUDP, 20, append(ports(41003, 7002), 'x')))
	second := pflogBytes("plexd", pfActionPass, pfDirOut, 3, ipv4Packet(connNode, connPeer, ipProtoTCP, 20, ports(50000, 7006)))
	frame := bpfFrame(first)
	buf := slices.Concat(frame, bpfFrame(second))

	var got [][]byte
	bpfRecords(buf, func(b []byte) { got = append(got, b) })
	if len(got) != 2 || !bytes.Equal(got[0], first) || !bytes.Equal(got[1], second) {
		t.Errorf("records = %d, want the two records unchanged", len(got))
	}

	got = nil
	bpfRecords(buf[:len(frame)+30], func(b []byte) { got = append(got, b) })
	if len(got) != 1 || !bytes.Equal(got[0], first) {
		t.Errorf("records of a cut buffer = %d, want the first one alone", len(got))
	}
}

// The reader reports the passes of plexd's logged lines and nothing else. pf's
// direction in becomes in for an address of the host and forward otherwise.
func TestPflogReader_Events(t *testing.T) {
	node6 := netip.MustParseAddr("fd00:99::1")
	peer6 := netip.MustParseAddr("fd00:99::3")
	routed := netip.MustParseAddr("10.99.0.9")
	tags := map[uint32]string{8: "1/0", 10: "1/0", 12: "1/1"}

	syn := ipv4Packet(connPeer, connNode, ipProtoTCP, 20, ports(41001, 7001))
	forwarded := ipv4Packet(connPeer, routed, ipProtoTCP, 20, ports(41002, 7001))
	out := ipv4Packet(connNode, connPeer, ipProtoTCP, 20, ports(50000, 7006))
	udp6 := ipv6Packet(peer6, node6, ipProtoUDP, append(ports(41003, 7002), 'x'))

	first := slices.Concat(
		bpfFrame(pflogBytes("plexd", pfActionPass, pfDirIn, 8, syn)),
		bpfFrame(pflogBytes("plexd", pfActionPass, pfDirIn, 8, forwarded)),
		bpfFrame(pflogBytes("other", pfActionPass, pfDirIn, 8, syn)),  // another anchor
		bpfFrame(pflogBytes("plexd", 1, pfDirIn, 8, syn)),             // a drop
		bpfFrame(pflogBytes("plexd", pfActionPass, pfDirIn, 99, syn)), // no logged line
	)
	second := slices.Concat(
		bpfFrame(pflogBytes("plexd", pfActionPass, pfDirOut, 10, out)),
		bpfFrame(pflogBytes("plexd", pfActionPass, 0, 8, syn)), // no direction
		bpfFrame(pflogBytes("plexd", pfActionPass, pfDirIn, 12, udp6)),
	)

	sink := &pflogTestSink{}
	r := &pflogReader{
		sink:   sink,
		logger: testLogger(),
		tag: func(nr uint32) (string, bool) {
			tag, ok := tags[nr]
			return tag, ok
		},
		local: localAddrs{
			list: func() ([]net.Addr, error) {
				return []net.Addr{
					&net.IPNet{IP: net.ParseIP("10.99.0.1"), Mask: net.CIDRMask(24, 32)},
					&net.IPNet{IP: net.ParseIP("fd00:99::1"), Mask: net.CIDRMask(64, 128)},
				}, nil
			},
			now: time.Now,
		},
		read:    pflogReads(pflogRead{data: first}, pflogRead{data: second}),
		drops:   func() (uint32, error) { return 0, nil },
		release: func() {},
		buf:     make([]byte, 4096),
	}
	r.start()
	defer r.close()

	want := []ConnEvent{
		{Tag: "1/0", Dir: ConnIn, Src: connPeer, Dst: connNode, Protocol: ipProtoTCP, SrcPort: 41001, DstPort: 7001},
		{Tag: "1/0", Dir: ConnForward, Src: connPeer, Dst: routed, Protocol: ipProtoTCP, SrcPort: 41002, DstPort: 7001},
		{Tag: "1/0", Dir: ConnOut, Src: connNode, Dst: connPeer, Protocol: ipProtoTCP, SrcPort: 50000, DstPort: 7006},
		{Tag: "1/1", Dir: ConnIn, Src: peer6, Dst: node6, Protocol: ipProtoUDP, SrcPort: 41003, DstPort: 7002},
	}
	waitForCondition(t, 5*time.Second, func() bool {
		events, _ := sink.snapshot()
		return len(events) >= len(want)
	})
	r.close()

	events, lost := sink.snapshot()
	if !slices.Equal(events, want) {
		t.Errorf("events =\n%+v\nwant\n%+v", events, want)
	}
	if len(lost) != 0 {
		t.Errorf("Lost calls = %v, want none", lost)
	}
}

// The drops the device counts reach the sink as their increase after each
// read. EINTR repeats the read, and any other read error logs the Warn line,
// ends the loop and releases the device.
func TestPflogReader_LostAndReadError(t *testing.T) {
	var buf bytes.Buffer
	sink := &pflogTestSink{}
	counts := []uint32{3, 3, 7}
	calls := 0
	released := new(atomic.Bool)
	r := &pflogReader{
		sink:   sink,
		logger: captureLogger(&buf),
		tag:    func(uint32) (string, bool) { return "", false },
		local:  localAddrs{list: net.InterfaceAddrs, now: time.Now},
		read: pflogReads(
			pflogRead{},
			pflogRead{err: unix.EINTR},
			pflogRead{},
			pflogRead{},
			pflogRead{err: unix.EIO},
		),
		drops: func() (uint32, error) {
			n := counts[min(calls, len(counts)-1)]
			calls++
			return n, nil
		},
		release: func() { released.Store(true) },
		buf:     make([]byte, 64),
	}
	r.start()

	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		r.close()
		t.Fatal("the reader still runs after a read error")
	}

	if _, lost := sink.snapshot(); !slices.Equal(lost, []int{3, 4}) {
		t.Errorf("Lost calls = %v, want [3 4]", lost)
	}
	if !released.Load() {
		t.Error("the device was not released")
	}
	if r.running() {
		t.Error("running() = true after the loop ended")
	}
	out := buf.String()
	if got := countLines(out, `level=WARN msg="policy connection log reader stopped"`); got != 1 {
		t.Errorf("stop lines = %d, want 1:\n%s", got, out)
	}
	if !strings.Contains(out, `error="policy: pf: pflog: read: input/output error"`) {
		t.Errorf("stop line misses the error:\n%s", out)
	}

	// The loop has ended, so close returns at once.
	r.close()
}

// close stops a reader that is waiting for records, releases its device, and
// may be called again.
func TestPflogReader_Close(t *testing.T) {
	r, released := idlePflogReader()
	if !r.running() {
		t.Fatal("running() = false before close")
	}

	closed := make(chan struct{})
	go func() {
		r.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("close() did not return")
	}

	if r.running() || !released.Load() {
		t.Error("the reader still runs or holds its device after close")
	}
	r.close()
}

// The host's addresses are read again once they are localAddrsTTL old, and a
// failed read keeps the ones read before.
func TestLocalAddrs(t *testing.T) {
	now, advance := fixedClock(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC))
	calls := 0
	fail := false
	l := localAddrs{
		list: func() ([]net.Addr, error) {
			calls++
			if fail {
				return nil, errors.New("no addresses")
			}
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("10.99.0.1"), Mask: net.CIDRMask(24, 32)},
				&net.IPAddr{IP: net.ParseIP("fd00:99::1")},
			}, nil
		},
		now: now,
	}

	for _, tt := range []struct {
		addr netip.Addr
		want bool
	}{
		{addr: connNode, want: true},
		{addr: netip.AddrFrom16(connNode.As16()), want: true},
		{addr: netip.MustParseAddr("fd00:99::1"), want: true},
		{addr: connPeer, want: false},
	} {
		if got := l.has(tt.addr); got != tt.want {
			t.Errorf("has(%v) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	if calls != 1 {
		t.Errorf("list calls = %d, want 1", calls)
	}

	advance(localAddrsTTL - time.Second)
	l.has(connNode)
	if calls != 1 {
		t.Errorf("list calls before the TTL = %d, want 1", calls)
	}

	advance(time.Second)
	l.has(connNode)
	if calls != 2 {
		t.Errorf("list calls at the TTL = %d, want 2", calls)
	}

	fail = true
	advance(localAddrsTTL)
	if !l.has(connNode) {
		t.Error("has() after a failed read = false, want the address read before")
	}
	if calls != 3 {
		t.Errorf("list calls after a failed read = %d, want 3", calls)
	}
}
