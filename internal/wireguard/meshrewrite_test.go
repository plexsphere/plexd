package wireguard

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// rwMeshPrefix is the address and prefix the tests' mesh interface carries.
var rwMeshPrefix = netip.MustParsePrefix("10.255.241.1/24")

// rwOffset is the headroom wireguard-go leaves before a packet in the buffers
// it hands a tun device.
const rwOffset = 16

// payloadMarker is the payload of the packets whose content no log line may
// hold.
const payloadMarker = "plexd-214-payload-marker"

// rwLogLines counts the lines of log that have msg and every one of the
// key=value fields.
func rwLogLines(log, msg string, fields ...string) int {
	n := 0
	for line := range strings.SplitSeq(log, "\n") {
		if rwLogged(line, msg, fields...) {
			n++
		}
	}
	return n
}

// rwLogged reports whether one line of log has msg and every one of the
// key=value fields.
func rwLogged(log, msg string, fields ...string) bool {
	for line := range strings.SplitSeq(log, "\n") {
		if !strings.Contains(line, "msg=\""+msg+"\"") {
			continue
		}
		words := strings.Fields(line)
		if !slices.ContainsFunc(fields, func(f string) bool { return !slices.Contains(words, f) }) {
			return true
		}
	}
	return false
}

// fakeAddrs is an addrs seam over a fixed table; an interface outside it does
// not exist.
func fakeAddrs(table map[string][]netip.Prefix) func(string) ([]netip.Prefix, error) {
	return func(iface string) ([]netip.Prefix, error) {
		prefixes, ok := table[iface]
		if !ok {
			return nil, fmt.Errorf("route ip+net: no such network interface %s", iface)
		}
		return prefixes, nil
	}
}

// fakeTUN is a tun.Device for the wrapper's tests: Write records every call,
// Read hands out what the test sends on in, and its MTU is what the test sets.
type fakeTUN struct {
	mtu    int
	in     chan []byte
	events chan tun.Event
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	writes   [][][]byte
	writeErr error
	closes   int
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		mtu:    1420,
		in:     make(chan []byte),
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (f *fakeTUN) File() *os.File { return nil }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-f.closed:
		return 0, os.ErrClosed
	case p := <-f.in:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := make([][]byte, len(bufs))
	for i, b := range bufs {
		call[i] = bytes.Clone(b[offset:])
	}
	f.writes = append(f.writes, call)
	return len(bufs), f.writeErr
}

func (f *fakeTUN) MTU() (int, error) { return f.mtu, nil }

func (f *fakeTUN) Name() (string, error) { return "fake0", nil }

func (f *fakeTUN) Events() <-chan tun.Event { return f.events }

func (f *fakeTUN) BatchSize() int { return 1 }

func (f *fakeTUN) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	f.once.Do(func() {
		close(f.closed)
		close(f.events)
	})
	return nil
}

// written returns every packet the device was handed, in order.
func (f *fakeTUN) written() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all [][]byte
	for _, call := range f.writes {
		all = append(all, call...)
	}
	return all
}

// closeCount returns the number of Close calls the device saw.
func (f *fakeTUN) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closes
}

// writeCalls returns the number of Write calls the device saw.
func (f *fakeTUN) writeCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// rewriterTest is a MeshRewriter on a fake clock with the mesh, provider and
// tunnel devices wrapped over fake tuns, and no rewrite yet.
type rewriterTest struct {
	r                    *MeshRewriter
	clock                *fakeClock
	logs                 *syncBuffer
	mesh, access, tunnel *fakeTUN
	meshDev, accessDev   tun.Device
	tunnelDev            tun.Device
}

func newRewriterTest(t *testing.T) *rewriterTest {
	t.Helper()
	logs := &syncBuffer{}
	rt := &rewriterTest{
		r:      NewMeshRewriter(slogTextLogger(logs)),
		clock:  &fakeClock{now: rwStart},
		logs:   logs,
		mesh:   newFakeTUN(),
		access: newFakeTUN(),
		tunnel: newFakeTUN(),
	}
	rt.r.nat.now = rt.clock.Now
	rt.r.addrs = fakeAddrs(map[string][]netip.Prefix{
		rwMesh:   {netip.MustParsePrefix("fe80::1/64"), rwMeshPrefix},
		rwAccess: {rwPoolPrefix},
		rwTunnel: nil,
	})
	rt.meshDev = rt.r.Wrap(rwMesh, rt.mesh)
	rt.accessDev = rt.r.Wrap(rwAccess, rt.access)
	rt.tunnelDev = rt.r.Wrap(rwTunnel, rt.tunnel)
	t.Cleanup(func() {
		for _, d := range []tun.Device{rt.meshDev, rt.accessDev, rt.tunnelDev} {
			_ = d.Close()
		}
	})
	return rt
}

func (rt *rewriterTest) advance(d time.Duration) { rt.clock.Set(rt.clock.Now().Add(d)) }

// add adds the rewrite from from into the mesh interface.
func (rt *rewriterTest) add(t *testing.T, from string) {
	t.Helper()
	if err := rt.r.AddMeshSourceRewrite(from, rwMesh); err != nil {
		t.Fatalf("AddMeshSourceRewrite(%s, %s): %v", from, rwMesh, err)
	}
}

// writeTo writes pkts to dev the way wireguard-go does, behind rwOffset bytes
// of headroom, and fails unless Write reports all of them.
func writeTo(t *testing.T, dev tun.Device, pkts ...[]byte) {
	t.Helper()
	bufs := make([][]byte, len(pkts))
	for i, p := range pkts {
		bufs[i] = append(make([]byte, rwOffset), p...)
	}
	n, err := dev.Write(bufs, rwOffset)
	if err != nil || n != len(pkts) {
		t.Fatalf("Write of %d packets = %d, %v, want %d, nil", len(pkts), n, err, len(pkts))
	}
}

// readFrom reads the next packet from dev the way wireguard-go does, and fails
// after 5 s.
func readFrom(t *testing.T, dev tun.Device) []byte {
	t.Helper()
	type result struct {
		pkt []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		bufs := [][]byte{make([]byte, rwOffset+maxPacketSize)}
		sizes := []int{0}
		n, err := dev.Read(bufs, sizes, rwOffset)
		if n != 1 {
			done <- result{err: fmt.Errorf("read %d packets, error %v", n, err)}
			return
		}
		done <- result{pkt: bufs[0][rwOffset : rwOffset+sizes[0]], err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Read: %v", r.err)
		}
		return r.pkt
	case <-time.After(5 * time.Second):
		t.Fatal("Read returned no packet within 5s")
		return nil
	}
}

// queuedFor returns the number of translated packets waiting in dev's queue.
func queuedFor(dev tun.Device) int { return len(dev.(*meshTUN).queue) }

// assertWritten fails unless dev's wrapped device was handed exactly want.
func assertWritten(t *testing.T, what string, dev *fakeTUN, want ...[]byte) {
	t.Helper()
	got := dev.written()
	if len(got) != len(want) {
		t.Fatalf("%s: the wrapped device was handed %d packets, want %d", what, len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("%s: packet %d reached the wrapped device as %x, want it unchanged %x", what, i, got[i], want[i])
		}
	}
}

func TestMeshRewriter_WrapNil(t *testing.T) {
	r := NewMeshRewriter(discardLogger())
	if got := r.Wrap(rwMesh, nil); got != nil {
		t.Errorf("Wrap(%q, nil) = %v, want nil", rwMesh, got)
	}
	if r.nat.known(rwMesh) {
		t.Error("a nil device is known by its name")
	}
}

func TestMeshRewriter_AddRemoveReset(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	if !rwLogged(rt.logs.String(), "mesh source rewrite added", "level=DEBUG", "component=bridge", "from_iface="+rwAccess, "mesh_iface="+rwMesh, "mesh_addr=10.255.241.1") {
		t.Errorf("no added line in the log:\n%s", rt.logs)
	}

	// A second add, even naming another mesh interface, changes nothing.
	before := *rt.r.nat.rewrites[rwAccess]
	rt.add(t, rwAccess)
	if err := rt.r.AddMeshSourceRewrite(rwAccess, rwTunnel); err != nil {
		t.Errorf("AddMeshSourceRewrite naming another mesh interface = %v, want nil", err)
	}
	if after := *rt.r.nat.rewrites[rwAccess]; after.mesh != before.mesh || after.meshAddr != before.meshAddr {
		t.Errorf("rewrite after a second add = %+v, want %+v", after, before)
	}
	if !rwLogged(rt.logs.String(), "mesh source rewrite already present, idempotent success", "component=bridge", "from_iface="+rwAccess) {
		t.Errorf("no already-present line in the log:\n%s", rt.logs)
	}

	if err := rt.r.RemoveMeshSourceRewrite(rwTunnel, rwMesh); err != nil {
		t.Errorf("RemoveMeshSourceRewrite of an interface without a rewrite = %v, want nil", err)
	}
	if !rwLogged(rt.logs.String(), "mesh source rewrite not found, idempotent success", "component=bridge", "from_iface="+rwTunnel) {
		t.Errorf("no not-found line in the log:\n%s", rt.logs)
	}

	datagram := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	writeTo(t, rt.accessDev, datagram)
	if queuedFor(rt.meshDev) != 1 || rt.access.writeCalls() != 0 {
		t.Fatalf("with the rewrite: %d packets queued for the mesh device, %d writes to the wrapped device, want 1 and 0", queuedFor(rt.meshDev), rt.access.writeCalls())
	}
	readFrom(t, rt.meshDev)

	if err := rt.r.RemoveMeshSourceRewrite(rwAccess, rwMesh); err != nil {
		t.Fatalf("RemoveMeshSourceRewrite: %v", err)
	}
	if !rwLogged(rt.logs.String(), "mesh source rewrite removed", "component=bridge", "from_iface="+rwAccess, "mesh_iface="+rwMesh) {
		t.Errorf("no removed line in the log:\n%s", rt.logs)
	}
	writeTo(t, rt.accessDev, datagram)
	assertWritten(t, "D's datagram after the remove", rt.access, datagram)

	rt.add(t, rwAccess)
	if err := rt.r.ResetMeshSourceRewrite(); err != nil {
		t.Fatalf("ResetMeshSourceRewrite: %v", err)
	}
	if !rwLogged(rt.logs.String(), "mesh source rewrites reset", "level=DEBUG", "component=bridge") {
		t.Errorf("no reset line in the log:\n%s", rt.logs)
	}
	writeTo(t, rt.accessDev, datagram)
	assertWritten(t, "D's datagram after the reset", rt.access, datagram, datagram)
	if queuedFor(rt.meshDev) != 0 {
		t.Errorf("%d packets queued for the mesh device without a rewrite, want none", queuedFor(rt.meshDev))
	}
}

// SetMeshAddress moves the rewrite to the mesh interface's new address: a far
// end's next datagram leaves from it and its reply comes back, while a reply
// to the old address finds no flow and reaches the wrapped device as the
// host's.
func TestMeshRewriter_SetMeshAddress(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	datagram := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	writeTo(t, rt.accessDev, datagram)
	oldPort := pktSport(readFrom(t, rt.meshDev))

	moved := netip.MustParseAddr("10.255.241.9")
	rt.r.SetMeshAddress(rwMesh, moved)
	if !rwLogged(rt.logs.String(), "mesh source rewrite moved to a new mesh address", "level=DEBUG", "component=bridge",
		"mesh_iface="+rwMesh, "mesh_addr=10.255.241.9", "rewrites=1", "flows_removed=1") {
		t.Errorf("no moved line in the log:\n%s", rt.logs)
	}

	reply := udpPacket(rwNodeN, rwMeshAddr, 7001, oldPort, []byte("answer"))
	writeTo(t, rt.meshDev, reply)
	assertWritten(t, "N's reply to the old address", rt.mesh, reply)
	if queuedFor(rt.accessDev) != 0 {
		t.Errorf("%d packets queued for the provider's device after a reply to the old address, want none", queuedFor(rt.accessDev))
	}

	writeTo(t, rt.accessDev, datagram)
	out := readFrom(t, rt.meshDev)
	if pktSrc(out) != moved {
		t.Fatalf("D's next datagram left from %s, want %s", pktSrc(out), moved)
	}
	writeTo(t, rt.meshDev, udpPacket(rwNodeN, moved, 7001, pktSport(out), []byte("answer")))
	if got := readFrom(t, rt.accessDev); pktDst(got) != rwDeviceD || pktDport(got) != 5555 {
		t.Errorf("N's reply to the new address went to %s:%d, want %s:5555", pktDst(got), pktDport(got), rwDeviceD)
	}

	// The rules take an IPv4-mapped address as IPv4 and refuse anything else.
	mapped := netip.MustParseAddr("::ffff:10.255.241.10")
	rt.r.SetMeshAddress(rwMesh, mapped)
	if got := rt.r.nat.rewrites[rwAccess].meshAddr; got != mapped.Unmap() {
		t.Errorf("rewrite translates to %s after a mapped address, want %s", got, mapped.Unmap())
	}
	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("fd00::9")} {
		rt.r.SetMeshAddress(rwMesh, addr)
		if got := rt.r.nat.rewrites[rwAccess].meshAddr; got != mapped.Unmap() {
			t.Errorf("rewrite translates to %s after SetMeshAddress(%s), want it kept at %s", got, addr, mapped.Unmap())
		}
	}
	if n := rwLogLines(rt.logs.String(), "mesh source rewrite kept its address, the new one is no IPv4 address", "level=WARN", "mesh_iface="+rwMesh); n != 2 {
		t.Errorf("%d kept lines in the log, want 2:\n%s", n, rt.logs)
	}
}

func TestMeshRewriter_AddUnknownInterfaces(t *testing.T) {
	rt := newRewriterTest(t)
	if err := rt.r.AddMeshSourceRewrite("tailscale0", rwMesh); err != nil {
		t.Errorf("AddMeshSourceRewrite from a device Wrap never saw = %v, want nil", err)
	}
	if !rwLogged(rt.logs.String(), "mesh source rewrite not needed, the interface is no device of this process",
		"level=INFO", "component=bridge", "from_iface=tailscale0", "mesh_iface="+rwMesh) {
		t.Errorf("no not-needed line in the log:\n%s", rt.logs)
	}

	r := NewMeshRewriter(discardLogger())
	r.addrs = fakeAddrs(map[string][]netip.Prefix{rwAccess: {rwPoolPrefix}})
	access := r.Wrap(rwAccess, newFakeTUN())
	t.Cleanup(func() { _ = access.Close() })
	err := r.AddMeshSourceRewrite(rwAccess, rwMesh)
	const want = `bridge: add mesh source rewrite from "wg-ua-a0a0a0e1" to "plexd0": the mesh interface is no device of this process`
	if err == nil || err.Error() != want {
		t.Errorf("AddMeshSourceRewrite into an unknown mesh interface = %v, want %q", err, want)
	}
	if r.nat.involved(rwAccess) {
		t.Error("a rewrite exists after the failed add")
	}
}

func TestMeshRewriter_AddMeshAddressErrors(t *testing.T) {
	seamErr := errors.New("the seam failed")
	for _, tc := range []struct {
		name   string
		addrs  func(string) ([]netip.Prefix, error)
		suffix string
		is     error
	}{
		{
			name: "mesh interface without an IPv4 address",
			addrs: fakeAddrs(map[string][]netip.Prefix{
				rwMesh:   {netip.MustParsePrefix("fe80::1/64")},
				rwAccess: {rwPoolPrefix},
			}),
			suffix: "address of the mesh interface: no IPv4 address",
		},
		{
			name: "seam error for the mesh interface",
			addrs: func(iface string) ([]netip.Prefix, error) {
				if iface == rwMesh {
					return nil, seamErr
				}
				return []netip.Prefix{rwPoolPrefix}, nil
			},
			suffix: "address of the mesh interface: the seam failed",
			is:     seamErr,
		},
		{
			name: "seam error for the source interface",
			addrs: func(iface string) ([]netip.Prefix, error) {
				if iface == rwAccess {
					return nil, seamErr
				}
				return []netip.Prefix{rwMeshPrefix}, nil
			},
			suffix: "address of the mesh interface: the seam failed",
			is:     seamErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRewriterTest(t)
			rt.r.addrs = tc.addrs
			err := rt.r.AddMeshSourceRewrite(rwAccess, rwMesh)
			if err == nil {
				t.Fatal("AddMeshSourceRewrite = nil, want an error")
			}
			const prefix = `bridge: add mesh source rewrite from "wg-ua-a0a0a0e1" to "plexd0": `
			if !strings.HasPrefix(err.Error(), prefix) || !strings.HasSuffix(err.Error(), tc.suffix) {
				t.Errorf("error = %q, want %q ... %q", err, prefix, tc.suffix)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("error = %v, want it to wrap the seam's error", err)
			}
			if rt.r.nat.involved(rwAccess) || rt.r.nat.involved(rwMesh) {
				t.Error("a rewrite exists after the failed add")
			}
		})
	}
}

// The production seam reads the host's interface table, of which the test
// reads the loopback interfaces alone: on windows-latest the daemon tests of
// another package add and remove a real adapter while this test runs, and a
// lookup by name of an adapter that went away fails.
func TestMeshRewriter_InterfacePrefixes(t *testing.T) {
	if _, err := interfacePrefixes("plexd-no-such-interface"); err == nil {
		t.Error("interfacePrefixes of an interface that does not exist = nil error, want one")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	found := false
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback == 0 {
			continue
		}
		prefixes, err := interfacePrefixes(ifi.Name)
		if err != nil {
			t.Fatalf("interfacePrefixes(%q): %v", ifi.Name, err)
		}
		for _, p := range prefixes {
			if !p.Addr().Is4() {
				t.Errorf("interfacePrefixes(%q) holds %s, want IPv4 prefixes only", ifi.Name, p)
			}
			if p.Addr() == loopback {
				found = true
				if p.Bits() != 8 {
					t.Errorf("loopback prefix %s, want 127.0.0.1/8", p)
				}
			}
		}
	}
	if !found {
		t.Error("no loopback interface of the host carries 127.0.0.1")
	}
}

// Row A1 at the wrapper: what the rules cannot read reaches the wrapped
// device unchanged, and no prefix of a valid packet makes Write panic, on a
// source interface or on the mesh interface.
func TestMeshRewriter_A1_PassesWhatTheRulesCannotRead(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)

	tooShort := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	binary.BigEndian.PutUint16(tooShort[2:4], uint16(len(tooShort)+1))
	refreshHeaderSum(tooShort)
	ipv6 := make([]byte, 48)
	ipv6[0] = 0x60
	unreadable := [][]byte{{}, ipv6, tooShort}

	writeTo(t, rt.accessDev, unreadable...)
	assertWritten(t, "from D", rt.access, unreadable...)
	writeTo(t, rt.meshDev, unreadable...)
	assertWritten(t, "from N", rt.mesh, unreadable...)

	// The sweep runs with a flow in place, so N's packets reach the rows
	// that look one up.
	writeTo(t, rt.accessDev, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query")))
	meshPort := pktSport(readFrom(t, rt.meshDev))
	for name, pkt := range testPackets(meshPort) {
		for n := 0; n <= len(pkt); n++ {
			for _, dev := range []tun.Device{rt.accessDev, rt.meshDev} {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s, %d of %d bytes: Write panicked: %v", name, n, len(pkt), r)
						}
					}()
					writeTo(t, dev, pkt[:n])
				}()
			}
		}
	}
}

// Row A2 at the wrapper: a far end's packet for the host reaches the wrapped
// device unchanged.
func TestMeshRewriter_A2_ToTheHostReachesTheWrappedDevice(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	var pkts [][]byte
	for _, dst := range []netip.Addr{rwMeshAddr, rwPoolAddr, netip.MustParseAddr("224.0.0.251"), netip.MustParseAddr("255.255.255.255")} {
		pkts = append(pkts, udpPacket(rwDeviceD, dst, 5353, 5353, []byte("query")))
	}
	writeTo(t, rt.accessDev, pkts...)
	assertWritten(t, "D's packets for the host", rt.access, pkts...)
	if rt.access.writeCalls() != 1 {
		t.Errorf("the wrapped device saw %d Write calls, want the batch in one", rt.access.writeCalls())
	}
}

// Row A3 at the wrapper: what the host hands a tunnel's device through Read
// makes the site's answer the host's.
func TestMeshRewriter_A3_HostFlowsFromRead(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwTunnel)

	fromN := udpPacket(rwNodeN, rwSiteS, 5000, 7002, []byte("query"))
	rt.tunnel.in <- fromN
	if got := readFrom(t, rt.tunnelDev); !bytes.Equal(got, fromN) {
		t.Fatalf("Read = %x, want N's datagram unchanged %x", got, fromN)
	}

	answer := udpPacket(rwSiteS, rwNodeN, 7002, 5000, []byte("answer"))
	writeTo(t, rt.tunnelDev, answer)
	assertWritten(t, "S's answer", rt.tunnel, answer)

	writeTo(t, rt.tunnelDev, udpPacket(rwSiteS, rwNodeN, 7003, 5000, []byte("query")))
	if out := readFrom(t, rt.meshDev); pktSrc(out) != rwMeshAddr {
		t.Errorf("S's datagram from another port left from %s, want %s", pktSrc(out), rwMeshAddr)
	}

	rt.advance(121 * time.Second)
	writeTo(t, rt.tunnelDev, answer)
	if out := readFrom(t, rt.meshDev); pktSrc(out) != rwMeshAddr || pktSport(out) == 7002 {
		t.Errorf("S's datagram 121 s after the host flow's last packet left from %s:%d, want %s and a mesh port", pktSrc(out), pktSport(out), rwMeshAddr)
	}
	assertWritten(t, "after the host flow expired", rt.tunnel, answer)
}

// Rows B1 and B4 at the wrapper: a mesh peer's packet that is no reply of a
// translated flow reaches the mesh interface's wrapped device unchanged.
func TestMeshRewriter_B1B4_OtherPacketsReachTheWrappedDevice(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	writeTo(t, rt.accessDev, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query")))
	readFrom(t, rt.meshDev)

	pkts := [][]byte{
		udpPacket(rwNodeN, rwMeshAddr, 7001, 40000, []byte("no flow")),
		udpPacket(rwNodeN, rwSiteS, 5000, 7002, []byte("to the site")),
	}
	writeTo(t, rt.meshDev, pkts...)
	assertWritten(t, "N's packets", rt.mesh, pkts...)
}

// Write hands what the rules leave the host to the wrapped device in one call
// and in order, queues the rest, and returns len(bufs) with the wrapped
// device's error.
func TestMeshRewriter_WriteSplitsABatch(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	rt.access.writeErr = errors.New("ring full")

	first := udpPacket(rwDeviceD, rwMeshAddr, 5353, 53, []byte("first"))
	second := udpPacket(rwDeviceD, rwPoolAddr, 5353, 53, []byte("second"))
	bufs := [][]byte{
		append(make([]byte, rwOffset), first...),
		append(make([]byte, rwOffset), udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))...),
		append(make([]byte, rwOffset), second...),
	}
	n, err := rt.accessDev.Write(bufs, rwOffset)
	if n != 3 || err == nil || err.Error() != "ring full" {
		t.Errorf("Write = %d, %v, want 3 and the wrapped device's error", n, err)
	}
	if rt.access.writeCalls() != 1 {
		t.Errorf("the wrapped device saw %d Write calls, want 1", rt.access.writeCalls())
	}
	assertWritten(t, "the batch", rt.access, first, second)
	if queuedFor(rt.meshDev) != 1 {
		t.Errorf("%d packets queued for the mesh device, want the translated one", queuedFor(rt.meshDev))
	}

	// The translated packet is a copy: wireguard-go reuses its buffers.
	for _, b := range bufs {
		clear(b)
	}
	if out := readFrom(t, rt.meshDev); pktSrc(out) != rwMeshAddr || !headerSumOK(out) {
		t.Errorf("queued packet %x, want the translated copy intact", out)
	}
}

// Read fills up to len(bufs) packets from the queue without blocking again,
// behind the offset it is given.
func TestMeshRewriter_ReadFillsABatch(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	var sent [][]byte
	for port := uint16(5001); port <= 5003; port++ {
		sent = append(sent, udpPacket(rwDeviceD, rwNodeN, port, 7001, []byte("query")))
	}
	writeTo(t, rt.accessDev, sent...)

	bufs := make([][]byte, 2)
	for i := range bufs {
		bufs[i] = make([]byte, rwOffset+maxPacketSize)
	}
	sizes := make([]int, len(bufs))
	n, err := rt.meshDev.Read(bufs, sizes, rwOffset)
	if n != 2 || err != nil {
		t.Fatalf("Read into 2 buffers with 3 queued = %d, %v, want 2, nil", n, err)
	}
	for i := range n {
		out := bufs[i][rwOffset : rwOffset+sizes[i]]
		if pktSrc(out) != rwMeshAddr || len(out) != len(sent[i]) {
			t.Errorf("packet %d = %x, want the translated datagram of %d bytes", i, out, len(sent[i]))
		}
	}

	// One packet waits: Read returns it into the first of four buffers
	// rather than waiting for more.
	bufs = make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, rwOffset+maxPacketSize)
	}
	sizes = make([]int, len(bufs))
	n, err = rt.meshDev.Read(bufs, sizes, rwOffset)
	if n != 1 || err != nil {
		t.Fatalf("Read into 4 buffers with 1 queued = %d, %v, want 1, nil", n, err)
	}
	if out := bufs[0][rwOffset : rwOffset+sizes[0]]; pktSrc(out) != rwMeshAddr || pktSport(out) == 5003 {
		t.Errorf("third packet = %x, want the translated datagram", out)
	}
}

// A wrapper whose interface takes part in no rewrite passes every packet, and
// the wrapped device answers MTU, Name, Events and BatchSize.
func TestMeshRewriter_PassesWithoutARewrite(t *testing.T) {
	rt := newRewriterTest(t)
	rt.mesh.mtu = 1280
	pkts := [][]byte{udpPacket(rwNodeN, rwMeshAddr, 7001, 40000, nil), udpPacket(rwDeviceD, rwNodeN, 5555, 7001, nil)}
	writeTo(t, rt.meshDev, pkts...)
	assertWritten(t, "without a rewrite", rt.mesh, pkts...)

	fromHost := udpPacket(rwNodeN, rwSiteS, 5000, 7002, nil)
	rt.mesh.in <- fromHost
	if got := readFrom(t, rt.meshDev); !bytes.Equal(got, fromHost) {
		t.Errorf("Read = %x, want %x", got, fromHost)
	}

	if mtu, err := rt.meshDev.MTU(); mtu != 1280 || err != nil {
		t.Errorf("MTU = %d, %v, want the wrapped device's 1280", mtu, err)
	}
	if name, err := rt.meshDev.Name(); name != "fake0" || err != nil {
		t.Errorf("Name = %q, %v, want the wrapped device's", name, err)
	}
	if rt.meshDev.Events() != (<-chan tun.Event)(rt.mesh.events) {
		t.Error("Events is not the wrapped device's channel")
	}
	if rt.meshDev.BatchSize() != 1 || rt.meshDev.File() != nil {
		t.Error("BatchSize or File differ from the wrapped device's")
	}
}

func TestMeshRewriter_QueueFull(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	pkts := make([][]byte, meshQueueLen+1)
	for i := range pkts {
		pkts[i] = udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query"))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		bufs := make([][]byte, len(pkts))
		for i, p := range pkts {
			bufs[i] = append(make([]byte, rwOffset), p...)
		}
		_, _ = rt.accessDev.Write(bufs, rwOffset)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked on a device nothing reads")
	}

	if got := queuedFor(rt.meshDev); got != meshQueueLen {
		t.Errorf("%d packets queued, want %d", got, meshQueueLen)
	}
	if got := rt.r.nat.dropCount(dropQueueFull); got != 1 {
		t.Errorf("queue_full drops = %d, want 1", got)
	}
	if !rwLogged(rt.logs.String(), "mesh source rewrite dropped packets", "level=WARN", "component=bridge", "reason=queue_full", "count=1") {
		t.Errorf("no queue_full line in the log:\n%s", rt.logs)
	}
}

func TestMeshRewriter_DropLog(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	const msg = "mesh source rewrite dropped packets"
	expiring := udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte(payloadMarker), withTTL(1))
	gre := ipPacket(rwDeviceD, rwNodeN, 47, []byte(payloadMarker))

	writeTo(t, rt.accessDev, expiring, gre)
	if n := rwLogLines(rt.logs.String(), msg); n != 2 {
		t.Fatalf("%d drop lines after drops of two reasons, want 2:\n%s", n, rt.logs)
	}
	for _, reason := range []string{"ttl", "unsupported_protocol"} {
		if !rwLogged(rt.logs.String(), msg, "level=WARN", "component=bridge", "reason="+reason, "count=1") {
			t.Errorf("no %s line with count=1:\n%s", reason, rt.logs)
		}
	}

	for range 3 {
		rt.advance(10 * time.Second)
		writeTo(t, rt.accessDev, expiring)
	}
	if n := rwLogLines(rt.logs.String(), msg); n != 2 {
		t.Errorf("%d drop lines after more drops within 60 s, want still 2:\n%s", n, rt.logs)
	}
	rt.advance(30 * time.Second)
	writeTo(t, rt.accessDev, expiring)
	if !rwLogged(rt.logs.String(), msg, "reason=ttl", "count=4") {
		t.Errorf("no ttl line with the count since the last, 4:\n%s", rt.logs)
	}

	// A translated packet and a passed one carry the marker as well; no
	// line of the log holds it, as text or as hex.
	writeTo(t, rt.accessDev, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte(payloadMarker)))
	writeTo(t, rt.accessDev, udpPacket(rwDeviceD, rwMeshAddr, 5555, 53, []byte(payloadMarker)))
	assertNoPayload(t, rt.logs.String())
}

// assertNoPayload fails when log holds payloadMarker as text or as hex.
func assertNoPayload(t *testing.T, log string) {
	t.Helper()
	for _, form := range []string{payloadMarker, hex.EncodeToString([]byte(payloadMarker))} {
		if strings.Contains(log, form) {
			t.Errorf("the log holds a packet's payload %q:\n%s", form, log)
		}
	}
}

func TestMeshRewriter_Close(t *testing.T) {
	rt := newRewriterTest(t)
	rt.add(t, rwAccess)
	writeTo(t, rt.accessDev, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte("query")))
	meshPort := pktSport(readFrom(t, rt.meshDev))

	if err := rt.accessDev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := rt.accessDev.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if n := rt.access.closeCount(); n != 1 {
		t.Errorf("the wrapped device was closed %d times, want once", n)
	}
	_, err := rt.accessDev.Read([][]byte{make([]byte, 64)}, []int{0}, 0)
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("Read after Close = %v, want an error wrapping os.ErrClosed", err)
	}
	if rt.r.nat.known(rwAccess) || rt.r.nat.involved(rwMesh) {
		t.Error("the closed device or its rewrite is still known")
	}

	answer := udpPacket(rwNodeN, rwMeshAddr, 7001, meshPort, []byte("answer"))
	writeTo(t, rt.meshDev, answer)
	assertWritten(t, "N's answer after the source device closed", rt.mesh, answer)

	if err := rt.r.AddMeshSourceRewrite(rwAccess, rwMesh); err != nil {
		t.Errorf("AddMeshSourceRewrite from the closed device = %v, want nil", err)
	}
	if rt.r.nat.involved(rwMesh) {
		t.Error("a rewrite from the closed device was added")
	}
}

// A Read that waits for a packet when the device closes returns an error
// wrapping os.ErrClosed, as one that comes after Close does.
func TestMeshRewriter_ReadEndsOnClose(t *testing.T) {
	rt := newRewriterTest(t)
	errs := make(chan error, 1)
	go func() {
		_, err := rt.meshDev.Read([][]byte{make([]byte, 64)}, []int{0}, 0)
		errs <- err
	}()
	if err := rt.meshDev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("Read = %v, want an error wrapping os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after Close")
	}
}

// deviceTUN is a channel tun of the device test with a goroutine that drains
// its unbuffered Inbound into received, so a wireguard-go device never blocks
// delivering a packet while the test is not reading.
type deviceTUN struct {
	name     string
	tun      *tuntest.ChannelTUN
	received chan []byte
	stop     chan struct{}
	drained  chan struct{}
}

func newDeviceTUN(t *testing.T, name string) *deviceTUN {
	t.Helper()
	d := &deviceTUN{
		name:     name,
		tun:      tuntest.NewChannelTUN(),
		received: make(chan []byte, 256),
		stop:     make(chan struct{}),
		drained:  make(chan struct{}),
	}
	go func() {
		defer close(d.drained)
		for {
			select {
			case p := <-d.tun.Inbound:
				select {
				case d.received <- p:
				default:
					// Nobody waits for this many packets; the test
					// resends what it waits for.
				}
			case <-d.stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(d.stop)
		<-d.drained
	})
	return d
}

// exchange sends pkt into from about once a second until to reads a packet
// that match accepts, and returns that packet. It fails after 20 s. Resending
// covers a packet wireguard-go dropped before its handshake.
func exchange(t *testing.T, from, to *deviceTUN, pkt []byte, match func([]byte) bool) []byte {
	t.Helper()
	expired := time.After(20 * time.Second)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case from.tun.Outbound <- pkt:
		case <-expired:
			t.Fatalf("%s did not read the packet %s sent within 20s", to.name, from.name)
		}
	wait:
		for {
			select {
			case p := <-to.received:
				if match(p) {
					return p
				}
			case <-ticker.C:
				break wait
			case <-expired:
				t.Fatalf("%s did not read the packet %s sent within 20s", to.name, from.name)
			}
		}
	}
}

// isUDP, isTCP, isEcho and isUnreachable match what a tun reads by protocol,
// addresses and the ports or id the test knows.
func isUDP(src, dst netip.Addr, dport uint16) func([]byte) bool {
	return func(p []byte) bool {
		return len(p) >= 28 && pktProto(p) == protoUDP && pktSrc(p) == src && pktDst(p) == dst && pktDport(p) == dport
	}
}

func isTCP(src, dst netip.Addr, dport uint16) func([]byte) bool {
	return func(p []byte) bool {
		return len(p) >= 40 && pktProto(p) == protoTCP && pktSrc(p) == src && pktDst(p) == dst && pktDport(p) == dport
	}
}

func isEcho(src, dst netip.Addr, typ uint8) func([]byte) bool {
	return func(p []byte) bool {
		return len(p) >= 28 && pktProto(p) == protoICMP && pktSrc(p) == src && pktDst(p) == dst && pktICMPType(p) == typ
	}
}

func isUnreachable(src, dst netip.Addr) func([]byte) bool {
	return func(p []byte) bool {
		return len(p) >= 56 && pktProto(p) == protoICMP && pktSrc(p) == src && pktDst(p) == dst && pktICMPType(p) == icmpUnreachable
	}
}

// TestMeshRewriter_Devices runs four wireguard-go devices in one process over
// real UDP on 127.0.0.1. The bridge's mesh device (10.255.241.1) and its
// provider device (pool 10.255.242.0/24) sit on channel tuns the rewriter
// wraps; node N (10.255.241.2) and device D (10.255.242.2, also .3) are plain
// devices on channel tuns of their own. N's peer entry for the bridge allows
// 10.255.241.1/32 alone, so wireguard-go at N drops a packet that kept D's
// address, as a mesh node does.
func TestMeshRewriter_Devices(t *testing.T) {
	logs := &syncBuffer{}
	logger := slogTextLogger(logs)
	r := NewMeshRewriter(logger)
	// A channel tun is no interface of the host.
	r.addrs = fakeAddrs(map[string][]netip.Prefix{
		rwMesh:   {rwMeshPrefix},
		rwAccess: {rwPoolPrefix},
	})

	b := NewLoopbackUserspaceBackend(t)
	b.logger = logger
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", logs)
		}
	})

	mesh := newDeviceTUN(t, rwMesh)
	access := newDeviceTUN(t, rwAccess)
	nodeN := newDeviceTUN(t, "node N")
	devD := newDeviceTUN(t, "device D")

	keys := map[string]wgtypes.Key{}
	for _, d := range []struct {
		name string
		tun  tun.Device
	}{
		{rwMesh, r.Wrap(rwMesh, mesh.tun.TUN())},
		{rwAccess, r.Wrap(rwAccess, access.tun.TUN())},
		{"wg-node-n", nodeN.tun.TUN()},
		{"wg-device-d", devD.tun.TUN()},
	} {
		keys[d.name] = mustKey(t)
		key := keys[d.name]
		if err := b.CreateDevice(d.name, d.tun, key[:], 0); err != nil {
			t.Fatalf("CreateDevice(%s): %v", d.name, err)
		}
	}
	endpoint := func(name string) string {
		return fmt.Sprintf("127.0.0.1:%d", listenPort(t, ipcGet(t, b, name)))
	}
	for _, p := range []struct {
		on, peer string
		endpoint string
		allowed  []string
	}{
		{rwMesh, "wg-node-n", endpoint("wg-node-n"), []string{"10.255.241.2/32"}},
		{"wg-node-n", rwMesh, endpoint(rwMesh), []string{"10.255.241.1/32"}},
		// A provider's peer has no endpoint: D opens the handshake.
		{rwAccess, "wg-device-d", "", []string{"10.255.242.2/32", "10.255.242.3/32"}},
		{"wg-device-d", rwAccess, endpoint(rwAccess), []string{"10.255.241.0/24", "10.255.242.1/32"}},
	} {
		if err := b.AddPeer(p.on, PeerConfig{PublicKey: pubBytes(keys[p.peer]), Endpoint: p.endpoint, AllowedIPs: p.allowed}); err != nil {
			t.Fatalf("AddPeer(%s, %s): %v", p.on, p.peer, err)
		}
	}
	if err := r.AddMeshSourceRewrite(rwAccess, rwMesh); err != nil {
		t.Fatalf("AddMeshSourceRewrite: %v", err)
	}

	// UDP: D to N port 7001 and N's answer.
	atN := exchange(t, devD, nodeN, udpPacket(rwDeviceD, rwNodeN, 5555, 7001, []byte(payloadMarker)), isUDP(rwMeshAddr, rwNodeN, 7001))
	udpPort := pktSport(atN)
	if !pktMeshPort(udpPort) || !transportSumOK(atN) || !headerSumOK(atN) {
		t.Errorf("N read the datagram from %s:%d (checksums ok %t, %t), want %s and a port from %d to %d with valid checksums",
			pktSrc(atN), udpPort, headerSumOK(atN), transportSumOK(atN), rwMeshAddr, meshPortFirst, meshPortLast)
	}
	atD := exchange(t, nodeN, devD, udpPacket(rwNodeN, rwMeshAddr, 7001, udpPort, []byte("answer")), isUDP(rwNodeN, rwDeviceD, 5555))
	if pktSport(atD) != 7001 || !transportSumOK(atD) {
		t.Errorf("D read N's answer from port %d (checksum ok %t), want 7001 and a valid checksum", pktSport(atD), transportSumOK(atD))
	}

	// TCP: D's SYN and N's SYN-ACK.
	atN = exchange(t, devD, nodeN, tcpPacket(rwDeviceD, rwNodeN, 5556, 7001, tcpSYN), isTCP(rwMeshAddr, rwNodeN, 7001))
	if !pktMeshPort(pktSport(atN)) || atN[33] != tcpSYN || !transportSumOK(atN) {
		t.Errorf("N read a TCP segment from port %d flags %#x (checksum ok %t), want a SYN from a mesh port", pktSport(atN), atN[33], transportSumOK(atN))
	}
	atD = exchange(t, nodeN, devD, tcpPacket(rwNodeN, rwMeshAddr, 7001, pktSport(atN), tcpSYN|tcpACK), isTCP(rwNodeN, rwDeviceD, 5556))
	if pktSport(atD) != 7001 || atD[33] != tcpSYN|tcpACK || !transportSumOK(atD) {
		t.Errorf("D read a TCP segment from port %d flags %#x (checksum ok %t), want N's SYN-ACK from 7001", pktSport(atD), atD[33], transportSumOK(atD))
	}

	// ICMP echo: D reads its own id back.
	atN = exchange(t, devD, nodeN, echoPacket(rwDeviceD, rwNodeN, icmpEchoRequest, 0x1234, 1), isEcho(rwMeshAddr, rwNodeN, icmpEchoRequest))
	if !pktMeshPort(pktEchoID(atN)) || !transportSumOK(atN) {
		t.Errorf("N read an echo request with id %d (checksum ok %t), want a mesh id", pktEchoID(atN), transportSumOK(atN))
	}
	atD = exchange(t, nodeN, devD, echoPacket(rwNodeN, rwMeshAddr, icmpEchoReply, pktEchoID(atN), 1), isEcho(rwNodeN, rwDeviceD, icmpEchoReply))
	if pktEchoID(atD) != 0x1234 || !transportSumOK(atD) {
		t.Errorf("D read an echo reply with id %#x (checksum ok %t), want 0x1234", pktEchoID(atD), transportSumOK(atD))
	}

	// Two far ends with the same source port toward the same remote port
	// leave with different mesh ports, and each answer finds its sender.
	atN2 := exchange(t, devD, nodeN, udpPacket(rwDeviceD2, rwNodeN, 5555, 7001, []byte("second")), func(p []byte) bool {
		return isUDP(rwMeshAddr, rwNodeN, 7001)(p) && bytes.HasSuffix(p, []byte("second"))
	})
	if pktSport(atN2) == udpPort {
		t.Errorf("both far ends left with mesh port %d, want two", udpPort)
	}
	exchange(t, nodeN, devD, udpPacket(rwNodeN, rwMeshAddr, 7001, pktSport(atN2), []byte("to D2")), isUDP(rwNodeN, rwDeviceD2, 5555))
	exchange(t, nodeN, devD, udpPacket(rwNodeN, rwMeshAddr, 7001, udpPort, []byte("to D")), isUDP(rwNodeN, rwDeviceD, 5555))

	// B3: N's port unreachable about the datagram as N read it reaches D
	// about D's own datagram.
	translated := udpPacket(rwMeshAddr, rwNodeN, udpPort, 7001, []byte("query"))
	atD = exchange(t, nodeN, devD, portUnreachable(rwNodeN, rwMeshAddr, translated), isUnreachable(rwNodeN, rwDeviceD))
	if q := pktQuoted(atD); pktSrc(q) != rwDeviceD || pktSport(q) != 5555 || !icmpSumOK(atD) || !quotedSumOK(q) || !headerSumOK(atD) {
		t.Errorf("D read an error quoting %s:%d (sums ok %t, %t, %t), want %s:5555 and valid checksums",
			pktSrc(q), pktSport(q), headerSumOK(atD), icmpSumOK(atD), quotedSumOK(q), rwDeviceD)
	}

	// A4: D's port unreachable about N's answer as D read it reaches N
	// about N's own answer to the mesh address and port.
	answered := udpPacket(rwNodeN, rwDeviceD, 7001, 5555, []byte("answer"))
	atN = exchange(t, devD, nodeN, portUnreachable(rwDeviceD, rwNodeN, answered), isUnreachable(rwMeshAddr, rwNodeN))
	if q := pktQuoted(atN); pktDst(q) != rwMeshAddr || pktDport(q) != udpPort || !icmpSumOK(atN) || !quotedSumOK(q) || !headerSumOK(atN) {
		t.Errorf("N read an error quoting %s:%d (sums ok %t, %t, %t), want %s:%d and valid checksums",
			pktDst(q), pktDport(q), headerSumOK(atN), icmpSumOK(atN), quotedSumOK(q), rwMeshAddr, udpPort)
	}

	assertNoPayload(t, logs.String())
}
