//go:build linux

package bridge

import (
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/plexsphere/plexd/internal/bridge/relaybpf"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakePut is one Put call on adapterFakes.
type fakePut struct {
	index   uint32
	session relaybpf.Session
}

// adapterFakes stands in for everything relayKernelLinux reaches the kernel
// through: the Forwarder, the route lookup and the IPv6 forwarding flag. It
// records each call and answers with what the test planted. Its in runs the
// adapter's kernel accesses, and a seam called outside in is recorded too,
// since in the relay namespace of TestRelayKernel_Real such a call would
// reach the wrong namespace.
type adapterFakes struct {
	inside  bool
	outside []string

	attaches  []int
	puts      []fakePut
	deletes   []uint32
	closes    int
	attachErr error
	putErr    error
	deleteErr error

	// table answers route; an address it does not hold has no route.
	table      map[netip.Addr]relayRoute
	routeErrs  map[netip.Addr]error
	routeCalls []netip.Addr

	// flag is the content of the IPv6 forwarding flag.
	flag     string
	readErr  error
	writeErr error
	paths    []string
	writes   []string
}

func (f *adapterFakes) in(fn func() error) error {
	f.inside = true
	defer func() { f.inside = false }()
	return fn()
}

// enter records call when it happens outside in.
func (f *adapterFakes) enter(call string) {
	if !f.inside {
		f.outside = append(f.outside, call)
	}
}

func (f *adapterFakes) Attach(ifindex int) error {
	f.enter("Attach")
	if f.attachErr != nil {
		return f.attachErr
	}
	f.attaches = append(f.attaches, ifindex)
	return nil
}

func (f *adapterFakes) Put(index uint32, s relaybpf.Session) error {
	f.enter("Put")
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, fakePut{index: index, session: s})
	return nil
}

func (f *adapterFakes) Delete(index uint32) error {
	f.enter("Delete")
	f.deletes = append(f.deletes, index)
	return f.deleteErr
}

func (f *adapterFakes) Age(uint32) (time.Duration, bool, error) {
	f.enter("Age")
	return 0, false, nil
}

func (f *adapterFakes) Ages() (map[uint32]time.Duration, error) {
	f.enter("Ages")
	return nil, nil
}

func (f *adapterFakes) Counters() (map[string]uint64, error) {
	f.enter("Counters")
	return nil, nil
}

func (f *adapterFakes) Close() error {
	f.enter("Close")
	f.closes++
	return nil
}

func (f *adapterFakes) route(addr netip.Addr) (relayRoute, error) {
	f.enter("route")
	f.routeCalls = append(f.routeCalls, addr)
	if err := f.routeErrs[addr]; err != nil {
		return relayRoute{}, err
	}
	rt, ok := f.table[addr]
	if !ok {
		return relayRoute{}, unix.ENETUNREACH
	}
	return rt, nil
}

func (f *adapterFakes) readFile(path string) ([]byte, error) {
	f.enter("readFile")
	f.paths = append(f.paths, path)
	if f.readErr != nil {
		return nil, f.readErr
	}
	return []byte(f.flag), nil
}

func (f *adapterFakes) writeFile(path string, b []byte) error {
	f.enter("writeFile")
	f.paths = append(f.paths, path)
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, string(b))
	f.flag = string(b)
	return nil
}

// The addresses of the adapter tests. A and C are partners behind eth0, B and
// D owners behind eth1, and the IPv6 pair sits behind the same two links.
var (
	adapterA    = netip.MustParseAddrPort("192.0.2.10:40000")
	adapterC    = netip.MustParseAddrPort("192.0.2.11:40001")
	adapterB    = netip.MustParseAddrPort("198.51.100.20:51820")
	adapterD    = netip.MustParseAddrPort("198.51.100.30:51820")
	adapterA6   = netip.MustParseAddrPort("[2001:db8:1::10]:40000")
	adapterB6   = netip.MustParseAddrPort("[2001:db8:2::20]:51820")
	adapterEth0 = relayRoute{src: netip.MustParseAddr("192.0.2.1"), ifindex: 2, name: "eth0", ether: true}
	adapterEth1 = relayRoute{src: netip.MustParseAddr("198.51.100.1"), ifindex: 3, name: "eth1", ether: true}
)

// newFakeKernelLinux returns a relayKernelLinux for the mesh interface plexd0
// on adapterFakes, whose route table holds the adapter test addresses, and
// the log it writes. Its logger carries the component the relay's logger
// carries. The test fails when a seam was called outside in.
func newFakeKernelLinux(t *testing.T) (*relayKernelLinux, *adapterFakes, *relayLog) {
	t.Helper()
	logger, logs := newRelayLogger()
	logger = logger.With("component", "bridge")
	f := &adapterFakes{
		table: map[netip.Addr]relayRoute{
			adapterA.Addr():  adapterEth0,
			adapterC.Addr():  adapterEth0,
			adapterB.Addr():  adapterEth1,
			adapterD.Addr():  adapterEth1,
			adapterA6.Addr(): {src: netip.MustParseAddr("2001:db8:1::1"), ifindex: 2, name: "eth0", ether: true},
			adapterB6.Addr(): {src: netip.MustParseAddr("2001:db8:2::1"), ifindex: 3, name: "eth1", ether: true},
		},
		routeErrs: make(map[netip.Addr]error),
		flag:      "0\n",
	}
	k := &relayKernelLinux{
		logger:    logger,
		meshIface: "plexd0",
		in:        f.in,
		fwd:       f,
		route:     f.route,
		readFile:  f.readFile,
		writeFile: f.writeFile,
		routes:    make(map[netip.Addr]relayRoute),
		attached:  make(map[int]string),
		flows:     make(map[uint32]relayKernelFlow),
	}
	t.Cleanup(func() {
		if len(f.outside) > 0 {
			t.Errorf("seams called outside in: %v", f.outside)
		}
	})
	return k, f, logs
}

// mustForward calls forward and fails the test on an error.
func mustForward(t *testing.T, k *relayKernelLinux, index uint32, partner, owner netip.AddrPort) {
	t.Helper()
	if err := k.forward(index, relayKernelFlow{partner: partner, owner: owner}); err != nil {
		t.Fatalf("forward(%d, %s to %s): %v", index, partner, owner, err)
	}
}

// attachedLines returns how many "relay: kernel forwarding attached" lines
// name iface.
func attachedLines(logs *relayLog, iface string) int {
	return logs.count(`level=INFO msg="relay: kernel forwarding attached" component=bridge interface=` + iface + "\n")
}

// ---------------------------------------------------------------------------
// The Linux adapter
// ---------------------------------------------------------------------------

func TestRelayKernelLinux_ForwardWritesTheSession(t *testing.T) {
	k, f, logs := newFakeKernelLinux(t)

	mustForward(t, k, 1, adapterA, adapterB)
	mustForward(t, k, 2, adapterB, adapterA)
	mustForward(t, k, 3, adapterC, adapterB)
	mustForward(t, k, 4, adapterA6, adapterB6)
	mustForward(t, k, 5, adapterB6, adapterA6)

	want := []fakePut{
		{1, relaybpf.Session{Partner: adapterA, PartnerDst: adapterEth0.src, Owner: adapterB, OwnerSrc: adapterEth1.src, OwnerIf: 3}},
		{2, relaybpf.Session{Partner: adapterB, PartnerDst: adapterEth1.src, Owner: adapterA, OwnerSrc: adapterEth0.src, OwnerIf: 2}},
		{3, relaybpf.Session{Partner: adapterC, PartnerDst: adapterEth0.src, Owner: adapterB, OwnerSrc: adapterEth1.src, OwnerIf: 3}},
		{4, relaybpf.Session{
			Partner: adapterA6, PartnerDst: netip.MustParseAddr("2001:db8:1::1"),
			Owner: adapterB6, OwnerSrc: netip.MustParseAddr("2001:db8:2::1"), OwnerIf: 3,
		}},
		{5, relaybpf.Session{
			Partner: adapterB6, PartnerDst: netip.MustParseAddr("2001:db8:2::1"),
			Owner: adapterA6, OwnerSrc: netip.MustParseAddr("2001:db8:1::1"), OwnerIf: 2,
		}},
	}
	if !slices.Equal(f.puts, want) {
		t.Errorf("Put calls:\n got %v\nwant %v", f.puts, want)
	}

	// Five sessions with partners behind two interfaces attach twice, once
	// per interface, and log each attach once.
	if want := []int{2, 3}; !slices.Equal(f.attaches, want) {
		t.Errorf("Attach calls = %v, want %v", f.attaches, want)
	}
	for _, iface := range []string{"eth0", "eth1"} {
		if n := attachedLines(logs, iface); n != 1 {
			t.Errorf(`%d "relay: kernel forwarding attached" lines with interface=%s, want 1:%s`, n, iface, logs)
		}
	}

	// Each address is resolved once; the sessions after the first that use
	// it read the cache.
	if n := len(f.routeCalls); n != 5 {
		t.Errorf("route called %d times (%v), want 5, once per address", n, f.routeCalls)
	}
	if n := len(k.flows); n != 5 {
		t.Errorf("the adapter remembers %d flows, want 5", n)
	}
}

func TestRelayKernelLinux_ForwardRefusals(t *testing.T) {
	wg0 := netip.MustParseAddrPort("10.9.0.2:51820")
	unreachable := netip.MustParseAddrPort("203.0.113.5:51820")

	tests := []struct {
		name           string
		partner, owner netip.AddrPort
		attachErr      error
		want           string
		wantIs         error
		wantAttach     bool
	}{
		{
			name:    "families differ",
			partner: adapterA,
			owner:   adapterB6,
			want:    "bridge: relay: kernel forwarding: address families differ",
		},
		{
			name:    "link-local partner",
			partner: netip.MustParseAddrPort("[fe80::10]:40000"),
			owner:   adapterB6,
			want:    "bridge: relay: kernel forwarding: link-local address fe80::10",
		},
		{
			name:    "link-local owner",
			partner: adapterA6,
			owner:   netip.MustParseAddrPort("[fe80::20]:51820"),
			want:    "bridge: relay: kernel forwarding: link-local address fe80::20",
		},
		{
			name:    "route through a link without Ethernet",
			partner: adapterA,
			owner:   wg0,
			want:    "bridge: relay: kernel forwarding: interface wg0 is not Ethernet",
		},
		{
			name:    "no route",
			partner: adapterA,
			owner:   unreachable,
			want:    "bridge: relay: kernel forwarding: route to 203.0.113.5: network is unreachable",
			wantIs:  unix.ENETUNREACH,
		},
		{
			name:       "attach fails",
			partner:    adapterA,
			owner:      adapterB,
			attachErr:  unix.EPERM,
			want:       "bridge: relay: kernel forwarding: attach to eth0: operation not permitted",
			wantIs:     unix.EPERM,
			wantAttach: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, f, _ := newFakeKernelLinux(t)
			f.table[wg0.Addr()] = relayRoute{src: netip.MustParseAddr("10.9.0.1"), ifindex: 5, name: "wg0"}
			f.routeErrs[unreachable.Addr()] = unix.ENETUNREACH
			f.attachErr = tt.attachErr

			err := k.forward(7, relayKernelFlow{partner: tt.partner, owner: tt.owner})
			if err == nil || err.Error() != tt.want {
				t.Fatalf("forward error = %v, want %q", err, tt.want)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("forward error %v does not wrap %v", err, tt.wantIs)
			}
			if len(f.puts) != 0 {
				t.Errorf("Put calls %v after a refusal, want none", f.puts)
			}
			if !tt.wantAttach && len(f.attaches) != 0 {
				t.Errorf("Attach calls %v before the refusal, want none", f.attaches)
			}
			if len(k.flows) != 0 {
				t.Errorf("the adapter remembers flows %v after a refusal, want none", k.flows)
			}
		})
	}
}

func TestRelayKernelLinux_Refresh(t *testing.T) {
	eth2 := relayRoute{src: netip.MustParseAddr("203.0.113.1"), ifindex: 4, name: "eth2", ether: true}
	lan0 := adapterEth0
	lan0.name = "lan0"

	tests := []struct {
		name      string
		change    func(f *adapterFakes)
		deleteErr error
		want      []uint32
	}{
		{
			name:   "nothing changed",
			change: func(*adapterFakes) {},
		},
		{
			name: "source changed",
			change: func(f *adapterFakes) {
				rt := adapterEth1
				rt.src = netip.MustParseAddr("198.51.100.9")
				f.table[adapterB.Addr()] = rt
			},
			want: []uint32{1, 2},
		},
		{
			name:   "interface changed",
			change: func(f *adapterFakes) { f.table[adapterD.Addr()] = eth2 },
			want:   []uint32{3},
		},
		{
			name: "interface renamed",
			change: func(f *adapterFakes) {
				f.table[adapterA.Addr()] = lan0
				f.table[adapterC.Addr()] = lan0
			},
			want: []uint32{1, 2, 3},
		},
		{
			name:   "no longer resolves",
			change: func(f *adapterFakes) { f.routeErrs[adapterA.Addr()] = unix.ENETUNREACH },
			want:   []uint32{1, 2},
		},
		{
			name: "no longer Ethernet",
			change: func(f *adapterFakes) {
				rt := adapterEth1
				rt.ether = false
				f.table[adapterD.Addr()] = rt
			},
			want: []uint32{3},
		},
		{
			name: "delete fails",
			change: func(f *adapterFakes) {
				rt := adapterEth1
				rt.src = netip.MustParseAddr("198.51.100.9")
				f.table[adapterB.Addr()] = rt
			},
			deleteErr: unix.EBADF,
			want:      []uint32{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, f, _ := newFakeKernelLinux(t)
			mustForward(t, k, 1, adapterA, adapterB)
			mustForward(t, k, 2, adapterB, adapterA)
			mustForward(t, k, 3, adapterC, adapterD)

			tt.change(f)
			f.deleteErr = tt.deleteErr
			// refresh returns the indices in map order.
			got := slices.Sorted(slices.Values(k.refresh()))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("refresh() = %v, want %v", got, tt.want)
			}
			if got := slices.Sorted(slices.Values(f.deletes)); !slices.Equal(got, tt.want) {
				t.Errorf("Delete calls = %v, want %v", got, tt.want)
			}
			for _, i := range tt.want {
				if _, ok := k.flows[i]; ok {
					t.Errorf("the adapter still remembers the flow of index %d it forgot", i)
				}
			}
			if n := len(k.flows); n != 3-len(tt.want) {
				t.Errorf("the adapter remembers %d flows, want %d", n, 3-len(tt.want))
			}

			// The routes stand as they are now, so a second refresh changes
			// nothing.
			f.deleteErr = nil
			if got := k.refresh(); got != nil {
				t.Errorf("second refresh() = %v, want nil", got)
			}
		})
	}

	// A session installed again after a refresh uses the route the refresh
	// resolved, without a lookup of its own.
	t.Run("installed again with the new source", func(t *testing.T) {
		k, f, _ := newFakeKernelLinux(t)
		mustForward(t, k, 1, adapterA, adapterB)
		rt := adapterEth1
		rt.src = netip.MustParseAddr("198.51.100.9")
		f.table[adapterB.Addr()] = rt
		if got := k.refresh(); !slices.Equal(got, []uint32{1}) {
			t.Fatalf("refresh() = %v, want [1]", got)
		}
		lookups := len(f.routeCalls)
		mustForward(t, k, 1, adapterA, adapterB)
		if got := f.puts[len(f.puts)-1].session.OwnerSrc; got != rt.src {
			t.Errorf("OwnerSrc of the session installed again = %s, want %s", got, rt.src)
		}
		if n := len(f.routeCalls) - lookups; n != 0 {
			t.Errorf("forward after refresh resolved %d addresses, want 0", n)
		}
	})

	// An address no session uses leaves the cache, and so does an
	// attachment no cached route names.
	t.Run("unused addresses and attachments dropped", func(t *testing.T) {
		k, _, _ := newFakeKernelLinux(t)
		mustForward(t, k, 1, adapterA, adapterB)
		mustForward(t, k, 2, adapterB, adapterA)
		mustForward(t, k, 3, adapterC, adapterD)

		if err := k.forget(3); err != nil {
			t.Fatalf("forget(3): %v", err)
		}
		if got := k.refresh(); got != nil {
			t.Fatalf("refresh() = %v, want nil", got)
		}
		if got := slices.SortedFunc(maps.Keys(k.routes), netip.Addr.Compare); !slices.Equal(got, []netip.Addr{adapterA.Addr(), adapterB.Addr()}) {
			t.Errorf("cached addresses = %v, want those of A and B", got)
		}
		if want := map[int]string{2: "eth0", 3: "eth1"}; !maps.Equal(k.attached, want) {
			t.Errorf("attached = %v, want %v", k.attached, want)
		}

		for _, i := range []uint32{1, 2} {
			if err := k.forget(i); err != nil {
				t.Fatalf("forget(%d): %v", i, err)
			}
		}
		if got := k.refresh(); got != nil {
			t.Fatalf("refresh() = %v, want nil", got)
		}
		if len(k.routes) != 0 || len(k.attached) != 0 {
			t.Errorf("cached addresses %v and attached %v, want none of either", k.routes, k.attached)
		}
	})

	// A renamed interface is attached and logged again by the next session
	// through it.
	t.Run("renamed interface attached again", func(t *testing.T) {
		k, f, logs := newFakeKernelLinux(t)
		mustForward(t, k, 1, adapterA, adapterB)
		f.table[adapterA.Addr()] = lan0
		if got := k.refresh(); !slices.Equal(got, []uint32{1}) {
			t.Fatalf("refresh() = %v, want [1]", got)
		}
		mustForward(t, k, 1, adapterA, adapterB)
		if want := []int{2, 2}; !slices.Equal(f.attaches, want) {
			t.Errorf("Attach calls = %v, want %v", f.attaches, want)
		}
		if n := attachedLines(logs, "lan0"); n != 1 {
			t.Errorf(`%d "relay: kernel forwarding attached" lines with interface=lan0, want 1:%s`, n, logs)
		}
	})
}

func TestRelayKernelLinux_IPv6ForwardingFlag(t *testing.T) {
	const path = "/proc/sys/net/ipv6/conf/plexd0/forwarding"
	const notSet = `level=DEBUG msg="relay: ipv6 forwarding flag not set on the mesh interface" component=bridge error=`

	tests := []struct {
		name       string
		meshIface  string
		flag       string
		readErr    error
		writeErr   error
		wantWrites []string // after raiseIPv6Forwarding and close
		wantPaths  int
		wantLog    string
	}{
		{
			name:       "flag 0 is raised and restored",
			flag:       "0\n",
			wantWrites: []string{"1", "0"},
			wantPaths:  3,
		},
		{
			name:      "flag 1 is left alone",
			flag:      "1\n",
			wantPaths: 1,
		},
		{
			name:      "write refused",
			flag:      "0\n",
			writeErr:  fs.ErrPermission,
			wantPaths: 2,
			wantLog:   notSet + `"permission denied"` + "\n",
		},
		{
			name:      "read refused",
			readErr:   fs.ErrPermission,
			wantPaths: 1,
			wantLog:   notSet + `"permission denied"` + "\n",
		},
		{
			name:      "name unfit for a path",
			meshIface: "../all",
			wantLog:   notSet + `"bridge: invalid interface name \"../all\": contains prohibited character"` + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, f, logs := newFakeKernelLinux(t)
			if tt.meshIface != "" {
				k.meshIface = tt.meshIface
			}
			f.flag = tt.flag
			f.readErr = tt.readErr
			f.writeErr = tt.writeErr

			k.raiseIPv6Forwarding()
			if err := k.close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			if !slices.Equal(f.writes, tt.wantWrites) {
				t.Errorf("flag writes = %q, want %q", f.writes, tt.wantWrites)
			}
			if len(f.paths) != tt.wantPaths {
				t.Errorf("flag accesses %q, want %d", f.paths, tt.wantPaths)
			}
			for _, p := range f.paths {
				if p != path {
					t.Errorf("flag access to %s, want %s", p, path)
				}
			}
			if f.closes != 1 {
				t.Errorf("Forwarder closed %d times, want 1", f.closes)
			}

			n := strings.Count(logs.String(), "relay: ipv6 forwarding flag not set on the mesh interface")
			switch {
			case tt.wantLog == "" && n != 0:
				t.Errorf("unexpected flag line:\n%s", logs)
			case tt.wantLog != "" && (n != 1 || logs.count(tt.wantLog) != 1):
				t.Errorf("log lacks one line %q:\n%s", tt.wantLog, logs)
			}
		})
	}
}

func TestRelayKernelLinux_UnknownMeshInterface(t *testing.T) {
	logger, _ := newRelayLogger()
	k, err := newRelayKernelLinux(51821, "plexd-absent", logger, func(f func() error) error { return f() })
	const want = `bridge: relay: kernel forwarding: mesh interface "plexd-absent":`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("newRelayKernelLinux error = %v, want one starting with %q", err, want)
	}
	if k != nil {
		t.Errorf("newRelayKernelLinux returned %v with its error, want nil", k)
	}
}
