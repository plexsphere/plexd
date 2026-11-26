package bridge

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fakeKernelCall is one call the relay made on a fakeRelayKernel.
type fakeKernelCall struct {
	op    string // forward, forget, age, ages, refresh, counters or close
	index uint32 // for forward, forget and age
	flow  relayKernelFlow
}

// fakeRelayKernel is a relayKernel that records every call in order and
// answers from what the test scripted. Its own mutex guards the record and
// the script, because the relay calls it from the dispatch loop while the
// test reads and scripts it.
type fakeRelayKernel struct {
	mu    sync.Mutex
	calls []fakeKernelCall

	// forwardErrs answers the forward calls in order; past its end, forward
	// succeeds.
	forwardErrs []error
	// kernelAges answers ages, and age for the indices it holds; age answers
	// false for any other.
	kernelAges map[uint32]time.Duration
	agesErr    error
	// refreshed answers the next refresh call, and only that one.
	refreshed []uint32
	// counterValues answers counters.
	counterValues map[string]uint64
}

// record appends c to the calls. Callers hold f.mu.
func (f *fakeRelayKernel) record(c fakeKernelCall) {
	f.calls = append(f.calls, c)
}

func (f *fakeRelayKernel) forward(index uint32, flow relayKernelFlow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "forward", index: index, flow: flow})
	if len(f.forwardErrs) == 0 {
		return nil
	}
	err := f.forwardErrs[0]
	f.forwardErrs = f.forwardErrs[1:]
	return err
}

func (f *fakeRelayKernel) forget(index uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "forget", index: index})
	return nil
}

func (f *fakeRelayKernel) age(index uint32) (time.Duration, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "age", index: index})
	d, ok := f.kernelAges[index]
	return d, ok, nil
}

func (f *fakeRelayKernel) ages() (map[uint32]time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "ages"})
	if f.agesErr != nil {
		return nil, f.agesErr
	}
	out := make(map[uint32]time.Duration, len(f.kernelAges))
	for i, d := range f.kernelAges {
		out[i] = d
	}
	return out, nil
}

func (f *fakeRelayKernel) refresh() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "refresh"})
	out := f.refreshed
	f.refreshed = nil
	return out
}

func (f *fakeRelayKernel) counters() (map[string]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "counters"})
	out := make(map[string]uint64, len(f.counterValues))
	for name, n := range f.counterValues {
		out[name] = n
	}
	return out, nil
}

func (f *fakeRelayKernel) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(fakeKernelCall{op: "close"})
	return nil
}

// set runs fn with the fake's mutex held, for scripting its answers.
func (f *fakeRelayKernel) set(fn func(f *fakeRelayKernel)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// mark returns how many calls the fake has recorded, for since.
func (f *fakeRelayKernel) mark() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// since returns the calls recorded after mark returned from.
func (f *fakeRelayKernel) since(from int) []fakeKernelCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls[from:])
}

// ops returns the calls named op among calls.
func ops(calls []fakeKernelCall, op string) []fakeKernelCall {
	var out []fakeKernelCall
	for _, c := range calls {
		if c.op == op {
			out = append(out, c)
		}
	}
	return out
}

// indicesOf returns the indices of calls, sorted.
func indicesOf(calls []fakeKernelCall) []uint32 {
	out := make([]uint32, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.index)
	}
	slices.Sort(out)
	return out
}

// kernelRelay returns testRelay's relay with a fakeRelayKernel as its kernel
// path, and the fake.
func kernelRelay(t *testing.T) (*Relay, *relayLog, *relayClock, *fakeRelayKernel) {
	t.Helper()
	r, logs, clock := testRelay(t)
	fake := &fakeRelayKernel{}
	r.newKernel = func(int) (relayKernel, error) { return fake, nil }
	return r, logs, clock, fake
}

// indexState returns used and kernel of index i, and whether the relay holds
// it.
func indexState(r *Relay, i uint32) (time.Time, relayKernelFlow, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx, ok := r.indices[i]
	if !ok {
		return time.Time{}, relayKernelFlow{}, false
	}
	return idx.used, idx.kernel, true
}

// installedLine is the Debug line of a session the kernel took.
func installedLine(partner, owner *wgPeer) string {
	return fmt.Sprintf(`level=DEBUG msg="relay: kernel session installed" component=bridge partner_id=%s owner_id=%s`+"\n", partner.id, owner.id)
}

// ---------------------------------------------------------------------------
// The kernel path
// ---------------------------------------------------------------------------

func TestRelay_KernelTakesASessionAfterItsFirstTransport(t *testing.T) {
	r, logs, _, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshakeOnly(t, r, a, b, 3, 2)
	if got := ops(fake.since(0), "forward"); len(got) != 0 {
		t.Fatalf("a handshake caused forward calls %v, want none", got)
	}

	// The process writes the first transport datagram to the socket itself.
	mark := fake.mark()
	toB := transportTo(2, 1)
	send(t, a.conn, r, toB)
	expectRecv(t, b, toB)
	want := []fakeKernelCall{{op: "forward", index: 2, flow: relayKernelFlow{partner: a.addr(), owner: b.addr()}}}
	if got := ops(fake.since(mark), "forward"); !slices.Equal(got, want) {
		t.Fatalf("forward calls after the first transport = %v, want %v", got, want)
	}
	if n := logs.count(installedLine(a, b)); n != 1 {
		t.Fatalf("%q logged %d times, want once:\n%s", installedLine(a, b), n, logs.String())
	}

	// A second datagram of the flow, which the kernel passed up: nothing new.
	mark = fake.mark()
	toB = transportTo(2, 2)
	send(t, a.conn, r, toB)
	expectRecv(t, b, toB)
	if got := ops(fake.since(mark), "forward"); len(got) != 0 {
		t.Errorf("forward calls after a second datagram of the flow = %v, want none", got)
	}
	if n := logs.count(`msg="relay: kernel session installed"`); n != 1 {
		t.Errorf("kernel session installed logged %d times, want once:\n%s", n, logs.String())
	}
}

func TestRelay_KernelFollowsARoam(t *testing.T) {
	r, logs, _, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	c := newWGPeer(t, "node-c", 0x30)
	d := newWGPeer(t, "node-d", 0x40)
	e := newWGPeer(t, "node-e", 0x50)
	f := newWGPeer(t, "node-f", 0x60)
	mustConfigure(t, r, a, b, c, d, e, f)
	// Three sessions, all installed in the kernel: A-B, C-D and E-F.
	handshake(t, r, a, b, 3, 2)
	handshake(t, r, c, d, 5, 4)
	handshake(t, r, e, f, 7, 6)
	if got := indicesOf(ops(fake.since(0), "forward")); !slices.Equal(got, []uint32{2, 3, 4, 5, 6, 7}) {
		t.Fatalf("installed indices = %v, want 2 to 7", got)
	}

	// A's NAT hands A the public port C had: A's transport to B arrives from
	// C's address, and the relay takes the address from C.
	mark := fake.mark()
	toB := transportTo(2, 1)
	send(t, c.conn, r, toB)
	expectRecv(t, b, toB)

	calls := fake.since(mark)
	if len(calls) == 0 {
		t.Fatal("the roam caused no kernel call")
	}
	forgets, last := calls[:len(calls)-1], calls[len(calls)-1]
	// Every index naming A (2, 3) or C, which lost the address (4, 5), and
	// none of E and F's.
	if got := indicesOf(ops(forgets, "forget")); len(ops(forgets, "forget")) != len(forgets) || !slices.Equal(got, []uint32{2, 3, 4, 5}) {
		t.Errorf("calls before the last = %v, want forget for 2, 3, 4 and 5 alone", forgets)
	}
	if want := (fakeKernelCall{op: "forward", index: 2, flow: relayKernelFlow{partner: c.addr(), owner: b.addr()}}); last != want {
		t.Errorf("last call = %v, want %v", last, want)
	}
	if want := fmt.Sprintf(`level=INFO msg="relay: peer address learned" component=bridge peer_id=node-a address=%s`, c.addr()); !strings.Contains(logs.String(), want) {
		t.Errorf("log lacks %q:\n%s", want, logs.String())
	}

	// B's next datagram to A reaches the process too, goes to A's new address
	// and installs index 3 again with it.
	mark = fake.mark()
	toA := transportTo(3, 1)
	send(t, b.conn, r, toA)
	if got := recv(t, c.conn); !bytes.Equal(got, toA) {
		t.Fatalf("A's new address received %x, want %x", got, toA)
	}
	want := []fakeKernelCall{{op: "forward", index: 3, flow: relayKernelFlow{partner: b.addr(), owner: c.addr()}}}
	if got := fake.since(mark); !slices.Equal(got, want) {
		t.Errorf("calls after B's next datagram = %v, want %v", got, want)
	}
}

func TestRelay_KernelForgetsWhatTheTableDrops(t *testing.T) {
	tests := []struct {
		name string
		// drop makes the table drop or change indices of A and B's session,
		// both installed in the kernel.
		drop func(t *testing.T, r *Relay, clock *relayClock, a, b, c *wgPeer)
		want []uint32
	}{
		{
			name: "the sweep expires the session",
			drop: func(_ *testing.T, r *Relay, clock *relayClock, _, _, _ *wgPeer) {
				clock.Add(relayIndexTTL)
				r.sweep(clock.Now())
			},
			want: []uint32{2, 3},
		},
		{
			name: "Configure removes B",
			drop: func(t *testing.T, r *Relay, _ *relayClock, a, _, c *wgPeer) {
				mustConfigure(t, r, a, c)
			},
			want: []uint32{2, 3},
		},
		{
			// C has no session with anyone, so its initiation is never held.
			name: "an initiation reuses B's index as its sender index",
			drop: func(t *testing.T, r *Relay, _ *relayClock, a, _, c *wgPeer) {
				expectForwarded(t, r, c, a, 2)
			},
			want: []uint32{2},
		},
		{
			name: "a response reuses A's index as its sender index",
			drop: func(t *testing.T, r *Relay, _ *relayClock, a, _, c *wgPeer) {
				expectForwarded(t, r, c, a, 50)
				resp := responseFor(3, 50, c)
				send(t, a.conn, r, resp)
				expectRecv(t, c, resp)
			},
			want: []uint32{3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, clock, fake := kernelRelay(t)
			a := newWGPeer(t, "node-a", 0x10)
			b := newWGPeer(t, "node-b", 0x20)
			c := newWGPeer(t, "node-c", 0x30)
			mustConfigure(t, r, a, b, c)
			handshake(t, r, a, b, 3, 2)
			if got := indicesOf(ops(fake.since(0), "forward")); !slices.Equal(got, []uint32{2, 3}) {
				t.Fatalf("installed indices = %v, want 2 and 3", got)
			}

			mark := fake.mark()
			tt.drop(t, r, clock, a, b, c)
			if got := indicesOf(ops(fake.since(mark), "forget")); !slices.Equal(got, tt.want) {
				t.Errorf("forget calls for %v, want %v", got, tt.want)
			}
			for _, i := range tt.want {
				if _, kernel, ok := indexState(r, i); ok && kernel != (relayKernelFlow{}) {
					t.Errorf("index %d still records %v in the kernel", i, kernel)
				}
			}

			for range 2 {
				if err := r.Stop(); err != nil {
					t.Fatalf("Stop: %v", err)
				}
			}
			if n := len(ops(fake.since(0), "close")); n != 1 {
				t.Errorf("two Stop calls closed the kernel path %d times, want once", n)
			}
		})
	}
}

func TestRelay_KernelAgeKeepsASessionAlive(t *testing.T) {
	r, logs, clock, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	// The kernel carried index 2 a second ago; the process last did 200 s ago.
	clock.Add(200 * time.Second)
	fake.set(func(f *fakeRelayKernel) { f.kernelAges = map[uint32]time.Duration{2: time.Second} })

	// No sweep and no ActiveCount ran, so only the hold itself can have read
	// the kernel.
	mark := fake.mark()
	expectHeld(t, r, logs, a, b, 10)
	calls := fake.since(mark)
	if len(ops(calls, "ages")) != 0 || len(ops(calls, "age")) == 0 {
		t.Errorf("kernel calls of the held initiation = %v, want age and no ages", calls)
	}
	if used, _, _ := indexState(r, 2); !used.Equal(clock.Now().Add(-time.Second)) {
		t.Errorf("index 2 used = %v, want a second before now", used)
	}
	// A, the partner of index 2, sent that datagram from the address the
	// kernel matched; B, whose index 3 the kernel has no age for, did not.
	seen := make(map[string]time.Time)
	r.mu.Lock()
	for _, p := range r.peers {
		seen[p.nodeID] = p.seen
	}
	r.mu.Unlock()
	if !seen[a.id].Equal(clock.Now().Add(-time.Second)) || !seen[b.id].Equal(relayStart) {
		t.Errorf("seen: A %v, B %v; want A a second before now, B at the handshake", seen[a.id], seen[b.id])
	}

	r.sweep(clock.Now())
	if _, _, ok := indexState(r, 2); !ok {
		t.Fatal("the sweep deleted index 2, which the kernel carried a second ago")
	}
	if n := r.ActiveCount(); n != 1 {
		t.Errorf("ActiveCount = %d, want 1", n)
	}

	// ActiveCount reads the kernel itself: 180 s on, with no sweep in between,
	// the kernel carried index 2 a second ago again.
	clock.Add(relayIndexTTL)
	if n := r.ActiveCount(); n != 1 {
		t.Errorf("ActiveCount %s later with no sweep = %d, want 1", relayIndexTTL, n)
	}
}

func TestRelay_KernelIdleSessionExpires(t *testing.T) {
	r, _, clock, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	clock.Add(200 * time.Second)
	fake.set(func(f *fakeRelayKernel) {
		f.kernelAges = map[uint32]time.Duration{2: relayIndexTTL, 3: relayIndexTTL - time.Second}
	})
	mark := fake.mark()
	r.sweep(clock.Now())

	if _, _, ok := indexState(r, 2); ok {
		t.Error("index 2, idle in the kernel for 180 s, survived the sweep")
	}
	if _, _, ok := indexState(r, 3); !ok {
		t.Error("index 3, idle in the kernel for 179 s, did not survive the sweep")
	}
	if got := indicesOf(ops(fake.since(mark), "forget")); !slices.Equal(got, []uint32{2}) {
		t.Errorf("forget calls for %v, want 2 alone", got)
	}
}

func TestRelay_KernelSweepForgetsStrays(t *testing.T) {
	r, _, clock, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	// A's first initiation of the handshake stays pending as 1000003.
	handshake(t, r, a, b, 3, 2)

	// 99 is in no table, and 1000003 is pending: neither is a session index.
	fake.set(func(f *fakeRelayKernel) {
		f.kernelAges = map[uint32]time.Duration{2: time.Second, 3: time.Second, 99: time.Second, 1_000_003: time.Second}
	})
	mark := fake.mark()
	r.sweep(clock.Now())

	if got := indicesOf(ops(fake.since(mark), "forget")); !slices.Equal(got, []uint32{99, 1_000_003}) {
		t.Errorf("forget calls for %v, want 99 and 1000003", got)
	}
	for _, i := range []uint32{2, 3, 1_000_003} {
		if _, _, ok := indexState(r, i); !ok {
			t.Errorf("the sweep deleted index %d", i)
		}
	}
}

func TestRelay_KernelRefreshReinstalls(t *testing.T) {
	r, logs, clock, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	// The route towards B changed, so the kernel forgot index 2.
	fake.set(func(f *fakeRelayKernel) {
		f.refreshed = []uint32{2}
		f.counterValues = map[string]uint64{
			"forwarded": 40, "no_session": 1, "mismatch": 2, "fib_fwd_disabled": 3,
			"fib_frag_needed": 4, "fib_no_neigh": 5, "fib_other": 6, "route_changed": 7,
		}
	})
	r.sweep(clock.Now())
	if _, kernel, _ := indexState(r, 2); kernel != (relayKernelFlow{}) {
		t.Fatalf("index 2 records %v in the kernel after refresh forgot it", kernel)
	}

	mark := fake.mark()
	toB := transportTo(2, 1)
	send(t, a.conn, r, toB)
	expectRecv(t, b, toB)
	toA := transportTo(3, 1)
	send(t, b.conn, r, toA)
	expectRecv(t, a, toA)
	want := []fakeKernelCall{{op: "forward", index: 2, flow: relayKernelFlow{partner: a.addr(), owner: b.addr()}}}
	if got := ops(fake.since(mark), "forward"); !slices.Equal(got, want) {
		t.Errorf("forward calls after the refresh = %v, want %v", got, want)
	}

	// Each sweep logs the nine counters; gso, which the kernel did not
	// return, as 0.
	r.sweep(clock.Now())
	const line = `level=DEBUG msg="relay: kernel forwarding counters" component=bridge ` +
		`forwarded=40 no_session=1 mismatch=2 fib_fwd_disabled=3 fib_frag_needed=4 ` +
		`fib_no_neigh=5 fib_other=6 route_changed=7 gso=0` + "\n"
	if n := logs.count(line); n != 2 {
		t.Errorf("%q logged %d times after two sweeps, want twice:\n%s", line, n, logs.String())
	}
}

func TestRelay_KernelEmptyTable(t *testing.T) {
	r, logs, clock, fake := kernelRelay(t)
	if err := r.Configure(51821, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if got := fake.since(0); len(ops(got, "forward"))+len(ops(got, "forget")) != 0 {
		t.Fatalf("Configure with no peers made kernel calls %v, want neither forward nor forget", got)
	}

	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)
	used2, kernel2, _ := indexState(r, 2)
	used3, kernel3, _ := indexState(r, 3)

	// An empty table in the kernel changes nothing.
	fake.set(func(f *fakeRelayKernel) { f.kernelAges = map[uint32]time.Duration{} })
	mark := fake.mark()
	r.sweep(clock.Now())
	if got := ops(fake.since(mark), "forget"); len(got) != 0 {
		t.Errorf("forget calls after an empty ages = %v, want none", got)
	}
	for _, s := range []struct {
		i      uint32
		used   time.Time
		kernel relayKernelFlow
	}{
		{i: 2, used: used2, kernel: kernel2},
		{i: 3, used: used3, kernel: kernel3},
	} {
		used, kernel, ok := indexState(r, s.i)
		if !ok || !used.Equal(s.used) || kernel != s.kernel || kernel == (relayKernelFlow{}) {
			t.Errorf("index %d after an empty ages: held %v, used %v, kernel %v; want held, used %v, kernel %v", s.i, ok, used, kernel, s.used, s.kernel)
		}
	}

	// age answers false for index 2: its used stays.
	clock.Add(10 * time.Second)
	mark = fake.mark()
	expectHeld(t, r, logs, a, b, 10)
	if got := ops(fake.since(mark), "age"); len(got) == 0 || got[0].index != 2 {
		t.Fatalf("age calls of the held initiation = %v, want one for index 2 first", got)
	}
	if used, _, _ := indexState(r, 2); !used.Equal(used2) {
		t.Errorf("index 2 used = %v after age answered false, want %v", used, used2)
	}
}

func TestRelay_KernelUnavailable(t *testing.T) {
	t.Run("newKernel fails", func(t *testing.T) {
		r, logs, _ := testRelay(t)
		calls := 0
		r.newKernel = func(int) (relayKernel, error) {
			calls++
			return nil, errors.New("relaybpf: load: operation not permitted")
		}
		a := newWGPeer(t, "node-a", 0x10)
		b := newWGPeer(t, "node-b", 0x20)
		if err := r.Configure(51821, snapshotPeers(a, b)); err != nil {
			t.Fatalf("Configure = %v, want nil", err)
		}
		mustConfigure(t, r, a, b) // the same port: no second try
		handshake(t, r, a, b, 3, 2)

		const line = `level=INFO msg="relay: kernel forwarding unavailable, forwarding in the process" component=bridge error="relaybpf: load: operation not permitted"` + "\n"
		if n := logs.count(line); n != 1 {
			t.Errorf("%q logged %d times, want once:\n%s", line, n, logs.String())
		}
		if n := logs.count(`msg="relay: kernel`); n != 1 {
			t.Errorf("%d kernel lines, want only the unavailable one:\n%s", n, logs.String())
		}
		if calls != 1 {
			t.Errorf("newKernel called %d times, want once", calls)
		}
	})
	t.Run("nil newKernel", func(t *testing.T) {
		r, logs, _ := testRelay(t)
		a := newWGPeer(t, "node-a", 0x10)
		b := newWGPeer(t, "node-b", 0x20)
		mustConfigure(t, r, a, b)
		handshake(t, r, a, b, 3, 2)
		r.sweep(relayStart)
		if r.ActiveCount() != 1 {
			t.Errorf("ActiveCount = %d, want 1", r.ActiveCount())
		}
		if err := r.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if strings.Contains(logs.String(), "kernel") {
			t.Errorf("a relay without newKernel logged about the kernel:\n%s", logs.String())
		}
	})
}

func TestRelay_KernelRefusalIsRetriedAfterAPause(t *testing.T) {
	r, logs, clock, fake := kernelRelay(t)
	fake.set(func(f *fakeRelayKernel) {
		f.forwardErrs = []error{errors.New("bridge: relay: kernel forwarding: address families differ")}
	})
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshakeOnly(t, r, a, b, 3, 2)

	forwards := func() int { return len(ops(fake.since(0), "forward")) }
	sendToB := func(counter uint64) {
		t.Helper()
		toB := transportTo(2, counter)
		send(t, a.conn, r, toB)
		expectRecv(t, b, toB)
	}

	sendToB(1)
	if n := forwards(); n != 1 {
		t.Fatalf("forward calls after the first transport = %d, want 1", n)
	}
	const line = `level=DEBUG msg="relay: kernel session not installed" component=bridge partner_id=node-a owner_id=node-b error="bridge: relay: kernel forwarding: address families differ"` + "\n"
	if n := logs.count(line); n != 1 {
		t.Fatalf("%q logged %d times, want once:\n%s", line, n, logs.String())
	}

	// Within relayKernelRetry the process forwards, and offers nothing.
	sendToB(2)
	clock.Add(time.Second)
	sendToB(3)
	clock.Add(relayKernelRetry - time.Second - time.Nanosecond)
	sendToB(4)
	if n := forwards(); n != 1 {
		t.Fatalf("forward calls within %s of the refusal = %d, want 1", relayKernelRetry, n)
	}

	clock.Add(time.Nanosecond)
	sendToB(5)
	if n := forwards(); n != 2 {
		t.Fatalf("forward calls %s after the refusal = %d, want 2", relayKernelRetry, n)
	}
	if n := logs.count(installedLine(a, b)); n != 1 {
		t.Errorf("%q logged %d times after the retry, want once:\n%s", installedLine(a, b), n, logs.String())
	}
}

func TestRelay_KernelReadErrorEndsKernelForwarding(t *testing.T) {
	r, logs, clock, fake := kernelRelay(t)
	a := newWGPeer(t, "node-a", 0x10)
	b := newWGPeer(t, "node-b", 0x20)
	mustConfigure(t, r, a, b)
	handshake(t, r, a, b, 3, 2)

	fake.set(func(f *fakeRelayKernel) {
		f.agesErr = errors.New("bridge: relay: kernel forwarding: bad file descriptor")
	})
	mark := fake.mark()
	r.sweep(clock.Now())

	const line = `level=WARN msg="relay: kernel forwarding stopped, forwarding in the process" component=bridge error="bridge: relay: kernel forwarding: bad file descriptor"` + "\n"
	if n := logs.count(line); n != 1 {
		t.Errorf("%q logged %d times, want once:\n%s", line, n, logs.String())
	}
	want := []fakeKernelCall{{op: "ages"}, {op: "close"}}
	if got := fake.since(mark); !slices.Equal(got, want) {
		t.Errorf("kernel calls of the sweep = %v, want %v", got, want)
	}

	mark = fake.mark()
	for i := range uint64(3) {
		toB := transportTo(2, 10+i)
		send(t, a.conn, r, toB)
		expectRecv(t, b, toB)
		toA := transportTo(3, 10+i)
		send(t, b.conn, r, toA)
		expectRecv(t, a, toA)
	}
	r.sweep(clock.Now())
	if n := r.ActiveCount(); n != 1 {
		t.Errorf("ActiveCount = %d, want 1", n)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := fake.since(mark); len(got) != 0 {
		t.Errorf("kernel calls after the kernel path stopped = %v, want none", got)
	}
}

func TestRelay_KernelWarnsWhenForwardingIsOff(t *testing.T) {
	r, logs, clock, fake := kernelRelay(t)
	// useKernel names the mesh interface; the fake stays the kernel path.
	r.useKernel("plexd0")
	r.newKernel = func(int) (relayKernel, error) { return fake, nil }
	if err := r.Configure(51821, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if want := `level=INFO msg="relay: kernel forwarding started" component=bridge listen_port=51821 mesh_interface=plexd0` + "\n"; logs.count(want) != 1 {
		t.Fatalf("log lacks %q once:\n%s", want, logs.String())
	}

	const line = `level=WARN msg="relay: kernel forwarding passes datagrams to the process, forwarding is off on the mesh interface" component=bridge mesh_interface=plexd0` + "\n"
	for _, step := range []struct {
		after       time.Duration
		fwdDisabled uint64
		warns       int
	}{
		{0, 0, 0},
		{relaySweepInterval, 0, 0},  // no growth
		{relaySweepInterval, 5, 1},  // grew: Warn
		{59 * time.Second, 9, 1},    // grew 59 s after the Warn
		{time.Second, 12, 2},        // grew a minute after it: Warn
		{time.Second, 15, 2},        // grew a second after that one
		{2 * time.Minute, 15, 2},    // minutes passed, but no growth
		{relaySweepInterval, 15, 2}, // still none
		{relaySweepInterval, 16, 3}, // grew again: Warn
	} {
		clock.Add(step.after)
		fake.set(func(f *fakeRelayKernel) { f.counterValues = map[string]uint64{"fib_fwd_disabled": step.fwdDisabled} })
		r.sweep(clock.Now())
		if n := logs.count(line); n != step.warns {
			t.Fatalf("fib_fwd_disabled=%d at %s: %d Warn lines, want %d:\n%s", step.fwdDisabled, clock.Now().Sub(relayStart), n, step.warns, logs.String())
		}
	}
}
