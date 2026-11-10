package meshdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/plexsphere/plexd/internal/api"
)

// testIface is the interface the test managers register for. Every test uses
// a fake registrar, so the name only has to show up in the calls it records.
const testIface = "plexd-test0"

// The manager's log lines, spelled out rather than taken from manager.go, so
// a test pins the text an operator searches for.
const (
	msgNoBlock     = "state pull carries no dns block, keeping the names held"
	msgSkipped     = "mesh dns skipped invalid entries"
	msgUpdated     = "mesh dns records updated"
	msgRegistered  = "mesh dns registered with systemd-resolved"
	msgUnavailable = "mesh dns not registered, systemd-resolved is not usable"
	msgFailed      = "mesh dns registration failed"
	msgReverted    = "mesh dns registration reverted"
)

// errUnavailableTest is what ResolvedRegistrar returns on a host without
// systemd-resolved.
var errUnavailableTest = fmt.Errorf("meshdns: resolved: systemd-resolved is not running: %w", ErrUnavailable)

// registrarCall is one call the fake registrar received.
type registrarCall struct {
	// method is "Apply" or "Revert".
	method string
	// reg is the registration of an Apply.
	reg Registration
	// iface is the interface of a Revert.
	iface string
	// left is how long the call's context had until its deadline when the
	// call arrived, or 0 when it had none.
	left time.Duration
}

// fakeRegistrar records every call and answers with the error set for its
// method. It is safe for concurrent use, so a test can race Handle against
// Shutdown.
type fakeRegistrar struct {
	mu        sync.Mutex
	calls     []registrarCall
	applyErr  error
	revertErr error
}

func (r *fakeRegistrar) Apply(ctx context.Context, reg Registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, registrarCall{method: "Apply", reg: reg, left: timeLeft(ctx)})
	return r.applyErr
}

func (r *fakeRegistrar) Revert(ctx context.Context, iface string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, registrarCall{method: "Revert", iface: iface, left: timeLeft(ctx)})
	return r.revertErr
}

func (r *fakeRegistrar) setApplyErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyErr = err
}

func (r *fakeRegistrar) setRevertErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revertErr = err
}

// recorded returns a copy of the calls so far, in the order they arrived.
func (r *fakeRegistrar) recorded() []registrarCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// methods returns the method of each call so far, in order.
func (r *fakeRegistrar) methods() []string {
	var out []string
	for _, c := range r.recorded() {
		out = append(out, c.method)
	}
	return out
}

// count returns how many calls of method arrived so far.
func (r *fakeRegistrar) count(method string) int {
	n := 0
	for _, c := range r.recorded() {
		if c.method == method {
			n++
		}
	}
	return n
}

func timeLeft(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}

// checkBounded fails the test unless the call's context had a deadline of at
// most five seconds, so a hanging system bus cannot hold up the reconcile
// loop for longer.
func checkBounded(t *testing.T, c registrarCall) {
	t.Helper()
	if c.left <= 0 || c.left > 5*time.Second {
		t.Errorf("%s context had %v left, want a deadline within 5s", c.method, c.left)
	}
}

// logEntry is one record the recording handler kept, with the attributes of
// the logger it went through.
type logEntry struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

// logRecorder holds the records of every handler derived from it.
type logRecorder struct {
	mu      sync.Mutex
	entries []logEntry
}

// recordingHandler keeps every record in its logRecorder. Unlike a handler
// that drops WithAttrs, it keeps the attributes a logger was built with, so a
// test sees the component attribute the manager adds to its logger.
type recordingHandler struct {
	rec   *logRecorder
	attrs []slog.Attr
}

// Enabled admits every level, so the server's Debug lines are checked for the
// component attribute too.
func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]slog.Value, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.Resolve()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Resolve()
		return true
	})
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	h.rec.entries = append(h.rec.entries, logEntry{level: r.Level, msg: r.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &recordingHandler{rec: h.rec, attrs: append(slices.Clip(h.attrs), as...)}
}

// WithGroup returns h unchanged: the manager logs no groups.
func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// all returns a copy of the records so far.
func (l *logRecorder) all() []logEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.entries)
}

// find returns the records that say msg, at any level.
func (l *logRecorder) find(msg string) []logEntry {
	var out []logEntry
	for _, e := range l.all() {
		if e.msg == msg {
			out = append(out, e)
		}
	}
	return out
}

// count returns how many records say msg, at any level.
func (l *logRecorder) count(msg string) int {
	return len(l.find(msg))
}

// checkComponent fails the test for every record without "component"
// "meshdns", so an operator filtering on it sees every line.
func (l *logRecorder) checkComponent(t *testing.T) {
	t.Helper()
	for _, e := range l.all() {
		if got := e.attrs["component"]; got.String() != "meshdns" {
			t.Errorf("line %q has component %q, want %q", e.msg, got, "meshdns")
		}
	}
}

// wantLine fails the test unless exactly one record says msg, at level, with
// every attribute of attrs rendered as given.
func wantLine(t *testing.T, logs *logRecorder, level slog.Level, msg string, attrs map[string]string) {
	t.Helper()
	found := logs.find(msg)
	if len(found) != 1 {
		t.Errorf("%d lines say %q, want 1", len(found), msg)
		return
	}
	if found[0].level != level {
		t.Errorf("%q logged at %v, want %v", msg, found[0].level, level)
	}
	for k, want := range attrs {
		got, ok := found[0].attrs[k]
		if !ok {
			t.Errorf("%q has no attribute %q, want %q", msg, k, want)
			continue
		}
		if got.String() != want {
			t.Errorf("%q has %s=%q, want %q", msg, k, got, want)
		}
	}
}

// wantCount fails the test unless n records say msg.
func wantCount(t *testing.T, logs *logRecorder, msg string, n int) {
	t.Helper()
	if got := logs.count(msg); got != n {
		t.Errorf("%d lines say %q, want %d", got, msg, n)
	}
}

// wantMethods fails the test unless the registrar received exactly the calls
// named in want, in that order.
func wantMethods(t *testing.T, reg *fakeRegistrar, want ...string) {
	t.Helper()
	if got := reg.methods(); !slices.Equal(got, want) {
		t.Errorf("registrar calls = %q, want %q", got, want)
	}
}

// newTestManager returns a manager on 127.0.0.1 with a port the kernel picks
// at Start, registering with reg and logging to the returned recorder. When
// the test ends it checks that every line carried the component attribute.
func newTestManager(t *testing.T, reg *fakeRegistrar) (*Manager, *logRecorder) {
	t.Helper()
	logs := &logRecorder{}
	m := NewManager(Config{ListenPort: 0}, testIface, netip.MustParseAddr("127.0.0.1"), reg, slog.New(&recordingHandler{rec: logs}))
	t.Cleanup(func() { logs.checkComponent(t) })
	return m, logs
}

// startManager returns a test manager that listens and serves until the test
// ends, so a test can ask its resolver over a real socket. configure runs
// before the resolver starts serving.
func startManager(t *testing.T, reg *fakeRegistrar, configure ...func(*Manager)) (*Manager, *logRecorder) {
	t.Helper()
	m, logs := newTestManager(t, reg)
	for _, f := range configure {
		f(m)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run() = %v, want nil after the cancel", err)
			}
		case <-time.After(ioTimeout):
			t.Errorf("Run did not return within %v of the cancel", ioTimeout)
		}
	})
	return m, logs
}

// snapshot returns a state pull that carries block.
func snapshot(block api.NodeStateDNS) *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{DNS: &block}
}

// emptyBlock is a dns block with four empty lists: the control plane says
// the Domain has no names.
func emptyBlock() api.NodeStateDNS {
	return api.NodeStateDNS{SearchDomain: "", Zones: []string{}, Hosts: []api.NodeStateDNSHost{}, ReverseZones: []string{}}
}

// queryA asks m's resolver over UDP for the A records of name, as a stub
// resolver would, and returns the response code and the addresses answered.
func queryA(t *testing.T, m *Manager, name string) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	conn, err := net.DialTimeout("udp", m.Addr().String(), ioTimeout)
	if err != nil {
		t.Fatalf("dial udp %s: %v", m.Addr(), err)
	}
	defer func() { _ = conn.Close() }()
	resp := parseResponse(t, exchangeUDP(t, conn, newQuery(t, 0x6d64, name+".", dnsmessage.TypeA)))
	var addrs []netip.Addr
	for _, rr := range resp.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			addrs = append(addrs, netip.AddrFrom4(a.A))
		}
	}
	return resp.RCode, addrs
}

// wantAddr fails the test unless m's resolver answers name with addr alone.
func wantAddr(t *testing.T, m *Manager, name, addr string) {
	t.Helper()
	rcode, addrs := queryA(t, m, name)
	want := []netip.Addr{netip.MustParseAddr(addr)}
	if rcode != dnsmessage.RCodeSuccess || !slices.Equal(addrs, want) {
		t.Errorf("query %s A = %v %v, want %v %v", name, rcode, addrs, dnsmessage.RCodeSuccess, want)
	}
}

// wantRCode fails the test unless m's resolver answers name with rcode and
// no address.
func wantRCode(t *testing.T, m *Manager, name string, rcode dnsmessage.RCode) {
	t.Helper()
	got, addrs := queryA(t, m, name)
	if got != rcode || len(addrs) != 0 {
		t.Errorf("query %s A = %v %v, want %v and no address", name, got, addrs, rcode)
	}
}

func TestManager_HandleBlock(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	wantRCode(t, m, "db-1.openstack.lab.internal", dnsmessage.RCodeRefused)

	m.Handle(ctx, snapshot(exampleBlock()))

	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")
	wantMethods(t, reg, "Apply")
	if m.Addr().Port() == 0 {
		t.Fatalf("Addr() = %v, want the port the kernel picked", m.Addr())
	}
	want := Registration{
		Interface:      testIface,
		Server:         m.Addr(),
		SearchDomain:   "openstack.lab.internal",
		RoutingDomains: []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"},
	}
	calls := reg.recorded()
	if !calls[0].reg.Equal(want) {
		t.Errorf("Apply(%+v), want Apply(%+v)", calls[0].reg, want)
	}
	checkBounded(t, calls[0])
	wantLine(t, logs, slog.LevelInfo, msgUpdated, map[string]string{
		"hosts":         "3",
		"records":       "6",
		"zones":         "3",
		"reverse_zones": "1",
		"search_domain": "openstack.lab.internal",
	})
	wantLine(t, logs, slog.LevelInfo, msgRegistered, map[string]string{
		"interface":       testIface,
		"server":          m.Addr().String(),
		"search_domain":   "openstack.lab.internal",
		"routing_domains": "3",
	})

	// The next pull decodes a block of its own, equal to the first.
	m.Handle(ctx, snapshot(exampleBlock()))

	wantMethods(t, reg, "Apply")
	wantCount(t, logs, msgUpdated, 1)
	wantCount(t, logs, msgRegistered, 1)
	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")
}

func TestManager_HandleNilSnapshot(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)

	m.Handle(context.Background(), nil)

	wantMethods(t, reg)
	if got := logs.all(); len(got) != 0 {
		t.Errorf("Handle(nil) logged %d lines, want none: %+v", len(got), got)
	}
}

func TestManager_HandleWithoutDNSBlock(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(exampleBlock()))
	for range 3 {
		m.Handle(ctx, &api.NodeStateSnapshot{})
	}

	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")
	wantMethods(t, reg, "Apply")
	wantLine(t, logs, slog.LevelInfo, msgNoBlock, nil)

	// A block in between makes the next pull without one log again.
	m.Handle(ctx, snapshot(exampleBlock()))
	m.Handle(ctx, &api.NodeStateSnapshot{})
	m.Handle(ctx, &api.NodeStateSnapshot{})

	wantCount(t, logs, msgNoBlock, 2)
	wantMethods(t, reg, "Apply")
	wantAddr(t, m, "web.openstack.lab.internal", "10.42.0.2")
}

func TestManager_HandleWithoutDNSBlockBeforeFirst(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)

	m.Handle(context.Background(), &api.NodeStateSnapshot{})
	m.Handle(context.Background(), &api.NodeStateSnapshot{})

	wantLine(t, logs, slog.LevelInfo, msgNoBlock, nil)
	wantMethods(t, reg)
	wantRCode(t, m, "db-1.openstack.lab.internal", dnsmessage.RCodeRefused)
}

func TestManager_HandleRenamedHost(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(exampleBlock()))
	renamed := exampleBlock()
	renamed.Hosts[0].FQDN = "db-2.openstack.lab.internal"
	m.Handle(ctx, snapshot(renamed))

	wantAddr(t, m, "db-2.openstack.lab.internal", "10.42.0.3")
	wantRCode(t, m, "db-1.openstack.lab.internal", dnsmessage.RCodeNameError)
	wantMethods(t, reg, "Apply")
	wantCount(t, logs, msgUpdated, 2)
}

func TestManager_AppliesOnlyWhenRegistrationChanges(t *testing.T) {
	tests := []struct {
		name      string
		change    func(*api.NodeStateDNS)
		wantApply bool
	}{
		{"host renamed", func(b *api.NodeStateDNS) { b.Hosts[0].FQDN = "db-2.openstack.lab.internal" }, false},
		{"host moved to another address", func(b *api.NodeStateDNS) { b.Hosts[0].MeshIP = "10.42.0.4" }, false},
		{"host added", func(b *api.NodeStateDNS) {
			b.Hosts = append(b.Hosts, api.NodeStateDNSHost{NodeID: "n-new", FQDN: "new.lab.internal", MeshIP: "10.42.0.7"})
		}, false},
		{"host removed", func(b *api.NodeStateDNS) { b.Hosts = b.Hosts[1:] }, false},
		// lab.internal already routes every name below it.
		{"zone added below a routed zone", func(b *api.NodeStateDNS) { b.Zones = append(b.Zones, "rack.lab.internal") }, false},
		{"zone added", func(b *api.NodeStateDNS) { b.Zones = append(b.Zones, "ops.example.net") }, true},
		// The zone goes with its host and its record, as the control plane
		// removes them, so the block stays one without skipped entries.
		{"zone removed", func(b *api.NodeStateDNS) {
			b.Zones = b.Zones[1:]
			b.Hosts = slices.DeleteFunc(b.Hosts, func(h api.NodeStateDNSHost) bool { return h.FQDN == "gw.edge.example.com" })
			b.Records = slices.DeleteFunc(b.Records, func(r api.NodeStateDNSRecord) bool { return r.FQDN == "edge.example.com" })
		}, true},
		{"reverse zone added", func(b *api.NodeStateDNS) { b.ReverseZones = append(b.ReverseZones, "43.10.in-addr.arpa") }, true},
		{"search domain changed", func(b *api.NodeStateDNS) { b.SearchDomain = "lab.internal" }, true},
		{"search domain dropped", func(b *api.NodeStateDNS) { b.SearchDomain = "" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeRegistrar{}
			m, logs := newTestManager(t, reg)
			ctx := context.Background()

			m.Handle(ctx, snapshot(exampleBlock()))
			changed := exampleBlock()
			tc.change(&changed)
			m.Handle(ctx, snapshot(changed))

			wantCount(t, logs, msgUpdated, 2)
			if !tc.wantApply {
				wantMethods(t, reg, "Apply")
				return
			}
			wantMethods(t, reg, "Apply", "Apply")
			want := mustBuild(t, changed).Registration(testIface, m.Addr(), nil)
			if got := reg.recorded()[1].reg; !got.Equal(want) {
				t.Errorf("second Apply(%+v), want Apply(%+v)", got, want)
			}
			wantCount(t, logs, msgRegistered, 2)
		})
	}
}

func TestManager_HandleEmptyBlockReverts(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(exampleBlock()))
	m.Handle(ctx, snapshot(emptyBlock()))

	wantMethods(t, reg, "Apply", "Revert")
	revert := reg.recorded()[1]
	if revert.iface != testIface {
		t.Errorf("Revert(%q), want Revert(%q)", revert.iface, testIface)
	}
	checkBounded(t, revert)
	wantRCode(t, m, "db-1.openstack.lab.internal", dnsmessage.RCodeRefused)
	wantCount(t, logs, msgUpdated, 2)

	// Nothing counts as applied any more, so a further empty block calls
	// nothing, and a block with names applies again.
	m.Handle(ctx, snapshot(emptyBlock()))
	wantMethods(t, reg, "Apply", "Revert")
	m.Handle(ctx, snapshot(exampleBlock()))
	wantMethods(t, reg, "Apply", "Revert", "Apply")
	wantCount(t, logs, msgFailed, 0)
}

func TestManager_HandleEmptyBlockWithoutRegistration(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)

	m.Handle(context.Background(), snapshot(emptyBlock()))

	wantMethods(t, reg)
	// The first block counts as a change even when it holds no names.
	wantLine(t, logs, slog.LevelInfo, msgUpdated, map[string]string{
		"hosts":         "0",
		"zones":         "0",
		"reverse_zones": "0",
		"search_domain": "",
	})
}

func TestManager_EmptyBlockRevertFails(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)
	ctx := context.Background()
	denied := errors.New("meshdns: resolved: RevertLink: org.freedesktop.DBus.Error.AccessDenied: access denied")

	m.Handle(ctx, snapshot(exampleBlock()))
	reg.setRevertErr(denied)
	m.Handle(ctx, snapshot(emptyBlock()))
	m.Handle(ctx, snapshot(emptyBlock()))

	// The registration still counts as applied, so each pull reverts again,
	// and the failure is logged once for its text.
	wantMethods(t, reg, "Apply", "Revert", "Revert")
	wantLine(t, logs, slog.LevelWarn, msgFailed, map[string]string{"error": denied.Error()})

	reg.setRevertErr(nil)
	m.Handle(ctx, snapshot(emptyBlock()))
	m.Handle(ctx, snapshot(emptyBlock()))
	wantMethods(t, reg, "Apply", "Revert", "Revert", "Revert")
}

func TestManager_EmptyBlockAfterFailedApplyReverts(t *testing.T) {
	denied := errors.New("meshdns: resolved: SetLinkDefaultRoute: org.freedesktop.DBus.Error.AccessDenied: access denied")
	tests := []struct {
		name string
		err  error
	}{
		{"systemd-resolved unavailable", errUnavailableTest},
		{"call refused", denied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeRegistrar{}
			m, _ := newTestManager(t, reg)
			ctx := context.Background()

			m.Handle(ctx, snapshot(exampleBlock()))
			// The failed Apply leaves nothing counted as applied, but the link
			// may still carry the earlier registration or part of the new one.
			reg.setApplyErr(tc.err)
			changed := exampleBlock()
			changed.Zones = append(changed.Zones, "ops.example.net")
			m.Handle(ctx, snapshot(changed))
			wantMethods(t, reg, "Apply", "Apply")

			reg.setApplyErr(nil)
			m.Handle(ctx, snapshot(emptyBlock()))
			wantMethods(t, reg, "Apply", "Apply", "Revert")
			if calls := reg.recorded(); len(calls) == 3 {
				if calls[2].iface != testIface {
					t.Errorf("Revert(%q), want Revert(%q)", calls[2].iface, testIface)
				}
				checkBounded(t, calls[2])
			}

			// The revert cleared the link, so a further empty block calls
			// nothing.
			m.Handle(ctx, snapshot(emptyBlock()))
			wantMethods(t, reg, "Apply", "Apply", "Revert")
		})
	}
}

func TestManager_EmptyBlockAfterFirstApplyFails(t *testing.T) {
	noReply := errors.New("meshdns: resolved: SetLinkDNSEx: org.freedesktop.DBus.Error.NoReply: did not receive a reply")
	denied := errors.New("meshdns: resolved: RevertLink: org.freedesktop.DBus.Error.AccessDenied: access denied")
	reg := &fakeRegistrar{applyErr: noReply}
	m, _ := newTestManager(t, reg)
	ctx := context.Background()

	// No Apply ever succeeded, but the failed one may have reached the link
	// with its first calls, so an empty block reverts, and a failed revert
	// is retried on the next pull.
	m.Handle(ctx, snapshot(exampleBlock()))
	reg.setRevertErr(denied)
	m.Handle(ctx, snapshot(emptyBlock()))
	m.Handle(ctx, snapshot(emptyBlock()))
	wantMethods(t, reg, "Apply", "Revert", "Revert")

	reg.setRevertErr(nil)
	m.Handle(ctx, snapshot(emptyBlock()))
	m.Handle(ctx, snapshot(emptyBlock()))
	wantMethods(t, reg, "Apply", "Revert", "Revert", "Revert")
}

func TestManager_ApplyUnavailable(t *testing.T) {
	reg := &fakeRegistrar{applyErr: errUnavailableTest}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	for range 3 {
		m.Handle(ctx, snapshot(exampleBlock()))
	}

	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")
	wantMethods(t, reg, "Apply", "Apply", "Apply")
	wantLine(t, logs, slog.LevelInfo, msgUnavailable, map[string]string{
		"listen": m.Addr().String(),
		"reason": errUnavailableTest.Error(),
	})
	wantCount(t, logs, msgRegistered, 0)
	wantCount(t, logs, msgFailed, 0)

	// systemd-resolved started: the next pull registers, the one after it
	// has nothing to do.
	reg.setApplyErr(nil)
	m.Handle(ctx, snapshot(exampleBlock()))
	m.Handle(ctx, snapshot(exampleBlock()))

	wantMethods(t, reg, "Apply", "Apply", "Apply", "Apply")
	wantLine(t, logs, slog.LevelInfo, msgRegistered, map[string]string{
		"interface": testIface,
		"server":    m.Addr().String(),
	})

	// The success reset the tracker, so the next change into the state is
	// logged again.
	reg.setApplyErr(errUnavailableTest)
	changed := exampleBlock()
	changed.SearchDomain = "lab.internal"
	m.Handle(ctx, snapshot(changed))
	wantCount(t, logs, msgUnavailable, 2)
}

func TestManager_ApplyFailure(t *testing.T) {
	errBusy := errors.New("meshdns: resolved: SetLinkDomains: org.freedesktop.resolve1.LinkBusy: Link plexd-test0 is managed")
	errDeadline := fmt.Errorf("meshdns: resolved: SetLinkDNSOverTLS: %w", context.DeadlineExceeded)

	// Each step is one pull of the same block, answered with err.
	steps := []struct {
		err         error
		wantApplies int
		wantWarns   int
		wantInfos   int
	}{
		{errBusy, 1, 1, 0},
		{errBusy, 2, 1, 0},
		{errDeadline, 3, 2, 0},
		{errDeadline, 4, 2, 0},
		// The text differs from the one logged last.
		{errBusy, 5, 3, 0},
		// Leaving the failure for the unavailable state and coming back is a
		// change too.
		{errUnavailableTest, 6, 3, 1},
		{errBusy, 7, 4, 1},
		{nil, 8, 4, 1},
		{nil, 8, 4, 1},
	}

	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)
	for i, step := range steps {
		reg.setApplyErr(step.err)
		m.Handle(context.Background(), snapshot(exampleBlock()))

		if got := reg.count("Apply"); got != step.wantApplies {
			t.Errorf("step %d (%v): %d Apply calls, want %d", i, step.err, got, step.wantApplies)
		}
		if got := logs.count(msgFailed); got != step.wantWarns {
			t.Errorf("step %d (%v): %d lines say %q, want %d", i, step.err, got, msgFailed, step.wantWarns)
		}
		if got := logs.count(msgUnavailable); got != step.wantInfos {
			t.Errorf("step %d (%v): %d lines say %q, want %d", i, step.err, got, msgUnavailable, step.wantInfos)
		}
	}

	var texts []string
	for _, e := range logs.find(msgFailed) {
		if e.level != slog.LevelWarn {
			t.Errorf("%q logged at %v, want %v", msgFailed, e.level, slog.LevelWarn)
		}
		texts = append(texts, e.attrs["error"].String())
	}
	wantTexts := []string{errBusy.Error(), errDeadline.Error(), errBusy.Error(), errBusy.Error()}
	if !slices.Equal(texts, wantTexts) {
		t.Errorf("%q errors = %q, want %q", msgFailed, texts, wantTexts)
	}
	wantCount(t, logs, msgRegistered, 1)
	if reg.count("Revert") != 0 {
		t.Errorf("registrar calls = %q, want no Revert: the registrar cleans up a failed Apply itself", reg.methods())
	}
}

func TestManager_LogsSkippedEntries(t *testing.T) {
	sevenBadZones := exampleBlock()
	sevenBadZones.Zones = append(sevenBadZones.Zones, "", "local", "printer.local", "localhost", "arpa", "10.in-addr.arpa", "bad..zone")
	twoBad := exampleBlock()
	twoBad.ReverseZones = append(twoBad.ReverseZones, "lab.internal")
	twoBad.Hosts = append(twoBad.Hosts, api.NodeStateDNSHost{NodeID: "n-bad-ip", FQDN: "bad-ip.lab.internal", MeshIP: "not-an-ip"})

	tests := []struct {
		name      string
		block     api.NodeStateDNS
		wantCount int
		wantShown int
	}{
		{"more than five", sevenBadZones, 7, 5},
		{"fewer than five", twoBad, 2, 2},
		{"none", exampleBlock(), 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeRegistrar{}
			m, logs := newTestManager(t, reg)

			m.Handle(context.Background(), snapshot(tc.block))

			_, sentences := BuildRecords(tc.block)
			if len(sentences) != tc.wantCount {
				t.Fatalf("BuildRecords skipped %d entries, want %d: %q", len(sentences), tc.wantCount, sentences)
			}
			if tc.wantCount == 0 {
				wantCount(t, logs, msgSkipped, 0)
				return
			}
			wantLine(t, logs, slog.LevelWarn, msgSkipped, map[string]string{"count": fmt.Sprint(tc.wantCount)})
			got, ok := logs.find(msgSkipped)[0].attrs["skipped"].Any().([]string)
			if !ok {
				t.Fatalf("%q has skipped=%v, want a list of sentences", msgSkipped, logs.find(msgSkipped)[0].attrs["skipped"])
			}
			if want := sentences[:tc.wantShown]; !slices.Equal(got, want) {
				t.Errorf("%q has skipped=%q, want %q", msgSkipped, got, want)
			}
			// The valid entries are answered and registered all the same.
			wantMethods(t, reg, "Apply")
		})
	}
}

func TestManager_Shutdown(t *testing.T) {
	tests := []struct {
		name     string
		applyErr error
		pulls    int
		before   []string
	}{
		{"after a successful apply", nil, 1, []string{"Apply"}},
		{"after a failed apply", errors.New("meshdns: resolved: SetLinkDomains: org.freedesktop.resolve1.LinkBusy"), 1, []string{"Apply"}},
		{"on a host without systemd-resolved", errUnavailableTest, 1, []string{"Apply"}},
		{"without any pull", nil, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeRegistrar{applyErr: tc.applyErr}
			m, logs := newTestManager(t, reg)
			for range tc.pulls {
				m.Handle(context.Background(), snapshot(exampleBlock()))
			}

			if err := m.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown() = %v, want nil", err)
			}

			wantMethods(t, reg, append(tc.before, "Revert")...)
			if got := reg.recorded()[len(tc.before)].iface; got != testIface {
				t.Errorf("Revert(%q), want Revert(%q)", got, testIface)
			}
			wantLine(t, logs, slog.LevelInfo, msgReverted, nil)
		})
	}
}

func TestManager_ShutdownRevertError(t *testing.T) {
	denied := errors.New("meshdns: resolved: RevertLink: org.freedesktop.DBus.Error.AccessDenied: access denied")
	reg := &fakeRegistrar{revertErr: denied}
	m, logs := newTestManager(t, reg)
	m.Handle(context.Background(), snapshot(exampleBlock()))

	err := m.Shutdown(context.Background())

	if !errors.Is(err, denied) {
		t.Errorf("Shutdown() = %v, want an error wrapping %v", err, denied)
	}
	if want := "meshdns: shutdown: " + denied.Error(); err == nil || err.Error() != want {
		t.Errorf("Shutdown() = %v, want %q", err, want)
	}
	wantMethods(t, reg, "Apply", "Revert")
	wantCount(t, logs, msgReverted, 0)
}

func TestManager_HandleAfterShutdown(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() = %v, want nil", err)
	}
	m.Handle(ctx, snapshot(exampleBlock()))
	m.Handle(ctx, &api.NodeStateSnapshot{})

	wantMethods(t, reg, "Revert")
	wantCount(t, logs, msgUpdated, 0)
	wantCount(t, logs, msgNoBlock, 0)
	wantRCode(t, m, "db-1.openstack.lab.internal", dnsmessage.RCodeRefused)
}

func TestManager_HandleRacingShutdown(t *testing.T) {
	reg := &fakeRegistrar{}
	m, _ := newTestManager(t, reg)
	// Two blocks whose registrations differ, so every pull applies.
	blocks := [2]api.NodeStateDNS{exampleBlock(), exampleBlock()}
	blocks[1].SearchDomain = "lab.internal"

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			<-start
			for j := range 20 {
				m.Handle(context.Background(), snapshot(blocks[(i+j)%2]))
			}
		})
	}
	close(start)
	if err := m.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() = %v, want nil", err)
	}
	wg.Wait()

	// Whatever ran before the shutdown, nothing registered after its revert.
	methods := reg.methods()
	if reg.count("Revert") != 1 || methods[len(methods)-1] != "Revert" {
		t.Errorf("registrar calls = %q, want the shutdown's Revert once and last", methods)
	}
}

func TestManager_HandleWithDoneContext(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)
	done, cancel := context.WithCancel(context.Background())
	cancel()

	// A pull racing the shutdown takes the records but leaves the link
	// alone.
	m.Handle(done, snapshot(exampleBlock()))
	wantMethods(t, reg)
	wantCount(t, logs, msgUpdated, 1)

	// Nothing counted as applied, so a live pull of the same block applies.
	m.Handle(context.Background(), snapshot(exampleBlock()))
	wantMethods(t, reg, "Apply")

	m.Handle(done, snapshot(emptyBlock()))
	wantMethods(t, reg, "Apply")
}

func TestManager_StartAddressInUse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a UDP port: %v", err)
	}
	defer func() { _ = pc.Close() }()
	addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()

	m := NewManager(Config{ListenPort: int(addr.Port())}, testIface, addr.Addr(), &fakeRegistrar{}, slog.New(slog.DiscardHandler))

	if err := m.Start(); !errors.Is(err, errAddrInUse) {
		t.Errorf("Start() = %v, want an error wrapping %v", err, errAddrInUse)
	}
	if got := m.Addr(); got != addr {
		t.Errorf("Addr() = %v, want %v, the address the bind was refused", got, addr)
	}
}

func TestManager_HandleChangedRecord(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := startManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(exampleBlock()))
	wantAddr(t, m, "db.lab.internal", "10.20.0.5")
	changed := exampleBlock()
	i := slices.IndexFunc(changed.Records, func(r api.NodeStateDNSRecord) bool { return r.FQDN == "db.lab.internal" && r.Type == "A" })
	changed.Records[i].Address = "10.20.0.6"
	m.Handle(ctx, snapshot(changed))

	// The records changed and the registration did not, so the line logs
	// again and the system resolver hears nothing.
	wantAddr(t, m, "db.lab.internal", "10.20.0.6")
	wantCount(t, logs, msgUpdated, 2)
	wantMethods(t, reg, "Apply")
}

func TestManager_RecordsFollowTheBlock(t *testing.T) {
	reg := &fakeRegistrar{}
	m, _ := startManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(exampleBlock()))
	// A pull without a dns block keeps the records with the names.
	m.Handle(ctx, &api.NodeStateSnapshot{})
	wantAddr(t, m, "db.lab.internal", "10.20.0.5")

	// A block without records has none: the block is the full set.
	without := exampleBlock()
	without.Records = nil
	m.Handle(ctx, snapshot(without))
	wantRCode(t, m, "db.lab.internal", dnsmessage.RCodeNameError)
	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")
}

func TestManager_LogsSkippedRecord(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)
	block := exampleBlock()
	block.Records = append(block.Records, api.NodeStateDNSRecord{FQDN: "bad.lab.internal", Type: "A", Address: "fd00::1"})

	m.Handle(context.Background(), snapshot(block))

	wantLine(t, logs, slog.LevelWarn, msgSkipped, map[string]string{"count": "1"})
	got, _ := logs.find(msgSkipped)[0].attrs["skipped"].Any().([]string)
	want := []string{`record "bad.lab.internal" of type "A" has address "fd00::1", which is not an IPv4 address`}
	if !slices.Equal(got, want) {
		t.Errorf("%q has skipped=%q, want %q", msgSkipped, got, want)
	}
	wantLine(t, logs, slog.LevelInfo, msgUpdated, map[string]string{"records": "6"})
}

// The manager's forwarding lines, spelled out as the others are.
const (
	msgForwarding = "mesh dns forwarding updated"
	msgNoMember   = "dns block carries no forwarding member, keeping the forwarding held"
)

// fwdResolver is the resolver of the manager tests' forward zone and
// catch-all, and fwdAnswer the address the fake behind it answers.
const (
	fwdResolver = "192.0.2.1"
	fwdAnswer   = "198.51.100.53"
)

// startForwardingManager returns a started test manager whose resolver sends
// every query for fwdResolver to a fake that answers fwdAnswer, and that fake.
func startForwardingManager(t *testing.T, reg *fakeRegistrar) (*Manager, *logRecorder, *fakeResolver) {
	t.Helper()
	fake := newFakeResolver(t, answerA(fwdAnswer))
	m, logs := startManager(t, reg, func(m *Manager) {
		m.server.upstream.target = routeFakes(t, map[string]*fakeResolver{fwdResolver: fake})
	})
	return m, logs, fake
}

// withForwarding returns block with a forwarding member of zones and
// catchAll. Nil lists go out as empty ones, as the control plane sends them.
func withForwarding(block api.NodeStateDNS, zones []api.NodeStateDNSForwardZone, catchAll ...string) api.NodeStateDNS {
	if zones == nil {
		zones = []api.NodeStateDNSForwardZone{}
	}
	if catchAll == nil {
		catchAll = []string{}
	}
	block.Forwarding = &api.NodeStateDNSForwarding{ForwardZones: zones, CatchAll: catchAll}
	return block
}

// corpZone is the forward zone corp.example.com on fwdResolver.
func corpZone() []api.NodeStateDNSForwardZone {
	return []api.NodeStateDNSForwardZone{fwdZone("corp.example.com", fwdResolver)}
}

// exampleDomains are the routing domains of exampleBlock.
var exampleDomains = []string{"edge.example.com", "lab.internal", "42.10.in-addr.arpa"}

// wantLastLine fails the test unless the last record that says msg carries
// every attribute of attrs rendered as given.
func wantLastLine(t *testing.T, logs *logRecorder, msg string, attrs map[string]string) {
	t.Helper()
	found := logs.find(msg)
	if len(found) == 0 {
		t.Errorf("no line says %q, want one", msg)
		return
	}
	last := found[len(found)-1]
	for k, want := range attrs {
		if got := last.attrs[k].String(); got != want {
			t.Errorf("last %q has %s=%q, want %q", msg, k, got, want)
		}
	}
}

func TestManager_HandleForwarding(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs, fake := startForwardingManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), corpZone())))

	wantAddr(t, m, "host.corp.example.com", fwdAnswer)
	wantRCode(t, m, "example.org", dnsmessage.RCodeRefused)
	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")
	if got := fake.count(); got != 1 {
		t.Errorf("the resolver received %d queries, want 1", got)
	}
	wantMethods(t, reg, "Apply")
	want := Registration{
		Interface:      testIface,
		Server:         m.Addr(),
		SearchDomain:   "openstack.lab.internal",
		RoutingDomains: append(slices.Clone(exampleDomains), "corp.example.com"),
	}
	if got := reg.recorded()[0].reg; !got.Equal(want) {
		t.Errorf("Apply(%+v), want Apply(%+v)", got, want)
	}
	wantLine(t, logs, slog.LevelInfo, msgForwarding, map[string]string{"forward_zones": "1", "catch_all": "0"})
	wantLine(t, logs, slog.LevelInfo, msgRegistered, map[string]string{"routing_domains": "4", "default_route": "false"})

	// The same block again changes nothing.
	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), corpZone())))
	wantMethods(t, reg, "Apply")
	wantCount(t, logs, msgForwarding, 1)
	wantCount(t, logs, msgNoMember, 0)
}

func TestManager_HandleKeepsForwarding(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs, _ := startForwardingManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), corpZone(), fwdResolver)))
	wantMethods(t, reg, "Apply")

	// Two blocks without the member and a pull without a block keep the
	// table and the registration.
	m.Handle(ctx, snapshot(exampleBlock()))
	m.Handle(ctx, snapshot(exampleBlock()))
	m.Handle(ctx, &api.NodeStateSnapshot{})

	wantMethods(t, reg, "Apply")
	wantLine(t, logs, slog.LevelInfo, msgNoMember, nil)
	wantCount(t, logs, msgForwarding, 1)
	wantAddr(t, m, "host.corp.example.com", fwdAnswer)
	wantAddr(t, m, "example.org", fwdAnswer)
	wantAddr(t, m, "db-1.openstack.lab.internal", "10.42.0.3")

	// A member in between makes the next block without one log again.
	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), corpZone(), fwdResolver)))
	m.Handle(ctx, snapshot(exampleBlock()))
	wantCount(t, logs, msgNoMember, 2)
	wantMethods(t, reg, "Apply")
}

// Only a kept member is worth the line: a node that never got one has
// nothing to keep.
func TestManager_HandleWithoutMemberBeforeFirst(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs, fake := startForwardingManager(t, reg)

	m.Handle(context.Background(), snapshot(exampleBlock()))
	m.Handle(context.Background(), snapshot(exampleBlock()))

	wantCount(t, logs, msgNoMember, 0)
	wantCount(t, logs, msgForwarding, 0)
	wantRCode(t, m, "example.org", dnsmessage.RCodeRefused)
	if got := fake.count(); got != 0 {
		t.Errorf("the resolver received %d queries, want none", got)
	}
}

func TestManager_HandleForwardingRemoved(t *testing.T) {
	t.Run("mesh zones left", func(t *testing.T) {
		reg := &fakeRegistrar{}
		m, logs, _ := startForwardingManager(t, reg)
		ctx := context.Background()

		m.Handle(ctx, snapshot(withForwarding(exampleBlock(), corpZone(), fwdResolver)))
		wantAddr(t, m, "host.corp.example.com", fwdAnswer)
		if got := reg.recorded()[0].reg; !got.DefaultRoute || !slices.Contains(got.RoutingDomains, "corp.example.com") {
			t.Errorf("Apply(%+v), want corp.example.com among the routing domains and DefaultRoute", got)
		}

		m.Handle(ctx, snapshot(withForwarding(exampleBlock(), nil)))

		wantMethods(t, reg, "Apply", "Apply")
		want := Registration{
			Interface:      testIface,
			Server:         m.Addr(),
			SearchDomain:   "openstack.lab.internal",
			RoutingDomains: exampleDomains,
		}
		if got := reg.recorded()[1].reg; !got.Equal(want) {
			t.Errorf("second Apply(%+v), want Apply(%+v)", got, want)
		}
		wantRCode(t, m, "host.corp.example.com", dnsmessage.RCodeRefused)
		wantRCode(t, m, "example.org", dnsmessage.RCodeRefused)
		wantCount(t, logs, msgForwarding, 2)
		wantLastLine(t, logs, msgForwarding, map[string]string{"forward_zones": "0", "catch_all": "0"})
		wantLastLine(t, logs, msgRegistered, map[string]string{"default_route": "false"})
	})

	t.Run("no mesh zone left", func(t *testing.T) {
		reg := &fakeRegistrar{}
		m, _, _ := startForwardingManager(t, reg)
		ctx := context.Background()

		m.Handle(ctx, snapshot(withForwarding(emptyBlock(), corpZone())))
		wantMethods(t, reg, "Apply")
		if got, want := reg.recorded()[0].reg.RoutingDomains, []string{"corp.example.com"}; !slices.Equal(got, want) {
			t.Errorf("Apply with routing domains %q, want %q", got, want)
		}
		wantAddr(t, m, "host.corp.example.com", fwdAnswer)

		m.Handle(ctx, snapshot(withForwarding(emptyBlock(), nil)))
		wantMethods(t, reg, "Apply", "Revert")
		wantRCode(t, m, "host.corp.example.com", dnsmessage.RCodeRefused)
	})
}

func TestManager_MeshZoneShadowsKeptForwardZone(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs, fake := startForwardingManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), corpZone())))
	wantAddr(t, m, "host.corp.example.com", fwdAnswer)
	asked := fake.count()

	// The next block makes corp.example.com a mesh zone and says nothing
	// about forwarding.
	block := exampleBlock()
	block.Zones = append(block.Zones, "corp.example.com")
	block.Hosts = append(block.Hosts, api.NodeStateDNSHost{NodeID: "n-corp", FQDN: "host.corp.example.com", MeshIP: "10.42.0.77"})
	m.Handle(ctx, snapshot(block))

	wantAddr(t, m, "host.corp.example.com", "10.42.0.77")
	if got := fake.count(); got != asked {
		t.Errorf("the resolver received %d more queries, want none", got-asked)
	}
	wantLine(t, logs, slog.LevelWarn, msgSkipped, map[string]string{"count": "1"})
	got, _ := logs.find(msgSkipped)[0].attrs["skipped"].Any().([]string)
	want := []string{`forward zone "corp.example.com" is shadowed by the mesh zone "corp.example.com", which answers its names`}
	if !slices.Equal(got, want) {
		t.Errorf("%q has skipped=%q, want %q", msgSkipped, got, want)
	}
	wantCount(t, logs, msgNoMember, 1)
	wantLastLine(t, logs, msgForwarding, map[string]string{"forward_zones": "0", "catch_all": "0"})
	// corp.example.com is a mesh zone now, listed with the others and no
	// longer as a forward zone after them.
	wantMethods(t, reg, "Apply", "Apply")
	if got, want := reg.recorded()[1].reg.RoutingDomains, []string{"corp.example.com", "edge.example.com", "lab.internal", "42.10.in-addr.arpa"}; !slices.Equal(got, want) {
		t.Errorf("second Apply with routing domains %q, want %q", got, want)
	}
}

// The sentences of both builds share the one line, the records' first.
func TestManager_LogsSkippedForwarding(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs := newTestManager(t, reg)
	block := withForwarding(exampleBlock(), []api.NodeStateDNSForwardZone{
		fwdZone("corp.example.com", fwdResolver, "127.0.0.53"),
	}, "not-an-ip")
	block.Zones = append(block.Zones, "localhost")

	m.Handle(context.Background(), snapshot(block))

	wantLine(t, logs, slog.LevelWarn, msgSkipped, map[string]string{"count": "3"})
	got, _ := logs.find(msgSkipped)[0].attrs["skipped"].Any().([]string)
	want := []string{
		`zone "localhost" is localhost itself, which the contract rules out`,
		`resolver "127.0.0.53" of forward zone "corp.example.com" is not an address plexd forwards to`,
		`resolver "not-an-ip" of the catch-all is not an IP address`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q has skipped=%q, want %q", msgSkipped, got, want)
	}
	wantLine(t, logs, slog.LevelInfo, msgForwarding, map[string]string{"forward_zones": "1", "catch_all": "0"})
}

func TestManager_FirstBlockWithoutForwarding(t *testing.T) {
	reg := &fakeRegistrar{}
	m, logs, _ := startForwardingManager(t, reg)
	ctx := context.Background()

	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), nil)))

	wantCount(t, logs, msgForwarding, 0)
	wantLine(t, logs, slog.LevelInfo, msgRegistered, map[string]string{"default_route": "false"})

	// A catch-all makes the link the default route.
	m.Handle(ctx, snapshot(withForwarding(exampleBlock(), nil, fwdResolver)))
	wantMethods(t, reg, "Apply", "Apply")
	if got := reg.recorded()[1].reg; !got.DefaultRoute || !slices.Equal(got.RoutingDomains, exampleDomains) {
		t.Errorf("second Apply(%+v), want DefaultRoute and the mesh domains only", got)
	}
	wantLastLine(t, logs, msgRegistered, map[string]string{"default_route": "true"})
	wantLine(t, logs, slog.LevelInfo, msgForwarding, map[string]string{"forward_zones": "0", "catch_all": "1"})
}

func TestManager_ApplyFailsWithCatchAll(t *testing.T) {
	denied := errors.New("meshdns: resolved: SetLinkDomains: org.freedesktop.DBus.Error.AccessDenied: access denied")
	reg := &fakeRegistrar{applyErr: denied}
	m, logs, fake := startForwardingManager(t, reg)
	ctx := context.Background()
	block := withForwarding(exampleBlock(), nil, fwdResolver)

	m.Handle(ctx, snapshot(block))

	wantMethods(t, reg, "Apply")
	if !reg.recorded()[0].reg.DefaultRoute {
		t.Errorf("Apply(%+v), want DefaultRoute", reg.recorded()[0].reg)
	}
	wantLine(t, logs, slog.LevelWarn, msgFailed, map[string]string{"error": denied.Error()})
	// The resolver forwards meanwhile.
	wantAddr(t, m, "example.org", fwdAnswer)
	if got := fake.count(); got != 1 {
		t.Errorf("the resolver received %d queries, want 1", got)
	}

	reg.setApplyErr(nil)
	m.Handle(ctx, snapshot(block))
	m.Handle(ctx, snapshot(block))

	wantMethods(t, reg, "Apply", "Apply")
	if !reg.recorded()[1].reg.DefaultRoute {
		t.Errorf("second Apply(%+v), want DefaultRoute", reg.recorded()[1].reg)
	}
	wantLine(t, logs, slog.LevelInfo, msgRegistered, map[string]string{"default_route": "true"})
	wantCount(t, logs, msgForwarding, 1)
}
