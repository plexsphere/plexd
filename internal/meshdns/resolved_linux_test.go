//go:build linux

package meshdns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// Compile-time check that ResolvedRegistrar is a Registrar the manager can
// drive.
var _ Registrar = (*ResolvedRegistrar)(nil)

// testLinkIndex is the index the fake interface table gives plexd0.
const testLinkIndex = 7

// The D-Bus error names the tests answer with beyond those the registrar
// itself names.
const (
	dbusErrLinkBusy     = "org.freedesktop.resolve1.LinkBusy"
	dbusErrAccessDenied = "org.freedesktop.DBus.Error.AccessDenied"
)

// probeMethod is the method the fake bus records for the property read Apply
// makes before it changes anything, and probeArgs are its arguments: the
// Manager interface and the property DNSEx.
const probeMethod = "org.freedesktop.DBus.Properties.Get"

var probeArgs = []any{"org.freedesktop.resolve1.Manager", "DNSEx"}

// resolvedSignatures holds the D-Bus signature of each method the registrar
// calls, as the systemd and D-Bus documentation give it.
var resolvedSignatures = map[string]string{
	probeMethod:           "ss",
	"SetLinkDefaultRoute": "ib",
	"SetLinkDomains":      "ia(sb)",
	"SetLinkDNSSEC":       "is",
	"SetLinkDNSOverTLS":   "is",
	"SetLinkLLMNR":        "is",
	"SetLinkMulticastDNS": "is",
	"SetLinkDNSEx":        "ia(iayqs)",
	"RevertLink":          "i",
}

// applyMethods is the order of Apply's calls: the probe, then the seven
// steps.
var applyMethods = []string{
	probeMethod,
	"SetLinkDefaultRoute",
	"SetLinkDomains",
	"SetLinkDNSSEC",
	"SetLinkDNSOverTLS",
	"SetLinkLLMNR",
	"SetLinkMulticastDNS",
	"SetLinkDNSEx",
}

// recordedBusCall is one call the fake bus received.
type recordedBusCall struct {
	method string
	args   []any
}

// fakeResolvedBus stands in for the system bus. It records every call that
// reached the bus, fails each method named in fail with its error, and counts
// the connections it opened and closed, so a test sees what Apply or Revert
// sent and that no connection outlived the call.
//
// It ends calls the way godbus v5.2.4 does, because the revert after a failed
// step depends on it: a call whose context is already done is never sent and
// returns ctx.Err(), and a connection closes once the context it was opened
// with ends, so every later call fails with dbus.ErrClosed. A fake that
// ignored the context would record a revert that never leaves plexd.
type fakeResolvedBus struct {
	connectErr error
	fail       map[string]error
	// block names a method that is sent and then answers only when its
	// context or the connection ends, like a call to a systemd-resolved that
	// has stalled.
	block string
	// blocked, when set, is closed once the call to block has been sent.
	blocked  chan struct{}
	calls    []recordedBusCall
	connects int
	closes   int
	// connCtx is the context the connection was opened with.
	connCtx context.Context
}

func (b *fakeResolvedBus) call(ctx context.Context, method string, args ...any) error {
	return b.send(ctx, method, args)
}

func (b *fakeResolvedBus) getProperty(ctx context.Context, property string) error {
	return b.send(ctx, probeMethod, []any{resolvedInterface, property})
}

func (b *fakeResolvedBus) send(ctx context.Context, method string, args []any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.connCtx.Err() != nil {
		return dbus.ErrClosed
	}
	b.calls = append(b.calls, recordedBusCall{method: method, args: args})
	if method != b.block {
		return b.fail[method]
	}
	if b.blocked != nil {
		close(b.blocked)
	}
	select {
	case <-ctx.Done():
	case <-b.connCtx.Done():
	}
	// When the call's context and the connection's end together, as when
	// they are the same context, godbus may report either. The fake reports
	// the call's own, so a test sees one answer.
	if err := ctx.Err(); err != nil {
		return err
	}
	return dbus.ErrClosed
}

func (b *fakeResolvedBus) connect(ctx context.Context) (caller, func() error, error) {
	b.connects++
	if b.connectErr != nil {
		return nil, nil, b.connectErr
	}
	b.connCtx = ctx
	return b, func() error {
		b.closes++
		return nil
	}, nil
}

// methods returns the names of the recorded calls in order.
func (b *fakeResolvedBus) methods() []string {
	var names []string
	for _, c := range b.calls {
		names = append(names, c.method)
	}
	return names
}

// checkClosed fails t unless every connection the fake handed out was
// closed again.
func (b *fakeResolvedBus) checkClosed(t *testing.T) {
	t.Helper()
	opened := b.connects
	if b.connectErr != nil {
		opened = 0
	}
	if b.closes != opened {
		t.Errorf("got %d closed connections, want %d", b.closes, opened)
	}
}

// newFakeResolved returns a registrar on bus whose interface table holds the
// loopback interface and plexd0 at testLinkIndex.
func newFakeResolved(bus *fakeResolvedBus) *ResolvedRegistrar {
	r := NewResolvedRegistrar(slog.New(slog.DiscardHandler))
	r.connect = bus.connect
	r.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "lo"},
			{Index: testLinkIndex, Name: "plexd0"},
		}, nil
	}
	return r
}

// noBusSocket is the error dbus.ConnectSystemBus returns on a host without a
// bus daemon.
func noBusSocket() error {
	return &net.OpError{
		Op:   "dial",
		Net:  "unix",
		Addr: &net.UnixAddr{Name: "/var/run/dbus/system_bus_socket", Net: "unix"},
		Err:  os.NewSyscallError("connect", syscall.ENOENT),
	}
}

// methodsUpTo returns Apply's methods up to and including method.
func methodsUpTo(t *testing.T, method string) []string {
	t.Helper()
	for i, m := range applyMethods {
		if m == method {
			return append([]string(nil), applyMethods[:i+1]...)
		}
	}
	t.Fatalf("%s is no method of Apply", method)
	return nil
}

func TestNewResolvedRegistrar(t *testing.T) {
	r := NewResolvedRegistrar(nil)
	if r == nil {
		t.Fatal("got a nil registrar, want one")
	}
	if r.logger == nil || r.connect == nil || r.interfaces == nil {
		t.Errorf("got logger set %t, connect set %t, interfaces set %t, want all set",
			r.logger != nil, r.connect != nil, r.interfaces != nil)
	}
}

func TestResolvedApplyCalls(t *testing.T) {
	tests := []struct {
		name    string
		reg     Registration
		domains []linkDomain
		server  linkDNSServer
	}{
		{
			name: "IPv4 server with search domain",
			reg: Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
				SearchDomain:   "app.e2e.internal",
				RoutingDomains: []string{"e2e.internal", "0.99.10.in-addr.arpa"},
			},
			domains: []linkDomain{
				{Domain: "app.e2e.internal", RoutingOnly: false},
				{Domain: "e2e.internal", RoutingOnly: true},
				{Domain: "0.99.10.in-addr.arpa", RoutingOnly: true},
			},
			server: linkDNSServer{Family: unix.AF_INET, Address: []byte{10, 99, 0, 1}, Port: 5354, Name: ""},
		},
		{
			name: "IPv6 server",
			reg: Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("[fd00:99::1]:5354"),
				SearchDomain:   "app.e2e.internal",
				RoutingDomains: []string{"0.9.0.0.0.0.d.f.ip6.arpa"},
			},
			domains: []linkDomain{
				{Domain: "app.e2e.internal", RoutingOnly: false},
				{Domain: "0.9.0.0.0.0.d.f.ip6.arpa", RoutingOnly: true},
			},
			server: linkDNSServer{
				Family:  unix.AF_INET6,
				Address: []byte{0xfd, 0x00, 0x00, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
				Port:    5354,
				Name:    "",
			},
		},
		{
			name: "no search domain",
			reg: Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
				RoutingDomains: []string{"e2e.internal", "0.99.10.in-addr.arpa"},
			},
			domains: []linkDomain{
				{Domain: "e2e.internal", RoutingOnly: true},
				{Domain: "0.99.10.in-addr.arpa", RoutingOnly: true},
			},
			server: linkDNSServer{Family: unix.AF_INET, Address: []byte{10, 99, 0, 1}, Port: 5354, Name: ""},
		},
		{
			name: "IPv4-mapped server goes out as IPv4",
			reg: Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("[::ffff:10.99.0.1]:5354"),
				RoutingDomains: []string{"e2e.internal"},
			},
			domains: []linkDomain{{Domain: "e2e.internal", RoutingOnly: true}},
			server:  linkDNSServer{Family: unix.AF_INET, Address: []byte{10, 99, 0, 1}, Port: 5354, Name: ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bus := &fakeResolvedBus{}
			if err := newFakeResolved(bus).Apply(context.Background(), tc.reg); err != nil {
				t.Fatalf("Apply: got %v, want nil", err)
			}
			index := int32(testLinkIndex)
			want := []recordedBusCall{
				{method: probeMethod, args: probeArgs},
				{method: "SetLinkDefaultRoute", args: []any{index, false}},
				{method: "SetLinkDomains", args: []any{index, tc.domains}},
				{method: "SetLinkDNSSEC", args: []any{index, "no"}},
				{method: "SetLinkDNSOverTLS", args: []any{index, "no"}},
				{method: "SetLinkLLMNR", args: []any{index, "no"}},
				{method: "SetLinkMulticastDNS", args: []any{index, "no"}},
				{method: "SetLinkDNSEx", args: []any{index, []linkDNSServer{tc.server}}},
			}
			if !reflect.DeepEqual(bus.calls, want) {
				t.Errorf("got calls %+v, want %+v", bus.calls, want)
			}
			for _, c := range bus.calls {
				if got := dbus.SignatureOf(c.args...).String(); got != resolvedSignatures[c.method] {
					t.Errorf("%s: got signature %q, want %q", c.method, got, resolvedSignatures[c.method])
				}
			}
			if bus.connects != 1 {
				t.Errorf("got %d connections, want 1", bus.connects)
			}
			bus.checkClosed(t)
		})
	}
}

func TestResolvedApplyRealInterfaceIndex(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	var lo *net.Interface
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 {
			lo = &ifaces[i]
			break
		}
	}
	if lo == nil {
		t.Fatal("got no loopback interface, want one")
	}

	bus := &fakeResolvedBus{}
	r := NewResolvedRegistrar(slog.New(slog.DiscardHandler))
	r.connect = bus.connect
	reg := Registration{
		Interface:      lo.Name,
		Server:         netip.MustParseAddrPort("127.0.0.1:5354"),
		RoutingDomains: []string{"e2e.internal"},
	}
	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply: got %v, want nil", err)
	}
	if got, want := bus.methods(), applyMethods; !reflect.DeepEqual(got, want) {
		t.Errorf("got calls %q, want %q", got, want)
	}
	for _, c := range bus.calls {
		if c.method == probeMethod {
			// The probe reads a property of the manager and names no link.
			continue
		}
		if got, want := c.args[0], int32(lo.Index); got != want {
			t.Errorf("%s: got index %v, want %d", c.method, got, want)
		}
	}
}

func TestResolvedApplyUnavailable(t *testing.T) {
	const (
		notRunning = "meshdns: resolved: systemd-resolved is not running: meshdns: no usable system resolver"
		tooOld     = "meshdns: resolved: systemd-resolved is older than 246: meshdns: no usable system resolver"
	)
	tests := []struct {
		name        string
		bus         *fakeResolvedBus
		wantErr     string
		wantMethods []string
	}{
		{
			name:    "connection fails",
			bus:     &fakeResolvedBus{connectErr: noBusSocket()},
			wantErr: notRunning,
		},
		// The probe answered, so these cases cover systemd-resolved going
		// away, or answering as an older one, between the probe and step 1.
		{
			name: "ServiceUnknown at step 1",
			bus: &fakeResolvedBus{fail: map[string]error{
				"SetLinkDefaultRoute": dbus.Error{Name: dbusErrServiceUnknown, Body: []any{"The name org.freedesktop.resolve1 was not provided by any .service files"}},
			}},
			wantErr:     notRunning,
			wantMethods: []string{probeMethod, "SetLinkDefaultRoute"},
		},
		{
			name: "NameHasNoOwner at step 1 as a pointer",
			bus: &fakeResolvedBus{fail: map[string]error{
				"SetLinkDefaultRoute": dbus.NewError(dbusErrNameHasNoOwner, []any{"Could not get owner of name 'org.freedesktop.resolve1'"}),
			}},
			wantErr:     notRunning,
			wantMethods: []string{probeMethod, "SetLinkDefaultRoute"},
		},
		{
			name: "NoSuchUnit at step 1",
			bus: &fakeResolvedBus{fail: map[string]error{
				"SetLinkDefaultRoute": dbus.Error{Name: dbusErrNoSuchUnit, Body: []any{"Unit dbus-org.freedesktop.resolve1.service not found."}},
			}},
			wantErr:     notRunning,
			wantMethods: []string{probeMethod, "SetLinkDefaultRoute"},
		},
		{
			name: "UnknownMethod at step 1",
			bus: &fakeResolvedBus{fail: map[string]error{
				"SetLinkDefaultRoute": dbus.Error{Name: dbusErrUnknownMethod, Body: []any{"Unknown method SetLinkDefaultRoute"}},
			}},
			wantErr:     tooOld,
			wantMethods: []string{probeMethod, "SetLinkDefaultRoute"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
				RoutingDomains: []string{"e2e.internal"},
			}
			err := newFakeResolved(tc.bus).Apply(context.Background(), reg)
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("got %v, want an error wrapping ErrUnavailable", err)
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("got error %v, want %q", err, tc.wantErr)
			}
			if got := tc.bus.methods(); !reflect.DeepEqual(got, tc.wantMethods) {
				t.Errorf("got calls %q, want %q", got, tc.wantMethods)
			}
			tc.bus.checkClosed(t)
		})
	}
}

// TestResolvedApplyProbe covers the property read before step 1. A
// systemd-resolved 240 to 245 accepts steps 1 to 6 and refuses only step 7,
// so without the probe every pull on such a host would change the link and
// revert it again. A failed probe changed nothing, so it is followed by no
// call at all, not even a revert.
func TestResolvedApplyProbe(t *testing.T) {
	const (
		notRunning = "meshdns: resolved: systemd-resolved is not running: meshdns: no usable system resolver"
		tooOld     = "meshdns: resolved: systemd-resolved is older than 246: meshdns: no usable system resolver"
	)
	tests := []struct {
		name     string
		probeErr error
		// stall runs Apply under a 300 ms deadline and makes the probe
		// answer only when its context ends.
		stall           bool
		wantErr         string
		wantUnavailable bool
		// wantIs is an error the result must wrap, nil for none beyond
		// what the other fields check.
		wantIs error
		// wantName is the D-Bus error name the result must carry as a
		// dbus.Error value, empty for none.
		wantName string
	}{
		{
			name:            "ServiceUnknown",
			probeErr:        dbus.Error{Name: dbusErrServiceUnknown, Body: []any{"The name org.freedesktop.resolve1 was not provided by any .service files"}},
			wantErr:         notRunning,
			wantUnavailable: true,
		},
		{
			// The bus daemon's answer with the no-auto-start flag when
			// systemd-resolved is stopped, as dbus-daemon gives it.
			name:            "NameHasNoOwner",
			probeErr:        dbus.Error{Name: dbusErrNameHasNoOwner, Body: []any{`Name "org.freedesktop.resolve1" does not exist`}},
			wantErr:         notRunning,
			wantUnavailable: true,
		},
		{
			name:            "NameHasNoOwner as a pointer",
			probeErr:        dbus.NewError(dbusErrNameHasNoOwner, []any{`Name "org.freedesktop.resolve1" does not exist`}),
			wantErr:         notRunning,
			wantUnavailable: true,
		},
		{
			name:            "NoSuchUnit",
			probeErr:        dbus.Error{Name: dbusErrNoSuchUnit, Body: []any{"Unit dbus-org.freedesktop.resolve1.service not found."}},
			wantErr:         notRunning,
			wantUnavailable: true,
		},
		{
			// The answer of systemd-resolved 245, as it gives it.
			name:            "UnknownProperty",
			probeErr:        dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownProperty", Body: []any{"Unknown interface org.freedesktop.resolve1.Manager or property DNSEx."}},
			wantErr:         tooOld,
			wantUnavailable: true,
		},
		{
			name:            "UnknownInterface",
			probeErr:        dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownInterface", Body: []any{"Unknown interface org.freedesktop.resolve1.Manager"}},
			wantErr:         tooOld,
			wantUnavailable: true,
		},
		{
			name:            "UnknownMethod",
			probeErr:        dbus.Error{Name: dbusErrUnknownMethod, Body: []any{"Unknown method Get"}},
			wantErr:         tooOld,
			wantUnavailable: true,
		},
		{
			name:            "InvalidArgs",
			probeErr:        dbus.Error{Name: "org.freedesktop.DBus.Error.InvalidArgs", Body: []any{"No such property DNSEx"}},
			wantErr:         tooOld,
			wantUnavailable: true,
		},
		{
			name:     "AccessDenied",
			probeErr: dbus.Error{Name: dbusErrAccessDenied, Body: []any{"Permission denied"}},
			wantErr:  "meshdns: resolved: DNSEx: Permission denied",
			wantName: dbusErrAccessDenied,
		},
		{
			name:    "DeadlineExceeded",
			stall:   true,
			wantErr: "meshdns: resolved: DNSEx: context deadline exceeded",
			wantIs:  context.DeadlineExceeded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bus := &fakeResolvedBus{fail: map[string]error{probeMethod: tc.probeErr}}
			ctx := context.Background()
			if tc.stall {
				bus.block = probeMethod
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
			}
			reg := Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
				SearchDomain:   "app.e2e.internal",
				RoutingDomains: []string{"e2e.internal"},
			}
			err := newFakeResolved(bus).Apply(ctx, reg)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("got error %v, want %q", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrUnavailable); got != tc.wantUnavailable {
				t.Errorf("got errors.Is(err, ErrUnavailable) %t, want %t", got, tc.wantUnavailable)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("got %v, want an error wrapping %v", err, tc.wantIs)
			}
			if tc.wantName != "" {
				var de dbus.Error
				if !errors.As(err, &de) || de.Name != tc.wantName {
					t.Errorf("got %v, want an error wrapping the D-Bus error %s", err, tc.wantName)
				}
			}
			want := []recordedBusCall{{method: probeMethod, args: probeArgs}}
			if !reflect.DeepEqual(bus.calls, want) {
				t.Errorf("got calls %+v, want only the probe %+v", bus.calls, want)
			}
			bus.checkClosed(t)
		})
	}
}

func TestResolvedApplyFailureRevertsLink(t *testing.T) {
	linkBusy := dbus.Error{Name: dbusErrLinkBusy, Body: []any{"Link plexd0 is managed."}}
	linkBusyPtr := dbus.NewError(dbusErrLinkBusy, []any{"Link plexd0 is managed."})
	tests := []struct {
		name            string
		failAt          string
		fail            map[string]error
		wantErr         string
		wantUnavailable bool
		// wantIs is an error the result must wrap, nil for none beyond
		// what the other fields check.
		wantIs error
		// wantName is the D-Bus error name the result must carry as a
		// dbus.Error value, empty for none.
		wantName string
		// timeout, when set, is the deadline Apply runs under, and failAt
		// then stalls until its context ends instead of answering.
		timeout time.Duration
	}{
		{
			name:            "UnknownMethod at step 7",
			failAt:          "SetLinkDNSEx",
			fail:            map[string]error{"SetLinkDNSEx": dbus.Error{Name: dbusErrUnknownMethod, Body: []any{"Unknown method SetLinkDNSEx"}}},
			wantErr:         "meshdns: resolved: systemd-resolved is older than 246: meshdns: no usable system resolver",
			wantUnavailable: true,
		},
		{
			name:     "LinkBusy at step 2",
			failAt:   "SetLinkDomains",
			fail:     map[string]error{"SetLinkDomains": linkBusy},
			wantErr:  "meshdns: resolved: SetLinkDomains: Link plexd0 is managed.",
			wantName: dbusErrLinkBusy,
		},
		{
			// Step 4 runs out Apply's whole budget, as a systemd-resolved
			// that hangs would. The fake ends calls as godbus does, so the
			// revert is recorded only if it goes out on a live context and
			// connection.
			name:    "DeadlineExceeded at step 4",
			failAt:  "SetLinkDNSOverTLS",
			timeout: 500 * time.Millisecond,
			wantErr: "meshdns: resolved: SetLinkDNSOverTLS: context deadline exceeded",
			wantIs:  context.DeadlineExceeded,
		},
		{
			name:     "UnknownMethod at step 3 is no version answer",
			failAt:   "SetLinkDNSSEC",
			fail:     map[string]error{"SetLinkDNSSEC": dbus.Error{Name: dbusErrUnknownMethod, Body: []any{"Unknown method SetLinkDNSSEC"}}},
			wantErr:  "meshdns: resolved: SetLinkDNSSEC: Unknown method SetLinkDNSSEC",
			wantName: dbusErrUnknownMethod,
		},
		{
			name:            "NameHasNoOwner at step 6",
			failAt:          "SetLinkMulticastDNS",
			fail:            map[string]error{"SetLinkMulticastDNS": dbus.Error{Name: dbusErrNameHasNoOwner}},
			wantErr:         "meshdns: resolved: systemd-resolved is not running: meshdns: no usable system resolver",
			wantUnavailable: true,
		},
		{
			name:   "failed RevertLink is ignored",
			failAt: "SetLinkLLMNR",
			fail: map[string]error{
				"SetLinkLLMNR": linkBusyPtr,
				"RevertLink":   dbus.Error{Name: dbusErrAccessDenied, Body: []any{"Access denied"}},
			},
			wantErr: "meshdns: resolved: SetLinkLLMNR: Link plexd0 is managed.",
			wantIs:  linkBusyPtr,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bus := &fakeResolvedBus{fail: tc.fail}
			ctx := context.Background()
			if tc.timeout > 0 {
				bus.block = tc.failAt
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}
			reg := Registration{
				Interface:      "plexd0",
				Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
				SearchDomain:   "app.e2e.internal",
				RoutingDomains: []string{"e2e.internal"},
			}
			err := newFakeResolved(bus).Apply(ctx, reg)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("got error %v, want %q", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrUnavailable); got != tc.wantUnavailable {
				t.Errorf("got errors.Is(err, ErrUnavailable) %t, want %t", got, tc.wantUnavailable)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("got %v, want an error wrapping %v", err, tc.wantIs)
			}
			if tc.wantName != "" {
				var de dbus.Error
				if !errors.As(err, &de) || de.Name != tc.wantName {
					t.Errorf("got %v, want an error wrapping the D-Bus error %s", err, tc.wantName)
				}
			}

			wantMethods := append(methodsUpTo(t, tc.failAt), "RevertLink")
			if got := bus.methods(); !reflect.DeepEqual(got, wantMethods) {
				t.Errorf("got calls %q, want %q", got, wantMethods)
			}
			last := bus.calls[len(bus.calls)-1]
			if want := []any{int32(testLinkIndex)}; !reflect.DeepEqual(last.args, want) {
				t.Errorf("RevertLink: got args %v, want %v", last.args, want)
			}
			if got := dbus.SignatureOf(last.args...).String(); got != resolvedSignatures["RevertLink"] {
				t.Errorf("RevertLink: got signature %q, want %q", got, resolvedSignatures["RevertLink"])
			}
			bus.checkClosed(t)
		})
	}
}

// TestResolvedApplyCancelSendsNoRevert covers a context cancelled during a
// step. godbus sends nothing on it any more, and plexd cancels only while it
// stops, when the drain's Shutdown reverts the link.
func TestResolvedApplyCancelSendsNoRevert(t *testing.T) {
	bus := &fakeResolvedBus{block: "SetLinkDNSOverTLS", blocked: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-bus.blocked:
		case <-ctx.Done():
		}
		cancel()
	}()
	reg := Registration{
		Interface:      "plexd0",
		Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
		RoutingDomains: []string{"e2e.internal"},
	}
	err := newFakeResolved(bus).Apply(ctx, reg)
	const wantErr = "meshdns: resolved: SetLinkDNSOverTLS: context canceled"
	if err == nil || err.Error() != wantErr {
		t.Errorf("got error %v, want %q", err, wantErr)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want an error wrapping context.Canceled", err)
	}
	if got, want := bus.methods(), methodsUpTo(t, "SetLinkDNSOverTLS"); !reflect.DeepEqual(got, want) {
		t.Errorf("got calls %q, want %q", got, want)
	}
	bus.checkClosed(t)
}

// sentBusCall is one call resolvedObject handed to the bus object.
type sentBusCall struct {
	method string
	flags  dbus.Flags
	args   []any
}

// recordingBusObject is the godbus object under resolvedObject. It records
// each CallWithContext and answers it with success; any other method of
// dbus.BusObject panics on the nil embedded value, because resolvedObject
// must not use it.
type recordingBusObject struct {
	dbus.BusObject
	sent []sentBusCall
}

func (o *recordingBusObject) CallWithContext(_ context.Context, method string, flags dbus.Flags, args ...any) *dbus.Call {
	o.sent = append(o.sent, sentBusCall{method: method, flags: flags, args: args})
	return &dbus.Call{}
}

// TestResolvedObjectNoAutoStart checks the method names and flags that go on
// the wire. Every call carries the no-auto-start flag, so plexd never makes
// the bus daemon start a stopped systemd-resolved.
func TestResolvedObjectNoAutoStart(t *testing.T) {
	obj := &recordingBusObject{}
	r := newFakeResolved(&fakeResolvedBus{})
	r.connect = func(context.Context) (caller, func() error, error) {
		return resolvedObject{obj: obj}, func() error { return nil }, nil
	}
	reg := Registration{
		Interface:      "plexd0",
		Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
		RoutingDomains: []string{"e2e.internal"},
	}
	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply: got %v, want nil", err)
	}
	if err := r.Revert(context.Background(), "plexd0"); err != nil {
		t.Fatalf("Revert: got %v, want nil", err)
	}

	want := []string{probeMethod}
	for _, m := range applyMethods[1:] {
		want = append(want, "org.freedesktop.resolve1.Manager."+m)
	}
	want = append(want, "org.freedesktop.resolve1.Manager.RevertLink")
	var got []string
	for _, c := range obj.sent {
		got = append(got, c.method)
		if c.flags != dbus.FlagNoAutoStart {
			t.Errorf("%s: got flags %#x, want FlagNoAutoStart %#x", c.method, c.flags, dbus.FlagNoAutoStart)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got methods %q, want %q", got, want)
	}
	if len(obj.sent) > 0 && !reflect.DeepEqual(obj.sent[0].args, probeArgs) {
		t.Errorf("%s: got args %v, want %v", probeMethod, obj.sent[0].args, probeArgs)
	}
}

func TestResolvedApplyMissingInterface(t *testing.T) {
	reg := Registration{
		Interface:      "nope0",
		Server:         netip.MustParseAddrPort("10.99.0.1:5354"),
		RoutingDomains: []string{"e2e.internal"},
	}

	t.Run("absent interface through the real lookup", func(t *testing.T) {
		bus := &fakeResolvedBus{}
		r := NewResolvedRegistrar(slog.New(slog.DiscardHandler))
		r.connect = bus.connect
		err := r.Apply(context.Background(), reg)
		const wantPrefix = "meshdns: resolved: interface nope0:"
		if err == nil || !strings.HasPrefix(err.Error(), wantPrefix) {
			t.Errorf("got error %v, want one starting with %q", err, wantPrefix)
		}
		if bus.connects != 0 {
			t.Errorf("got %d connections, want 0", bus.connects)
		}
	})

	t.Run("unreadable interface table", func(t *testing.T) {
		bus := &fakeResolvedBus{}
		r := newFakeResolved(bus)
		tableErr := os.NewSyscallError("netlinkrib", syscall.EMFILE)
		r.interfaces = func() ([]net.Interface, error) { return nil, tableErr }
		err := r.Apply(context.Background(), reg)
		const want = "meshdns: resolved: interface nope0: list interfaces: netlinkrib: too many open files"
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
		if !errors.Is(err, syscall.EMFILE) {
			t.Errorf("got %v, want an error wrapping EMFILE", err)
		}
		if bus.connects != 0 {
			t.Errorf("got %d connections, want 0", bus.connects)
		}
	})
}

func TestResolvedRevert(t *testing.T) {
	revertCall := []recordedBusCall{{method: "RevertLink", args: []any{int32(testLinkIndex)}}}
	tests := []struct {
		name  string
		iface string
		bus   *fakeResolvedBus
		// tableErr fails the interface listing when set.
		tableErr     error
		wantErr      string
		wantName     string
		wantConnects int
		wantCalls    []recordedBusCall
	}{
		{
			name:         "reverts the link by index",
			iface:        "plexd0",
			bus:          &fakeResolvedBus{},
			wantConnects: 1,
			wantCalls:    revertCall,
		},
		{
			name:  "missing interface",
			iface: "wg9",
			bus:   &fakeResolvedBus{},
		},
		{
			name:     "unreadable interface table",
			iface:    "plexd0",
			bus:      &fakeResolvedBus{},
			tableErr: os.NewSyscallError("netlinkrib", syscall.ENOBUFS),
			wantErr:  "meshdns: resolved: interface plexd0: list interfaces: netlinkrib: no buffer space available",
		},
		{
			name:         "connection fails",
			iface:        "plexd0",
			bus:          &fakeResolvedBus{connectErr: noBusSocket()},
			wantConnects: 1,
		},
		{
			name:  "ServiceUnknown",
			iface: "plexd0",
			bus: &fakeResolvedBus{fail: map[string]error{
				"RevertLink": dbus.Error{Name: dbusErrServiceUnknown},
			}},
			wantConnects: 1,
			wantCalls:    revertCall,
		},
		{
			name:  "NoSuchLink",
			iface: "plexd0",
			bus: &fakeResolvedBus{fail: map[string]error{
				"RevertLink": dbus.NewError(dbusErrNoSuchLink, []any{"Link 7 not known"}),
			}},
			wantConnects: 1,
			wantCalls:    revertCall,
		},
		{
			name:  "AccessDenied",
			iface: "plexd0",
			bus: &fakeResolvedBus{fail: map[string]error{
				"RevertLink": dbus.Error{Name: dbusErrAccessDenied, Body: []any{"Access denied"}},
			}},
			wantErr:      "meshdns: resolved: RevertLink: Access denied",
			wantName:     dbusErrAccessDenied,
			wantConnects: 1,
			wantCalls:    revertCall,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeResolved(tc.bus)
			if tc.tableErr != nil {
				r.interfaces = func() ([]net.Interface, error) { return nil, tc.tableErr }
			}
			err := r.Revert(context.Background(), tc.iface)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("got error %v, want nil", err)
			case tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr):
				t.Errorf("got error %v, want %q", err, tc.wantErr)
			}
			if tc.tableErr != nil && !errors.Is(err, tc.tableErr) {
				t.Errorf("got %v, want an error wrapping %v", err, tc.tableErr)
			}
			if tc.wantName != "" {
				var de dbus.Error
				if !errors.As(err, &de) || de.Name != tc.wantName {
					t.Errorf("got %v, want an error wrapping the D-Bus error %s", err, tc.wantName)
				}
			}
			if tc.bus.connects != tc.wantConnects {
				t.Errorf("got %d connections, want %d", tc.bus.connects, tc.wantConnects)
			}
			if !reflect.DeepEqual(tc.bus.calls, tc.wantCalls) {
				t.Errorf("got calls %+v, want %+v", tc.bus.calls, tc.wantCalls)
			}
			tc.bus.checkClosed(t)
		})
	}

	t.Run("absent interface through the real lookup", func(t *testing.T) {
		bus := &fakeResolvedBus{}
		r := NewResolvedRegistrar(slog.New(slog.DiscardHandler))
		r.connect = bus.connect
		if err := r.Revert(context.Background(), "nope0"); err != nil {
			t.Errorf("got error %v, want nil", err)
		}
		if bus.connects != 0 {
			t.Errorf("got %d connections, want 0", bus.connects)
		}
	})
}
