package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// dialStep is how scriptedDialer answers one dial: with err, by waiting for
// the dial's context to end when block is set, and otherwise with a
// connection whose far end is closed.
type dialStep struct {
	err   error
	block bool
}

// scriptedDialer replaces the manager's dial of a target with steps, one per
// dial, and sends on entered when a dial starts.
type scriptedDialer struct {
	mu      sync.Mutex
	steps   []dialStep
	entered chan struct{}
}

func (d *scriptedDialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	step := d.steps[0]
	d.steps = d.steps[1:]
	d.mu.Unlock()
	d.entered <- struct{}{}
	switch {
	case step.block:
		<-ctx.Done()
		return nil, ctx.Err()
	case step.err != nil:
		return nil, step.err
	}
	near, far := net.Pipe()
	_ = far.Close()
	return near, nil
}

// refusedDial is the error a dial to a port nothing listens on returns.
func refusedDial() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errConnRefused)}
}

// newDialFixture returns a set-up manager on a settable clock whose dials of
// a target follow steps, with a dial policy that denies nothing.
func newDialFixture(t *testing.T, steps ...dialStep) (*ingressFixture, *loopbackIngressController, *scriptedDialer, *fakeDialPolicy) {
	t.Helper()
	ctrl := newLoopbackIngressController(t)
	fx := buildIngressFixture(t, ctrl, ingressTestConfig(true))
	dialer := &scriptedDialer{steps: steps, entered: make(chan struct{}, len(steps))}
	fx.mgr.dial = dialer.dial
	fx.mgr.now = (&relayClock{now: relayStart}).Now
	policy := &fakeDialPolicy{}
	fx.mgr.SetDialPolicy(policy)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return fx, ctrl, dialer, policy
}

// connect opens a client connection to addr that is closed when the test
// ends.
func connect(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestClassifyDialError(t *testing.T) {
	if len(dialErrnoRefused) == 0 || len(dialErrnoUnreachable) == 0 {
		t.Fatalf("dialErrnoRefused = %v, dialErrnoUnreachable = %v, want both non-empty", dialErrnoRefused, dialErrnoUnreachable)
	}
	opErr := func(errno error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	type tc struct {
		name string
		err  error
		want string
	}
	tests := []tc{
		{"context.DeadlineExceeded", context.DeadlineExceeded, IngressDialReasonTimeout},
		{"a net.OpError that timed out", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, IngressDialReasonTimeout},
		{"errors.New", errors.New("x"), IngressDialReasonOther},
	}
	for _, errno := range dialErrnoRefused {
		tests = append(tests, tc{"refused " + errno.Error(), opErr(errno), IngressDialReasonRefused})
	}
	for _, errno := range dialErrnoUnreachable {
		tests = append(tests, tc{"unreachable " + errno.Error(), opErr(errno), IngressDialReasonUnreachable})
	}
	for _, errno := range dialErrnoTimeout {
		tests = append(tests, tc{"timeout " + errno.Error(), opErr(errno), IngressDialReasonTimeout})
	}
	for _, tt := range tests {
		if got := classifyDialError(tt.err); got != tt.want {
			t.Errorf("classifyDialError(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestRecordDial_FailedThenSucceeded(t *testing.T) {
	fx, ctrl, _, policy := newDialFixture(t, dialStep{err: refusedDial()}, dialStep{})
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(ingressRule("web", 7022, "", 9000), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	changed := fx.mgr.ReportChanged()
	drain(changed)

	connect(t, ctrl.addr(7022))
	requireSignal(t, changed, "a failed dial")
	want := IngressRuleReport{
		RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
		Dial: api.IngressDialFailed, DialReason: IngressDialReasonRefused, DialAt: relayStart,
	}
	if got := reportFor(t, fx.mgr.RuleReports(), id); got != want {
		t.Errorf("after a refused dial: report = %+v, want %+v", got, want)
	}
	// The rule carries no protocol, which the plan reads as tcp.
	wantAsked := []dialQuestion{{protocol: "tcp", target: netip.MustParseAddrPort("127.0.0.1:9000")}}
	if got := policy.askedWith(); !slices.Equal(got, wantAsked) {
		t.Errorf("the dial policy was asked %+v, want %+v", got, wantAsked)
	}
	fx.logs.waitFor(t, `msg="bridge: ingress: dial target failed"`, 1)
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id="+id, "protocol=tcp", "reason=refused"); got != 1 {
		t.Errorf("%d Error lines with rule_id=%s, protocol=tcp and reason=refused, want 1:\n%s", got, id, fx.logs.String())
	}

	// A second identical failure leaves the record as it was.
	fx.mgr.mu.Lock()
	route := fx.mgr.listeners[7022].table.Load().plain
	fx.mgr.mu.Unlock()
	if reason, recChanged := fx.mgr.recordDial(route, 0, refusedDial()); reason != IngressDialReasonRefused || recChanged {
		t.Errorf("recordDial of a second refused dial = (%q, %v), want (%q, false)", reason, recChanged, IngressDialReasonRefused)
	}
	requireNoSignal(t, changed, "a second identical failure")

	connect(t, ctrl.addr(7022))
	requireSignal(t, changed, "a dial that succeeded after a failed one")
	want.Dial, want.DialReason = api.IngressDialSucceeded, ""
	if got := reportFor(t, fx.mgr.RuleReports(), id); got != want {
		t.Errorf("after a dial that succeeded: report = %+v, want %+v", got, want)
	}
}

func TestRecordDial_CancelledDialIsNotRecorded(t *testing.T) {
	fx, ctrl, dialer, policy := newDialFixture(t, dialStep{block: true})
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fx.mgr.mu.Lock()
	lb := fx.mgr.listeners[7022].table.Load().plain.lb
	fx.mgr.mu.Unlock()
	connect(t, ctrl.addr(7022))
	select {
	case <-dialer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the bridge did not dial the target within 2s")
	}

	// Removing the rule cancels its route, which ends the dial in flight.
	if err := fx.mgr.Apply(t.Context(), rulesBlock()); err != nil {
		t.Fatalf("Apply without the rule: %v", err)
	}
	fx.logs.waitFor(t, `msg="bridge: ingress: dial target failed"`, 1)
	fx.mgr.mu.Lock()
	balancers := len(fx.mgr.balancers)
	fx.mgr.mu.Unlock()
	if balancers != 0 {
		t.Errorf("%d balancers after the rule was removed, want none", balancers)
	}
	if unit, targets := lb.snapshot(); !unit.at.IsZero() || !targets[0].at.IsZero() {
		t.Errorf("records after the dial was cancelled: unit %+v, target %+v, want no dial", unit, targets[0])
	}
	if out := outTargets(lb, relayStart); len(out) != 0 {
		t.Errorf("targets %v are out after the dial was cancelled, want the target in", out)
	}
	if got := policy.asked(); len(got) != 0 {
		t.Errorf("the dial policy was asked about %v, want no classification of context.Canceled", got)
	}
	if got := logLines(fx.logs, `msg="bridge: ingress: dial target failed"`, "reason="); got != 0 {
		t.Errorf("%d 'dial target failed' lines with a reason for a cancelled dial, want 0:\n%s", got, fx.logs.String())
	}
}

func TestRecordDial_RemovedAndReappliedReadsNone(t *testing.T) {
	fx, ctrl, _, _ := newDialFixture(t, dialStep{})
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	drain(fx.mgr.ReportChanged())
	connect(t, ctrl.addr(7022))
	requireSignal(t, fx.mgr.ReportChanged(), "a dial")
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialSucceeded {
		t.Fatalf("after a dial: report = %+v, want dial succeeded", got)
	}

	if err := fx.mgr.Apply(t.Context(), rulesBlock()); err != nil {
		t.Fatalf("Apply without the rule: %v", err)
	}
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply with the rule again: %v", err)
	}
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialNone || !got.DialAt.IsZero() {
		t.Errorf("after the rule was removed and applied again: report = %+v, want dial none", got)
	}
}

// outTargets returns the indexes of b's targets that are out at now.
func outTargets(b *ingressBalancer, now time.Time) []int {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []int
	for i, t := range b.targets {
		if now.Before(t.outUntil) {
			out = append(out, i)
		}
	}
	return out
}

// twoTargets returns two targets on the loopback, on 9000 and 9001.
func twoTargets() []api.IngressTarget {
	return []api.IngressTarget{
		{NodeID: "node-a", Address: "127.0.0.1", Port: 9000},
		{NodeID: "node-b", Address: "127.0.0.1", Port: 9001},
	}
}

// balancerFor returns the balancer the manager holds for the rule id.
func balancerFor(t *testing.T, mgr *IngressManager, id string) *ingressBalancer {
	t.Helper()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	b := mgr.balancers[id]
	if b == nil {
		t.Fatalf("no balancer for rule %s", id)
	}
	return b
}

func TestRecordDial_PerTarget(t *testing.T) {
	fx, ctrl, _, policy := newDialFixture(t, dialStep{err: refusedDial()}, dialStep{})
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	rule.Targets = twoTargets()
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	lb := balancerFor(t, fx.mgr, id)

	connect(t, ctrl.addr(7022))
	waitForCondition(t, 2*time.Second, func() bool {
		unit, _ := lb.snapshot()
		return !unit.at.IsZero()
	})
	unit, targets := lb.snapshot()
	if want := (dialRecord{at: relayStart}); unit != want {
		t.Errorf("unit = %+v, want succeeded at %v", unit, relayStart)
	}
	if want := []dialRecord{{failed: true, reason: IngressDialReasonRefused, at: relayStart}, {at: relayStart}}; !slices.Equal(targets, want) {
		t.Errorf("targets = %+v, want the first failed with refused and the second succeeded", targets)
	}
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialSucceeded || got.DialReason != "" || got.DialAt != relayStart {
		t.Errorf("report = %+v, want dial succeeded at %v", got, relayStart)
	}
	// Only the failed dial is named.
	if got, want := policy.asked(), []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9000")}; !slices.Equal(got, want) {
		t.Errorf("the dial policy was asked about %v, want %v", got, want)
	}
	if out := outTargets(lb, relayStart); !slices.Equal(out, []int{0}) {
		t.Errorf("out targets = %v, want the first", out)
	}
}

func TestRecordDial_AllTargetsFail(t *testing.T) {
	fx, ctrl, _, _ := newDialFixture(t, dialStep{err: refusedDial()}, dialStep{err: fmt.Errorf("dial: %w", context.DeadlineExceeded)})
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	rule.Targets = twoTargets()
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	changed := fx.mgr.ReportChanged()
	drain(changed)

	requireClosed(t, connect(t, ctrl.addr(7022)))
	requireSignal(t, changed, "a unit no target took")
	want := IngressRuleReport{
		RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
		Dial: api.IngressDialFailed, DialReason: IngressDialReasonTimeout, DialAt: relayStart,
	}
	if got := reportFor(t, fx.mgr.RuleReports(), id); got != want {
		t.Errorf("report = %+v, want %+v", got, want)
	}
	lb := balancerFor(t, fx.mgr, id)
	_, targets := lb.snapshot()
	if want := []dialRecord{{failed: true, reason: IngressDialReasonRefused, at: relayStart}, {failed: true, reason: IngressDialReasonTimeout, at: relayStart}}; !slices.Equal(targets, want) {
		t.Errorf("targets = %+v, want refused and timeout", targets)
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id="+id); got != 2 {
		t.Errorf("%d 'dial target failed' lines, want one per target:\n%s", got, fx.logs.String())
	}

	// A unit that fails with another reason changes the rule's record; the
	// same reason again does not.
	fx.mgr.mu.Lock()
	route := fx.mgr.listeners[7022].table.Load().plain
	fx.mgr.mu.Unlock()
	drain(changed)
	fx.mgr.recordUnitFailed(route, IngressDialReasonRefused)
	requireSignal(t, changed, "a unit that failed with another reason")
	fx.mgr.recordUnitFailed(route, IngressDialReasonRefused)
	requireNoSignal(t, changed, "a unit that failed with the same reason")
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialFailed || got.DialReason != IngressDialReasonRefused {
		t.Errorf("report = %+v, want dial failed with refused", got)
	}
}

func TestRecordDial_ChangedTargetsStartIn(t *testing.T) {
	fx, _, _, _ := newDialFixture(t)
	id := reportID("a1")
	routeOf := func(t *testing.T, host string) *ingressRoute {
		t.Helper()
		fx.mgr.mu.Lock()
		defer fx.mgr.mu.Unlock()
		h := fx.mgr.listeners[443].table.Load().exact[host]
		if h == nil {
			t.Fatalf("no route for %s", host)
		}
		return h.lead()
	}
	// dirty applies rule and leaves its first target failed and out, a
	// second target succeeded, and the rule's unit with an outcome.
	dirty := func(t *testing.T, rule api.IngressRule) *ingressRoute {
		t.Helper()
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		route := routeOf(t, rule.SNIHost)
		fx.mgr.recordDial(route, 0, refusedDial())
		if len(route.lb.targets) > 1 {
			fx.mgr.recordDial(route, 1, nil)
		} else {
			fx.mgr.recordUnitFailed(route, IngressDialReasonRefused)
		}
		if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial == api.IngressDialNone {
			t.Fatalf("after the dials: report = %+v, want a dial", got)
		}
		return route
	}

	base := withID(ingressRule("web", 443, "a.example.com", 9000), id)
	base.Targets = twoTargets()

	t.Run("another sni_host keeps the records and hold-outs", func(t *testing.T) {
		old := dirty(t, base)
		moved := base
		moved.SNIHost = "b.example.com"
		if err := fx.mgr.Apply(t.Context(), rulesBlock(moved)); err != nil {
			t.Fatalf("Apply with another sni_host: %v", err)
		}
		route := routeOf(t, "b.example.com")
		if route == old || route.lb != old.lb {
			t.Fatalf("route %p with balancer %p, want a new route with the balancer %p", route, route.lb, old.lb)
		}
		want := IngressRuleReport{
			RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
			Dial: api.IngressDialSucceeded, DialAt: relayStart,
		}
		if got := reportFor(t, fx.mgr.RuleReports(), id); got != want {
			t.Errorf("report = %+v, want %+v", got, want)
		}
		if _, targets := route.lb.snapshot(); !targets[0].failed || targets[1].failed || targets[1].at.IsZero() {
			t.Errorf("targets = %+v, want the first failed and the second succeeded", targets)
		}
		if out := outTargets(route.lb, relayStart); !slices.Equal(out, []int{0}) {
			t.Errorf("out targets = %v, want the first", out)
		}
	})

	legacy := withID(ingressRule("web", 443, "a.example.com", 9000), id)
	for _, tc := range []struct {
		name    string
		before  api.IngressRule
		targets []api.IngressTarget
		port    int // the target_port of a rule without targets
	}{
		{name: "an added target", before: base, targets: append(twoTargets(), api.IngressTarget{NodeID: "node-c", Address: "127.0.0.1", Port: 9002})},
		{name: "a removed target", before: base, targets: twoTargets()[:1]},
		{name: "reordered targets", before: base, targets: []api.IngressTarget{twoTargets()[1], twoTargets()[0]}},
		{name: "another target_port without targets", before: legacy, port: 9001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := dirty(t, tc.before)
			changed := tc.before
			changed.Targets = tc.targets
			if tc.port != 0 {
				changed.TargetPort = tc.port
			}
			if err := fx.mgr.Apply(t.Context(), rulesBlock(changed)); err != nil {
				t.Fatalf("Apply with the changed targets: %v", err)
			}
			route := routeOf(t, changed.SNIHost)
			if route.lb == old.lb {
				t.Fatal("the rule kept its balancer, want a new one")
			}
			got := reportFor(t, fx.mgr.RuleReports(), id)
			if got.Dial != api.IngressDialNone || got.DialReason != "" || !got.DialAt.IsZero() {
				t.Errorf("report = %+v, want dial none without a reason or a time", got)
			}
			unit, targets := route.lb.snapshot()
			if !unit.at.IsZero() {
				t.Errorf("unit = %+v, want no dial", unit)
			}
			for i, rec := range targets {
				if !rec.at.IsZero() {
					t.Errorf("target %d = %+v, want no dial", i, rec)
				}
			}
			if out := outTargets(route.lb, relayStart); len(out) != 0 {
				t.Errorf("out targets = %v, want every target in", out)
			}
		})
	}
}

// TestRecordDial_FailedBindKeepsTheBalancer keeps a rule's balancer over an
// Apply that moves the rule to a port that does not bind and the Apply that
// binds it, since its targets never change: the records and the hold-outs
// stay.
func TestRecordDial_FailedBindKeepsTheBalancer(t *testing.T) {
	id := reportID("a1")
	// moveAndRetry applies rule on port, where the bind fails, then applies
	// it again once the port binds, and checks that the rule keeps lb and
	// reports as before.
	moveAndRetry := func(t *testing.T, fx *ingressFixture, fail func(port int, err error), rule api.IngressRule, port int, lb *ingressBalancer) {
		t.Helper()
		before := reportFor(t, fx.mgr.RuleReports(), id)
		rule.ListenPort = port
		fail(port, syscall.EADDRINUSE)
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("Apply on port %d = %v, want the bind error", port, err)
		}
		if got := balancerFor(t, fx.mgr, id); got != lb {
			t.Errorf("after the failed bind: balancer %p, want the rule's balancer %p", got, lb)
		}
		fail(port, nil)
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply once port %d binds: %v", port, err)
		}
		if got := balancerFor(t, fx.mgr, id); got != lb {
			t.Errorf("after the retried bind: balancer %p, want the rule's balancer %p", got, lb)
		}
		if got := reportFor(t, fx.mgr.RuleReports(), id); got != before {
			t.Errorf("after the retried bind: report = %+v, want %+v", got, before)
		}
	}

	for _, tc := range []struct {
		name    string
		targets []api.IngressTarget
		steps   []dialStep
		out     []int
	}{
		{name: "one target", steps: []dialStep{{err: refusedDial()}}, out: []int{0}},
		{name: "two targets", targets: twoTargets(), steps: []dialStep{{err: refusedDial()}, {}}, out: []int{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx, ctrl, _, _ := newDialFixture(t, tc.steps...)
			rule := withID(ingressRule("web", 7022, "", 9000), id)
			rule.Targets = tc.targets
			if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			lb := balancerFor(t, fx.mgr, id)
			connect(t, ctrl.addr(7022))
			waitForCondition(t, 2*time.Second, func() bool {
				unit, _ := lb.snapshot()
				return !unit.at.IsZero()
			})
			if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial == api.IngressDialNone {
				t.Fatalf("after the dials: report = %+v, want a dial", got)
			}

			moveAndRetry(t, fx, ctrl.failListen, rule, 7023, lb)
			if out := outTargets(lb, relayStart); !slices.Equal(out, tc.out) {
				t.Errorf("out targets = %v, want %v", out, tc.out)
			}
		})
	}

	t.Run("a udp rule", func(t *testing.T) {
		fx, ctrl, _, _ := newDialFixture(t)
		rule := withID(udpIngressRule("dns", 7053, 9000), id)
		rule.Targets = twoTargets()
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		fx.mgr.mu.Lock()
		route := fx.mgr.udp[7053].route.Load()
		fx.mgr.mu.Unlock()
		fx.mgr.recordDial(route, 0, refusedDial())
		fx.mgr.recordDial(route, 1, nil)

		moveAndRetry(t, fx, ctrl.failListenUDP, rule, 7054, route.lb)
		if out := outTargets(route.lb, relayStart); !slices.Equal(out, []int{0}) {
			t.Errorf("out targets = %v, want the first", out)
		}
	})
}
