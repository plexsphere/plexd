package bridge

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
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
	if reason, recChanged := fx.mgr.recordDial(route, refusedDial()); reason != IngressDialReasonRefused || recChanged {
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

func TestRecordDial_ChangedTargetReadsNone(t *testing.T) {
	fx, ctrl, _, _ := newDialFixture(t, dialStep{err: refusedDial()})
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	drain(fx.mgr.ReportChanged())
	connect(t, ctrl.addr(7022))
	requireSignal(t, fx.mgr.ReportChanged(), "a failed dial")
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialFailed {
		t.Fatalf("after a refused dial: report = %+v, want dial failed", got)
	}

	rule.TargetPort = 9001
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply with another target port: %v", err)
	}
	got := reportFor(t, fx.mgr.RuleReports(), id)
	if got.Dial != api.IngressDialNone || got.DialReason != "" || !got.DialAt.IsZero() {
		t.Errorf("after the target changed: report = %+v, want dial none without a reason or a time", got)
	}
}

func TestRecordDial_CancelledDialIsNotRecorded(t *testing.T) {
	fx, ctrl, dialer, policy := newDialFixture(t, dialStep{block: true})
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
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
	records := len(fx.mgr.dials)
	fx.mgr.mu.Unlock()
	if records != 0 {
		t.Errorf("%d dial records after the dial was cancelled, want none", records)
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
