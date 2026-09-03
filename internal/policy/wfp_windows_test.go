//go:build windows

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// WFPController is the Windows FirewallController the enforcer is handed.
var _ FirewallController = (*WFPController)(nil)

// natController mirrors bridge.NATController. The contract is checked against
// a local copy because internal/policy must not import internal/bridge: the
// bridge package already depends on this one.
type natController interface {
	AddNATMasquerade(string) error
	RemoveNATMasquerade(string) error
}

var _ natController = (*WFPController)(nil)

// fakeEngine records what the controller would install in the filter engine.
// opens counts the sessions the controller opened through it, so a test sees
// that one session serves every chain.
//
// addRuleErrAt arms a failure: the fake counts only the AddRule calls made
// while it is set, so a test arms it after a successful apply and numbers the
// calls of the failing one from 1.
type fakeEngine struct {
	sublayers []*wf.Sublayer
	rules     map[wf.RuleID]*wf.Rule
	order     []wf.RuleID // the filters in the order they were added
	deleted   []wf.RuleID
	// deletedAfter holds, per deletion, how many filters had been added when
	// it ran, which is how a test sees that the new filters of an apply were
	// installed before the stale ones went.
	deletedAfter []int
	opens        int
	closed       int

	openErr        error
	addSublayerErr error
	addRuleErr     error
	addRuleErrAt   int // 1-based call number to fail, 0 for never
	addRuleCalls   int
	deleteErr      error
	closeErr       error
}

func (e *fakeEngine) AddSublayer(sl *wf.Sublayer) error {
	if e.addSublayerErr != nil {
		return e.addSublayerErr
	}
	e.sublayers = append(e.sublayers, sl)
	return nil
}

func (e *fakeEngine) AddRule(r *wf.Rule) error {
	if e.addRuleErrAt > 0 {
		e.addRuleCalls++
		if e.addRuleCalls == e.addRuleErrAt {
			return e.addRuleErr
		}
	}
	e.rules[r.ID] = r
	e.order = append(e.order, r.ID)
	return nil
}

// DeleteRule keeps the filter when deleteErr is set, so a test sees which IDs
// the controller holds on to after a failed deletion.
func (e *fakeEngine) DeleteRule(id wf.RuleID) error {
	e.deleted = append(e.deleted, id)
	e.deletedAfter = append(e.deletedAfter, len(e.order))
	if e.deleteErr != nil {
		return e.deleteErr
	}
	delete(e.rules, id)
	return nil
}

func (e *fakeEngine) Close() error {
	e.closed++
	return e.closeErr
}

// newTestWFPController returns a controller whose filter engine, interface
// lookups and host commands are recorded instead of run.
func newTestWFPController(t *testing.T) (*WFPController, *fakeEngine, *recordingRunner) {
	t.Helper()

	engine := &fakeEngine{rules: make(map[wf.RuleID]*wf.Rule)}
	runner := newRecordingRunner()

	ctrl := NewWFPController(testLogger(), "plexd0")
	ctrl.openEngine = func() (wfpEngine, error) {
		if engine.openErr != nil {
			return nil, engine.openErr
		}
		engine.opens++
		return engine, nil
	}
	ctrl.lookupIface = func(name string) (ifaceIDs, error) {
		switch name {
		case "plexd0":
			return ifaceIDs{index: 12, luid: 42}, nil
		case "Ethernet":
			return ifaceIDs{index: 7, luid: 7}, nil
		default:
			return ifaceIDs{}, errors.New("no such network interface")
		}
	}
	ctrl.meshPrefix = func(name string) (netip.Prefix, error) {
		if name != "plexd0" {
			return netip.Prefix{}, fmt.Errorf("interface %q has no IPv4 address", name)
		}
		return netip.MustParsePrefix("10.0.0.0/16"), nil
	}
	ctrl.run = runner.Run

	return ctrl, engine, runner
}

// sixRules covers every field combination buildFilters handles: both actions,
// each protocol and none, a prefix and a bare address on either side, a single
// port and a range, and the wildcard prefix on both sides. The last three name
// neither a port nor a protocol, so each of them yields a forward filter too.
var sixRules = []FirewallRule{
	{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"},
	{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"},
	{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Protocol: "icmp", Action: "allow"},
	{Interface: "plexd0", SrcIP: "10.0.0.9", DstIP: "10.1.0.0/24", Action: "allow"},
	{Interface: "plexd0", SrcIP: "10.0.0.9/32", DstIP: "0.0.0.0/0", Action: "deny"},
	{Interface: "plexd0", SrcIP: "0.0.0.0/0", DstIP: "0.0.0.0/0", Action: "deny"},
}

// conds flattens a filter's conditions, so a test compares them as values.
func conds(t *testing.T, r *wf.Rule) []wf.Match {
	t.Helper()

	out := make([]wf.Match, 0, len(r.Conditions))
	for _, m := range r.Conditions {
		out = append(out, *m)
	}
	return out
}

// findFilter returns the filter the engine holds under name, or nil.
func findFilter(e *fakeEngine, name string) *wf.Rule {
	for _, r := range e.rules {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// mustFilter returns the filter the engine holds under name and fails when it
// holds none.
func mustFilter(t *testing.T, e *fakeEngine, name string) *wf.Rule {
	t.Helper()

	r := findFilter(e, name)
	if r == nil {
		t.Fatalf("the filter engine holds no filter %q", name)
	}
	return r
}

// applyRejected applies rules to a controller that already holds sixRules and
// returns the error, having asserted that nothing reached the filter engine
// and that the chain still holds the filters of the successful apply.
func applyRejected(t *testing.T, chain string, rules []FirewallRule) error {
	t.Helper()

	ctrl, engine, _ := newTestWFPController(t)
	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	installed := slices.Clone(ctrl.chains["plexd-mesh"])

	err := ctrl.ApplyRules(chain, rules)
	if err == nil {
		t.Fatal("ApplyRules() error = nil, want a rejected rule")
	}
	if got := len(engine.order); got != len(installed) {
		t.Errorf("AddRule calls = %d, want %d: the rejected rules reached the filter engine", got, len(installed))
	}
	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, installed) {
		t.Errorf("chain plexd-mesh = %v, want the filters of the last apply %v", got, installed)
	}
	return err
}

func TestWFPController_Probe_OK(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.Probe(); err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}
	if engine.opens != 1 {
		t.Errorf("opened %d sessions, want 1", engine.opens)
	}
	if engine.closed != 1 {
		t.Errorf("closed %d sessions, want 1", engine.closed)
	}
}

func TestWFPController_Probe_AccessDenied(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)
	engine.openErr = windows.ERROR_ACCESS_DENIED

	err := ctrl.Probe()
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("Probe() error = %v, want ERROR_ACCESS_DENIED", err)
	}
	if !strings.HasPrefix(err.Error(), "policy: wfp: probe:") {
		t.Errorf("Probe() error = %v, want the prefix %q", err, "policy: wfp: probe:")
	}
	if !strings.HasSuffix(err.Error(), "(policy enforcement on Windows requires Administrator)") {
		t.Errorf("Probe() error = %v, want the Administrator hint", err)
	}
}

// A session that fails to close during the pre-flight leaves the engine handle
// in an unknown state. Swallowing that would report a usable backend for a node
// whose first ApplyFirewallRules then fails — after registration has spent the
// bootstrap token, which is the outcome Preflight exists to prevent.
func TestWFPController_Probe_CloseFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)
	engine.closeErr = errors.New("boom")

	err := ctrl.Probe()
	want := "policy: wfp: probe: close session:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("Probe() error = %v, want the prefix %q", err, want)
	}
}

func TestWFPController_EnsureChain_OpensSessionAndSublayer(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if engine.opens != 1 {
		t.Errorf("opened %d sessions, want 1", engine.opens)
	}
	if len(engine.sublayers) != 1 {
		t.Fatalf("added %d sublayers, want 1", len(engine.sublayers))
	}
	sl := engine.sublayers[0]
	if sl.ID != plexdSublayerID {
		t.Errorf("sublayer ID = %v, want %v", sl.ID, plexdSublayerID)
	}
	if sl.Name != "plexd policy" {
		t.Errorf("sublayer name = %q, want %q", sl.Name, "plexd policy")
	}
	if sl.Weight != 0xFFFE {
		t.Errorf("sublayer weight = %#x, want 0xfffe", sl.Weight)
	}

	// The second call finds the chain and the session in place.
	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() repeat error = %v, want nil", err)
	}
	if engine.opens != 1 {
		t.Errorf("opened %d sessions after the repeat, want 1", engine.opens)
	}
	if len(engine.sublayers) != 1 {
		t.Errorf("added %d sublayers after the repeat, want 1", len(engine.sublayers))
	}
}

func TestWFPController_EnsureChain_EmptyName(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	err := ctrl.EnsureChain("")
	want := "policy: wfp: ensure chain: chain name is empty"
	if err == nil || err.Error() != want {
		t.Fatalf("EnsureChain() error = %v, want %q", err, want)
	}
	if engine.opens != 0 {
		t.Errorf("opened %d sessions, want 0", engine.opens)
	}
}

func TestWFPController_EnsureChain_OpenFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)
	engine.openErr = errors.New("boom")

	err := ctrl.EnsureChain("plexd-mesh")
	want := "policy: wfp: ensure chain: open session: boom"
	if err == nil || err.Error() != want {
		t.Fatalf("EnsureChain() error = %v, want %q", err, want)
	}
	if ctrl.engine != nil {
		t.Error("the controller kept a session after a failed open")
	}
	if len(ctrl.chains) != 0 {
		t.Errorf("chains = %v, want none", ctrl.chains)
	}
}

func TestWFPController_EnsureChain_SublayerFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)
	engine.addSublayerErr = errors.New("boom")

	err := ctrl.EnsureChain("plexd-mesh")
	want := "policy: wfp: ensure chain: add sublayer:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("EnsureChain() error = %v, want the prefix %q", err, want)
	}
	if engine.closed != 1 {
		t.Errorf("closed %d sessions, want 1", engine.closed)
	}
	if ctrl.engine != nil {
		t.Error("the controller kept a session whose sublayer was rejected")
	}
}

func TestWFPController_ApplyRules_Translation(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if got := len(engine.order); got != 10 {
		t.Fatalf("installed %d filters, want 10", got)
	}

	var (
		iface    = wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: uint64(42)}
		index    = wf.Match{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)}
		src24    = wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")}
		srcHost  = wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.9/32")}
		dstHost  = wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")}
		dst24    = wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")}
		fwdSrc   = wf.Match{Field: wf.FieldIPSourceAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.9/32")}
		fwdSrc24 = wf.Match{Field: wf.FieldIPSourceAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")}
		fwdDst   = wf.Match{Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")}
	)

	tests := []struct {
		name   string
		layer  wf.LayerID
		action wf.Action
		weight uint64
		conds  []wf.Match
	}{
		{
			name: "plexd plexd-mesh #0 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 6,
			conds: []wf.Match{
				iface, src24, dstHost,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
				{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(443)},
			},
		},
		{
			name: "plexd plexd-mesh #1 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 5,
			conds: []wf.Match{
				iface, src24, dst24,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
				{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeRange, Value: wf.Range{From: uint16(53), To: uint16(60)}},
			},
		},
		{
			name: "plexd plexd-mesh #2 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 4,
			conds: []wf.Match{
				iface, src24, dst24,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMP},
			},
		},
		{
			name: "plexd plexd-mesh #2 forward", layer: wf.LayerIPForwardV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 4,
			conds: []wf.Match{
				index, fwdSrc24, fwdDst,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMP},
			},
		},
		{
			name: "plexd plexd-mesh #3 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 3,
			conds: []wf.Match{iface, srcHost, dst24},
		},
		{
			name: "plexd plexd-mesh #3 forward", layer: wf.LayerIPForwardV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 3,
			conds: []wf.Match{index, fwdSrc, fwdDst},
		},
		{
			name: "plexd plexd-mesh #4 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionBlock, weight: uint64(1)<<32 | 2,
			conds: []wf.Match{iface, srcHost},
		},
		{
			name: "plexd plexd-mesh #4 forward", layer: wf.LayerIPForwardV4,
			action: wf.ActionBlock, weight: uint64(1)<<32 | 2,
			conds: []wf.Match{index, fwdSrc},
		},
		{
			name: "plexd plexd-mesh #5 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionBlock, weight: uint64(1)<<32 | 1,
			conds: []wf.Match{iface},
		},
		{
			name: "plexd plexd-mesh #5 forward", layer: wf.LayerIPForwardV4,
			action: wf.ActionBlock, weight: uint64(1)<<32 | 1,
			conds: []wf.Match{index},
		},
	}

	for _, tt := range tests {
		r := mustFilter(t, engine, tt.name)
		if r.Layer != tt.layer {
			t.Errorf("filter %q layer = %v, want %v", tt.name, r.Layer, tt.layer)
		}
		if r.Sublayer != plexdSublayerID {
			t.Errorf("filter %q sublayer = %v, want %v", tt.name, r.Sublayer, plexdSublayerID)
		}
		if r.Action != tt.action {
			t.Errorf("filter %q action = %v, want %v", tt.name, r.Action, tt.action)
		}
		if r.Weight != tt.weight {
			t.Errorf("filter %q weight = %#x, want %#x", tt.name, r.Weight, tt.weight)
		}
		if got := conds(t, r); !reflect.DeepEqual(got, tt.conds) {
			t.Errorf("filter %q conditions =\n%v\nwant\n%v", tt.name, got, tt.conds)
		}
	}

	// An allow that names a port has no forward filter: the layer carries no
	// port field, and installing the permit without it would widen the rule.
	for _, name := range []string{
		"plexd plexd-mesh #0 forward",
		"plexd plexd-mesh #1 forward",
	} {
		if r := findFilter(engine, name); r != nil {
			t.Errorf("the filter engine holds %q, want no forward filter for an allow with a port", name)
		}
	}

	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, engine.order) {
		t.Errorf("chain plexd-mesh = %v, want the ten installed filters %v", got, engine.order)
	}
	if ctrl.epoch != 1 {
		t.Errorf("epoch = %d, want 1", ctrl.epoch)
	}
}

// The ruleset is ordered and first-match-terminating, so a rule the forward
// layer cannot express exactly must not simply be dropped: the traffic it
// covered would be re-decided by whatever follows it. A port-scoped deny ahead
// of a broad allow is the shape that turns that into a bypass on a bridge
// node, so the deny is installed without the port instead — blocking more than
// it asked for, never less.
func TestWFPController_ApplyRules_ForwardLayerFailsClosed(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)
	var logs bytes.Buffer
	ctrl.logger = slog.New(slog.NewTextHandler(&logs, nil))

	rules := []FirewallRule{
		{Interface: "plexd0", DstIP: "10.10.0.0/24", Port: 22, Protocol: "tcp", Action: "deny"},
		{Interface: "plexd0", SrcIP: "10.0.0.0/8", Action: "allow"},
		{Interface: "plexd0", Action: "deny"},
	}
	if err := ctrl.ApplyRules("plexd-mesh", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	deny := mustFilter(t, engine, "plexd plexd-mesh #0 forward")
	if deny.Action != wf.ActionBlock {
		t.Errorf("forward filter action = %v, want %v", deny.Action, wf.ActionBlock)
	}
	want := []wf.Match{
		{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)},
		{Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.10.0.0/24")},
		{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
	}
	if got := conds(t, deny); !reflect.DeepEqual(got, want) {
		t.Errorf("forward filter conditions =\n%v\nwant\n%v", got, want)
	}

	// The deny has to outweigh the allow below it, or WFP would permit the
	// traffic the deny covers before it ever reaches the block.
	allow := mustFilter(t, engine, "plexd plexd-mesh #1 forward")
	if deny.Weight <= allow.Weight {
		t.Errorf("forward deny weight = %#x, want more than the following allow's %#x", deny.Weight, allow.Weight)
	}

	// Outweighing the allow is what makes the widening visible in traffic: on
	// this ruleset every forwarded TCP flow to 10.10.0.0/24 is blocked, not
	// only port 22. The operator debugging that has nothing else to go on, so
	// the widening has to be logged — the narrowed-allow counter above never
	// counts a deny.
	if got := logs.String(); !strings.Contains(got, "deny rules widened to every port") {
		t.Errorf("logs do not report the widened deny:\n%s", got)
	}
}

func TestWFPController_ApplyRules_ImplicitChain(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if engine.opens != 1 {
		t.Errorf("opened %d sessions, want 1", engine.opens)
	}
	if _, ok := ctrl.chains["plexd-mesh"]; !ok {
		t.Error("chain plexd-mesh is unknown after an apply that was never preceded by EnsureChain")
	}
}

func TestWFPController_ApplyRules_ReplacesWithHigherEpoch(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules[:3]); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	first := slices.Clone(ctrl.chains["plexd-mesh"])
	// The first three rules yield four filters: the two port-scoped allows
	// get no forward filter, the ICMP allow gets both layers.
	if len(first) != 4 {
		t.Fatalf("the first apply installed %d filters, want 4", len(first))
	}

	if err := ctrl.ApplyRules("plexd-mesh", sixRules[3:]); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	second := ctrl.chains["plexd-mesh"]
	if len(second) != 6 {
		t.Fatalf("the second apply left %d filters, want 6", len(second))
	}
	for _, id := range second {
		if got := engine.rules[id].Weight >> 32; got != 2 {
			t.Errorf("filter %q epoch = %d, want 2", engine.rules[id].Name, got)
		}
	}

	if !slices.Equal(engine.deleted, first) {
		t.Errorf("deleted = %v, want the filters of the first apply %v", engine.deleted, first)
	}
	if len(engine.order) != 10 {
		t.Fatalf("added %d filters over both applies, want 10", len(engine.order))
	}
	// The chain is never unfiltered: every stale filter went after all ten
	// filters had been added.
	for i, added := range engine.deletedAfter {
		if added != 10 {
			t.Errorf("deletion %d ran after %d additions, want 10", i, added)
		}
	}
}

func TestWFPController_ApplyRules_Empty(t *testing.T) {
	checkApplyClears(t, []FirewallRule{})
}

func TestWFPController_ApplyRules_Nil(t *testing.T) {
	checkApplyClears(t, nil)
}

// checkApplyClears applies sixRules and then a rule set that carries no rule,
// which has to leave the chain in place and empty.
func checkApplyClears(t *testing.T, rules []FirewallRule) {
	t.Helper()

	ctrl, engine, _ := newTestWFPController(t)
	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	installed := slices.Clone(ctrl.chains["plexd-mesh"])

	if err := ctrl.ApplyRules("plexd-mesh", rules); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	if !slices.Equal(engine.deleted, installed) {
		t.Errorf("deleted = %v, want the filters of the first apply %v", engine.deleted, installed)
	}
	got, ok := ctrl.chains["plexd-mesh"]
	if !ok {
		t.Fatal("chain plexd-mesh is unknown after an apply with no rules")
	}
	if len(got) != 0 {
		t.Errorf("chain plexd-mesh = %v, want no filters", got)
	}
	if len(engine.rules) != 0 {
		t.Errorf("the filter engine still holds %d filters, want none", len(engine.rules))
	}
}

func TestWFPController_ApplyRules_InvalidRule(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Interface: "plexd0", Action: "drop"}})
	want := `policy: wfp: apply rules: rule 0: policy: firewall rule: invalid action "drop"`
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ApplyRules() error = %v, want the prefix %q", err, want)
	}
}

func TestWFPController_ApplyRules_EmptyInterface(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Action: "allow"}})
	want := "policy: wfp: apply rules: rule 0: interface name is empty"
	if err.Error() != want {
		t.Errorf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestWFPController_ApplyRules_UnknownInterface(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Interface: "en99", Action: "allow"}})
	want := `policy: wfp: apply rules: rule 0: lookup interface "en99":`
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ApplyRules() error = %v, want the prefix %q", err, want)
	}
	if !strings.HasSuffix(err.Error(), "no such network interface") {
		t.Errorf("ApplyRules() error = %v, want the lookup failure at the end", err)
	}
}

func TestWFPController_ApplyRules_IPv6Address(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Interface: "plexd0", SrcIP: "fd00::/64", Action: "allow"}})
	want := `policy: wfp: apply rules: rule 0: non-IPv4 address "fd00::/64"`
	if err.Error() != want {
		t.Errorf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestWFPController_ApplyRules_InvalidAddress(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Interface: "plexd0", DstIP: "bogus", Action: "allow"}})
	want := `policy: wfp: apply rules: rule 0: invalid IP address "bogus"`
	if err.Error() != want {
		t.Errorf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestWFPController_ApplyRules_EmptyChain(t *testing.T) {
	err := applyRejected(t, "", sixRules)
	want := "policy: wfp: apply rules: chain name is empty"
	if err.Error() != want {
		t.Errorf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestWFPController_ApplyRules_AddFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	installed := slices.Clone(ctrl.chains["plexd-mesh"])

	// sixRules[3:] names neither a port nor a protocol, so every rule of it
	// yields an inbound and a forward filter: the third AddRule of the second
	// apply is rule 1's inbound filter, and two filters are already installed
	// when it fails.
	engine.addRuleErr = windows.ERROR_ACCESS_DENIED
	engine.addRuleErrAt = 3

	err := ctrl.ApplyRules("plexd-mesh", sixRules[3:])
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("ApplyRules() error = %v, want ERROR_ACCESS_DENIED", err)
	}
	want := `policy: wfp: apply rules: add filter "plexd plexd-mesh #1 inbound":`
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ApplyRules() error = %v, want the prefix %q", err, want)
	}
	if !strings.HasSuffix(err.Error(), "(policy enforcement on Windows requires Administrator)") {
		t.Errorf("ApplyRules() error = %v, want the Administrator hint", err)
	}

	if got := engine.deleted; !slices.Equal(got, engine.order[len(installed):]) {
		t.Errorf("deleted = %v, want the filters the failed apply had added %v", got, engine.order[len(installed):])
	}
	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, installed) {
		t.Errorf("chain plexd-mesh = %v, want the filters of the first apply %v", got, installed)
	}
	for _, id := range installed {
		if engine.rules[id] == nil {
			t.Errorf("filter %v of the first apply is gone after the failed one", id)
		}
	}
}

func TestWFPController_ApplyRules_StaleDeleteNotFound(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules[:3]); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	engine.deleteErr = fwpEFilterNotFound

	if err := ctrl.ApplyRules("plexd-mesh", sixRules[3:]); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil: a filter that is already gone is the wanted state", err)
	}
	if got := len(ctrl.chains["plexd-mesh"]); got != 6 {
		t.Errorf("chain plexd-mesh holds %d filters, want the 6 of the second apply", got)
	}
}

func TestWFPController_ApplyRules_StaleDeleteFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules[:3]); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	first := slices.Clone(ctrl.chains["plexd-mesh"])
	engine.deleteErr = errors.New("boom")

	err := ctrl.ApplyRules("plexd-mesh", sixRules[3:])
	want := "policy: wfp: apply rules: delete stale filters:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("ApplyRules() error = %v, want the prefix %q", err, want)
	}

	// The filters that could not be deleted are kept, so the next cycle of the
	// reconciler tries them again.
	wantIDs := append(slices.Clone(engine.order[len(first):]), first...)
	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, wantIDs) {
		t.Errorf("chain plexd-mesh = %v, want the new filters followed by the stale ones %v", got, wantIDs)
	}
}

func TestWFPController_FlushChain(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	installed := slices.Clone(ctrl.chains["plexd-mesh"])

	if err := ctrl.FlushChain("plexd-mesh"); err != nil {
		t.Fatalf("FlushChain() error = %v, want nil", err)
	}
	if !slices.Equal(engine.deleted, installed) {
		t.Errorf("deleted = %v, want every filter of the chain %v", engine.deleted, installed)
	}
	got, ok := ctrl.chains["plexd-mesh"]
	if !ok {
		t.Fatal("chain plexd-mesh is unknown after a flush, want the chain kept")
	}
	if len(got) != 0 {
		t.Errorf("chain plexd-mesh = %v, want no filters", got)
	}
	if engine.closed != 0 {
		t.Errorf("closed %d sessions, want the session kept", engine.closed)
	}
}

func TestWFPController_FlushChain_Unknown(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.FlushChain("plexd-mesh"); err != nil {
		t.Fatalf("FlushChain() error = %v, want nil", err)
	}
	if engine.opens != 0 {
		t.Errorf("opened %d sessions, want 0", engine.opens)
	}
}

func TestWFPController_FlushChain_DeleteFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	installed := slices.Clone(ctrl.chains["plexd-mesh"])
	engine.deleteErr = errors.New("boom")

	err := ctrl.FlushChain("plexd-mesh")
	want := `policy: wfp: flush chain "plexd-mesh":`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("FlushChain() error = %v, want the prefix %q", err, want)
	}
	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, installed) {
		t.Errorf("chain plexd-mesh = %v, want the filters that are still installed %v", got, installed)
	}
}

func TestWFPController_DeleteChain_LastClosesSession(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if len(engine.rules) != 0 {
		t.Errorf("the filter engine still holds %d filters, want none", len(engine.rules))
	}
	if engine.closed != 1 {
		t.Errorf("closed %d sessions, want 1", engine.closed)
	}
	if ctrl.engine != nil {
		t.Error("the controller kept a session after its last chain went")
	}
	if _, ok := ctrl.chains["plexd-mesh"]; ok {
		t.Error("chain plexd-mesh is still known after DeleteChain")
	}
}

func TestWFPController_DeleteChain_KeepsSessionForOtherChain(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	for _, chain := range []string{"plexd-mesh", "plexd-bridge"} {
		if err := ctrl.EnsureChain(chain); err != nil {
			t.Fatalf("EnsureChain(%q) error = %v, want nil", chain, err)
		}
	}
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if engine.closed != 0 {
		t.Errorf("closed %d sessions, want the session kept for plexd-bridge", engine.closed)
	}
	if ctrl.engine == nil {
		t.Error("the controller dropped its session while a chain is left")
	}
}

// A deletion that fails for any reason other than "already gone" has to keep
// the chain and the session: the reconciler retries the IDs that are still
// installed, and closing the session while filters are in the engine would
// drop them along with plexd's sublayer.
func TestWFPController_DeleteChain_DeleteFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	installed := slices.Clone(ctrl.chains["plexd-mesh"])
	engine.deleteErr = errors.New("boom")

	err := ctrl.DeleteChain("plexd-mesh")
	want := `policy: wfp: delete chain "plexd-mesh":`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("DeleteChain() error = %v, want the prefix %q", err, want)
	}
	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, installed) {
		t.Errorf("chain plexd-mesh = %v, want the filters that are still installed %v", got, installed)
	}
	if engine.closed != 0 {
		t.Errorf("closed %d sessions, want the session kept while filters are installed", engine.closed)
	}
	if ctrl.engine == nil {
		t.Error("the controller dropped its session while filters are still installed")
	}
}

func TestWFPController_DeleteChain_Unknown(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if engine.opens != 0 {
		t.Errorf("opened %d sessions, want 0", engine.opens)
	}
}

func TestWFPController_DeleteChain_CloseFails(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	engine.closeErr = errors.New("boom")

	err := ctrl.DeleteChain("plexd-mesh")
	want := "policy: wfp: delete chain: close session:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("DeleteChain() error = %v, want the prefix %q", err, want)
	}
	if ctrl.engine != nil {
		t.Error("the controller kept a session it could not close")
	}
}

func TestWFPController_Weight(t *testing.T) {
	if got, want := wfpWeight(3, 6, 0), uint64(3)<<32|6; got != want {
		t.Errorf("wfpWeight(3, 6, 0) = %#x, want %#x", got, want)
	}
	if got, want := wfpWeight(3, 6, 5), uint64(3)<<32|1; got != want {
		t.Errorf("wfpWeight(3, 6, 5) = %#x, want %#x", got, want)
	}
}

// firstRoutableInterface returns the name of an up, non-loopback interface
// with an IPv4 address, which is an adapter the filter engine knows.
func firstRoutableInterface(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("listing interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return ifi.Name
			}
		}
	}
	t.Skip("no up, non-loopback interface with an IPv4 address")
	return ""
}

// TestWFPController_Real drives the host's filter engine, which needs
// Administrator. The rules cover prefixes no host carries and no blanket deny,
// so the runner's own traffic is untouched, and the dynamic session drops
// every filter again when it closes.
func TestWFPController_Real(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WFP=1 in an elevated shell to program the filter engine")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("programming the filter engine needs Administrator")
	}

	iface := firstRoutableInterface(t)
	ctrl := NewWFPController(testLogger(), iface)

	// plexdFilters enumerates plexd's filters through a session of its own,
	// because the controller's session is what the test is checking.
	plexdFilters := func() []*wf.Rule {
		t.Helper()

		session, err := wf.New(&wf.Options{Name: "plexd test"})
		if err != nil {
			t.Fatalf("opening a session: %v", err)
		}
		defer func() { _ = session.Close() }()

		all, err := session.Rules()
		if err != nil {
			t.Fatalf("enumerating filters: %v", err)
		}
		var mine []*wf.Rule
		for _, r := range all {
			if strings.HasPrefix(r.Name, "plexd plexd-test") {
				mine = append(mine, r)
			}
		}
		return mine
	}

	if err := ctrl.Probe(); err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}

	t.Cleanup(func() {
		if err := ctrl.DeleteChain("plexd-test"); err != nil {
			t.Errorf("cleanup DeleteChain() error = %v", err)
		}
	})

	if err := ctrl.EnsureChain("plexd-test"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	rules := []FirewallRule{
		{Interface: iface, SrcIP: "10.255.252.0/30", DstIP: "10.255.252.4/30", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: iface, SrcIP: "10.255.252.8/30", DstIP: "0.0.0.0/0", Action: "deny"},
	}
	if err := ctrl.ApplyRules("plexd-test", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	// Rule 0 is an allow naming a port, which the forward layer cannot express,
	// so it has no forward filter.
	installed := plexdFilters()
	want := []string{
		"plexd plexd-test #0 inbound",
		"plexd plexd-test #1 inbound",
		"plexd plexd-test #1 forward",
	}
	if len(installed) != len(want) {
		t.Fatalf("the filter engine holds %d plexd filters, want %d: %v", len(installed), len(want), installed)
	}
	for _, name := range want {
		found := false
		for _, r := range installed {
			if r.Name != name {
				continue
			}
			found = true
			if r.Sublayer != plexdSublayerID {
				t.Errorf("filter %q sublayer = %v, want %v", name, r.Sublayer, plexdSublayerID)
			}
		}
		if !found {
			t.Errorf("the filter engine holds no filter %q: %v", name, installed)
		}
	}

	// Deleting a filter that is not there is what the stale-filter path
	// ignores, so this is the error fwpEFilterNotFound has to name.
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("generating a filter id: %v", err)
	}
	if err := ctrl.engine.DeleteRule(wf.RuleID(guid)); !errors.Is(err, fwpEFilterNotFound) {
		t.Errorf("DeleteRule() of an unknown filter = %v, want FWP_E_FILTER_NOT_FOUND", err)
	}

	if err := ctrl.DeleteChain("plexd-test"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if left := plexdFilters(); len(left) != 0 {
		t.Errorf("the filter engine still holds %d plexd filters: %v", len(left), left)
	}
}
