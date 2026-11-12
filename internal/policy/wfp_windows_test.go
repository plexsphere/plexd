//go:build windows

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/wf"
	"go4.org/netipx"
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

// wfpLayerFields is, per layer plexd installs filters at, the set of condition
// fields plexd may use there. The real engine reports the fields of each layer,
// and tailscale/wf refuses a condition on a field the layer does not have:
// FWPM_LAYER_IPFORWARD_V4 and _V6 have no IP_PROTOCOL and no port field, and a
// forward filter that named a protocol failed on the Windows runner with
// "cannot map Go type wf.IPProto to field type <nil>". fakeEngine.AddRule
// refuses the same conditions, so a unit test catches a filter the engine
// would reject. The forward and connect sets list only what plexd uses, not
// every field Microsoft documents for IPFORWARD and ALE_AUTH_CONNECT.
var wfpLayerFields = map[wf.LayerID]map[wf.FieldID]bool{
	wf.LayerALEAuthRecvAcceptV4: {
		wf.FieldIPLocalInterface: true,
		wf.FieldIPRemoteAddress:  true,
		wf.FieldIPLocalAddress:   true,
		wf.FieldIPProtocol:       true,
		wf.FieldIPLocalPort:      true,
	},
	wf.LayerALEAuthRecvAcceptV6: {
		wf.FieldIPLocalInterface: true,
		wf.FieldIPRemoteAddress:  true,
		wf.FieldIPLocalAddress:   true,
		wf.FieldIPProtocol:       true,
		wf.FieldIPLocalPort:      true,
	},
	wf.LayerALEAuthConnectV4: {
		wf.FieldIPLocalInterface: true,
		wf.FieldIPLocalAddress:   true,
		wf.FieldIPRemoteAddress:  true,
		wf.FieldIPProtocol:       true,
		wf.FieldIPRemotePort:     true,
	},
	wf.LayerALEAuthConnectV6: {
		wf.FieldIPLocalInterface: true,
		wf.FieldIPLocalAddress:   true,
		wf.FieldIPRemoteAddress:  true,
		wf.FieldIPProtocol:       true,
		wf.FieldIPRemotePort:     true,
	},
	wf.LayerIPForwardV4: {
		wf.FieldSourceInterfaceIndex: true,
		wf.FieldIPSourceAddress:      true,
		wf.FieldIPDestinationAddress: true,
	},
	wf.LayerIPForwardV6: {
		wf.FieldSourceInterfaceIndex: true,
		wf.FieldIPSourceAddress:      true,
		wf.FieldIPDestinationAddress: true,
	},
}

// checkLayerFields returns why the engine would refuse the filter: a layer
// wfpLayerFields does not list, or a condition on a field that layer does not
// have. It returns nil for a filter the engine takes.
func checkLayerFields(r *wf.Rule) error {
	fields, ok := wfpLayerFields[r.Layer]
	if !ok {
		return fmt.Errorf("fake engine: layer %v is not one plexd installs filters at", r.Layer)
	}
	for _, m := range r.Conditions {
		if !fields[m.Field] {
			return fmt.Errorf("fake engine: field %v not available at layer %v", m.Field, r.Layer)
		}
	}
	return nil
}

// checkEngineTakes fails for every filter fakeEngine.AddRule would refuse, so
// a test that calls buildFilters directly holds its filters to what the
// engine takes, as a test that goes through ApplyRules does.
func checkEngineTakes(t *testing.T, filters []*wf.Rule) {
	t.Helper()

	for _, f := range filters {
		if err := checkLayerFields(f); err != nil {
			t.Errorf("filter %q: %v", f.Name, err)
		}
	}
}

// relayProbeConds is the condition list of the relay probe permits on the
// interface with the given LUID: UDP to port 9, to any address.
func relayProbeConds(luid uint64) []wf.Match {
	return []wf.Match{
		{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid},
		{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(9)},
	}
}

// checkRelayProbes fails unless filters open with the relay probe permits of
// the interfaces with the given LUIDs, in that order, each pair at both
// connect layers and above the weight of rule 0 of n. It returns the filters
// that follow the permits.
func checkRelayProbes(t *testing.T, filters []*wf.Rule, chain string, epoch uint32, n int, luids ...uint64) []*wf.Rule {
	t.Helper()

	if len(filters) < 2*len(luids) {
		t.Fatalf("buildFilters() built %d filters, want at least the %d relay probe permits", len(filters), 2*len(luids))
	}
	weight := wfpWeight(epoch, n, -1)
	if weight <= wfpWeight(epoch, n, 0) {
		t.Fatalf("relay probe weight %#x does not outweigh rule 0's %#x", weight, wfpWeight(epoch, n, 0))
	}
	for i, luid := range luids {
		for j, want := range []struct {
			name  string
			layer wf.LayerID
		}{
			{name: "plexd " + chain + " relay probe", layer: wf.LayerALEAuthConnectV4},
			{name: "plexd " + chain + " relay probe v6", layer: wf.LayerALEAuthConnectV6},
		} {
			got := filters[2*i+j]
			if got.Name != want.name {
				t.Errorf("filter %d name = %q, want %q", 2*i+j, got.Name, want.name)
			}
			if got.Layer != want.layer {
				t.Errorf("filter %q layer = %v, want %v", got.Name, got.Layer, want.layer)
			}
			if got.Sublayer != plexdSublayerID {
				t.Errorf("filter %q sublayer = %v, want %v", got.Name, got.Sublayer, plexdSublayerID)
			}
			if got.Action != wf.ActionPermit {
				t.Errorf("filter %q action = %v, want %v", got.Name, got.Action, wf.ActionPermit)
			}
			if got.Weight != weight {
				t.Errorf("filter %q weight = %#x, want %#x", got.Name, got.Weight, weight)
			}
			if c := conds(t, got); !reflect.DeepEqual(c, relayProbeConds(luid)) {
				t.Errorf("filter %q conditions =\n%v\nwant\n%v", got.Name, c, relayProbeConds(luid))
			}
		}
	}
	return filters[2*len(luids):]
}

// v6AddrMatch is the condition buildFilters installs for an IPv6 address:
// the range from the prefix's first to its last address. See addrMatch for
// why the IPv6 layers take a range rather than an address and mask.
func v6AddrMatch(field wf.FieldID, prefix netip.Prefix) wf.Match {
	return wf.Match{Field: field, Op: wf.MatchTypeRange, Value: netipx.RangeOfPrefix(prefix)}
}

// An IPv4 prefix is matched as an address and mask, as it always was. An IPv6
// prefix is matched as the range of its addresses, which matches the same
// packets and keeps every allocation tailscale/wf makes for the filter
// aligned; a host prefix is a range of one address.
func TestAddrMatch(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		op     wf.MatchType
		value  any
	}{
		{prefix: "10.0.0.0/24", op: wf.MatchTypeEqual, value: netip.MustParsePrefix("10.0.0.0/24")},
		{
			prefix: "fd00:99::/64", op: wf.MatchTypeRange,
			value: netipx.IPRangeFrom(netip.MustParseAddr("fd00:99::"), netip.MustParseAddr("fd00:99::ffff:ffff:ffff:ffff")),
		},
		{
			prefix: "fd00:99::1/128", op: wf.MatchTypeRange,
			value: netipx.IPRangeFrom(netip.MustParseAddr("fd00:99::1"), netip.MustParseAddr("fd00:99::1")),
		},
	} {
		got := addrMatch(wf.FieldIPRemoteAddress, netip.MustParsePrefix(tt.prefix))
		if got.Field != wf.FieldIPRemoteAddress || got.Op != tt.op || !reflect.DeepEqual(got.Value, tt.value) {
			t.Errorf("addrMatch(%s) = {%v %v %v}, want {%v %v %v}",
				tt.prefix, got.Field, got.Op, got.Value, wf.FieldIPRemoteAddress, tt.op, tt.value)
		}
	}
}

// fakeEngine records what the controller would install in the filter engine.
// opens counts the sessions the controller opened through it, so a test sees
// that one session serves every chain.
//
// addRuleErrAt arms a failure: the fake counts only the AddRule calls made
// while it is set, so a test arms it after a successful apply and numbers the
// calls of the failing one from 1.
//
// AddRule refuses a filter at a layer wfpLayerFields does not list, or with a
// condition on a field that layer does not have, as the real engine does.
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
	if err := checkLayerFields(r); err != nil {
		return err
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

// sixRules covers every field combination buildFilters handles in an IPv4
// rule: both actions, each protocol and none, a prefix and a bare address on
// either side, a single port and a range, and the wildcard prefix on both
// sides. Each of them yields an inbound and an outbound filter. The last three
// name neither a port nor a protocol, so each of them yields a forward filter
// too. TestWFPController_BuildFilters_Families covers IPv6 rules and the rule
// without addresses.
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
	// Two relay probe permits, an inbound and an outbound filter per rule,
	// and a forward filter for each of the last three rules.
	if got := len(engine.order); got != 17 {
		t.Fatalf("installed %d filters, want 17", got)
	}

	// The inbound filters match the rule's source as the remote address and
	// its destination as the local one, the outbound filters the other way
	// round.
	var (
		iface      = wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: uint64(42)}
		index      = wf.Match{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)}
		src24      = wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")}
		srcHost    = wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.9/32")}
		dstHost    = wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")}
		dst24      = wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")}
		outSrc24   = wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")}
		outSrcHost = wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.9/32")}
		outDstHost = wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")}
		outDst24   = wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")}
		fwdSrc     = wf.Match{Field: wf.FieldIPSourceAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.9/32")}
		fwdDst     = wf.Match{Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")}
	)

	tests := []struct {
		name   string
		layer  wf.LayerID
		action wf.Action
		weight uint64
		conds  []wf.Match
	}{
		{
			name: "plexd plexd-mesh relay probe", layer: wf.LayerALEAuthConnectV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 7,
			conds: relayProbeConds(42),
		},
		{
			name: "plexd plexd-mesh relay probe v6", layer: wf.LayerALEAuthConnectV6,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 7,
			conds: relayProbeConds(42),
		},
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
			name: "plexd plexd-mesh #0 outbound", layer: wf.LayerALEAuthConnectV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 6,
			conds: []wf.Match{
				iface, outSrc24, outDstHost,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(443)},
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
			name: "plexd plexd-mesh #1 outbound", layer: wf.LayerALEAuthConnectV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 5,
			conds: []wf.Match{
				iface, outSrc24, outDst24,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeRange, Value: wf.Range{From: uint16(53), To: uint16(60)}},
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
			name: "plexd plexd-mesh #2 outbound", layer: wf.LayerALEAuthConnectV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 4,
			conds: []wf.Match{
				iface, outSrc24, outDst24,
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMP},
			},
		},
		{
			name: "plexd plexd-mesh #3 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 3,
			conds: []wf.Match{iface, srcHost, dst24},
		},
		{
			name: "plexd plexd-mesh #3 outbound", layer: wf.LayerALEAuthConnectV4,
			action: wf.ActionPermit, weight: uint64(1)<<32 | 3,
			conds: []wf.Match{iface, outSrcHost, outDst24},
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
			name: "plexd plexd-mesh #4 outbound", layer: wf.LayerALEAuthConnectV4,
			action: wf.ActionBlock, weight: uint64(1)<<32 | 2,
			conds: []wf.Match{iface, outSrcHost},
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
			name: "plexd plexd-mesh #5 outbound", layer: wf.LayerALEAuthConnectV4,
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

	// An allow that names a protocol or a port has no forward filter: the
	// layer carries neither field, and installing the permit without them
	// would widen the rule.
	for _, name := range []string{
		"plexd plexd-mesh #0 forward",
		"plexd plexd-mesh #1 forward",
		"plexd plexd-mesh #2 forward",
	} {
		if r := findFilter(engine, name); r != nil {
			t.Errorf("the filter engine holds %q, want no forward filter for an allow with a protocol or a port", name)
		}
	}

	// The relay probe permits go in ahead of the rule filters.
	for i, name := range []string{"plexd plexd-mesh relay probe", "plexd plexd-mesh relay probe v6"} {
		if got := engine.rules[engine.order[i]].Name; got != name {
			t.Errorf("filter %d installed = %q, want %q", i, got, name)
		}
	}

	if got := ctrl.chains["plexd-mesh"]; !slices.Equal(got, engine.order) {
		t.Errorf("chain plexd-mesh = %v, want the seventeen installed filters %v", got, engine.order)
	}
	if ctrl.epoch != 1 {
		t.Errorf("epoch = %d, want 1", ctrl.epoch)
	}
}

// The ruleset is ordered and first-match-terminating, so a rule the forward
// layer cannot express exactly must not simply be dropped: the traffic it
// covered would be re-decided by whatever follows it. A deny that names a
// protocol and a port ahead of a broad allow is the shape that turns that into
// a bypass on a bridge node, so the deny is installed without its protocol and
// its port instead — blocking more than it asked for, never less.
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
	// this ruleset every forwarded flow to 10.10.0.0/24 is blocked, of every
	// protocol, not only TCP port 22. The operator debugging that has nothing
	// else to go on, so the widening has to be logged — the narrowed-allow
	// counter above never counts a deny.
	if got := logs.String(); !strings.Contains(got, "deny rules widened to every protocol and port") {
		t.Errorf("logs do not report the widened deny:\n%s", got)
	}
}

// IPFORWARD_V4 and IPFORWARD_V6 have no protocol field, and the engine refuses
// a condition on one, so no forward filter may carry a protocol. An allow that
// names one keeps it at the inbound and the outbound layer and gets no forward
// filter; a deny that names one is installed at the forward layer without it. The fake
// refuses a protocol at a forward layer as the engine does, so the apply
// succeeding is part of what this test checks.
func TestWFPController_ApplyRules_ForwardFiltersCarryNoProtocol(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	rules := []FirewallRule{
		{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Protocol: "icmp", Action: "allow"},
		{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::/64", Protocol: "icmp", Action: "allow"},
		{Interface: "plexd0", Protocol: "tcp", Action: "allow"},
		{Interface: "plexd0", Protocol: "tcp", Action: "deny"},
		{Interface: "plexd0", Action: "deny"},
	}
	if err := ctrl.ApplyRules("plexd-mesh", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	var (
		iface = wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: uint64(42)}
		index = wf.Match{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)}
		v6Net = netip.MustParsePrefix("fd00:99::/64")
	)
	proto := func(p wf.IPProto) wf.Match {
		return wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: p}
	}

	// The relay probe permits come first. The three allows yield inbound and
	// outbound filters alone, each with its protocol, since the connect
	// layers carry one. The tcp deny and the default deny name no address,
	// so each yields a filter at all six layers, and the forward ones carry
	// the interface index and nothing else.
	want := []struct {
		name  string
		layer wf.LayerID
		conds []wf.Match
	}{
		{name: "plexd plexd-mesh relay probe", layer: wf.LayerALEAuthConnectV4, conds: relayProbeConds(42)},
		{name: "plexd plexd-mesh relay probe v6", layer: wf.LayerALEAuthConnectV6, conds: relayProbeConds(42)},
		{
			name: "plexd plexd-mesh #0 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
			conds: []wf.Match{
				iface,
				{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
				{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")},
				proto(wf.IPProtoICMP),
			},
		},
		{
			name: "plexd plexd-mesh #0 outbound", layer: wf.LayerALEAuthConnectV4,
			conds: []wf.Match{
				iface,
				{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
				{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.0/24")},
				proto(wf.IPProtoICMP),
			},
		},
		{
			name: "plexd plexd-mesh #1 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6,
			conds: []wf.Match{
				iface,
				v6AddrMatch(wf.FieldIPRemoteAddress, v6Net),
				v6AddrMatch(wf.FieldIPLocalAddress, v6Net),
				proto(wf.IPProtoICMPV6),
			},
		},
		{
			name: "plexd plexd-mesh #1 outbound v6", layer: wf.LayerALEAuthConnectV6,
			conds: []wf.Match{
				iface,
				v6AddrMatch(wf.FieldIPLocalAddress, v6Net),
				v6AddrMatch(wf.FieldIPRemoteAddress, v6Net),
				proto(wf.IPProtoICMPV6),
			},
		},
		{name: "plexd plexd-mesh #2 inbound", layer: wf.LayerALEAuthRecvAcceptV4, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #2 outbound", layer: wf.LayerALEAuthConnectV4, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #2 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #2 outbound v6", layer: wf.LayerALEAuthConnectV6, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #3 inbound", layer: wf.LayerALEAuthRecvAcceptV4, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #3 outbound", layer: wf.LayerALEAuthConnectV4, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #3 forward", layer: wf.LayerIPForwardV4, conds: []wf.Match{index}},
		{name: "plexd plexd-mesh #3 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #3 outbound v6", layer: wf.LayerALEAuthConnectV6, conds: []wf.Match{iface, proto(wf.IPProtoTCP)}},
		{name: "plexd plexd-mesh #3 forward v6", layer: wf.LayerIPForwardV6, conds: []wf.Match{index}},
		{name: "plexd plexd-mesh #4 inbound", layer: wf.LayerALEAuthRecvAcceptV4, conds: []wf.Match{iface}},
		{name: "plexd plexd-mesh #4 outbound", layer: wf.LayerALEAuthConnectV4, conds: []wf.Match{iface}},
		{name: "plexd plexd-mesh #4 forward", layer: wf.LayerIPForwardV4, conds: []wf.Match{index}},
		{name: "plexd plexd-mesh #4 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6, conds: []wf.Match{iface}},
		{name: "plexd plexd-mesh #4 outbound v6", layer: wf.LayerALEAuthConnectV6, conds: []wf.Match{iface}},
		{name: "plexd plexd-mesh #4 forward v6", layer: wf.LayerIPForwardV6, conds: []wf.Match{index}},
	}

	if len(engine.order) != len(want) {
		names := make([]string, 0, len(engine.order))
		for _, id := range engine.order {
			names = append(names, engine.rules[id].Name)
		}
		t.Fatalf("installed %d filters %q, want %d", len(engine.order), names, len(want))
	}
	for i, w := range want {
		got := engine.rules[engine.order[i]]
		if got.Name != w.name {
			t.Errorf("filter %d name = %q, want %q", i, got.Name, w.name)
		}
		if got.Layer != w.layer {
			t.Errorf("filter %q layer = %v, want %v", got.Name, got.Layer, w.layer)
		}
		if c := conds(t, got); !reflect.DeepEqual(c, w.conds) {
			t.Errorf("filter %q conditions =\n%v\nwant\n%v", got.Name, c, w.conds)
		}
	}
}

// The fake has to refuse what the engine refuses, or the test above would pass
// on a forward filter that names a protocol: an empty or mistyped entry in
// wfpLayerFields would turn the check into a no-op without failing anything.
func TestFakeEngine_RefusesFieldTheLayerLacks(t *testing.T) {
	engine := &fakeEngine{rules: make(map[wf.RuleID]*wf.Rule)}

	refused := &wf.Rule{
		Name:       "protocol at the forward layer",
		Layer:      wf.LayerIPForwardV4,
		Conditions: []*wf.Match{{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP}},
	}
	err := engine.AddRule(refused)
	want := fmt.Sprintf("fake engine: field %v not available at layer %v", wf.FieldIPProtocol, wf.LayerIPForwardV4)
	if err == nil || err.Error() != want {
		t.Fatalf("AddRule() error = %v, want %q", err, want)
	}
	if len(engine.order) != 0 || len(engine.rules) != 0 {
		t.Errorf("the fake recorded the refused filter: order %v", engine.order)
	}

	// The interface index at the same layer is taken, so the refusal is the
	// field's, not the layer's.
	accepted := &wf.Rule{
		Name:       "interface index at the forward layer",
		Layer:      wf.LayerIPForwardV4,
		Conditions: []*wf.Match{{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)}},
	}
	if err := engine.AddRule(accepted); err != nil {
		t.Fatalf("AddRule() error = %v, want nil", err)
	}
}

// A rule's addresses choose the layers its filters sit at: an IPv4 rule the
// IPv4 layers, as before IPv6 rules existed, an IPv6 rule the IPv6 layers, and
// a rule without addresses, the default deny, the layers of both, since a WFP
// layer sees one family only. An allow that names a protocol gets the inbound
// and the outbound filter of its family alone, because the forward layers
// have no protocol field. Every filter of a rule carries the rule's weight.
// The relay probe permits ahead of the rule filters sit at both connect layers
// whatever the rule's family.
func TestWFPController_BuildFilters_Families(t *testing.T) {
	type filter struct {
		name  string
		layer wf.LayerID
		conds []wf.Match
	}

	var (
		iface = wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: uint64(42)}
		index = wf.Match{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)}
		v6Net = netip.MustParsePrefix("fd00:99::/64")
		v6One = netip.MustParsePrefix("fd00:99::1/128")
	)
	proto := func(p wf.IPProto) wf.Match {
		return wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: p}
	}

	tests := []struct {
		name   string
		rule   FirewallRule
		action wf.Action
		want   []filter
	}{
		{
			name:   "ipv4 rule",
			rule:   FirewallRule{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Protocol: "udp", Action: "allow"},
			action: wf.ActionPermit,
			want: []filter{
				{
					name: "plexd plexd-mesh #0 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
					conds: []wf.Match{
						iface,
						{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
						{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")},
						proto(wf.IPProtoUDP),
					},
				},
				{
					name: "plexd plexd-mesh #0 outbound", layer: wf.LayerALEAuthConnectV4,
					conds: []wf.Match{
						iface,
						{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
						{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")},
						proto(wf.IPProtoUDP),
					},
				},
			},
		},
		{
			name:   "ipv4 rule without a protocol",
			rule:   FirewallRule{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Action: "allow"},
			action: wf.ActionPermit,
			want: []filter{
				{
					name: "plexd plexd-mesh #0 inbound", layer: wf.LayerALEAuthRecvAcceptV4,
					conds: []wf.Match{
						iface,
						{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
						{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")},
					},
				},
				{
					name: "plexd plexd-mesh #0 outbound", layer: wf.LayerALEAuthConnectV4,
					conds: []wf.Match{
						iface,
						{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
						{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")},
					},
				},
				{
					name: "plexd plexd-mesh #0 forward", layer: wf.LayerIPForwardV4,
					conds: []wf.Match{
						index,
						{Field: wf.FieldIPSourceAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.0.0.0/24")},
						{Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("10.1.0.5/32")},
					},
				},
			},
		},
		{
			name:   "ipv6 rule",
			rule:   FirewallRule{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1", Protocol: "tcp", Action: "allow"},
			action: wf.ActionPermit,
			want: []filter{
				{
					name: "plexd plexd-mesh #0 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6,
					conds: []wf.Match{
						iface,
						v6AddrMatch(wf.FieldIPRemoteAddress, v6Net),
						v6AddrMatch(wf.FieldIPLocalAddress, v6One),
						proto(wf.IPProtoTCP),
					},
				},
				{
					name: "plexd plexd-mesh #0 outbound v6", layer: wf.LayerALEAuthConnectV6,
					conds: []wf.Match{
						iface,
						v6AddrMatch(wf.FieldIPLocalAddress, v6Net),
						v6AddrMatch(wf.FieldIPRemoteAddress, v6One),
						proto(wf.IPProtoTCP),
					},
				},
			},
		},
		{
			// A port range is a wf.Range on the local port of the inbound
			// filter and on the remote port of the outbound one.
			name:   "ipv6 rule with a port range",
			rule:   FirewallRule{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1", Port: 8000, PortTo: 8080, Protocol: "tcp", Action: "allow"},
			action: wf.ActionPermit,
			want: []filter{
				{
					name: "plexd plexd-mesh #0 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6,
					conds: []wf.Match{
						iface,
						v6AddrMatch(wf.FieldIPRemoteAddress, v6Net),
						v6AddrMatch(wf.FieldIPLocalAddress, v6One),
						proto(wf.IPProtoTCP),
						{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeRange, Value: wf.Range{From: uint16(8000), To: uint16(8080)}},
					},
				},
				{
					name: "plexd plexd-mesh #0 outbound v6", layer: wf.LayerALEAuthConnectV6,
					conds: []wf.Match{
						iface,
						v6AddrMatch(wf.FieldIPLocalAddress, v6Net),
						v6AddrMatch(wf.FieldIPRemoteAddress, v6One),
						proto(wf.IPProtoTCP),
						{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeRange, Value: wf.Range{From: uint16(8000), To: uint16(8080)}},
					},
				},
			},
		},
		{
			// ::/0 is every IPv6 address: the layer selects the family, so the
			// side it names carries no address condition.
			name:   "ipv6 rule with every source",
			rule:   FirewallRule{Interface: "plexd0", SrcIP: "::/0", DstIP: "fd00:99::/64", Action: "allow"},
			action: wf.ActionPermit,
			want: []filter{
				{
					name: "plexd plexd-mesh #0 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6,
					conds: []wf.Match{iface, v6AddrMatch(wf.FieldIPLocalAddress, v6Net)},
				},
				{
					name: "plexd plexd-mesh #0 outbound v6", layer: wf.LayerALEAuthConnectV6,
					conds: []wf.Match{iface, v6AddrMatch(wf.FieldIPRemoteAddress, v6Net)},
				},
				{
					name: "plexd plexd-mesh #0 forward v6", layer: wf.LayerIPForwardV6,
					conds: []wf.Match{index, v6AddrMatch(wf.FieldIPDestinationAddress, v6Net)},
				},
			},
		},
		{
			// icmp in an IPv6 rule means ICMPv6, a protocol of its own number.
			// The allow names a protocol, so it has no forward filter.
			name:   "ipv6 icmp rule",
			rule:   FirewallRule{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::/64", Protocol: "icmp", Action: "allow"},
			action: wf.ActionPermit,
			want: []filter{
				{
					name: "plexd plexd-mesh #0 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6,
					conds: []wf.Match{
						iface,
						v6AddrMatch(wf.FieldIPRemoteAddress, v6Net),
						v6AddrMatch(wf.FieldIPLocalAddress, v6Net),
						proto(wf.IPProtoICMPV6),
					},
				},
				{
					name: "plexd plexd-mesh #0 outbound v6", layer: wf.LayerALEAuthConnectV6,
					conds: []wf.Match{
						iface,
						v6AddrMatch(wf.FieldIPLocalAddress, v6Net),
						v6AddrMatch(wf.FieldIPRemoteAddress, v6Net),
						proto(wf.IPProtoICMPV6),
					},
				},
			},
		},
		{
			// Six filters: one at each RECV_ACCEPT, CONNECT and IPFORWARD
			// layer of both families.
			name:   "default deny",
			rule:   FirewallRule{Interface: "plexd0", Action: "deny"},
			action: wf.ActionBlock,
			want: []filter{
				{name: "plexd plexd-mesh #0 inbound", layer: wf.LayerALEAuthRecvAcceptV4, conds: []wf.Match{iface}},
				{name: "plexd plexd-mesh #0 outbound", layer: wf.LayerALEAuthConnectV4, conds: []wf.Match{iface}},
				{name: "plexd plexd-mesh #0 forward", layer: wf.LayerIPForwardV4, conds: []wf.Match{index}},
				{name: "plexd plexd-mesh #0 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6, conds: []wf.Match{iface}},
				{name: "plexd plexd-mesh #0 outbound v6", layer: wf.LayerALEAuthConnectV6, conds: []wf.Match{iface}},
				{name: "plexd plexd-mesh #0 forward v6", layer: wf.LayerIPForwardV6, conds: []wf.Match{index}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _, _ := newTestWFPController(t)

			all, err := ctrl.buildFilters("plexd-mesh", []FirewallRule{tt.rule}, 1)
			if err != nil {
				t.Fatalf("buildFilters() error = %v, want nil", err)
			}
			checkEngineTakes(t, all)
			filters := checkRelayProbes(t, all, "plexd-mesh", 1, 1, 42)
			if len(filters) != len(tt.want) {
				names := make([]string, 0, len(filters))
				for _, f := range filters {
					names = append(names, f.Name)
				}
				t.Fatalf("buildFilters() built %d rule filters %q, want %d", len(filters), names, len(tt.want))
			}

			weight := wfpWeight(1, 1, 0)
			for i, want := range tt.want {
				got := filters[i]
				if got.Name != want.name {
					t.Errorf("filter %d name = %q, want %q", i, got.Name, want.name)
				}
				if got.Layer != want.layer {
					t.Errorf("filter %q layer = %v, want %v", got.Name, got.Layer, want.layer)
				}
				if got.Sublayer != plexdSublayerID {
					t.Errorf("filter %q sublayer = %v, want %v", got.Name, got.Sublayer, plexdSublayerID)
				}
				if got.Action != tt.action {
					t.Errorf("filter %q action = %v, want %v", got.Name, got.Action, tt.action)
				}
				if got.Weight != weight {
					t.Errorf("filter %q weight = %#x, want %#x", got.Name, got.Weight, weight)
				}
				if c := conds(t, got); !reflect.DeepEqual(c, want.conds) {
					t.Errorf("filter %q conditions =\n%v\nwant\n%v", got.Name, c, want.conds)
				}
			}
		})
	}
}

// The forward layer's two warnings name how many rules lost their protocol or
// port there, not how many filters: a rule without addresses yields a filter
// per family at each layer, but it is one rule the operator has to look for.
// A rule that names a protocol and no port counts too, since the forward
// layers carry neither a protocol nor a port.
func TestWFPController_BuildFilters_CountsRulesNotFilters(t *testing.T) {
	ctrl, _, _ := newTestWFPController(t)
	var logs bytes.Buffer
	ctrl.logger = slog.New(slog.NewTextHandler(&logs, nil))

	rules := []FirewallRule{
		{Interface: "plexd0", Port: 22, Protocol: "tcp", Action: "deny"},
		{Interface: "plexd0", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: "plexd0", Protocol: "udp", Action: "deny"},
		{Interface: "plexd0", Protocol: "udp", Action: "allow"},
	}
	filters, err := ctrl.buildFilters("plexd-mesh", rules, 1)
	if err != nil {
		t.Fatalf("buildFilters() error = %v, want nil", err)
	}
	checkEngineTakes(t, filters)

	// The denies keep their forward filters, widened to every protocol and
	// port; the allows have none. Every rule has its outbound filters, whose
	// layers carry the protocol and the port, so they count toward neither
	// warning.
	var names []string
	for _, f := range filters {
		names = append(names, f.Name)
	}
	want := []string{
		"plexd plexd-mesh relay probe",
		"plexd plexd-mesh relay probe v6",
		"plexd plexd-mesh #0 inbound",
		"plexd plexd-mesh #0 outbound",
		"plexd plexd-mesh #0 forward",
		"plexd plexd-mesh #0 inbound v6",
		"plexd plexd-mesh #0 outbound v6",
		"plexd plexd-mesh #0 forward v6",
		"plexd plexd-mesh #1 inbound",
		"plexd plexd-mesh #1 outbound",
		"plexd plexd-mesh #1 inbound v6",
		"plexd plexd-mesh #1 outbound v6",
		"plexd plexd-mesh #2 inbound",
		"plexd plexd-mesh #2 outbound",
		"plexd plexd-mesh #2 forward",
		"plexd plexd-mesh #2 inbound v6",
		"plexd plexd-mesh #2 outbound v6",
		"plexd plexd-mesh #2 forward v6",
		"plexd plexd-mesh #3 inbound",
		"plexd plexd-mesh #3 outbound",
		"plexd plexd-mesh #3 inbound v6",
		"plexd plexd-mesh #3 outbound v6",
	}
	if !slices.Equal(names, want) {
		t.Errorf("buildFilters() built %q, want %q", names, want)
	}

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	for _, msg := range []string{
		"allow rules narrowed away",
		"deny rules widened to every protocol and port",
	} {
		found := false
		for _, line := range lines {
			if !strings.Contains(line, msg) {
				continue
			}
			found = true
			if !strings.HasSuffix(line, " count=2") {
				t.Errorf("warning %q does not count two rules: %s", msg, line)
			}
		}
		if !found {
			t.Errorf("logs miss the warning %q:\n%s", msg, logs.String())
		}
	}
}

// The relay probe permits come once per interface the rules name, in the order
// the interfaces first appear, and ahead of every rule filter. They outweigh
// rule 0, so a rule that denies UDP to port 9 still leaves the probe alone.
func TestWFPController_BuildFilters_RelayProbe(t *testing.T) {
	ctrl, _, _ := newTestWFPController(t)

	rules := []FirewallRule{
		{Interface: "plexd0", DstIP: "10.1.0.0/24", Port: 9, Protocol: "udp", Action: "deny"},
		{Interface: "Ethernet", Action: "deny"},
		{Interface: "plexd0", Action: "deny"},
	}
	filters, err := ctrl.buildFilters("plexd-mesh", rules, 3)
	if err != nil {
		t.Fatalf("buildFilters() error = %v, want nil", err)
	}
	checkEngineTakes(t, filters)

	// plexd0 has LUID 42 and Ethernet LUID 7 in the fake lookup.
	rest := checkRelayProbes(t, filters, "plexd-mesh", 3, len(rules), 42, 7)
	if len(rest) == 0 {
		t.Fatal("buildFilters() built the relay probe permits alone, want the rule filters after them")
	}
	if rest[0].Name != "plexd plexd-mesh #0 inbound" {
		t.Errorf("the relay probe permits are followed by %q, want rule 0's inbound filter", rest[0].Name)
	}
	for _, f := range rest {
		if strings.Contains(f.Name, "relay probe") {
			t.Errorf("buildFilters() built %q among the rule filters, want the permits once per interface ahead of them", f.Name)
		}
	}
	if probe, deny := filters[0].Weight, wfpWeight(3, len(rules), 0); probe <= deny {
		t.Errorf("relay probe weight = %#x, want more than rule 0's %#x", probe, deny)
	}
}

// A chain without rules names no interface, so it gets no relay probe permit
// either, and an apply of it leaves the chain without a filter.
func TestWFPController_BuildFilters_NoRules(t *testing.T) {
	for _, rules := range [][]FirewallRule{nil, {}} {
		ctrl, _, _ := newTestWFPController(t)

		filters, err := ctrl.buildFilters("plexd-mesh", rules, 1)
		if err != nil {
			t.Errorf("buildFilters(%#v) error = %v, want nil", rules, err)
		}
		if len(filters) != 0 {
			t.Errorf("buildFilters(%#v) built %d filters, want none", rules, len(filters))
		}
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
	// The first three rules yield eight filters: the two relay probe permits
	// and an inbound and an outbound filter per rule. Each is an allow that
	// names a protocol, so none of them gets a forward filter.
	if len(first) != 8 {
		t.Fatalf("the first apply installed %d filters, want 8", len(first))
	}

	// The last three yield eleven: the two permits and an inbound, an
	// outbound and a forward filter per rule.
	if err := ctrl.ApplyRules("plexd-mesh", sixRules[3:]); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	second := ctrl.chains["plexd-mesh"]
	if len(second) != 11 {
		t.Fatalf("the second apply left %d filters, want 11", len(second))
	}
	for _, id := range second {
		if got := engine.rules[id].Weight >> 32; got != 2 {
			t.Errorf("filter %q epoch = %d, want 2", engine.rules[id].Name, got)
		}
	}

	if !slices.Equal(engine.deleted, first) {
		t.Errorf("deleted = %v, want the filters of the first apply %v", engine.deleted, first)
	}
	if len(engine.order) != 19 {
		t.Fatalf("added %d filters over both applies, want 19", len(engine.order))
	}
	// The chain is never unfiltered: every stale filter went after all
	// nineteen filters had been added.
	for i, added := range engine.deletedAfter {
		if added != 19 {
			t.Errorf("deletion %d ran after %d additions, want 19", i, added)
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

// An IPv6 rule is installed at the IPv6 layers alone: a WFP layer sees one
// family, and the IPv4 layers would never see a packet the rule names. Only
// the relay probe permits of its interface sit at an IPv4 layer.
func TestWFPController_ApplyRules_IPv6Address(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)

	if err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "plexd0", SrcIP: "fd00::/64", Action: "allow"}}); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if got := len(engine.order); got != 5 {
		t.Fatalf("installed %d filters, want 5: the two relay probe permits and three for the rule", got)
	}

	src := netip.MustParsePrefix("fd00::/64")
	tests := []struct {
		name  string
		layer wf.LayerID
		conds []wf.Match
	}{
		{
			name: "plexd plexd-mesh #0 inbound v6", layer: wf.LayerALEAuthRecvAcceptV6,
			conds: []wf.Match{
				{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: uint64(42)},
				v6AddrMatch(wf.FieldIPRemoteAddress, src),
			},
		},
		{
			name: "plexd plexd-mesh #0 outbound v6", layer: wf.LayerALEAuthConnectV6,
			conds: []wf.Match{
				{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: uint64(42)},
				v6AddrMatch(wf.FieldIPLocalAddress, src),
			},
		},
		{
			name: "plexd plexd-mesh #0 forward v6", layer: wf.LayerIPForwardV6,
			conds: []wf.Match{
				{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: uint32(12)},
				v6AddrMatch(wf.FieldIPSourceAddress, src),
			},
		},
	}
	for _, tt := range tests {
		r := mustFilter(t, engine, tt.name)
		if r.Layer != tt.layer {
			t.Errorf("filter %q layer = %v, want %v", tt.name, r.Layer, tt.layer)
		}
		if r.Action != wf.ActionPermit {
			t.Errorf("filter %q action = %v, want %v", tt.name, r.Action, wf.ActionPermit)
		}
		if got := conds(t, r); !reflect.DeepEqual(got, tt.conds) {
			t.Errorf("filter %q conditions =\n%v\nwant\n%v", tt.name, got, tt.conds)
		}
	}
}

// A mapped address names an IPv4 host through an IPv6 address, which neither
// family's layers can match as the rule meant, so the rule is refused before
// any filter reaches the engine.
func TestWFPController_ApplyRules_MappedAddress(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Interface: "plexd0", SrcIP: "::ffff:10.0.0.1/128", Action: "allow"}})
	want := `policy: wfp: apply rules: rule 0: policy: firewall rule: IPv4-mapped IPv6 address "::ffff:10.0.0.1/128"`
	if err.Error() != want {
		t.Errorf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestWFPController_ApplyRules_InvalidAddress(t *testing.T) {
	err := applyRejected(t, "plexd-mesh", []FirewallRule{{Interface: "plexd0", DstIP: "bogus", Action: "allow"}})
	want := `policy: wfp: apply rules: rule 0: policy: firewall rule: invalid IP address "bogus"`
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

	// The second apply installs the two relay probe permits and then rule 0's
	// inbound filter, so its fourth AddRule is the first outbound filter of a
	// rule, and three filters are already installed when it fails.
	engine.addRuleErr = windows.ERROR_ACCESS_DENIED
	engine.addRuleErrAt = 4

	err := ctrl.ApplyRules("plexd-mesh", sixRules[3:])
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("ApplyRules() error = %v, want ERROR_ACCESS_DENIED", err)
	}
	want := `policy: wfp: apply rules: add filter "plexd plexd-mesh #0 outbound":`
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ApplyRules() error = %v, want the prefix %q", err, want)
	}
	if !strings.HasSuffix(err.Error(), "(policy enforcement on Windows requires Administrator)") {
		t.Errorf("ApplyRules() error = %v, want the Administrator hint", err)
	}

	if got := len(engine.order) - len(installed); got != 3 {
		t.Errorf("the failed apply added %d filters before the failure, want 3", got)
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
	if got := len(ctrl.chains["plexd-mesh"]); got != 11 {
		t.Errorf("chain plexd-mesh holds %d filters, want the 11 of the second apply", got)
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
	// Index -1, the relay probe permits, sits one above rule 0.
	if got, want := wfpWeight(3, 6, -1), uint64(3)<<32|7; got != want {
		t.Errorf("wfpWeight(3, 6, -1) = %#x, want %#x", got, want)
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
// Administrator. The rules with addresses cover prefixes no host carries, and
// the default deny sits below an allow of everything on the same interface:
// within plexd's sublayer the heaviest matching filter decides, so the deny
// never does and the runner's own traffic, inbound and outbound, is
// untouched. The relay probe permits pass UDP to port 9 alone. The dynamic
// session drops every filter again when it closes.
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

	rules := []FirewallRule{
		{Interface: iface, SrcIP: "10.255.252.0/30", DstIP: "10.255.252.4/30", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: iface, SrcIP: "10.255.252.8/30", DstIP: "0.0.0.0/0", Action: "deny"},
		{Interface: iface, SrcIP: "fd00:255:252::/64", DstIP: "fd00:255:252:1::/64", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: iface, SrcIP: "fd00:255:252:2::/64", DstIP: "::/0", Protocol: "icmp", Action: "allow"},
		{Interface: iface, SrcIP: "fd00:255:252:8::/64", DstIP: "fd00:255:252:9::/64", Action: "allow"},
		{Interface: iface, Action: "allow"},
		{Interface: iface, Action: "deny"},
	}

	t.Cleanup(func() {
		// DeleteChain deletes in installation order, which would leave the
		// default deny alone on the runner's interface between the deletion
		// of the allow's filters and of its own. A test that failed with the
		// deny installed therefore first replaces the ruleset with the allow
		// of everything alone, so the deny goes while the allow still stands.
		if len(ctrl.chains["plexd-test"]) > 0 {
			if err := ctrl.ApplyRules("plexd-test", rules[5:6]); err != nil {
				t.Errorf("cleanup ApplyRules() of the allow alone error = %v", err)
			}
		}
		if err := ctrl.DeleteChain("plexd-test"); err != nil {
			t.Errorf("cleanup DeleteChain() error = %v", err)
		}
	})

	if err := ctrl.EnsureChain("plexd-test"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	// The plan of #176 assumes the engine takes plexd's conditions at the
	// IPv6 layers as it does at the IPv4 ones: the interface LUID, IPv6
	// prefixes, ICMPv6 and the local port at ALE_AUTH_RECV_ACCEPT_V6, the
	// interface index at IPFORWARD_V6. An error that names a " v6" filter
	// means that assumption failed, not this test: report it, and do not
	// narrow the rules until the engine takes them. A protocol or a port at
	// a forward layer is not that failure: IPFORWARD_V4 and IPFORWARD_V6
	// both lack the fields, buildFilters puts neither there, and fakeEngine
	// refuses them, so the unit tests catch such a filter first. The plan of
	// #178 assumes the same of ALE_AUTH_CONNECT_V4 and _V6: the interface
	// LUID, both addresses, the protocol and the remote port. An error that
	// names an "outbound" or a "relay probe" filter means that assumption
	// failed, and is reported the same way.
	if err := ctrl.ApplyRules("plexd-test", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	// checkInstalled fails unless the filter engine holds exactly the named
	// plexd filters, each at its layer and in plexd's sublayer, and returns
	// them.
	checkInstalled := func(want map[string]wf.LayerID) []*wf.Rule {
		t.Helper()

		installed := plexdFilters()
		if len(installed) != len(want) {
			t.Fatalf("the filter engine holds %d plexd filters, want %d: %v", len(installed), len(want), installed)
		}
		for name, layer := range want {
			found := false
			for _, r := range installed {
				if r.Name != name {
					continue
				}
				found = true
				if r.Layer != layer {
					t.Errorf("filter %q layer = %v, want %v", name, r.Layer, layer)
				}
				if r.Sublayer != plexdSublayerID {
					t.Errorf("filter %q sublayer = %v, want %v", name, r.Sublayer, plexdSublayerID)
				}
			}
			if !found {
				t.Errorf("the filter engine holds no filter %q: %v", name, installed)
			}
		}
		return installed
	}

	// Rules 0, 2 and 3 are allows naming a protocol, 0 and 2 a port as well,
	// which the forward layers cannot express, so they have no forward
	// filter. Rule 4 names IPv6 addresses alone, so IPFORWARD_V6 takes an
	// IPv6 prefix from it, as it does from an address-only IPv6 rule in
	// production. Every rule has an outbound filter at the connect layer of
	// its family, and the engine takes the protocol and the remote port
	// there. The two rules without addresses have a filter at each of the six
	// layers. The relay probe permits of the runner's interface come once.
	withoutDeny := map[string]wf.LayerID{
		"plexd plexd-test relay probe":    wf.LayerALEAuthConnectV4,
		"plexd plexd-test relay probe v6": wf.LayerALEAuthConnectV6,
		"plexd plexd-test #0 inbound":     wf.LayerALEAuthRecvAcceptV4,
		"plexd plexd-test #0 outbound":    wf.LayerALEAuthConnectV4,
		"plexd plexd-test #1 inbound":     wf.LayerALEAuthRecvAcceptV4,
		"plexd plexd-test #1 outbound":    wf.LayerALEAuthConnectV4,
		"plexd plexd-test #1 forward":     wf.LayerIPForwardV4,
		"plexd plexd-test #2 inbound v6":  wf.LayerALEAuthRecvAcceptV6,
		"plexd plexd-test #2 outbound v6": wf.LayerALEAuthConnectV6,
		"plexd plexd-test #3 inbound v6":  wf.LayerALEAuthRecvAcceptV6,
		"plexd plexd-test #3 outbound v6": wf.LayerALEAuthConnectV6,
		"plexd plexd-test #4 inbound v6":  wf.LayerALEAuthRecvAcceptV6,
		"plexd plexd-test #4 outbound v6": wf.LayerALEAuthConnectV6,
		"plexd plexd-test #4 forward v6":  wf.LayerIPForwardV6,
		"plexd plexd-test #5 inbound":     wf.LayerALEAuthRecvAcceptV4,
		"plexd plexd-test #5 outbound":    wf.LayerALEAuthConnectV4,
		"plexd plexd-test #5 forward":     wf.LayerIPForwardV4,
		"plexd plexd-test #5 inbound v6":  wf.LayerALEAuthRecvAcceptV6,
		"plexd plexd-test #5 outbound v6": wf.LayerALEAuthConnectV6,
		"plexd plexd-test #5 forward v6":  wf.LayerIPForwardV6,
	}
	withDeny := maps.Clone(withoutDeny)
	withDeny["plexd plexd-test #6 inbound"] = wf.LayerALEAuthRecvAcceptV4
	withDeny["plexd plexd-test #6 outbound"] = wf.LayerALEAuthConnectV4
	withDeny["plexd plexd-test #6 forward"] = wf.LayerIPForwardV4
	withDeny["plexd plexd-test #6 inbound v6"] = wf.LayerALEAuthRecvAcceptV6
	withDeny["plexd plexd-test #6 outbound v6"] = wf.LayerALEAuthConnectV6
	withDeny["plexd plexd-test #6 forward v6"] = wf.LayerIPForwardV6
	installed := checkInstalled(withDeny)

	// The default deny's outbound filters block what the runner sends over
	// its own interface unless the allow of everything outweighs them. This
	// test cannot read a weight back to show that: github.com/tailscale/wf
	// declares FWPM_FILTER0's union of rawContext and providerContextKey as two
	// fields, so it reads effectiveWeight 8 bytes off and reports 0 for every
	// filter. The unit tests pin each filter's weight through the fake engine,
	// and TestWFPController_RealTraffic shows on the real engine that a permit
	// at ALE_AUTH_CONNECT outweighs the default deny. Here the allow's
	// outbound filters have to be permits.
	named := func(name string) *wf.Rule {
		t.Helper()

		for _, r := range installed {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("the filter engine holds no filter %q", name)
		return nil
	}
	for _, suffix := range []string{"", " v6"} {
		allow := named("plexd plexd-test #5 outbound" + suffix)
		if allow.Action != wf.ActionPermit {
			t.Errorf("filter %q action = %v, want %v", allow.Name, allow.Action, wf.ActionPermit)
		}
	}

	// DeleteChain deletes in installation order, which would leave the deny
	// alone on the runner's interface between the deletion of the allow's
	// filters and of its own. A ruleset without the deny replaces it instead:
	// the new filters outweigh the old ones before any of them goes, and the
	// stale filters, those at the IPv6 layers among them, are deleted.
	if err := ctrl.ApplyRules("plexd-test", rules[:6]); err != nil {
		t.Fatalf("ApplyRules() without the deny error = %v, want nil", err)
	}
	checkInstalled(withoutDeny)

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

// A logged rule is enforced like any other on Windows, and every apply that
// holds one logs that its connections are not logged.
func TestWFPController_ApplyRules_LoggedRulesWarn(t *testing.T) {
	ctrl, engine, _ := newTestWFPController(t)
	var buf bytes.Buffer
	ctrl.logger = captureLogger(&buf)

	logged := []FirewallRule{
		{Interface: "plexd0", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5/32", Port: 443, Protocol: "tcp", Action: "allow", LogTag: "1/0"},
		{Interface: "plexd0", Action: "deny"},
	}
	untagged := withoutLogTags(logged)

	if err := ctrl.ApplyRules("plexd-mesh", untagged); err != nil {
		t.Fatalf("ApplyRules() of untagged rules error = %v", err)
	}
	if strings.Contains(buf.String(), connLogUnavailable) {
		t.Errorf("an untagged apply logged %q", buf.String())
	}
	untaggedFilters := len(engine.rules)

	for range 2 {
		if err := ctrl.ApplyRules("plexd-mesh", logged); err != nil {
			t.Fatalf("ApplyRules() of a logged rule error = %v", err)
		}
	}
	const want = `level=WARN msg="policy connection logging unavailable, logged rules are enforced without it" component=policy chain=plexd-mesh error="policy: wfp: connection logging is not available on Windows"`
	if n := strings.Count(buf.String(), want); n != 2 {
		t.Errorf("two logged applies logged %d lines containing %q, want 2:\n%s", n, want, buf.String())
	}
	if len(engine.rules) != untaggedFilters {
		t.Errorf("a logged apply installed %d filters, want %d, the same as without the tag", len(engine.rules), untaggedFilters)
	}
}
