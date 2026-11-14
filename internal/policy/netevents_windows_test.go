//go:build windows

package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WFPController reports the connections its logged filters permit.
var _ ConnReporter = (*WFPController)(nil)

// wfpOptionSet is one setOption call a fakeNetEvents saw.
type wfpOptionSet struct {
	id, value uint32
}

// fakeNetEvents is a netEventSession that holds the two engine options in
// memory. sets records every setOption call, the failed ones too, and onSet
// runs before a call takes effect, so a test sees the state directory as it
// was at that moment. handler is the function subscribe was given, which a
// test calls in place of the engine.
type fakeNetEvents struct {
	opts  map[uint32]uint32
	sets  []wfpOptionSet
	onSet func(id, value uint32)

	handler                          func(allowEvent)
	subscribes, unsubscribes, closes int

	optionErr, setErr, subscribeErr, unsubscribeErr, closeErr error
}

func (f *fakeNetEvents) option(id uint32) (uint32, error) {
	if f.optionErr != nil {
		return 0, f.optionErr
	}
	return f.opts[id], nil
}

func (f *fakeNetEvents) setOption(id, value uint32) error {
	f.sets = append(f.sets, wfpOptionSet{id: id, value: value})
	if f.onSet != nil {
		f.onSet(id, value)
	}
	if f.setErr != nil {
		return f.setErr
	}
	f.opts[id] = value
	return nil
}

func (f *fakeNetEvents) subscribe(fn func(allowEvent)) error {
	f.subscribes++
	if f.subscribeErr != nil {
		return f.subscribeErr
	}
	f.handler = fn
	return nil
}

func (f *fakeNetEvents) unsubscribe() error {
	f.unsubscribes++
	if f.unsubscribeErr != nil {
		return f.unsubscribeErr
	}
	f.handler = nil
	return nil
}

func (f *fakeNetEvents) close() error {
	f.closes++
	f.handler = nil
	return f.closeErr
}

// wfpTestSink records what a controller reports.
type wfpTestSink struct {
	mu     sync.Mutex
	events []ConnEvent
}

func (s *wfpTestSink) Event(ev ConnEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *wfpTestSink) Lost(int) {}

func (s *wfpTestSink) got() []ConnEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

// wfpLogFixture is a controller wired for connection logging: the fake filter
// engine, a fake net event session at the given options, a state directory, a
// recording sink and a buffer that collects Info lines and up.
type wfpLogFixture struct {
	ctrl   *WFPController
	engine *fakeEngine
	events *fakeNetEvents
	sink   *wfpTestSink
	logs   *bytes.Buffer
	dir    string
	opens  int
}

func newWFPLogFixture(t *testing.T, collect, keywords uint32) *wfpLogFixture {
	t.Helper()

	ctrl, engine, _ := newTestWFPController(t)
	f := &wfpLogFixture{
		ctrl:   ctrl,
		engine: engine,
		events: newFakeNetEvents(collect, keywords),
		sink:   &wfpTestSink{},
		logs:   &bytes.Buffer{},
		dir:    t.TempDir(),
	}
	ctrl.logger = captureLogger(f.logs)
	ctrl.openNetEvents = func() (netEventSession, error) {
		f.opens++
		return f.events, nil
	}
	ctrl.SetStateDir(f.dir)
	ctrl.SetConnSink(f.sink)
	return f
}

func newFakeNetEvents(collect, keywords uint32) *fakeNetEvents {
	return &fakeNetEvents{opts: map[uint32]uint32{
		fwpmEngineCollectNetEvents:         collect,
		fwpmEngineNetEventMatchAnyKeywords: keywords,
	}}
}

func (f *wfpLogFixture) recordPath() string {
	return filepath.Join(f.dir, wfpAllowEventsFile)
}

// writeRecord writes the record a crashed run would have left behind.
func (f *wfpLogFixture) writeRecord(t *testing.T, content string) {
	t.Helper()

	if err := os.WriteFile(f.recordPath(), []byte(content), 0o600); err != nil {
		t.Fatalf("writing the record: %v", err)
	}
}

// readRecord returns the record's content, or "" when there is none.
func (f *wfpLogFixture) readRecord(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(f.recordPath())
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("reading the record: %v", err)
	}
	return string(data)
}

func (f *wfpLogFixture) enable() error {
	f.ctrl.mu.Lock()
	defer f.ctrl.mu.Unlock()
	return f.ctrl.enableAllowEvents()
}

func (f *wfpLogFixture) restore() error {
	f.ctrl.mu.Lock()
	defer f.ctrl.mu.Unlock()
	return f.ctrl.restoreAllowEvents()
}

// loggedRules is a ruleset with one logged rule, TCP from the peer to the
// node's port 7001, and the default deny.
var loggedRules = []FirewallRule{
	{Interface: "plexd0", SrcIP: "10.99.0.3/32", DstIP: "10.99.0.1/32", Port: 7001, Protocol: "tcp", Action: "allow", LogTag: "1/0"},
	{Interface: "plexd0", Action: "deny"},
}

// The structs are read from and handed to fwpuclnt.dll, so each has to sit
// in memory as the Windows SDK lays it out. The values are what fwptypes.h
// and fwpmtypes.h imply on 64-bit Windows, with 8-byte pointers, 8-byte
// alignment for a UINT64 and 4-byte alignment for a GUID. The offsets of
// FWPM_NET_EVENT5 are the ones the events of run 43612480437 carried.
func TestNetEventLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the layouts are pinned for 64-bit Windows")
	}

	var (
		value  fwpValue0
		filter fwpmFilter0
		header fwpmNetEventHeader3
		event  fwpmNetEvent5
		allow  fwpmNetEventClassifyAllow0
		sub    fwpmNetEventSubscription0
	)
	for _, tt := range []struct {
		name      string
		got, want uintptr
	}{
		{name: "sizeof FWP_VALUE0", got: unsafe.Sizeof(value), want: 16},
		{name: "FWP_VALUE0 union", got: unsafe.Offsetof(value.Value), want: 8},
		{name: "sizeof FWP_BYTE_BLOB", got: unsafe.Sizeof(fwpByteBlob{}), want: 16},
		{name: "sizeof FWPM_ACTION0", got: unsafe.Sizeof(fwpmAction0{}), want: 20},

		{name: "sizeof FWPM_FILTER0", got: unsafe.Sizeof(filter), want: 200},
		{name: "FWPM_FILTER0.filterKey", got: unsafe.Offsetof(filter.FilterKey), want: 0},
		{name: "FWPM_FILTER0.providerData", got: unsafe.Offsetof(filter.ProviderData), want: 48},
		{name: "FWPM_FILTER0.layerKey", got: unsafe.Offsetof(filter.LayerKey), want: 64},
		{name: "FWPM_FILTER0.weight", got: unsafe.Offsetof(filter.Weight), want: 96},
		{name: "FWPM_FILTER0.filterCondition", got: unsafe.Offsetof(filter.FilterCondition), want: 120},
		{name: "FWPM_FILTER0.action", got: unsafe.Offsetof(filter.Action), want: 128},
		{name: "FWPM_FILTER0 context union", got: unsafe.Offsetof(filter.ProviderContext), want: 152},
		{name: "FWPM_FILTER0.reserved", got: unsafe.Offsetof(filter.Reserved), want: 168},
		{name: "FWPM_FILTER0.filterId", got: unsafe.Offsetof(filter.FilterID), want: 176},
		{name: "FWPM_FILTER0.effectiveWeight", got: unsafe.Offsetof(filter.EffectiveWeight), want: 184},

		{name: "sizeof FWPM_NET_EVENT_HEADER3", got: unsafe.Sizeof(header), want: 136},
		{name: "FWPM_NET_EVENT_HEADER3.flags", got: unsafe.Offsetof(header.Flags), want: 8},
		{name: "FWPM_NET_EVENT_HEADER3.ipVersion", got: unsafe.Offsetof(header.IPVersion), want: 12},
		{name: "FWPM_NET_EVENT_HEADER3.ipProtocol", got: unsafe.Offsetof(header.IPProtocol), want: 16},
		{name: "FWPM_NET_EVENT_HEADER3 local address union", got: unsafe.Offsetof(header.LocalAddr), want: 20},
		{name: "FWPM_NET_EVENT_HEADER3 remote address union", got: unsafe.Offsetof(header.RemoteAddr), want: 36},
		{name: "FWPM_NET_EVENT_HEADER3.localPort", got: unsafe.Offsetof(header.LocalPort), want: 52},
		{name: "FWPM_NET_EVENT_HEADER3.remotePort", got: unsafe.Offsetof(header.RemotePort), want: 54},
		{name: "FWPM_NET_EVENT_HEADER3.scopeId", got: unsafe.Offsetof(header.ScopeID), want: 56},
		{name: "FWPM_NET_EVENT_HEADER3.appId", got: unsafe.Offsetof(header.AppID), want: 64},
		{name: "FWPM_NET_EVENT_HEADER3.userId", got: unsafe.Offsetof(header.UserID), want: 80},
		{name: "FWPM_NET_EVENT_HEADER3.addressFamily", got: unsafe.Offsetof(header.AddressFamily), want: 88},
		{name: "FWPM_NET_EVENT_HEADER3.packageSid", got: unsafe.Offsetof(header.PackageSID), want: 96},
		{name: "FWPM_NET_EVENT_HEADER3.enterpriseId", got: unsafe.Offsetof(header.EnterpriseID), want: 104},
		{name: "FWPM_NET_EVENT_HEADER3.policyFlags", got: unsafe.Offsetof(header.PolicyFlags), want: 112},
		{name: "FWPM_NET_EVENT_HEADER3.effectiveName", got: unsafe.Offsetof(header.EffectiveName), want: 120},

		{name: "sizeof FWPM_NET_EVENT5", got: unsafe.Sizeof(event), want: 152},
		{name: "FWPM_NET_EVENT5.type", got: unsafe.Offsetof(event.Type), want: 136},
		{name: "FWPM_NET_EVENT5 detail union", got: unsafe.Offsetof(event.ClassifyAllow), want: 144},

		{name: "sizeof FWPM_NET_EVENT_CLASSIFY_ALLOW0", got: unsafe.Sizeof(allow), want: 32},
		{name: "FWPM_NET_EVENT_CLASSIFY_ALLOW0.layerId", got: unsafe.Offsetof(allow.LayerID), want: 8},
		{name: "FWPM_NET_EVENT_CLASSIFY_ALLOW0.reauthReason", got: unsafe.Offsetof(allow.ReauthReason), want: 12},
		{name: "FWPM_NET_EVENT_CLASSIFY_ALLOW0.msFwpDirection", got: unsafe.Offsetof(allow.MsFwpDirection), want: 24},
		{name: "FWPM_NET_EVENT_CLASSIFY_ALLOW0.isLoopback", got: unsafe.Offsetof(allow.IsLoopback), want: 28},

		{name: "sizeof FWPM_NET_EVENT_SUBSCRIPTION0", got: unsafe.Sizeof(sub), want: 32},
		{name: "FWPM_NET_EVENT_SUBSCRIPTION0.flags", got: unsafe.Offsetof(sub.Flags), want: 8},
		{name: "FWPM_NET_EVENT_SUBSCRIPTION0.sessionKey", got: unsafe.Offsetof(sub.SessionKey), want: 12},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

// v4Event returns a classify-allow event of IPv4 TCP as the engine hands it
// to the callback: each address as a UINT32 in host byte order.
func v4Event(filterID uint64, local, remote netip.Addr, localPort, remotePort uint16) *fwpmNetEvent5 {
	ev := &fwpmNetEvent5{
		Type:          fwpmNetEventTypeClassifyAllow,
		ClassifyAllow: &fwpmNetEventClassifyAllow0{FilterID: filterID},
	}
	ev.Header.IPVersion = fwpIPVersionV4
	ev.Header.IPProtocol = ipProtoTCP
	l, r := local.As4(), remote.As4()
	binary.LittleEndian.PutUint32(ev.Header.LocalAddr[:4], binary.BigEndian.Uint32(l[:]))
	binary.LittleEndian.PutUint32(ev.Header.RemoteAddr[:4], binary.BigEndian.Uint32(r[:]))
	ev.Header.LocalPort = localPort
	ev.Header.RemotePort = remotePort
	return ev
}

// recordedEvent returns a classify-allow event whose first 64 bytes, the time
// stamp, the flags, the IP version and protocol, both addresses, both ports
// and the scope, are the bytes an FWPM_NET_EVENT5 of run 43612480437 carried.
// The bytes behind them hold pointers, which a test cannot take from a run,
// so the details come from the test.
func recordedEvent(t *testing.T, head string, allow *fwpmNetEventClassifyAllow0) *fwpmNetEvent5 {
	t.Helper()

	b, err := hex.DecodeString(head)
	if err != nil || len(b) != 64 {
		t.Fatalf("the recorded header is %d bytes (%v), want 64", len(b), err)
	}
	ev := &fwpmNetEvent5{Type: fwpmNetEventTypeClassifyAllow, ClassifyAllow: allow}
	copy((*[64]byte)(unsafe.Pointer(&ev.Header))[:], b)
	return ev
}

// The callback reads the filter, the reauthorization reason, the loopback
// flag and the five-tuple off a classify-allow event. An IPv4 address is a
// UINT32 in host byte order, so 10.255.247.1 is 0x0afff701 and sits in memory
// as 01 f7 ff 0a. An IPv6 address sits in network order. Both events below are
// ones the engine delivered on windows-latest: P's SYN to N:7001 under plexd's
// filter, and an LLMNR query the runner sent from its link-local address.
func TestParseNetEvent(t *testing.T) {
	const (
		syn   = "e5ae95a65074dd017f050000000000000600000001f7ff0a00000000000000000000000002f7ff0a000000000000000000000000591b29a00000000000000000"
		llmnr = "fea0a9a65074dd017f0700000100000011000000fe8000000000000098fcee4001cb3582ff02000000000000000000000001000367d6eb140000000000000000"
	)

	got, ok := parseNetEvent(recordedEvent(t, syn, &fwpmNetEventClassifyAllow0{FilterID: 89127, ReauthReason: 2, IsLoopback: 1}))
	want := allowEvent{
		filterID: 89127, reauthReason: 2, isLoopback: true, protocol: ipProtoTCP,
		local: netip.MustParseAddr("10.255.247.1"), remote: netip.MustParseAddr("10.255.247.2"),
		localPort: 7001, remotePort: 41001,
	}
	if !ok || got != want {
		t.Errorf("parseNetEvent() of the SYN = %+v, %v, want %+v, true", got, ok, want)
	}

	got, ok = parseNetEvent(recordedEvent(t, llmnr, &fwpmNetEventClassifyAllow0{FilterID: 74000}))
	want = allowEvent{
		filterID: 74000, protocol: ipProtoUDP,
		local: netip.MustParseAddr("fe80::98fc:ee40:1cb:3582"), remote: netip.MustParseAddr("ff02::1:3"),
		localPort: 54887, remotePort: 5355,
	}
	if !ok || got != want {
		t.Errorf("parseNetEvent() of the LLMNR query = %+v, %v, want %+v, true", got, ok, want)
	}

	node, peer := netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.3")
	drop := v4Event(70005, node, peer, 7001, 41001)
	drop.Type = 3 // FWPM_NET_EVENT_TYPE_CLASSIFY_DROP
	noDetail := v4Event(70006, node, peer, 7001, 41001)
	noDetail.ClassifyAllow = nil
	noVersion := v4Event(70007, node, peer, 7001, 41001)
	noVersion.Header.IPVersion = 2 // FWP_IP_VERSION_NONE
	for name, ev := range map[string]*fwpmNetEvent5{
		"a classify-drop event":          drop,
		"an event without its details":   noDetail,
		"an event without an IP version": noVersion,
	} {
		if got, ok := parseNetEvent(ev); ok {
			t.Errorf("parseNetEvent() of %s = %+v, true, want false", name, got)
		}
	}
}

// The engine calls one callback for every subscription and passes back the
// context the subscription named, so the callback finds the handler by that
// key, and a key with no handler, an event of another type or no event at
// all reach no handler. The callback returns 0 each time.
func TestOnNetEvent_DispatchesByKey(t *testing.T) {
	var got []allowEvent
	key := registerNetEventHandler(func(ev allowEvent) { got = append(got, ev) })
	t.Cleanup(func() { unregisterNetEventHandler(key) })

	node, peer := netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.3")
	ev := v4Event(70003, node, peer, 7001, 41001)
	drop := v4Event(70003, node, peer, 7001, 41001)
	drop.Type = 3

	for name, call := range map[string]func() uintptr{
		"the event":      func() uintptr { return onNetEvent(key, ev) },
		"a drop":         func() uintptr { return onNetEvent(key, drop) },
		"no event":       func() uintptr { return onNetEvent(key, nil) },
		"an unknown key": func() uintptr { return onNetEvent(key+1000, ev) },
	} {
		if r := call(); r != 0 {
			t.Errorf("onNetEvent() for %s = %d, want 0", name, r)
		}
	}
	if len(got) != 1 || got[0].filterID != 70003 {
		t.Errorf("handler got %+v, want the one classify-allow event under its key", got)
	}

	unregisterNetEventHandler(key)
	onNetEvent(key, ev)
	if len(got) != 1 {
		t.Errorf("handler got %d events after it was unregistered, want 1", len(got))
	}
}

// The first enable records the options as the host had them before it sets
// anything, then sets the keyword alone, since collection was already on. A
// second call finds its own record and the keyword set, so it writes nothing,
// sets nothing, logs no Info line and does not subscribe again. With
// collection off, enable turns it on as well. A record that is already there
// is from a run that crashed with the options set, and enable keeps it byte
// for byte.
func TestWFPController_EnableAllowEvents(t *testing.T) {
	t.Run("records before it sets", func(t *testing.T) {
		f := newWFPLogFixture(t, 1, 0x1)
		var recordAtSet []string
		f.events.onSet = func(uint32, uint32) { recordAtSet = append(recordAtSet, f.readRecord(t)) }

		if err := f.enable(); err != nil {
			t.Fatalf("enableAllowEvents() error = %v, want nil", err)
		}

		const record = `{"collect_net_events":1,"match_any_keywords":1}`
		if want := []wfpOptionSet{{id: fwpmEngineNetEventMatchAnyKeywords, value: 0x11}}; !slices.Equal(f.events.sets, want) {
			t.Fatalf("setOption calls = %+v, want %+v", f.events.sets, want)
		}
		if recordAtSet[0] != record {
			t.Errorf("record when the keyword was set = %q, want %q", recordAtSet[0], record)
		}
		logs := f.logs.String()
		if !strings.Contains(logs, `msg="wfp allow-event collection enabled"`) || !strings.Contains(logs, "previous_keywords=1") {
			t.Errorf("logs = %q, want the enabled line with previous_keywords=1", logs)
		}
		if f.events.subscribes != 1 || f.events.handler == nil {
			t.Errorf("subscribe calls = %d, want 1 with a handler", f.events.subscribes)
		}

		f.logs.Reset()
		if err := f.enable(); err != nil {
			t.Fatalf("enableAllowEvents() second error = %v, want nil", err)
		}
		if got := f.readRecord(t); got != record {
			t.Errorf("record after the second call = %q, want it unchanged %q", got, record)
		}
		if len(f.events.sets) != 1 {
			t.Errorf("setOption calls after the second call = %+v, want only the first", f.events.sets)
		}
		if strings.Contains(f.logs.String(), "level=INFO") {
			t.Errorf("the second call logged %q, want no Info line", f.logs.String())
		}
		if f.events.subscribes != 1 || f.opens != 1 {
			t.Errorf("subscribe calls = %d, sessions opened = %d, want 1 and 1", f.events.subscribes, f.opens)
		}
	})

	t.Run("turns collection on", func(t *testing.T) {
		f := newWFPLogFixture(t, 0, 0)

		if err := f.enable(); err != nil {
			t.Fatalf("enableAllowEvents() error = %v, want nil", err)
		}
		want := []wfpOptionSet{
			{id: fwpmEngineCollectNetEvents, value: 1},
			{id: fwpmEngineNetEventMatchAnyKeywords, value: fwpmNetEventKeywordClassifyAllow},
		}
		if !slices.Equal(f.events.sets, want) {
			t.Errorf("setOption calls = %+v, want %+v", f.events.sets, want)
		}
		if got, want := f.readRecord(t), `{"collect_net_events":0,"match_any_keywords":0}`; got != want {
			t.Errorf("record = %q, want %q", got, want)
		}
		if !strings.Contains(f.logs.String(), "previous_keywords=0") {
			t.Errorf("logs = %q, want previous_keywords=0", f.logs.String())
		}
	})

	t.Run("keeps a crash record", func(t *testing.T) {
		f := newWFPLogFixture(t, 1, 0x11)
		const crashed = `{"collect_net_events":0,"match_any_keywords":1}`
		f.writeRecord(t, crashed)

		if err := f.enable(); err != nil {
			t.Fatalf("enableAllowEvents() error = %v, want nil", err)
		}
		if got := f.readRecord(t); got != crashed {
			t.Errorf("record = %q, want the crashed run's %q", got, crashed)
		}
		if len(f.events.sets) != 0 {
			t.Errorf("setOption calls = %+v, want none: the options are already set", f.events.sets)
		}
		if f.events.subscribes != 1 {
			t.Errorf("subscribe calls = %d, want 1", f.events.subscribes)
		}
	})
}

// A logged apply whose allow events cannot be turned on enforces the rules
// without the log: it logs the shared Warn line with chain and the cause,
// returns nil and keeps the filters. A failed enable restores at once, so the
// keyword ends clear and the record gone whatever step failed.
func TestWFPController_ApplyRules_EnableFails(t *testing.T) {
	for _, tt := range []struct {
		name string
		// arm prepares the fixture for the failure.
		arm         func(t *testing.T, f *wfpLogFixture)
		wantErr     []string
		wantNoSet   bool // no setOption may run at all
		wantRecord  string
		wantKeyword uint32
	}{
		{
			name:      "no state directory",
			arm:       func(t *testing.T, f *wfpLogFixture) { f.ctrl.SetStateDir("") },
			wantErr:   []string{"policy: wfp: allow events: no state directory"},
			wantNoSet: true,
		},
		{
			name:      "the state directory is missing",
			arm:       func(t *testing.T, f *wfpLogFixture) { f.ctrl.SetStateDir(filepath.Join(f.dir, "missing")) },
			wantErr:   []string{"policy: wfp: allow events: record options"},
			wantNoSet: true,
		},
		{
			name: "the session is refused",
			arm: func(t *testing.T, f *wfpLogFixture) {
				f.ctrl.openNetEvents = func() (netEventSession, error) {
					return nil, fmt.Errorf("FwpmEngineOpen0: %w", windows.ERROR_ACCESS_DENIED)
				}
			},
			wantErr:   []string{"policy: wfp: allow events: open session", "(policy enforcement on Windows requires Administrator)"},
			wantNoSet: true,
		},
		{
			name:    "an option is refused",
			arm:     func(t *testing.T, f *wfpLogFixture) { f.events.setErr = errors.New("set refused") },
			wantErr: []string{"policy: wfp: allow events: set match_any_keywords", "set refused"},
		},
		{
			name:    "the subscription is refused",
			arm:     func(t *testing.T, f *wfpLogFixture) { f.events.subscribeErr = errors.New("subscribe refused") },
			wantErr: []string{"policy: wfp: allow events: subscribe", "subscribe refused"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newWFPLogFixture(t, 1, 0x1)
			tt.arm(t, f)

			if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
				t.Fatalf("ApplyRules() error = %v, want nil", err)
			}
			logs := f.logs.String()
			if !strings.Contains(logs, `msg="policy connection logging unavailable, logged rules are enforced without it"`) ||
				!strings.Contains(logs, "chain=plexd-mesh") {
				t.Errorf("logs = %q, want %q with chain", logs, connLogUnavailable)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(logs, want) {
					t.Errorf("logs = %q, want the cause %q", logs, want)
				}
			}
			if tt.wantNoSet && len(f.events.sets) != 0 {
				t.Errorf("setOption calls = %+v, want none", f.events.sets)
			}
			if got := f.events.opts[fwpmEngineNetEventMatchAnyKeywords]; got != 0x1 {
				t.Errorf("match_any_keywords = %#x, want 0x1, the keyword clear", got)
			}
			if got := f.readRecord(t); got != "" {
				t.Errorf("record = %q, want none after the restore", got)
			}
			if got := len(f.ctrl.chains["plexd-mesh"]); got == 0 || got != len(f.engine.rules) {
				t.Errorf("chain plexd-mesh holds %d filters, want the %d installed", got, len(f.engine.rules))
			}
		})
	}
}

// restoreAllowEvents clears the keyword only when the record shows the host
// had it clear, leaves bits others set since, turns collection off only when
// the record shows it off, deletes the record and closes the session. A
// record that is not valid JSON is read as collection on and the keyword
// clear.
func TestWFPController_RestoreAllowEvents(t *testing.T) {
	for _, tt := range []struct {
		name              string
		record            string
		collect, keywords uint32
		wantSets          []wfpOptionSet
		wantCollect       uint32
		wantKeywords      uint32
		wantUnreadable    bool
	}{
		{
			name:        "keyword was clear",
			record:      `{"collect_net_events":1,"match_any_keywords":1}`,
			collect:     1,
			keywords:    0x13,
			wantSets:    []wfpOptionSet{{id: fwpmEngineNetEventMatchAnyKeywords, value: 0x3}},
			wantCollect: 1, wantKeywords: 0x3,
		},
		{
			name:        "keyword was set",
			record:      `{"collect_net_events":1,"match_any_keywords":17}`,
			collect:     1,
			keywords:    0x13,
			wantCollect: 1, wantKeywords: 0x13,
		},
		{
			name:     "collection was off",
			record:   `{"collect_net_events":0,"match_any_keywords":1}`,
			collect:  1,
			keywords: 0x11,
			wantSets: []wfpOptionSet{
				{id: fwpmEngineNetEventMatchAnyKeywords, value: 0x1},
				{id: fwpmEngineCollectNetEvents, value: 0},
			},
			wantCollect: 0, wantKeywords: 0x1,
		},
		{
			name:        "collection is off already",
			record:      `{"collect_net_events":0,"match_any_keywords":17}`,
			collect:     0,
			keywords:    0x11,
			wantCollect: 0, wantKeywords: 0x11,
		},
		{
			name:        "the record is unreadable",
			record:      `not json`,
			collect:     1,
			keywords:    0x13,
			wantSets:    []wfpOptionSet{{id: fwpmEngineNetEventMatchAnyKeywords, value: 0x3}},
			wantCollect: 1, wantKeywords: 0x3,
			wantUnreadable: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newWFPLogFixture(t, tt.collect, tt.keywords)
			f.writeRecord(t, tt.record)

			if err := f.restore(); err != nil {
				t.Fatalf("restoreAllowEvents() error = %v, want nil", err)
			}
			if !slices.Equal(f.events.sets, tt.wantSets) {
				t.Errorf("setOption calls = %+v, want %+v", f.events.sets, tt.wantSets)
			}
			if got := f.events.opts[fwpmEngineCollectNetEvents]; got != tt.wantCollect {
				t.Errorf("collect_net_events = %d, want %d", got, tt.wantCollect)
			}
			if got := f.events.opts[fwpmEngineNetEventMatchAnyKeywords]; got != tt.wantKeywords {
				t.Errorf("match_any_keywords = %#x, want %#x", got, tt.wantKeywords)
			}
			if got := f.readRecord(t); got != "" {
				t.Errorf("record = %q after the restore, want it deleted", got)
			}
			logs := f.logs.String()
			if !strings.Contains(logs, `msg="wfp allow-event collection restored"`) {
				t.Errorf("logs = %q, want the restored line", logs)
			}
			if got := strings.Contains(logs, `level=WARN msg="policy: wfp: allow-event record unreadable"`); got != tt.wantUnreadable {
				t.Errorf("logs = %q, unreadable-record Warn logged %v, want %v", logs, got, tt.wantUnreadable)
			}
			if f.events.closes != 1 || f.ctrl.netEvents != nil {
				t.Errorf("sessions closed = %d, want the session closed once restored", f.events.closes)
			}
		})
	}
}

// Without a record and a session a restore touches nothing, which is every
// apply of a ruleset without a logged rule on a node that never logged.
func TestWFPController_RestoreAllowEvents_NothingToRestore(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x11)

	if err := f.restore(); err != nil {
		t.Fatalf("restoreAllowEvents() error = %v, want nil", err)
	}
	if f.opens != 0 || len(f.events.sets) != 0 || f.logs.Len() != 0 {
		t.Errorf("sessions opened = %d, setOption calls = %+v, logs = %q, want nothing", f.opens, f.events.sets, f.logs.String())
	}
}

// A restore that fails keeps the record, so the next one puts the options
// back, and neither changes what ApplyRules returns. An apply without a
// logged rule after one with a logged rule is what restores here.
func TestWFPController_RestoreAllowEvents_FailureKeepsRecord(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x1)
	if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	const record = `{"collect_net_events":1,"match_any_keywords":1}`

	f.events.setErr = errors.New("set refused")
	if err := f.ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() without a logged rule error = %v, want nil", err)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `msg="policy: wfp: restore allow-event collection"`) || !strings.Contains(logs, "set refused") {
		t.Errorf("logs = %q, want the restore warning with the refusal", logs)
	}
	if got := f.readRecord(t); got != record {
		t.Errorf("record = %q after the failed restore, want %q kept", got, record)
	}
	if f.events.unsubscribes != 1 {
		t.Errorf("unsubscribe calls = %d, want 1", f.events.unsubscribes)
	}

	f.events.setErr = nil
	if err := f.ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() retry error = %v, want nil", err)
	}
	if got := f.events.opts[fwpmEngineNetEventMatchAnyKeywords]; got != 0x1 {
		t.Errorf("match_any_keywords = %#x after the retry, want 0x1", got)
	}
	if got := f.readRecord(t); got != "" {
		t.Errorf("record = %q after the retry, want it deleted", got)
	}
}

// A session that fails to close after the options are back keeps the record
// too, so the next restore finds the options as the record has them, sets
// nothing and deletes it.
func TestWFPController_RestoreAllowEvents_CloseFailureKeepsRecord(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x11)
	const record = `{"collect_net_events":1,"match_any_keywords":1}`
	f.writeRecord(t, record)
	f.events.closeErr = errors.New("close refused")

	err := f.restore()
	if err == nil || !strings.Contains(err.Error(), "policy: wfp: allow events: close session: close refused") {
		t.Fatalf("restoreAllowEvents() error = %v, want the close failure", err)
	}
	if got := f.events.opts[fwpmEngineNetEventMatchAnyKeywords]; got != 0x1 {
		t.Errorf("match_any_keywords = %#x, want 0x1", got)
	}
	if got := f.readRecord(t); got != record {
		t.Errorf("record = %q after the failed close, want %q kept", got, record)
	}
	if strings.Contains(f.logs.String(), "wfp allow-event collection restored") {
		t.Errorf("logs = %q, want no restored line before the record is gone", f.logs.String())
	}

	f.events.closeErr = nil
	sets := len(f.events.sets)
	if err := f.restore(); err != nil {
		t.Fatalf("restoreAllowEvents() retry error = %v, want nil", err)
	}
	if len(f.events.sets) != sets {
		t.Errorf("setOption calls on the retry = %+v, want none", f.events.sets[sets:])
	}
	if got := f.readRecord(t); got != "" {
		t.Errorf("record = %q after the retry, want it deleted", got)
	}
	if !strings.Contains(f.logs.String(), `msg="wfp allow-event collection restored"`) {
		t.Errorf("logs = %q, want the restored line after the retry", f.logs.String())
	}
}

// A run that crashed with the options set left a record behind. The next
// start hands the controller its state directory, and SetStateDir restores
// from the record at once, also on a node with enforcement disabled, which
// applies no rule. A state directory without a record opens no session.
func TestWFPController_SetStateDir_RestoresCrashRecord(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x11)
	f.writeRecord(t, `{"collect_net_events":0,"match_any_keywords":1}`)

	next := NewWFPController(captureLogger(f.logs), "plexd0")
	next.openNetEvents = f.ctrl.openNetEvents
	next.SetStateDir(f.dir)

	if got := f.events.opts[fwpmEngineNetEventMatchAnyKeywords]; got != 0x1 {
		t.Errorf("match_any_keywords = %#x, want 0x1", got)
	}
	if got := f.events.opts[fwpmEngineCollectNetEvents]; got != 0 {
		t.Errorf("collect_net_events = %d, want 0", got)
	}
	if got := f.readRecord(t); got != "" {
		t.Errorf("record = %q, want it deleted", got)
	}
	if !strings.Contains(f.logs.String(), `msg="wfp allow-event collection restored"`) {
		t.Errorf("logs = %q, want the restored line", f.logs.String())
	}

	opens := f.opens
	again := NewWFPController(captureLogger(f.logs), "plexd0")
	again.openNetEvents = f.ctrl.openNetEvents
	again.SetStateDir(f.dir)
	if f.opens != opens {
		t.Errorf("SetStateDir without a record opened %d sessions, want none", f.opens-opens)
	}
}

// A restore that failed at start leaves the record behind. A shutdown with
// enforcement disabled deletes a chain it never ensured, and that DeleteChain
// restores from the record. So does the DeleteChain of the last chain that
// held a logged filter, which also ends the subscription and closes the
// session.
func TestWFPController_DeleteChain_Restores(t *testing.T) {
	t.Run("a chain never ensured", func(t *testing.T) {
		f := newWFPLogFixture(t, 1, 0x11)
		f.writeRecord(t, `{"collect_net_events":0,"match_any_keywords":1}`)

		if err := f.ctrl.DeleteChain("plexd-mesh"); err != nil {
			t.Fatalf("DeleteChain() error = %v, want nil", err)
		}
		if got := f.events.opts; got[fwpmEngineNetEventMatchAnyKeywords] != 0x1 || got[fwpmEngineCollectNetEvents] != 0 {
			t.Errorf("options = %v, want match_any_keywords 0x1 and collect_net_events 0", got)
		}
		if got := f.readRecord(t); got != "" {
			t.Errorf("record = %q, want it deleted", got)
		}
		if !strings.Contains(f.logs.String(), `msg="wfp allow-event collection restored"`) {
			t.Errorf("logs = %q, want the restored line", f.logs.String())
		}
	})

	t.Run("the last logged chain", func(t *testing.T) {
		f := newWFPLogFixture(t, 0, 0)
		if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
			t.Fatalf("ApplyRules() error = %v, want nil", err)
		}
		if f.events.handler == nil {
			t.Fatal("ApplyRules() of a logged rule left no subscription")
		}

		if err := f.ctrl.DeleteChain("plexd-mesh"); err != nil {
			t.Fatalf("DeleteChain() error = %v, want nil", err)
		}
		if f.events.unsubscribes != 1 || f.events.closes != 1 {
			t.Errorf("unsubscribe calls = %d, close calls = %d, want 1 and 1", f.events.unsubscribes, f.events.closes)
		}
		if got := f.events.opts; got[fwpmEngineCollectNetEvents] != 0 || got[fwpmEngineNetEventMatchAnyKeywords] != 0 {
			t.Errorf("options = %v, want both back at 0", got)
		}
		if got := f.readRecord(t); got != "" {
			t.Errorf("record = %q, want it deleted", got)
		}
		if f.ctrl.netEvents != nil || f.ctrl.subscribed || len(f.ctrl.connLogs) != 0 {
			t.Errorf("controller keeps session %v, subscribed %v, logged chains %v, want none", f.ctrl.netEvents, f.ctrl.subscribed, f.ctrl.connLogs)
		}
	})
}

// The engine names the filter that permitted a connection. At the inbound
// layer the remote side opened it, so the remote address is the source and
// the local port the destination port; at the outbound layer the node opened
// it. A reauthorization repeats a connection already reported, loopback never
// crosses the mesh interface, and a filter that is not a logged one of plexd,
// id 0 included, names no rule, so all of them are dropped. After
// SetConnSink(nil) nothing is reported.
func TestWFPController_AllowEventConversion(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x11)
	if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if f.events.handler == nil {
		t.Fatal("ApplyRules() of a logged rule left no subscription")
	}
	in := f.engine.filterID(t, "plexd plexd-mesh #0 inbound")
	out := f.engine.filterID(t, "plexd plexd-mesh #0 outbound")
	node, peer := netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.3")

	for _, ev := range []allowEvent{
		{filterID: in, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41001},
		{filterID: out, protocol: ipProtoTCP, local: peer, remote: node, localPort: 41002, remotePort: 7001},
		{filterID: in, reauthReason: 5, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41003},
		{filterID: in, isLoopback: true, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41004},
		{filterID: 12345, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41005},
		{filterID: 0, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41006},
	} {
		f.events.handler(ev)
	}

	want := []ConnEvent{
		{Tag: "1/0", Dir: ConnIn, Src: peer, Dst: node, Protocol: ipProtoTCP, SrcPort: 41001, DstPort: 7001},
		{Tag: "1/0", Dir: ConnOut, Src: peer, Dst: node, Protocol: ipProtoTCP, SrcPort: 41002, DstPort: 7001},
	}
	if got := f.sink.got(); !slices.Equal(got, want) {
		t.Errorf("sink events =\n%+v\nwant\n%+v", got, want)
	}

	f.ctrl.SetConnSink(nil)
	f.events.handler(allowEvent{filterID: in, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41007})
	if got := f.sink.got(); len(got) != len(want) {
		t.Errorf("sink got %d events after SetConnSink(nil), want %d", len(got), len(want))
	}
}

// The engine reports ICMP type and code where TCP and UDP carry ports, and a
// connection line names no port for ICMP.
func TestWFPLogFilter_ConnEvent_ICMPHasNoPorts(t *testing.T) {
	lf := wfpLogFilter{tag: "2/1", dir: ConnIn}
	node, peer := netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.3")

	got := lf.connEvent(allowEvent{protocol: ipProtoICMP, local: node, remote: peer, localPort: 8, remotePort: 0})
	want := ConnEvent{Tag: "2/1", Dir: ConnIn, Src: peer, Dst: node, Protocol: ipProtoICMP}
	if got != want {
		t.Errorf("connEvent() = %+v, want %+v", got, want)
	}
}

// The engine delivers an event after the connection, so one that arrives
// just after an apply can still name a filter of the apply before. It is
// reported, and once a second apply follows it names no rule.
func TestWFPController_AllowEvents_PreviousApply(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x11)
	node, peer := netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.3")
	syn := func(id uint64) allowEvent {
		return allowEvent{filterID: id, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41001}
	}

	if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	first := f.engine.filterID(t, "plexd plexd-mesh #0 inbound")

	if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	second := f.engine.filterID(t, "plexd plexd-mesh #0 inbound")
	if first == second {
		t.Fatalf("both applies gave the inbound filter runtime id %d", first)
	}
	f.events.handler(syn(first))
	f.events.handler(syn(second))
	if got := len(f.sink.got()); got != 2 {
		t.Errorf("sink got %d events, want both the previous and the current apply's", got)
	}

	if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
		t.Fatalf("ApplyRules() third error = %v, want nil", err)
	}
	f.events.handler(syn(first))
	if got := len(f.sink.got()); got != 2 {
		t.Errorf("sink got %d events, want the first apply's filter to name no rule after two more applies", got)
	}
	if f.events.subscribes != 1 {
		t.Errorf("subscribe calls = %d, want 1 across the applies", f.events.subscribes)
	}
}

// The engine calls onAllowEvent on threads of its own while the reconciler
// applies and deletes chains. Under -race this shows that the callback reads
// only what logMu guards.
func TestWFPController_AllowEvents_Concurrent(t *testing.T) {
	f := newWFPLogFixture(t, 1, 0x11)
	if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	in := f.engine.filterID(t, "plexd plexd-mesh #0 inbound")
	node, peer := netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.3")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				f.ctrl.onAllowEvent(allowEvent{filterID: in, protocol: ipProtoTCP, local: node, remote: peer, localPort: 7001, remotePort: 41001})
			}
		}()
	}
	for range 20 {
		if err := f.ctrl.ApplyRules("plexd-mesh", loggedRules); err != nil {
			t.Errorf("ApplyRules() error = %v, want nil", err)
		}
		if err := f.ctrl.DeleteChain("plexd-mesh"); err != nil {
			t.Errorf("DeleteChain() error = %v, want nil", err)
		}
	}
	close(stop)
	wg.Wait()
}
