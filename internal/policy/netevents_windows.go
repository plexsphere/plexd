//go:build windows

package policy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// The engine options, the keyword and the event type plexd reads and sets.
// The options are FWPM_ENGINE_OPTION, the keyword is
// FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW and the event type
// FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, all from fwpmtypes.h in the Windows SDK.
// fwpUint32 is FWP_UINT32 of FWP_DATA_TYPE in fwptypes.h, the value type both
// options carry. TestWFPController_RealConnLog proves the keyword and the event
// type on a real filter engine.
const (
	fwpmEngineCollectNetEvents         = 0
	fwpmEngineNetEventMatchAnyKeywords = 1
	fwpmNetEventKeywordClassifyAllow   = 0x10
	fwpmNetEventTypeClassifyAllow      = 6
	fwpUint32                          = 3

	// FWP_IP_VERSION_V4 and FWP_IP_VERSION_V6 from fwptypes.h.
	fwpIPVersionV4 = 0
	fwpIPVersionV6 = 1

	// rpcCAuthnWinNT is RPC_C_AUTHN_WINNT from rpcdce.h, the authentication
	// service FwpmEngineOpen0 takes for the local filter engine.
	rpcCAuthnWinNT = 10

	// filterEnumPage is how many filters one FwpmFilterEnum0 call asks for.
	filterEnumPage = 100
)

// wfpAllowEventsFile is the file under the state directory that records the
// two engine options as they were before plexd changed them.
const wfpAllowEventsFile = "wfp-allow-events.json"

// allowEventsRecord is the content of wfpAllowEventsFile.
type allowEventsRecord struct {
	CollectNetEvents uint32 `json:"collect_net_events"`
	MatchAnyKeywords uint32 `json:"match_any_keywords"`
}

// The structs below mirror the Windows SDK layouts plexd reads and passes to
// fwpuclnt.dll, field for field: FWP_VALUE0 and FWP_BYTE_BLOB from
// fwptypes.h, the rest from fwpmtypes.h. A C union becomes the member the code
// reads, or an array of its size and alignment. TestNetEventLayouts pins their
// sizes and the offsets of the fields plexd reads to what the SDK layout
// implies on 64-bit Windows, the only Windows plexd is built for.

// fwpValue0 is FWP_VALUE0. Its union is 8 bytes on 64-bit Windows, and a
// FWP_UINT32 value sits in its low 4 bytes.
type fwpValue0 struct {
	Type  uint32
	Value uint64
}

// fwpByteBlob is FWP_BYTE_BLOB.
type fwpByteBlob struct {
	Size uint32
	Data *uint8
}

// fwpmDisplayData0 is FWPM_DISPLAY_DATA0.
type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

// fwpmAction0 is FWPM_ACTION0. Its union holds two GUIDs.
type fwpmAction0 struct {
	Type       uint32
	FilterType windows.GUID
}

// fwpmFilter0 is FWPM_FILTER0. The union of rawContext and providerContextKey
// is ProviderContext: 16 bytes at 8-byte alignment.
type fwpmFilter0 struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData0
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterCondition     unsafe.Pointer
	Action              fwpmAction0
	ProviderContext     [2]uint64
	Reserved            *windows.GUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
}

// fwpmNetEventHeader3 is FWPM_NET_EVENT_HEADER3. Each address is a union of a
// UINT32, the IPv4 address in host byte order, and FWP_BYTE_ARRAY16, the IPv6
// address in network order. The union is 4-byte aligned, which puts the pad
// after IPProtocol.
type fwpmNetEventHeader3 struct {
	TimeStamp     windows.Filetime
	Flags         uint32
	IPVersion     uint32
	IPProtocol    uint8
	_             [3]byte
	LocalAddr     [16]byte
	RemoteAddr    [16]byte
	LocalPort     uint16
	RemotePort    uint16
	ScopeID       uint32
	AppID         fwpByteBlob
	UserID        *windows.SID
	AddressFamily uint32
	PackageSID    *windows.SID
	EnterpriseID  *uint16
	PolicyFlags   uint64
	EffectiveName fwpByteBlob
}

// fwpmNetEvent5 is FWPM_NET_EVENT5, the event FWPM_NET_EVENT_CALLBACK4
// receives. Its union holds one pointer to the details of the event's type.
// ClassifyAllow is that pointer, and it names a FWPM_NET_EVENT_CLASSIFY_ALLOW0
// only when Type is fwpmNetEventTypeClassifyAllow.
type fwpmNetEvent5 struct {
	Header        fwpmNetEventHeader3
	Type          uint32
	ClassifyAllow *fwpmNetEventClassifyAllow0
}

// fwpmNetEventClassifyAllow0 is FWPM_NET_EVENT_CLASSIFY_ALLOW0.
type fwpmNetEventClassifyAllow0 struct {
	FilterID        uint64
	LayerID         uint16
	ReauthReason    uint32
	OriginalProfile uint32
	CurrentProfile  uint32
	MsFwpDirection  uint32
	IsLoopback      int32
}

// fwpmNetEventSubscription0 is FWPM_NET_EVENT_SUBSCRIPTION0. A nil
// EnumTemplate subscribes to every event.
type fwpmNetEventSubscription0 struct {
	EnumTemplate unsafe.Pointer
	Flags        uint32
	SessionKey   windows.GUID
}

// x/sys/windows carries no binding for the filter engine's options, its net
// events and its filter enumeration, so the procedures are resolved from
// fwpuclnt at first use. NewLazySystemDLL loads the library from System32
// only.
var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0              = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0             = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmEngineGetOption0         = modfwpuclnt.NewProc("FwpmEngineGetOption0")
	procFwpmEngineSetOption0         = modfwpuclnt.NewProc("FwpmEngineSetOption0")
	procFwpmFreeMemory0              = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmNetEventSubscribe4       = modfwpuclnt.NewProc("FwpmNetEventSubscribe4")
	procFwpmNetEventUnsubscribe0     = modfwpuclnt.NewProc("FwpmNetEventUnsubscribe0")
	procFwpmFilterCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = modfwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
)

// findProcs resolves every procedure before the first call, so a fwpuclnt
// without one of them fails before a handle is open rather than panicking in
// the middle of a call sequence. The error names the missing procedure.
func findProcs(procs ...*windows.LazyProc) error {
	for _, proc := range procs {
		if err := proc.Find(); err != nil {
			return err
		}
	}
	return nil
}

// fwpError turns the DWORD an Fwpm procedure returns into an error: 0 is
// success, anything else a Win32 or FWP_E_* code.
func fwpError(name string, r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", name, syscall.Errno(r1))
}

// fwpmEngineOpen opens a session to the local filter engine. It passes no
// FWPM_SESSION0, so the session is not dynamic: the engine refuses
// FwpmEngineSetOption0 inside a dynamic session. The session adds no object,
// so nothing outlives it but the options it sets.
func fwpmEngineOpen() (windows.Handle, error) {
	var engine windows.Handle
	r1, _, _ := procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&engine)))
	if err := fwpError("FwpmEngineOpen0", r1); err != nil {
		return 0, err
	}
	return engine, nil
}

func fwpmEngineClose(engine windows.Handle) error {
	r1, _, _ := procFwpmEngineClose0.Call(uintptr(engine))
	return fwpError("FwpmEngineClose0", r1)
}

// fwpmFreeMemory frees what an Fwpm procedure allocated. p points at the
// pointer the procedure returned.
func fwpmFreeMemory(p unsafe.Pointer) {
	_, _, _ = procFwpmFreeMemory0.Call(uintptr(p))
}

// wfpSession is the production wfpEngine: a dynamic *wf.Session that also
// reports each filter's runtime id.
//
// DECISION: github.com/tailscale/wf declares the union of rawContext and
// providerContextKey in FWPM_FILTER0 as two fields, so it reads every field
// behind the union 8 bytes off, and its Rule.KernelID holds the type tag of
// effectiveWeight for every filter, not filterId. Its AddRule discards the id
// FwpmFilterAdd0 hands back. A net event names its filter by filterId alone,
// so FilterIDs reads it through fwpmFilter0, laid out as fwpmtypes.h has it
// (measured on windows-latest, run 43271551927). Upstream's head declares the
// union the same way, so there is no version to move to.
type wfpSession struct {
	*wf.Session
}

// FilterIDs returns the runtime id of every filter in the engine by its key.
func (wfpSession) FilterIDs() (map[wf.RuleID]uint64, error) {
	return filterIDs()
}

// filterIDs enumerates every filter of the engine and returns its runtime id
// by its key. It opens a session of its own, since *wf.Session does not
// expose its handle.
func filterIDs() (map[wf.RuleID]uint64, error) {
	if err := findProcs(
		procFwpmEngineOpen0,
		procFwpmEngineClose0,
		procFwpmFreeMemory0,
		procFwpmFilterCreateEnumHandle0,
		procFwpmFilterEnum0,
		procFwpmFilterDestroyEnumHandle0,
	); err != nil {
		return nil, err
	}
	engine, err := fwpmEngineOpen()
	if err != nil {
		return nil, err
	}
	defer func() { _ = fwpmEngineClose(engine) }()

	var enum windows.Handle
	r1, _, _ := procFwpmFilterCreateEnumHandle0.Call(uintptr(engine), 0, uintptr(unsafe.Pointer(&enum)))
	if err := fwpError("FwpmFilterCreateEnumHandle0", r1); err != nil {
		return nil, err
	}
	defer func() { _, _, _ = procFwpmFilterDestroyEnumHandle0.Call(uintptr(engine), uintptr(enum)) }()

	ids := make(map[wf.RuleID]uint64)
	for {
		var (
			entries **fwpmFilter0
			n       uint32
		)
		r1, _, _ = procFwpmFilterEnum0.Call(
			uintptr(engine),
			uintptr(enum),
			filterEnumPage,
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&n)),
		)
		if err := fwpError("FwpmFilterEnum0", r1); err != nil {
			return nil, err
		}
		if n == 0 || entries == nil {
			if entries != nil {
				fwpmFreeMemory(unsafe.Pointer(&entries))
			}
			return ids, nil
		}
		for _, f := range unsafe.Slice(entries, n) {
			ids[wf.RuleID(f.FilterKey)] = f.FilterID
		}
		fwpmFreeMemory(unsafe.Pointer(&entries))
	}
}

// allowEvent is what plexd reads off one classify-allow net event: the filter
// that permitted the connection and the connection as the node sees it.
type allowEvent struct {
	filterID              uint64
	reauthReason          uint32
	isLoopback            bool
	protocol              uint8
	local, remote         netip.Addr
	localPort, remotePort uint16
}

// parseNetEvent reads a classify-allow event off the event the engine handed
// the callback. It returns false for any other event type, for an event
// without its details, and for an IP version other than 4 and 6.
func parseNetEvent(ev *fwpmNetEvent5) (allowEvent, bool) {
	if ev.Type != fwpmNetEventTypeClassifyAllow || ev.ClassifyAllow == nil {
		return allowEvent{}, false
	}
	h := &ev.Header
	out := allowEvent{
		filterID:     ev.ClassifyAllow.FilterID,
		reauthReason: ev.ClassifyAllow.ReauthReason,
		isLoopback:   ev.ClassifyAllow.IsLoopback != 0,
		protocol:     h.IPProtocol,
		localPort:    h.LocalPort,
		remotePort:   h.RemotePort,
	}
	switch h.IPVersion {
	case fwpIPVersionV4:
		out.local = addrFromV4Union(h.LocalAddr)
		out.remote = addrFromV4Union(h.RemoteAddr)
	case fwpIPVersionV6:
		out.local = netip.AddrFrom16(h.LocalAddr)
		out.remote = netip.AddrFrom16(h.RemoteAddr)
	default:
		return allowEvent{}, false
	}
	return out, true
}

// addrFromV4Union reads the UINT32 member of an address union. It holds the
// IPv4 address in host byte order, which is little-endian on Windows, so the
// first octet is the most significant byte.
func addrFromV4Union(b [16]byte) netip.Addr {
	v := binary.LittleEndian.Uint32(b[:4])
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// The filter engine calls one callback for every subscription. A callback made
// with windows.NewCallback is never freed and the runtime allows a bounded
// number of them, so the process makes one and dispatches by the context
// pointer, which carries a key into netEventHandlers rather than a Go pointer
// the engine would hold.
var (
	netEventCallbackOnce sync.Once
	netEventCallback     uintptr

	netEventMu       sync.Mutex
	netEventHandlers = make(map[uintptr]func(allowEvent))
	netEventNextKey  uintptr
)

// onNetEvent is FWPM_NET_EVENT_CALLBACK4. The engine calls it on a thread of
// its own, and the event is valid only during the call, so it is copied out
// before the handler sees it.
func onNetEvent(context uintptr, event *fwpmNetEvent5) uintptr {
	netEventMu.Lock()
	fn := netEventHandlers[context]
	netEventMu.Unlock()
	if fn == nil || event == nil {
		return 0
	}
	if ev, ok := parseNetEvent(event); ok {
		fn(ev)
	}
	return 0
}

func registerNetEventHandler(fn func(allowEvent)) uintptr {
	netEventMu.Lock()
	defer netEventMu.Unlock()
	netEventNextKey++
	netEventHandlers[netEventNextKey] = fn
	return netEventNextKey
}

func unregisterNetEventHandler(key uintptr) {
	netEventMu.Lock()
	defer netEventMu.Unlock()
	delete(netEventHandlers, key)
}

// netEventSession is the part of the filter engine the allow-event logging
// uses. It is a seam: production opens a session through fwpuclnt.dll, tests
// hold the two options in memory and call the handler themselves.
type netEventSession interface {
	// option reads an FWPM_ENGINE_OPTION that carries a FWP_UINT32.
	option(id uint32) (uint32, error)
	// setOption sets an FWPM_ENGINE_OPTION to a FWP_UINT32.
	setOption(id, value uint32) error
	// subscribe calls fn for every classify-allow event until unsubscribe.
	subscribe(fn func(allowEvent)) error
	// unsubscribe ends the subscription. It returns once no call of fn runs.
	unsubscribe() error
	// close ends the subscription and closes the session.
	close() error
}

// wfpNetEventSession is the production netEventSession.
type wfpNetEventSession struct {
	engine windows.Handle
	events windows.Handle // the subscription, 0 while there is none
	key    uintptr        // the handler's key in netEventHandlers
}

// openNetEventSession opens a session for the engine options and the net
// event subscription. A fwpuclnt.dll without FwpmNetEventSubscribe4 fails
// here, with an error that names the procedure.
func openNetEventSession() (netEventSession, error) {
	if err := findProcs(
		procFwpmEngineOpen0,
		procFwpmEngineClose0,
		procFwpmEngineGetOption0,
		procFwpmEngineSetOption0,
		procFwpmFreeMemory0,
		procFwpmNetEventSubscribe4,
		procFwpmNetEventUnsubscribe0,
	); err != nil {
		return nil, err
	}
	engine, err := fwpmEngineOpen()
	if err != nil {
		return nil, err
	}
	return &wfpNetEventSession{engine: engine}, nil
}

func (s *wfpNetEventSession) option(id uint32) (uint32, error) {
	var value *fwpValue0
	r1, _, _ := procFwpmEngineGetOption0.Call(uintptr(s.engine), uintptr(id), uintptr(unsafe.Pointer(&value)))
	if r1 != 0 {
		return 0, fmt.Errorf("FwpmEngineGetOption0(%d): %w", id, syscall.Errno(r1))
	}
	if value == nil {
		return 0, fmt.Errorf("FwpmEngineGetOption0(%d): no value", id)
	}
	defer fwpmFreeMemory(unsafe.Pointer(&value))

	if value.Type != fwpUint32 {
		return 0, fmt.Errorf("FwpmEngineGetOption0(%d): value type %d, want %d", id, value.Type, fwpUint32)
	}
	return uint32(value.Value), nil
}

func (s *wfpNetEventSession) setOption(id, value uint32) error {
	v := fwpValue0{Type: fwpUint32, Value: uint64(value)}
	r1, _, _ := procFwpmEngineSetOption0.Call(uintptr(s.engine), uintptr(id), uintptr(unsafe.Pointer(&v)))
	if r1 != 0 {
		return fmt.Errorf("FwpmEngineSetOption0(%d): %w", id, syscall.Errno(r1))
	}
	return nil
}

// subscribe subscribes to every net event of the engine.
//
// DECISION: the reader is a FwpmNetEventSubscribe4 subscription, with no
// polling of the engine's event buffer beside or behind it. On windows-latest
// (run 43612480437) it delivered every classify-allow event within 126 ms and
// all 50,000 of a burst of UDP flows, while FwpmNetEventSubscribe1, 2 and 3
// delivered only drop events and the buffer FwpmNetEventEnum2 reads kept about
// 1,500 of the 50,000. A fwpuclnt.dll without FwpmNetEventSubscribe4 makes
// logging unavailable: openNetEventSession names the procedure it lacks.
func (s *wfpNetEventSession) subscribe(fn func(allowEvent)) error {
	if s.events != 0 {
		return errors.New("FwpmNetEventSubscribe4: already subscribed")
	}
	netEventCallbackOnce.Do(func() {
		netEventCallback = windows.NewCallback(onNetEvent)
	})

	key := registerNetEventHandler(fn)
	var sub fwpmNetEventSubscription0
	var events windows.Handle
	r1, _, _ := procFwpmNetEventSubscribe4.Call(
		uintptr(s.engine),
		uintptr(unsafe.Pointer(&sub)),
		netEventCallback,
		key,
		uintptr(unsafe.Pointer(&events)),
	)
	if err := fwpError("FwpmNetEventSubscribe4", r1); err != nil {
		unregisterNetEventHandler(key)
		return err
	}
	s.events, s.key = events, key
	return nil
}

func (s *wfpNetEventSession) unsubscribe() error {
	if s.events == 0 {
		return nil
	}
	r1, _, _ := procFwpmNetEventUnsubscribe0.Call(uintptr(s.engine), uintptr(s.events))
	if err := fwpError("FwpmNetEventUnsubscribe0", r1); err != nil {
		return err
	}
	unregisterNetEventHandler(s.key)
	s.events, s.key = 0, 0
	return nil
}

func (s *wfpNetEventSession) close() error {
	return errors.Join(s.unsubscribe(), fwpmEngineClose(s.engine))
}

// openAllowEvents opens the net event session when none is open.
//
// The caller holds c.mu.
func (c *WFPController) openAllowEvents() error {
	if c.netEvents != nil {
		return nil
	}
	s, err := c.openNetEvents()
	if err != nil {
		return fmt.Errorf("policy: wfp: allow events: open session: %w%s", err, adminHint(err))
	}
	c.netEvents = s
	return nil
}

// closeAllowEvents closes the net event session, when one is open.
//
// The caller holds c.mu.
func (c *WFPController) closeAllowEvents() error {
	if c.netEvents == nil {
		return nil
	}
	err := c.netEvents.close()
	c.netEvents = nil
	c.subscribed = false
	if err != nil {
		return fmt.Errorf("policy: wfp: allow events: close session: %w", err)
	}
	return nil
}

// readAllowEventsOptions reads the two engine options.
//
// The caller holds c.mu.
func (c *WFPController) readAllowEventsOptions() (collect, keywords uint32, err error) {
	if collect, err = c.netEvents.option(fwpmEngineCollectNetEvents); err != nil {
		return 0, 0, fmt.Errorf("policy: wfp: allow events: read collect_net_events: %w", err)
	}
	if keywords, err = c.netEvents.option(fwpmEngineNetEventMatchAnyKeywords); err != nil {
		return 0, 0, fmt.Errorf("policy: wfp: allow events: read match_any_keywords: %w", err)
	}
	return collect, keywords, nil
}

// enableAllowEvents makes the filter engine record the connections it permits
// and subscribes to those records.
//
// DECISION: the engine records a permitted connection only while
// fwpmNetEventKeywordClassifyAllow is set in
// fwpmEngineNetEventMatchAnyKeywords, an option of the whole host that
// persists across reboots, and while it does, Windows records every permitted
// ALE connection on the host (author, 2026-11-12, #179). plexd sets the option
// only while the applied ruleset holds a logged rule. Before it changes
// anything it writes the host's setting to wfpAllowEventsFile, and
// restoreAllowEvents puts it back when no logged rule is left, at shutdown,
// and at the next start after a crash. An existing file is kept as it is: it
// is the one an earlier logged apply of this run wrote, or one a run that
// crashed, or a restore that failed, left behind, and either way it holds the
// host's setting.
//
// The caller holds c.mu.
func (c *WFPController) enableAllowEvents() error {
	if c.stateDir == "" {
		return errors.New("policy: wfp: allow events: no state directory")
	}
	if err := c.openAllowEvents(); err != nil {
		return err
	}
	collect, keywords, err := c.readAllowEventsOptions()
	if err != nil {
		return err
	}

	_, err = os.Stat(filepath.Join(c.stateDir, wfpAllowEventsFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		data, err := json.Marshal(allowEventsRecord{CollectNetEvents: collect, MatchAnyKeywords: keywords})
		if err != nil {
			return fmt.Errorf("policy: wfp: allow events: record options: %w", err)
		}
		if err := fsutil.WriteFileAtomic(c.stateDir, wfpAllowEventsFile, data, 0o600); err != nil {
			return fmt.Errorf("policy: wfp: allow events: record options: %w", err)
		}
	case err != nil:
		return fmt.Errorf("policy: wfp: allow events: record options: %w", err)
	}

	changed := false
	if collect == 0 {
		if err := c.netEvents.setOption(fwpmEngineCollectNetEvents, 1); err != nil {
			return fmt.Errorf("policy: wfp: allow events: set collect_net_events: %w", err)
		}
		changed = true
	}
	if keywords&fwpmNetEventKeywordClassifyAllow == 0 {
		if err := c.netEvents.setOption(fwpmEngineNetEventMatchAnyKeywords, keywords|fwpmNetEventKeywordClassifyAllow); err != nil {
			return fmt.Errorf("policy: wfp: allow events: set match_any_keywords: %w", err)
		}
		changed = true
	}
	if changed {
		c.logger.Info("wfp allow-event collection enabled",
			"component", "policy",
			"previous_keywords", keywords,
		)
	}

	if !c.subscribed {
		if err := c.netEvents.subscribe(c.onAllowEvent); err != nil {
			return fmt.Errorf("policy: wfp: allow events: subscribe: %w", err)
		}
		c.subscribed = true
	}
	return nil
}

// readAllowEventsRecord reads wfpAllowEventsFile. found is false when there
// is no state directory or no file.
//
// DECISION: a record that is not valid JSON is read as collect_net_events 1
// and match_any_keywords 0, so the restore clears the keyword plexd sets and
// leaves collection on. plexd writes a record only before it sets the
// keyword, so the keyword being plexd's is the likelier reading, and a record
// that never parses would otherwise keep the option set for good.
//
// The caller holds c.mu.
func (c *WFPController) readAllowEventsRecord() (rec allowEventsRecord, found bool, err error) {
	if c.stateDir == "" {
		return allowEventsRecord{}, false, nil
	}
	data, err := os.ReadFile(filepath.Join(c.stateDir, wfpAllowEventsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return allowEventsRecord{}, false, nil
	}
	if err != nil {
		return allowEventsRecord{}, false, fmt.Errorf("policy: wfp: allow events: read record: %w", err)
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		c.logger.Warn("policy: wfp: allow-event record unreadable",
			"component", "policy",
			"error", fmt.Errorf("%s: %w", wfpAllowEventsFile, err),
		)
		return allowEventsRecord{CollectNetEvents: 1, MatchAnyKeywords: 0}, true, nil
	}
	return rec, true, nil
}

// restoreAllowEvents ends the subscription and puts back what
// enableAllowEvents changed, from the record it wrote. It clears the keyword
// unless the record holds it, and turns net event collection off when the
// record holds it off. Bits set by others since stay as they are. Once the
// options are back it closes the session, and only then deletes the record,
// so on any error it keeps the record and the next call tries again. Without
// a record it only closes the session, when one is open.
//
// The caller holds c.mu.
func (c *WFPController) restoreAllowEvents() error {
	if c.subscribed {
		if err := c.netEvents.unsubscribe(); err != nil {
			return fmt.Errorf("policy: wfp: allow events: unsubscribe: %w", err)
		}
		c.subscribed = false
	}

	rec, found, err := c.readAllowEventsRecord()
	if err != nil {
		return err
	}
	if !found {
		return c.closeAllowEvents()
	}

	if err := c.openAllowEvents(); err != nil {
		return err
	}
	collect, keywords, err := c.readAllowEventsOptions()
	if err != nil {
		return err
	}
	if rec.MatchAnyKeywords&fwpmNetEventKeywordClassifyAllow == 0 && keywords&fwpmNetEventKeywordClassifyAllow != 0 {
		if err := c.netEvents.setOption(fwpmEngineNetEventMatchAnyKeywords, keywords&^fwpmNetEventKeywordClassifyAllow); err != nil {
			return fmt.Errorf("policy: wfp: allow events: set match_any_keywords: %w", err)
		}
	}
	if rec.CollectNetEvents == 0 && collect != 0 {
		if err := c.netEvents.setOption(fwpmEngineCollectNetEvents, 0); err != nil {
			return fmt.Errorf("policy: wfp: allow events: set collect_net_events: %w", err)
		}
	}
	if err := c.closeAllowEvents(); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(c.stateDir, wfpAllowEventsFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("policy: wfp: allow events: delete record: %w", err)
	}

	c.logger.Info("wfp allow-event collection restored", "component", "policy")
	return nil
}

// restoreAllowEventsOrWarn restores the engine's allow-event options and logs
// a failure instead of returning it.
//
// The caller holds c.mu.
func (c *WFPController) restoreAllowEventsOrWarn() {
	if err := c.restoreAllowEvents(); err != nil {
		c.logger.Warn("policy: wfp: restore allow-event collection",
			"component", "policy",
			"error", err,
		)
	}
}

// onAllowEvent reports a connection a logged filter permitted to the sink.
//
// DECISION: an event with a reauthReason other than 0, or with isLoopback
// set, is dropped. After every filter change the engine reports every live
// flow again with a reauthReason (0x5 on windows-latest, run 43612480437), and
// every apply replaces the filters, so each reconcile would otherwise log
// every live connection again. Loopback traffic never crosses the mesh
// interface.
//
// While a logged rule is applied, the engine calls this for every connection
// it permits on the host, not only on the mesh adapter, so it does nothing
// before the lookup but two comparisons, and the lookup is at most two map
// reads per chain, its current map and then its previous one. The
// ConnLogger's rate limit bounds the lines.
//
// It never takes c.mu: FwpmNetEventUnsubscribe0, which restoreAllowEvents
// calls under c.mu, waits for the calls that are running.
func (c *WFPController) onAllowEvent(ev allowEvent) {
	if ev.reauthReason != 0 || ev.isLoopback {
		return
	}
	c.logMu.RLock()
	sink := c.sink
	lf, ok := c.logFilterByID(ev.filterID)
	c.logMu.RUnlock()
	if !ok || sink == nil {
		return
	}
	sink.Event(lf.connEvent(ev))
}

// connEvent builds the event the sink gets. At the inbound layer the remote
// side opened the connection, at the outbound layer the node did. Ports are 0
// unless the protocol is TCP or UDP: for any other protocol the header's port
// fields do not hold ports.
func (lf wfpLogFilter) connEvent(ev allowEvent) ConnEvent {
	ce := ConnEvent{Tag: lf.tag, Dir: lf.dir, Protocol: ev.protocol}
	if lf.dir == ConnIn {
		ce.Src, ce.Dst = ev.remote, ev.local
		ce.SrcPort, ce.DstPort = ev.remotePort, ev.localPort
	} else {
		ce.Src, ce.Dst = ev.local, ev.remote
		ce.SrcPort, ce.DstPort = ev.localPort, ev.remotePort
	}
	if ev.protocol != ipProtoTCP && ev.protocol != ipProtoUDP {
		ce.SrcPort, ce.DstPort = 0, 0
	}
	return ce
}
