//go:build windows

package policy

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/plexsphere/plexd/internal/wintundll"
)

// tunUDPLogsEveryPacket tells runTunConnLogChecks that the filter engine
// reports a UDP flow once: it authorizes the flow's first datagram at the ALE
// layer, and the later datagrams of the flow pass without another
// authorization.
const tunUDPLogsEveryPacket = false

// newTunTestHarness creates a Wintun adapter that carries N's address, and a
// WFP controller. The rules the checks apply name that adapter alone, so
// nothing else on the machine running the test is filtered.
func newTunTestHarness(t *testing.T) tunHarness {
	t.Helper()

	// The Wintun loader looks for its DLL beside the executable.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("path of the test binary: %v", err)
	}
	if _, _, err := wintundll.Ensure(filepath.Dir(exe)); err != nil {
		t.Fatalf("write wintun.dll beside the test binary: %v", err)
	}

	const name = "plexd-fwtest"
	dev, err := tun.CreateTUN(name, tunTestMTU)
	if err != nil {
		t.Fatalf("create the Wintun adapter %s: %v", name, err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		t.Fatalf("tun.CreateTUN returned a %T, want a *tun.NativeTun", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	if err := luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(tunNodeAddr, 30)}); err != nil {
		t.Fatalf("assign %s/30 to %s: %v", tunNodeAddr, name, err)
	}

	return tunHarness{
		ctrl:   NewWFPController(tunTestLogger(t), name),
		dev:    dev,
		offset: 0,
		iface:  name,
	}
}

// TestWFPController_RealTraffic drives the host's filter engine with traffic
// through a Wintun adapter the test creates. Its rules name that adapter
// alone, so nothing else on the machine running the test is filtered. The
// Windows Firewall blocks the unsolicited packets the test injects on its
// own, so the CI step turns its profiles off first.
func TestWFPController_RealTraffic(t *testing.T) {
	// Gated like TestWFPController_Real: the CI runner is already elevated,
	// and without the variable the ordinary test step would create an
	// adapter and install filters.
	if os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WFP=1 in an elevated shell to program the filter engine")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter and programming the filter engine need Administrator")
	}

	runTunTrafficChecks(t, newTunTestHarness(t))
}

// TestWFPController_RealConnLog runs the connection-log checks through a
// Wintun adapter the test creates, which the controller reports through the
// engine's classify-allow net events and its FwpmNetEventSubscribe4
// subscription. A reported connection proves the keyword and the event type
// plexd reads from the Windows SDK, the layout of FWPM_NET_EVENT5, and that
// an event names the filter plexd installed by the id FilterIDs read. Like the
// traffic test, it needs the Windows Firewall's profiles off.
//
// It also proves what the controller does with the engine's two allow-event
// options, which belong to the whole host and outlive the process: it reads
// them before the first logged apply, finds them on and their record in the
// state directory after each logged apply, and finds them back at their
// starting values and the record gone after DeleteChain. It then leaves the
// options and the record as a run that crashed with logging on would, and
// shows that SetStateDir of a new controller with the same state directory
// puts the options back and deletes the record.
func TestWFPController_RealConnLog(t *testing.T) {
	// Gated like TestWFPController_Real: the CI runner is already elevated,
	// and without the variable the ordinary test step would create an
	// adapter, install filters and turn on the host's allow events.
	if os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WFP=1 in an elevated shell to program the filter engine")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter and programming the filter engine need Administrator")
	}

	// The test reads the options through a session of its own, as an
	// operator's tool would.
	s, err := openNetEventSession()
	if err != nil {
		t.Fatalf("open a filter engine session: %v", err)
	}
	t.Cleanup(func() { _ = s.close() })
	startCollect, startKeywords := engineAllowEventOptions(t, s)
	t.Logf("before the first logged apply: collect_net_events %d, match_any_keywords %#x", startCollect, startKeywords)
	if startKeywords&fwpmNetEventKeywordClassifyAllow != 0 {
		t.Fatalf("match_any_keywords %#x already holds the classify-allow keyword %#x, so the test cannot show that the controller sets and restores it",
			startKeywords, fwpmNetEventKeywordClassifyAllow)
	}
	// A check that fails may leave the options changed. The host gets its
	// setting back either way.
	t.Cleanup(func() {
		collect, keywords := engineAllowEventOptions(t, s)
		if keywords != startKeywords {
			if err := s.setOption(fwpmEngineNetEventMatchAnyKeywords, startKeywords); err != nil {
				t.Errorf("put match_any_keywords back to %#x: %v", startKeywords, err)
			}
		}
		if collect != startCollect {
			if err := s.setOption(fwpmEngineCollectNetEvents, startCollect); err != nil {
				t.Errorf("put collect_net_events back to %d: %v", startCollect, err)
			}
		}
	})

	stateDir := t.TempDir()
	record := filepath.Join(stateDir, wfpAllowEventsFile)
	want := allowEventsRecord{CollectNetEvents: startCollect, MatchAnyKeywords: startKeywords}

	h := newTunTestHarness(t)
	ctrl := h.ctrl.(*WFPController)
	ctrl.SetStateDir(stateDir)
	h.ctrl = wfpLoggedApplyHook{
		WFPController: ctrl,
		afterLogged: func() {
			collect, keywords := engineAllowEventOptions(t, s)
			if keywords&fwpmNetEventKeywordClassifyAllow == 0 {
				t.Errorf("after an apply with a logged rule: match_any_keywords %#x, want the classify-allow keyword %#x set",
					keywords, fwpmNetEventKeywordClassifyAllow)
			}
			if collect == 0 {
				t.Errorf("after an apply with a logged rule: collect_net_events 0, want it on")
			}
			got, err := allowEventsRecordAt(record)
			switch {
			case err != nil:
				t.Errorf("after an apply with a logged rule: read the record: %v", err)
			case got != want:
				t.Errorf("after an apply with a logged rule: %s holds %+v, want the starting values %+v", wfpAllowEventsFile, got, want)
			}
		},
	}

	runTunConnLogChecks(t, h)

	t.Log("DeleteChain put the starting values back and deleted the record")
	expectEngineAllowEventOptions(t, s, startCollect, startKeywords)
	expectNoAllowEventsRecord(t, record)

	t.Log("a run that crashed with logging on left the options set and the record behind")
	if startCollect == 0 {
		if err := s.setOption(fwpmEngineCollectNetEvents, 1); err != nil {
			t.Fatalf("set collect_net_events: %v", err)
		}
	}
	if err := s.setOption(fwpmEngineNetEventMatchAnyKeywords, startKeywords|fwpmNetEventKeywordClassifyAllow); err != nil {
		t.Fatalf("set match_any_keywords: %v", err)
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("encode the record: %v", err)
	}
	if err := os.WriteFile(record, data, 0o600); err != nil {
		t.Fatalf("write the record: %v", err)
	}

	t.Log("the next start's SetStateDir puts the starting values back and deletes the record")
	next := NewWFPController(tunTestLogger(t), h.iface)
	next.SetStateDir(stateDir)
	expectEngineAllowEventOptions(t, s, startCollect, startKeywords)
	expectNoAllowEventsRecord(t, record)
}

// wfpLoggedApplyHook calls afterLogged once each ApplyRules that holds a
// logged rule has succeeded, so a test can look at the host while the
// controller logs. Every other method is the WFPController's own.
type wfpLoggedApplyHook struct {
	*WFPController
	afterLogged func()
}

func (c wfpLoggedApplyHook) ApplyRules(chain string, rules []FirewallRule) error {
	if err := c.WFPController.ApplyRules(chain, rules); err != nil {
		return err
	}
	if hasLogTags(rules) {
		c.afterLogged()
	}
	return nil
}

// engineAllowEventOptions reads the two engine options the controller
// changes to log connections.
func engineAllowEventOptions(t *testing.T, s netEventSession) (collect, keywords uint32) {
	t.Helper()
	collect, err := s.option(fwpmEngineCollectNetEvents)
	if err != nil {
		t.Fatalf("read collect_net_events: %v", err)
	}
	keywords, err = s.option(fwpmEngineNetEventMatchAnyKeywords)
	if err != nil {
		t.Fatalf("read match_any_keywords: %v", err)
	}
	return collect, keywords
}

// expectEngineAllowEventOptions fails the test unless the two engine options
// hold collect and keywords.
func expectEngineAllowEventOptions(t *testing.T, s netEventSession, collect, keywords uint32) {
	t.Helper()
	gotCollect, gotKeywords := engineAllowEventOptions(t, s)
	if gotKeywords != keywords {
		t.Errorf("match_any_keywords = %#x, want the starting value %#x", gotKeywords, keywords)
	}
	if gotCollect != collect {
		t.Errorf("collect_net_events = %d, want the starting value %d", gotCollect, collect)
	}
}

// allowEventsRecordAt reads the record the controller keeps at path.
func allowEventsRecordAt(path string) (allowEventsRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return allowEventsRecord{}, err
	}
	var rec allowEventsRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return allowEventsRecord{}, err
	}
	return rec, nil
}

// expectNoAllowEventsRecord fails the test unless no record exists at path.
func expectNoAllowEventsRecord(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat %s: %v, want the record deleted", path, err)
	}
}
