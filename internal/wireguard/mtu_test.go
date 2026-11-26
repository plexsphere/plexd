package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// stubProbe is a path MTU probe that answers every round with pathMTU and err
// as the test last set them, and counts its rounds. It is for tests that call
// adjustMTU from their own goroutine.
type stubProbe struct {
	pathMTU int
	err     error
	rounds  int
}

func (p *stubProbe) probe(context.Context) (int, error) {
	p.rounds++
	return p.pathMTU, p.err
}

// newAdjustManager returns a Manager whose interface was last programmed at
// mtu, as Setup leaves it, with a stubProbe set and a debug-level text logger
// writing to logs.
func newAdjustManager(mtu int, logs io.Writer) (*Manager, *mockController, *stubProbe) {
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, slogTextLogger(logs))
	p := &stubProbe{}
	mgr.SetPathMTUProbe(p.probe)
	mgr.mtu = mtu
	return mgr, ctrl, p
}

// adjustAt runs one adjustMTU round whose probe measures pathMTU.
func adjustAt(mgr *Manager, p *stubProbe, pathMTU int) {
	p.pathMTU, p.err = pathMTU, nil
	mgr.adjustMTU(context.Background())
}

// setMTUs returns the MTU of every SetMTU call ctrl recorded, in order, and
// fails the test for a call on another interface than plexd0.
func setMTUs(t *testing.T, ctrl *mockController) []int {
	t.Helper()
	var mtus []int
	for _, call := range ctrl.callsFor("SetMTU") {
		if call.Args[0] != "plexd0" {
			t.Errorf("SetMTU iface = %v, want plexd0", call.Args[0])
		}
		mtu, ok := call.Args[1].(int)
		if !ok {
			t.Fatalf("SetMTU arg = %T, want int", call.Args[1])
		}
		mtus = append(mtus, mtu)
	}
	return mtus
}

// callMethods returns the method of every call ctrl recorded, in order.
func callMethods(ctrl *mockController) []string {
	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()
	methods := make([]string, 0, len(ctrl.calls))
	for _, call := range ctrl.calls {
		methods = append(methods, call.Method)
	}
	return methods
}

// logLine returns the first line of out that contains msg, or "" when none
// does. Several lines carry an mtu key, so attributes are checked on the line
// they belong to.
func logLine(out, msg string) string {
	for line := range strings.Lines(out) {
		if strings.Contains(line, msg) {
			return line
		}
	}
	return ""
}

// assertLogLine fails the test unless out has a line containing msg that also
// contains every entry of attrs.
func assertLogLine(t *testing.T, out, msg string, attrs ...string) {
	t.Helper()
	line := logLine(out, msg)
	if line == "" {
		t.Errorf("no %q line:\n%s", msg, out)
		return
	}
	for _, want := range attrs {
		if !strings.Contains(line, want) {
			t.Errorf("%q line does not contain %q:\n%s", msg, want, line)
		}
	}
}

// clampMSSes returns the MSS of every ClampMSS call ctrl recorded, in order,
// and fails the test for a call on another interface than plexd0.
func clampMSSes(t *testing.T, ctrl *mockController) []int {
	t.Helper()
	var mss []int
	for _, call := range ctrl.callsFor("ClampMSS") {
		if call.Args[0] != "plexd0" {
			t.Errorf("ClampMSS iface = %v, want plexd0", call.Args[0])
		}
		v, ok := call.Args[1].(int)
		if !ok {
			t.Fatalf("ClampMSS arg = %T, want int", call.Args[1])
		}
		mss = append(mss, v)
	}
	return mss
}

// clearCalls drops the calls ctrl recorded, so a test sees only the calls
// of what it does next.
func clearCalls(ctrl *mockController) {
	ctrl.mu.Lock()
	ctrl.calls = nil
	ctrl.mu.Unlock()
}

// programClamp records the clamp for mgr's MTU through a successful
// clampMSS, the state Setup leaves when its ClampMSS call succeeds, which a
// manager from newAdjustManager does not have. It drops the call and its log
// line, so the test sees only what its own rounds do.
func programClamp(t *testing.T, mgr *Manager, ctrl *mockController) {
	t.Helper()
	logger := mgr.logger
	mgr.logger = discardLogger()
	mgr.clampMSS(mgr.mtu)
	mgr.logger = logger
	if got, want := mgr.mss.Load(), int32(ForwardMSS(mgr.mtu)); got != want {
		t.Fatalf("mss after clampMSS(%d) = %d, want %d", mgr.mtu, got, want)
	}
	clearCalls(ctrl)
}

// setupWithProbe returns a manager over ctrl that Setup sized with a probe
// measuring pathMTU, and that probe for the test's rounds. It fails the test
// when Setup fails, and drops the calls and log lines of Setup, so the test
// sees only what it does next.
func setupWithProbe(t *testing.T, ctrl *mockController, pathMTU int, logs *bytes.Buffer) (*Manager, *stubProbe) {
	t.Helper()
	mgr := NewManager(ctrl, Config{}, slogTextLogger(logs))
	p := &stubProbe{pathMTU: pathMTU}
	mgr.SetPathMTUProbe(p.probe)
	if err := mgr.Setup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	clearCalls(ctrl)
	logs.Reset()
	return mgr, p
}

// ---------------------------------------------------------------------------
// MeshMTU
// ---------------------------------------------------------------------------

func TestMeshMTU(t *testing.T) {
	tests := []struct {
		pathMTU int
		want    int
	}{
		{9000, 1420},
		{1500, 1420},
		{1492, 1412},
		{1452, 1372},
		{1360, 1280},
		{1300, 1280},
		{48, 1280},
		{0, 1280},
	}
	for _, tt := range tests {
		if got := MeshMTU(tt.pathMTU); got != tt.want {
			t.Errorf("MeshMTU(%d) = %d, want %d", tt.pathMTU, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ForwardMSS
// ---------------------------------------------------------------------------

func TestForwardMSS(t *testing.T) {
	tests := []struct {
		mtu  int
		want int
	}{
		{1420, 1380},
		{1372, 1332},
		{1280, 1240},
		{577, 537},
		{576, 536},
		{500, 536},
		{0, 536},
		{-1, 536},
	}
	for _, tt := range tests {
		if got := ForwardMSS(tt.mtu); got != tt.want {
			t.Errorf("ForwardMSS(%d) = %d, want %d", tt.mtu, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RunMTUProbe
// ---------------------------------------------------------------------------

// runMTUProbeReturnsAtOnce runs RunMTUProbe on a live context and fails the
// test unless it returns nil within a second, without logging.
func runMTUProbeReturnsAtOnce(t *testing.T, mgr *Manager, logs *syncBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.RunMTUProbe(ctx, time.Millisecond) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunMTUProbe() = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunMTUProbe did not return at once")
	}
	if out := logs.String(); out != "" {
		t.Errorf("RunMTUProbe logged, want nothing:\n%s", out)
	}
}

func TestRunMTUProbe_DisabledByConfig(t *testing.T) {
	var logs syncBuffer
	mgr := NewManager(&mockController{}, Config{MTU: 1400}, slogTextLogger(&logs))
	p := &stubProbe{pathMTU: 1500}
	mgr.SetPathMTUProbe(p.probe)

	runMTUProbeReturnsAtOnce(t, mgr, &logs)
	if p.rounds != 0 {
		t.Errorf("probe ran %d times, want never with a pinned MTU", p.rounds)
	}
}

func TestRunMTUProbe_NoProbe(t *testing.T) {
	var logs syncBuffer
	mgr := NewManager(&mockController{}, Config{}, slogTextLogger(&logs))

	runMTUProbeReturnsAtOnce(t, mgr, &logs)
}

func TestRunMTUProbe_Ticks(t *testing.T) {
	var logs syncBuffer
	mgr := NewManager(&mockController{}, Config{}, slogTextLogger(&logs))
	rounds := make(chan struct{}, 2)
	mgr.SetPathMTUProbe(func(context.Context) (int, error) {
		select {
		case rounds <- struct{}{}:
		default:
		}
		return 1500, nil
	})
	mgr.mtu = DefaultMTU

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.RunMTUProbe(ctx, 10*time.Millisecond) }()

	for i := range 2 {
		select {
		case <-rounds:
		case <-time.After(5 * time.Second):
			t.Fatalf("probe ran %d times, want at least 2", i)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunMTUProbe() = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunMTUProbe did not return within 1s after its context was canceled")
	}
	assertLogLine(t, logs.String(), "wireguard: mtu probe started", "component=wireguard", "interval=10ms")
}

func TestRunMTUProbe_FirstRoundAfterInterval(t *testing.T) {
	mgr := NewManager(&mockController{}, Config{}, discardLogger())
	rounds := make(chan struct{}, 1)
	mgr.SetPathMTUProbe(func(context.Context) (int, error) {
		select {
		case rounds <- struct{}{}:
		default:
		}
		return 1500, nil
	})
	mgr.mtu = DefaultMTU

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- mgr.RunMTUProbe(ctx, time.Hour) }()

	// The probe in Setup is the first round, so the loop's first comes an
	// interval after the call. A test cannot wait out the hour, so it watches
	// a short window for a round run at once. A round run before the loop's
	// first wait still sits in the buffered channel after RunMTUProbe returns,
	// however late its goroutine was scheduled.
	select {
	case <-rounds:
		t.Fatal("probe ran right after RunMTUProbe started, want the first round an interval later")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunMTUProbe() = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RunMTUProbe did not return within 1s after its context was canceled")
	}
	select {
	case <-rounds:
		t.Error("probe ran before the first tick, want the first round an interval after start")
	default:
	}
}

// ---------------------------------------------------------------------------
// adjustMTU
// ---------------------------------------------------------------------------

func TestAdjustMTU_LowersAtOnce(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1420, &logs)

	adjustAt(mgr, p, 1452)

	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1372}) {
		t.Errorf("SetMTU calls = %v, want [1372]", got)
	}
	if mgr.mtu != 1372 {
		t.Errorf("mtu = %d, want 1372", mgr.mtu)
	}
	assertLogLine(t, logs.String(), "wireguard: mesh mtu lowered",
		"level=INFO", "component=wireguard", "old_mtu=1420 mtu=1372 path_mtu=1452")
	if strings.Contains(logs.String(), "less than the mesh minimum mtu") {
		t.Errorf("floor warning for an uplink above the minimum:\n%s", logs.String())
	}
}

func TestAdjustMTU_Floor(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1420, &logs)

	adjustAt(mgr, p, 48)

	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1280}) {
		t.Errorf("SetMTU calls = %v, want [1280]", got)
	}
	out := logs.String()
	assertLogLine(t, out, "wireguard: mesh mtu lowered", "old_mtu=1420 mtu=1280 path_mtu=48")
	assertLogLine(t, out, "wireguard: uplink carries less than the mesh minimum mtu",
		"level=WARN", "component=wireguard", "path_mtu=48 mtu=1280")
}

// A 1360-byte uplink carries MinMTU mesh packets exactly, so only an uplink
// below it gets the floor warning.
func TestAdjustMTU_FloorBoundary(t *testing.T) {
	tests := []struct {
		name    string
		pathMTU int
		warn    bool
	}{
		{name: "uplink that fits the minimum", pathMTU: 1360, warn: false},
		{name: "uplink one byte short of the minimum", pathMTU: 1359, warn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			mgr, ctrl, p := newAdjustManager(1420, &logs)

			adjustAt(mgr, p, tt.pathMTU)

			if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1280}) {
				t.Errorf("SetMTU calls = %v, want [1280]", got)
			}
			out := logs.String()
			const warning = "wireguard: uplink carries less than the mesh minimum mtu"
			if !tt.warn {
				if strings.Contains(out, warning) {
					t.Errorf("floor warning for a %d-byte uplink:\n%s", tt.pathMTU, out)
				}
				return
			}
			assertLogLine(t, out, warning, "level=WARN", fmt.Sprintf("path_mtu=%d mtu=1280", tt.pathMTU))
		})
	}
}

func TestAdjustMTU_RaisesAfterTwoAgreeingRounds(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1372, &logs)

	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); len(got) != 0 {
		t.Fatalf("SetMTU calls after the first round = %v, want none", got)
	}
	assertLogLine(t, logs.String(), "wireguard: higher mesh mtu seen, raising when the next probe agrees",
		"level=DEBUG", "component=wireguard", "mtu=1372 raise_to=1420 path_mtu=1500")

	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1420}) {
		t.Errorf("SetMTU calls after the second round = %v, want [1420]", got)
	}
	assertLogLine(t, logs.String(), "wireguard: mesh mtu raised",
		"level=INFO", "component=wireguard", "old_mtu=1372 mtu=1420 path_mtu=1500")
}

func TestAdjustMTU_RaiseResetByDisagreement(t *testing.T) {
	mgr, ctrl, p := newAdjustManager(1372, io.Discard)

	for i, pathMTU := range []int{1500, 1480} {
		adjustAt(mgr, p, pathMTU)
		if got := setMTUs(t, ctrl); len(got) != 0 {
			t.Fatalf("SetMTU calls after round %d = %v, want none", i+1, got)
		}
	}
	adjustAt(mgr, p, 1480)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1400}) {
		t.Errorf("SetMTU calls after the third round = %v, want [1400]", got)
	}
}

func TestAdjustMTU_RaiseResetByInconclusive(t *testing.T) {
	mgr, ctrl, p := newAdjustManager(1372, io.Discard)

	adjustAt(mgr, p, 1500)
	p.pathMTU, p.err = 0, errors.New("nat: mtu probe: no STUN server answered")
	mgr.adjustMTU(context.Background())
	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); len(got) != 0 {
		t.Fatalf("SetMTU calls after three rounds = %v, want none", got)
	}

	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1420}) {
		t.Errorf("SetMTU calls after the fourth round = %v, want [1420]", got)
	}
}

func TestAdjustMTU_RaiseResetByUnchanged(t *testing.T) {
	mgr, ctrl, p := newAdjustManager(1372, io.Discard)

	for i, pathMTU := range []int{1500, 1452, 1500} {
		adjustAt(mgr, p, pathMTU)
		if got := setMTUs(t, ctrl); len(got) != 0 {
			t.Fatalf("SetMTU calls after round %d = %v, want none", i+1, got)
		}
	}
	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1420}) {
		t.Errorf("SetMTU calls after the fourth round = %v, want [1420]", got)
	}
}

func TestAdjustMTU_RaiseResetByLower(t *testing.T) {
	mgr, ctrl, p := newAdjustManager(1372, io.Discard)

	for _, pathMTU := range []int{1500, 1400, 1500} {
		adjustAt(mgr, p, pathMTU)
	}
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1320}) {
		t.Fatalf("SetMTU calls after three rounds = %v, want the lower [1320] only", got)
	}
	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1320, 1420}) {
		t.Errorf("SetMTU calls after the fourth round = %v, want [1320 1420]", got)
	}
}

func TestAdjustMTU_RaiseResetBySetMTUFailure(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1372, &logs)
	ctrl.setMTUErr = errors.New("netlink: device busy")

	adjustAt(mgr, p, 1500)
	adjustAt(mgr, p, 1500)

	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1420}) {
		t.Fatalf("SetMTU calls after two rounds = %v, want the failed raise [1420]", got)
	}
	if mgr.mtu != 1372 {
		t.Errorf("mtu after a failed SetMTU = %d, want 1372 kept", mgr.mtu)
	}
	assertLogLine(t, logs.String(), "wireguard: mesh mtu change failed",
		"level=WARN", "component=wireguard", "old_mtu=1372 mtu=1420", "netlink: device busy")
	if strings.Contains(logs.String(), "wireguard: mesh mtu raised") {
		t.Errorf("raised line for a failed SetMTU:\n%s", logs.String())
	}

	// The failed write dropped the pending raise, so the raise again takes
	// two agreeing rounds.
	ctrl.setMTUErr = nil
	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1420}) {
		t.Fatalf("SetMTU calls after the third round = %v, want the failed [1420] only", got)
	}
	adjustAt(mgr, p, 1500)
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1420, 1420}) {
		t.Errorf("SetMTU calls after the fourth round = %v, want the failed [1420] and its retry [1420]", got)
	}
	if mgr.mtu != 1420 {
		t.Errorf("mtu after the retry = %d, want 1420", mgr.mtu)
	}
}

func TestAdjustMTU_Unchanged(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1372, &logs)
	// The clamp Setup programs for MTU 1372 is current, so the round has no
	// clamp to retry either.
	programClamp(t, mgr, ctrl)

	adjustAt(mgr, p, 1452)

	if got := setMTUs(t, ctrl); len(got) != 0 {
		t.Errorf("SetMTU calls = %v, want none", got)
	}
	if strings.Contains(logs.String(), "level=INFO") {
		t.Errorf("Info line for an unchanged MTU:\n%s", logs.String())
	}
}

func TestAdjustMTU_Inconclusive(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1420, &logs)
	p.err = errors.New("nat: mtu probe: no STUN server answered")

	mgr.adjustMTU(context.Background())

	if got := setMTUs(t, ctrl); len(got) != 0 {
		t.Errorf("SetMTU calls = %v, want none", got)
	}
	if mgr.mtu != 1420 {
		t.Errorf("mtu = %d, want 1420 kept", mgr.mtu)
	}
	assertLogLine(t, logs.String(), "wireguard: mtu probe inconclusive, keeping the current mtu",
		"level=WARN", "component=wireguard", "mtu=1420", "nat: mtu probe: no STUN server answered")
}

func TestAdjustMTU_SetMTUFails(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1420, &logs)
	ctrl.setMTUErr = errors.New("netlink: device busy")

	adjustAt(mgr, p, 1452)

	if mgr.mtu != 1420 {
		t.Errorf("mtu after a failed SetMTU = %d, want 1420 kept", mgr.mtu)
	}
	assertLogLine(t, logs.String(), "wireguard: mesh mtu change failed",
		"level=WARN", "component=wireguard", "old_mtu=1420 mtu=1372", "netlink: device busy")
	if strings.Contains(logs.String(), "wireguard: mesh mtu lowered") {
		t.Errorf("lowered line for a failed SetMTU:\n%s", logs.String())
	}

	ctrl.setMTUErr = nil
	adjustAt(mgr, p, 1452)

	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1372, 1372}) {
		t.Errorf("SetMTU calls = %v, want the failed [1372] and its retry [1372]", got)
	}
	if mgr.mtu != 1372 {
		t.Errorf("mtu after the retry = %d, want 1372", mgr.mtu)
	}
}

func TestAdjustMTU_CanceledContext(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := NewManager(ctrl, Config{}, slogTextLogger(&logs))
	mgr.mtu = DefaultMTU
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.SetPathMTUProbe(func(context.Context) (int, error) {
		cancel()
		return 1452, nil
	})

	mgr.adjustMTU(ctx)

	if got := setMTUs(t, ctrl); len(got) != 0 {
		t.Errorf("SetMTU calls = %v, want none after the context was canceled", got)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("Warn line after the context was canceled:\n%s", logs.String())
	}
}

// A shutdown cuts the probe's round short and nat.ProbePathMTU returns the
// context's error, which says nothing about the uplink: the round leaves the
// device, the log and a pending raise alone.
func TestAdjustMTU_CanceledContextProbeError(t *testing.T) {
	var logs bytes.Buffer
	mgr, ctrl, p := newAdjustManager(1372, &logs)
	adjustAt(mgr, p, 1500)
	if mgr.raiseTo != 1420 {
		t.Fatalf("raiseTo after a round at 1500 = %d, want 1420 pending", mgr.raiseTo)
	}
	logs.Reset()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.SetPathMTUProbe(func(context.Context) (int, error) {
		cancel()
		return 0, fmt.Errorf("nat: mtu probe: %w", context.Canceled)
	})

	mgr.adjustMTU(ctx)

	if got := setMTUs(t, ctrl); len(got) != 0 {
		t.Errorf("SetMTU calls = %v, want none after the context was canceled", got)
	}
	if out := logs.String(); out != "" {
		t.Errorf("adjustMTU logged after the context was canceled, want nothing:\n%s", out)
	}
	if mgr.mtu != 1372 || mgr.raiseTo != 1420 {
		t.Errorf("mtu, raiseTo = %d, %d, want 1372, 1420 kept", mgr.mtu, mgr.raiseTo)
	}
}

// ---------------------------------------------------------------------------
// Forwarded TCP MSS clamp
// ---------------------------------------------------------------------------

// errClampDenied is the error the tests' controller returns for a clamp it
// cannot program or remove.
var errClampDenied = errors.New("nftables: operation not permitted")

func TestManager_Setup_ClampsMSSBeforeInterfaceUp(t *testing.T) {
	tests := []struct {
		name    string
		cfgMTU  int
		pathMTU int // 0: no probe
		mtu     int
		mss     int
		calls   []string
	}{
		{
			name:   "mtu from the config",
			cfgMTU: 1400,
			mtu:    1400,
			mss:    1360,
			calls:  []string{"CreateInterface", "ConfigureAddress", "SetMTU", "ClampMSS", "SetInterfaceUp"},
		},
		{
			name:    "mtu from the probe",
			pathMTU: 1452,
			mtu:     1372,
			mss:     1332,
			calls:   []string{"CreateInterface", "ConfigureAddress", "SetMTU", "ClampMSS", "SetInterfaceUp"},
		},
		{
			name:  "default mtu",
			mtu:   1420,
			mss:   1380,
			calls: []string{"CreateInterface", "ConfigureAddress", "ClampMSS", "SetInterfaceUp"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctrl := &mockController{}
			mgr := NewManager(ctrl, Config{MTU: tt.cfgMTU}, slogTextLogger(&logs))
			if tt.pathMTU != 0 {
				mgr.SetPathMTUProbe((&stubProbe{pathMTU: tt.pathMTU}).probe)
			}

			if err := mgr.Setup(context.Background(), testIdentity()); err != nil {
				t.Fatalf("Setup() returned error: %v", err)
			}

			if got := callMethods(ctrl); !slices.Equal(got, tt.calls) {
				t.Errorf("controller calls = %v, want %v", got, tt.calls)
			}
			if got := clampMSSes(t, ctrl); !slices.Equal(got, []int{tt.mss}) {
				t.Errorf("ClampMSS calls = %v, want [%d]", got, tt.mss)
			}
			if got := mgr.mss.Load(); got != int32(tt.mss) {
				t.Errorf("mss = %d, want %d", got, tt.mss)
			}
			out := logs.String()
			assertLogLine(t, out, "wireguard: forwarded tcp mss clamped",
				"level=INFO", "component=wireguard", "interface=plexd0",
				fmt.Sprintf("mss=%d mtu=%d", tt.mss, tt.mtu))
			if line := logLine(out, "wireguard: forwarded tcp mss clamped"); strings.Contains(line, "old_mss=") {
				t.Errorf("clamped line carries old_mss for the first clamp:\n%s", line)
			}
		})
	}
}

func TestManager_Setup_ClampFailureFailsNothing(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{clampMSSErr: errClampDenied}
	mgr := NewManager(ctrl, Config{}, slogTextLogger(&logs))

	if err := mgr.Setup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("Setup() = %v, want nil when only the clamp fails", err)
	}

	want := []string{"CreateInterface", "ConfigureAddress", "ClampMSS", "SetInterfaceUp"}
	if got := callMethods(ctrl); !slices.Equal(got, want) {
		t.Errorf("controller calls = %v, want %v", got, want)
	}
	if got := mgr.mss.Load(); got != 0 {
		t.Errorf("mss after a failed ClampMSS = %d, want 0", got)
	}
	out := logs.String()
	assertLogLine(t, out, "wireguard: forwarded tcp mss clamp failed",
		"level=WARN", "component=wireguard", "interface=plexd0", "mss=1380 mtu=1420",
		`error="nftables: operation not permitted"`)
	if strings.Contains(out, "wireguard: forwarded tcp mss clamped") {
		t.Errorf("clamped line for a failed ClampMSS:\n%s", out)
	}
	assertLogLine(t, out, "wireguard interface configured", "level=INFO", "mtu=1420")
}

func TestManager_NoClampWithoutMSSClamper(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	mgr := NewManager(plainController{ctrl}, Config{}, slogTextLogger(&logs))
	p := &stubProbe{pathMTU: 1452}
	mgr.SetPathMTUProbe(p.probe)

	if err := mgr.Setup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("Setup() returned error: %v", err)
	}
	adjustAt(mgr, p, 1400) // lowers the MTU to 1320
	adjustAt(mgr, p, 1400) // keeps it
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown() returned error: %v", err)
	}

	want := []string{"CreateInterface", "ConfigureAddress", "SetMTU", "SetInterfaceUp", "SetMTU", "DeleteInterface"}
	if got := callMethods(ctrl); !slices.Equal(got, want) {
		t.Errorf("controller calls = %v, want %v", got, want)
	}
	if got := setMTUs(t, ctrl); !slices.Equal(got, []int{1372, 1320}) {
		t.Errorf("SetMTU calls = %v, want [1372 1320]", got)
	}
	if got := mgr.mss.Load(); got != 0 {
		t.Errorf("mss = %d, want 0 without an MSSClamper", got)
	}
	if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
		t.Errorf("clamp line without an MSSClamper:\n%s", out)
	}
}

func TestAdjustMTU_LowerClampsAfterSetMTU(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	// Setup on a full-size uplink leaves MTU 1420 and the clamp at 1380.
	mgr, p := setupWithProbe(t, ctrl, 1500, &logs)

	adjustAt(mgr, p, 1452)

	if got, want := callMethods(ctrl), []string{"SetMTU", "ClampMSS"}; !slices.Equal(got, want) {
		t.Errorf("controller calls = %v, want %v", got, want)
	}
	if got := clampMSSes(t, ctrl); !slices.Equal(got, []int{1332}) {
		t.Errorf("ClampMSS calls = %v, want [1332]", got)
	}
	if got := mgr.mss.Load(); got != 1332 {
		t.Errorf("mss = %d, want 1332", got)
	}
	assertLogLine(t, logs.String(), "wireguard: forwarded tcp mss clamped",
		"level=INFO", "component=wireguard", "interface=plexd0", "mss=1332 mtu=1372 old_mss=1380")
}

func TestAdjustMTU_RaiseClampsOnlyInTheSecondRound(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	// Setup on a 1452-byte uplink leaves MTU 1372 and the clamp at 1332.
	mgr, p := setupWithProbe(t, ctrl, 1452, &logs)

	adjustAt(mgr, p, 1500)
	if mgr.raiseTo != 1420 {
		t.Fatalf("raiseTo after the first round = %d, want 1420 pending", mgr.raiseTo)
	}
	if got := callMethods(ctrl); len(got) != 0 {
		t.Errorf("controller calls of the round that records the raise = %v, want none", got)
	}
	if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
		t.Errorf("clamp line in the round that records the raise:\n%s", out)
	}

	adjustAt(mgr, p, 1500)
	if got, want := callMethods(ctrl), []string{"SetMTU", "ClampMSS"}; !slices.Equal(got, want) {
		t.Errorf("controller calls of the second round = %v, want %v", got, want)
	}
	if got := clampMSSes(t, ctrl); !slices.Equal(got, []int{1380}) {
		t.Errorf("ClampMSS calls = %v, want [1380]", got)
	}
	assertLogLine(t, logs.String(), "wireguard: forwarded tcp mss clamped",
		"level=INFO", "component=wireguard", "interface=plexd0", "mss=1380 mtu=1420 old_mss=1332")
}

func TestAdjustMTU_FailedSetMTUMakesNoClampCall(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	// Setup on a full-size uplink leaves MTU 1420 and the clamp at 1380, which
	// stays current for the MTU a failed SetMTU keeps.
	mgr, p := setupWithProbe(t, ctrl, 1500, &logs)
	ctrl.setMTUErr = errors.New("netlink: device busy")

	adjustAt(mgr, p, 1452)

	if got, want := callMethods(ctrl), []string{"SetMTU"}; !slices.Equal(got, want) {
		t.Errorf("controller calls = %v, want %v", got, want)
	}
	if got := mgr.mss.Load(); got != 1380 {
		t.Errorf("mss after a failed SetMTU = %d, want 1380 kept", got)
	}
	if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
		t.Errorf("clamp line after a failed SetMTU:\n%s", out)
	}
}

func TestAdjustMTU_UnchangedMakesNoClampCallWhileCurrent(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	// Setup on a 1452-byte uplink leaves MTU 1372 and the clamp at 1332.
	mgr, p := setupWithProbe(t, ctrl, 1452, &logs)

	adjustAt(mgr, p, 1452)

	if got := callMethods(ctrl); len(got) != 0 {
		t.Errorf("controller calls = %v, want none while the clamp is current", got)
	}
	if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
		t.Errorf("clamp line while the clamp is current:\n%s", out)
	}
}

func TestAdjustMTU_UnchangedRetriesAFailedClamp(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{clampMSSErr: errClampDenied}
	// Setup on a 1452-byte uplink programs MTU 1372, and its ClampMSS call
	// fails, so no clamp is recorded.
	mgr, p := setupWithProbe(t, ctrl, 1452, &logs)
	if got := mgr.mss.Load(); got != 0 {
		t.Fatalf("mss after Setup's failed ClampMSS = %d, want 0", got)
	}

	adjustAt(mgr, p, 1452)
	if got, want := callMethods(ctrl), []string{"ClampMSS"}; !slices.Equal(got, want) {
		t.Errorf("controller calls of the first round = %v, want %v", got, want)
	}
	if got := clampMSSes(t, ctrl); !slices.Equal(got, []int{1332}) {
		t.Errorf("ClampMSS calls of the first round = %v, want [1332]", got)
	}
	assertLogLine(t, logs.String(), "wireguard: forwarded tcp mss clamp failed",
		"level=WARN", "component=wireguard", "interface=plexd0", "mss=1332 mtu=1372",
		`error="nftables: operation not permitted"`)
	if got := mgr.mss.Load(); got != 0 {
		t.Fatalf("mss after a second failed ClampMSS = %d, want 0", got)
	}

	// The second failure recorded nothing, so the next round tries again.
	clearCalls(ctrl)
	logs.Reset()
	ctrl.clampMSSErr = nil
	adjustAt(mgr, p, 1452)
	if got := clampMSSes(t, ctrl); !slices.Equal(got, []int{1332}) {
		t.Errorf("ClampMSS calls of the second round = %v, want [1332]", got)
	}
	if got := mgr.mss.Load(); got != 1332 {
		t.Errorf("mss after the retry = %d, want 1332", got)
	}
	out := logs.String()
	assertLogLine(t, out, "wireguard: forwarded tcp mss clamped",
		"level=INFO", "component=wireguard", "interface=plexd0", "mss=1332 mtu=1372")
	if line := logLine(out, "wireguard: forwarded tcp mss clamped"); strings.Contains(line, "old_mss=") {
		t.Errorf("clamped line carries old_mss though no clamp was replaced:\n%s", line)
	}

	// Now the clamp is current, and a round makes no call.
	clearCalls(ctrl)
	adjustAt(mgr, p, 1452)
	if got := callMethods(ctrl); len(got) != 0 {
		t.Errorf("controller calls of the third round = %v, want none", got)
	}
}

func TestAdjustMTU_RoundCutShortMakesNoClampCall(t *testing.T) {
	tests := []struct {
		name  string
		probe func(cancel context.CancelFunc) (int, error)
	}{
		{
			name: "probe error",
			probe: func(context.CancelFunc) (int, error) {
				return 0, errors.New("nat: mtu probe: no STUN server answered")
			},
		},
		{
			name: "ctx done after the probe measured",
			probe: func(cancel context.CancelFunc) (int, error) {
				cancel()
				return 1400, nil
			},
		},
		{
			name: "ctx done and the probe failed with it",
			probe: func(cancel context.CancelFunc) (int, error) {
				cancel()
				return 0, fmt.Errorf("nat: mtu probe: %w", context.Canceled)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctrl := &mockController{clampMSSErr: errClampDenied}
			// Setup's ClampMSS call fails, so no clamp is recorded and a round
			// that got past the probe and ctx would call ClampMSS, which the
			// controller now accepts. A round cut short must not.
			mgr, _ := setupWithProbe(t, ctrl, 1452, &logs)
			ctrl.clampMSSErr = nil

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ran := false
			mgr.SetPathMTUProbe(func(context.Context) (int, error) {
				ran = true
				return tt.probe(cancel)
			})

			mgr.adjustMTU(ctx)

			if !ran {
				t.Fatal("the round did not call the probe")
			}
			if got := callMethods(ctrl); len(got) != 0 {
				t.Errorf("controller calls = %v, want none", got)
			}
			if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
				t.Errorf("clamp line in a round cut short:\n%s", out)
			}
		})
	}
}

func TestManager_Teardown_UnclampsMSSFirst(t *testing.T) {
	var logs bytes.Buffer
	ctrl := &mockController{}
	// Setup on a 1452-byte uplink leaves the clamp at 1332.
	mgr, _ := setupWithProbe(t, ctrl, 1452, &logs)

	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown() returned error: %v", err)
	}

	if got, want := callMethods(ctrl), []string{"UnclampMSS", "DeleteInterface"}; !slices.Equal(got, want) {
		t.Errorf("controller calls = %v, want %v", got, want)
	}
	if uc := ctrl.callsFor("UnclampMSS"); len(uc) == 1 && uc[0].Args[0] != "plexd0" {
		t.Errorf("UnclampMSS iface = %v, want plexd0", uc[0].Args[0])
	}
	if got := mgr.mss.Load(); got != 0 {
		t.Errorf("mss after UnclampMSS = %d, want 0", got)
	}
	if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
		t.Errorf("clamp line for a removal that succeeded:\n%s", out)
	}

	// The clamp is gone, so a second Teardown has none to remove.
	clearCalls(ctrl)
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown() returned error: %v", err)
	}
	if got, want := callMethods(ctrl), []string{"DeleteInterface"}; !slices.Equal(got, want) {
		t.Errorf("controller calls of a second Teardown = %v, want %v", got, want)
	}
}

func TestManager_Teardown_UnclampFailureStopsNothing(t *testing.T) {
	deleteErr := errors.New("netlink: no such device")
	tests := []struct {
		name      string
		deleteErr error
	}{
		{name: "delete succeeds", deleteErr: nil},
		{name: "delete fails", deleteErr: deleteErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctrl := &mockController{}
			// Setup on a 1452-byte uplink leaves the clamp at 1332.
			mgr, _ := setupWithProbe(t, ctrl, 1452, &logs)
			ctrl.unclampMSSErr = errClampDenied
			ctrl.deleteInterfaceErr = tt.deleteErr

			err := mgr.Teardown()

			if tt.deleteErr == nil && err != nil {
				t.Errorf("Teardown() = %v, want nil, the result of DeleteInterface", err)
			}
			if tt.deleteErr != nil && !errors.Is(err, tt.deleteErr) {
				t.Errorf("Teardown() = %v, want the error of DeleteInterface", err)
			}
			if errors.Is(err, errClampDenied) {
				t.Errorf("Teardown() = %v carries the UnclampMSS error, want DeleteInterface's result alone", err)
			}
			if got, want := callMethods(ctrl), []string{"UnclampMSS", "DeleteInterface"}; !slices.Equal(got, want) {
				t.Errorf("controller calls = %v, want %v", got, want)
			}
			assertLogLine(t, logs.String(), "wireguard: forwarded tcp mss clamp removal failed",
				"level=WARN", "component=wireguard", "interface=plexd0",
				`error="nftables: operation not permitted"`)
		})
	}
}

func TestManager_Teardown_NoUnclampWithoutAClamp(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, ctrl *mockController, logs *bytes.Buffer) *Manager
	}{
		{
			name: "Setup never ran",
			setup: func(_ *testing.T, ctrl *mockController, logs *bytes.Buffer) *Manager {
				return NewManager(ctrl, Config{}, slogTextLogger(logs))
			},
		},
		{
			name: "Setup failed before the clamp",
			setup: func(t *testing.T, ctrl *mockController, logs *bytes.Buffer) *Manager {
				ctrl.configureAddressErr = errors.New("netlink: permission denied")
				mgr := NewManager(ctrl, Config{}, slogTextLogger(logs))
				if err := mgr.Setup(context.Background(), testIdentity()); err == nil {
					t.Fatal("Setup() = nil, want the ConfigureAddress error")
				}
				clearCalls(ctrl)
				logs.Reset()
				return mgr
			},
		},
		{
			name: "the only ClampMSS call failed",
			setup: func(t *testing.T, ctrl *mockController, logs *bytes.Buffer) *Manager {
				ctrl.clampMSSErr = errClampDenied
				mgr, _ := setupWithProbe(t, ctrl, 1452, logs)
				return mgr
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctrl := &mockController{}
			mgr := tt.setup(t, ctrl, &logs)

			if err := mgr.Teardown(); err != nil {
				t.Fatalf("Teardown() returned error: %v", err)
			}

			if got, want := callMethods(ctrl), []string{"DeleteInterface"}; !slices.Equal(got, want) {
				t.Errorf("controller calls = %v, want %v", got, want)
			}
			if out := logs.String(); strings.Contains(out, "forwarded tcp mss") {
				t.Errorf("clamp line without a clamp:\n%s", out)
			}
		})
	}
}
