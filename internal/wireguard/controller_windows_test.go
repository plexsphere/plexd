//go:build windows

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Compile-time checks that WindowsController is a controller the manager can
// drive and swap the mesh address through, and that the handshake report and
// tunnel metrics can read peer state from. It deliberately does not implement
// OSInterfaceNamer: the Wintun adapter carries the configured name, which
// TestWindowsController_NoOSInterfaceNamer pins.
var (
	_ WGController    = (*WindowsController)(nil)
	_ PeerStatsReader = (*WindowsController)(nil)
	_ AddressReplacer = (*WindowsController)(nil)
)

// winTUN is a trackedTUN that also answers the two methods the controller needs
// from a Wintun device, recording what MTU the running device was told.
type winTUN struct {
	*trackedTUN
	luid uint64

	mu   sync.Mutex
	mtus []int
}

func (t *winTUN) LUID() uint64 { return t.luid }

func (t *winTUN) ForceMTU(mtu int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mtus = append(t.mtus, mtu)
}

func (t *winTUN) forced() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]int(nil), t.mtus...)
}

// tunRequest is one recorded call to the fake createTUN.
type tunRequest struct {
	name string
	mtu  int
}

// tunFactory records what the controller asked of createTUN and hands out the
// fake devices, so a test can assert the requested name and MTU and whether the
// device was closed.
type tunFactory struct {
	mu    sync.Mutex
	calls []tunRequest
	tuns  []*winTUN
	bare  *trackedTUN // the device handed out when plain is set
	err   error       // returned instead of a device when set
	luid  uint64      // the LUID every handed-out device reports
	plain bool        // hand out a device without LUID/ForceMTU
}

func (f *tunFactory) create(name string, mtu int) (tun.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, tunRequest{name: name, mtu: mtu})
	if f.err != nil {
		return nil, f.err
	}
	if f.plain {
		f.bare = newTrackedTUN()
		return f.bare, nil
	}

	tdev := &winTUN{trackedTUN: newTrackedTUN(), luid: f.luid}
	f.tuns = append(f.tuns, tdev)
	return tdev, nil
}

func (f *tunFactory) requests() []tunRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tunRequest(nil), f.calls...)
}

// only returns the single device handed out, failing when the count differs.
func (f *tunFactory) only(t *testing.T) *winTUN {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tuns) != 1 {
		t.Fatalf("handed out %d tun devices, want 1", len(f.tuns))
	}
	return f.tuns[0]
}

// addressCall and mtuCall are the recorded IP Helper API calls.
type addressCall struct {
	luid   uint64
	prefix netip.Prefix
}

type mtuCall struct {
	luid uint64
	mtu  int
}

// fakeIPConfig records what the controller programmed and returns stubbed
// errors, so the LUID and prefix reaching the IP Helper API are asserted
// without touching the host. sequence holds every address call in the order
// it ran, as "add <prefix>" or "delete <prefix>".
type fakeIPConfig struct {
	mu        sync.Mutex
	addresses []addressCall
	deletes   []addressCall
	sequence  []string
	mtus      []mtuCall
	addErr    error
	deleteErr error
	mtuErr    error
}

func (f *fakeIPConfig) AddIPAddress(luid uint64, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addresses = append(f.addresses, addressCall{luid: luid, prefix: prefix})
	f.sequence = append(f.sequence, "add "+prefix.String())
	return f.addErr
}

func (f *fakeIPConfig) DeleteIPAddress(luid uint64, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, addressCall{luid: luid, prefix: prefix})
	f.sequence = append(f.sequence, "delete "+prefix.String())
	return f.deleteErr
}

func (f *fakeIPConfig) stubDelete(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteErr = err
}

func (f *fakeIPConfig) deleteCalls() []addressCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]addressCall(nil), f.deletes...)
}

func (f *fakeIPConfig) addressSequence() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sequence...)
}

func (f *fakeIPConfig) SetMTU(luid uint64, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mtus = append(f.mtus, mtuCall{luid: luid, mtu: mtu})
	return f.mtuErr
}

func (f *fakeIPConfig) stubAdd(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addErr = err
}

func (f *fakeIPConfig) stubMTU(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mtuErr = err
}

func (f *fakeIPConfig) addressCalls() []addressCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]addressCall(nil), f.addresses...)
}

func (f *fakeIPConfig) mtuCalls() []mtuCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mtuCall(nil), f.mtus...)
}

// testLUID is the LUID the fake devices report.
const testLUID = uint64(42)

// newTestWindowsController returns a controller whose tun device, driver
// provisioning and IP Helper API are fakes and whose UAPI endpoint is a
// loopback TCP listener, so it needs no privileges. Every interface it creates
// is deleted on cleanup, which the package's goleak TestMain requires.
func newTestWindowsController(t *testing.T) (*WindowsController, *tunFactory, *fakeIPConfig) {
	t.Helper()

	tuns := &tunFactory{luid: testLUID}
	ipcfg := &fakeIPConfig{}

	c := NewWindowsController(discardLogger())
	c.createTUN = tuns.create
	c.ipcfg = ipcfg
	c.ensureDLL = func() (string, bool, error) { return `C:\plexd\wintun.dll`, false, nil }
	c.backend.uapiListen = func(string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	// The adapter resolves on the first attempt, so no test sleeps unless it
	// stubs lookup itself.
	c.lookup = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
	c.visibleTimeout = time.Second

	t.Cleanup(func() {
		c.mu.Lock()
		names := make([]string, 0, len(c.adapters))
		for name := range c.adapters {
			names = append(names, name)
		}
		c.mu.Unlock()
		for _, name := range names {
			_ = c.DeleteInterface(name)
		}
	})

	return c, tuns, ipcfg
}

// createTestInterface brings up an interface the test then operates on.
func createTestInterface(t *testing.T, c *WindowsController, name string) {
	t.Helper()
	key := mustKey(t)
	if err := c.CreateInterface(name, key[:], 0); err != nil {
		t.Fatalf("CreateInterface(%q): %v", name, err)
	}
}

// assertNoAdapter fails when the controller recorded an adapter or the backend
// a device, which every failed CreateInterface must leave true.
func assertNoAdapter(t *testing.T, c *WindowsController) {
	t.Helper()

	c.mu.Lock()
	adapters := len(c.adapters)
	c.mu.Unlock()
	if adapters != 0 {
		t.Errorf("recorded %d adapters, want none", adapters)
	}

	c.backend.mu.Lock()
	devices := len(c.backend.devices)
	c.backend.mu.Unlock()
	if devices != 0 {
		t.Errorf("backend holds %d devices, want none", devices)
	}
}

func TestWindowsController_NoOSInterfaceNamer(t *testing.T) {
	var ctrl WGController = NewWindowsController(discardLogger())

	if _, ok := ctrl.(OSInterfaceNamer); ok {
		t.Error("WindowsController implements OSInterfaceNamer, want the configured name used directly")
	}
}

func TestWindowsController_CreateInterface_CreatesAdapter(t *testing.T) {
	c, tuns, ipcfg := newTestWindowsController(t)

	createTestInterface(t, c, "plexd0")

	want := []tunRequest{{name: "plexd0", mtu: 1420}}
	if got := tuns.requests(); len(got) != 1 || got[0] != want[0] {
		t.Errorf("createTUN calls = %v, want %v", got, want)
	}

	// The adapter's MTU is programmed at creation, because nothing else does it.
	if got := ipcfg.mtuCalls(); len(got) != 1 || got[0] != (mtuCall{luid: testLUID, mtu: 1420}) {
		t.Errorf("MTU calls = %v, want one {%d 1420}", got, testLUID)
	}
	if got := ipcfg.addressCalls(); len(got) != 0 {
		t.Errorf("address calls = %v, want none before ConfigureAddress", got)
	}

	if dump := ipcGet(t, c.backend, "plexd0"); !strings.Contains(dump, "listen_port=") {
		t.Errorf("uapi dump = %q, want a listen_port= line", dump)
	}
}

func TestWindowsController_CreateInterface_Duplicate(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)
	key := mustKey(t)

	createTestInterface(t, c, "plexd0")

	if err := c.CreateInterface("plexd0", key[:], 0); !errors.Is(err, os.ErrExist) {
		t.Errorf("second CreateInterface = %v, want os.ErrExist", err)
	}
	if got := tuns.requests(); len(got) != 1 {
		t.Errorf("createTUN called %d times, want 1", len(got))
	}

	c.backend.mu.Lock()
	_, ok := c.backend.devices["plexd0"]
	c.backend.mu.Unlock()
	if !ok {
		t.Error("the first device is gone after a duplicate create")
	}
}

func TestWindowsController_CreateInterface_EnsureDLLError(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)
	c.ensureDLL = func() (string, bool, error) { return "", false, errors.New("boom") }
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	if err == nil || err.Error() != "wireguard: create interface: provision wintun.dll: boom" {
		t.Errorf("CreateInterface = %v, want the provisioning error", err)
	}
	if got := tuns.requests(); len(got) != 0 {
		t.Errorf("createTUN called %d times, want 0 when the driver is missing", len(got))
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_AccessDenied(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)
	tuns.err = windows.ERROR_ACCESS_DENIED
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("CreateInterface = %v, want ERROR_ACCESS_DENIED", err)
	}
	if !strings.Contains(err.Error(), "creating a Wintun adapter requires Administrator") {
		t.Errorf("error = %q, want the Administrator hint", err)
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_DLLMissing(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)
	tuns.err = windows.ERROR_MOD_NOT_FOUND
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	if !errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		t.Fatalf("CreateInterface = %v, want ERROR_MOD_NOT_FOUND", err)
	}
	if !strings.Contains(err.Error(), "wintun.dll is missing beside plexd.exe") {
		t.Errorf("error = %q, want the missing-DLL hint", err)
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_CreateTUNError(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)
	tuns.err = errors.New("boom")
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	if err == nil || err.Error() != "wireguard: create interface: create plexd0: boom" {
		t.Errorf("CreateInterface = %v, want the bare create error", err)
	}
	if strings.Contains(err.Error(), "Administrator") || strings.Contains(err.Error(), "wintun.dll") {
		t.Errorf("error = %q, want no hint for an unrelated failure", err)
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_NotWintun(t *testing.T) {
	c, tuns, ipcfg := newTestWindowsController(t)
	tuns.plain = true
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	if err == nil || err.Error() != "wireguard: create interface: tun device is not a wintun device" {
		t.Errorf("CreateInterface = %v, want the wintun device error", err)
	}
	if tuns.bare == nil || !tuns.bare.closed.Load() {
		t.Error("the tun device was left open after a rejected device type")
	}
	if got := ipcfg.mtuCalls(); len(got) != 0 {
		t.Errorf("MTU calls = %v, want none", got)
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_DefaultMTUError(t *testing.T) {
	c, tuns, ipcfg := newTestWindowsController(t)
	ipcfg.stubMTU(errors.New("nope"))
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: create interface: set default mtu:") {
		t.Errorf("CreateInterface = %v, want the default-MTU error", err)
	}
	if !tuns.only(t).closed.Load() {
		t.Error("the tun device was left open after a failed MTU")
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_NilKey(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)

	err := c.CreateInterface("plexd0", nil, 0)
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: create interface: parse private key:") {
		t.Errorf("CreateInterface = %v, want the key error from the backend", err)
	}
	if !tuns.only(t).closed.Load() {
		t.Error("the tun device was left open after a rejected key")
	}
	assertNoAdapter(t, c)
}

func TestWindowsController_CreateInterface_WaitsForAdapter(t *testing.T) {
	c, _, _ := newTestWindowsController(t)

	var buf strings.Builder
	c.logger = slogTextLogger(&buf)

	// The lookup fails the way Windows does while it is still wiring the adapter
	// into the IP stack, then resolves.
	calls := 0
	c.lookup = func(name string) (*net.Interface, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("no such network interface")
		}
		return &net.Interface{Name: name}, nil
	}

	createTestInterface(t, c, "plexd0")

	c.mu.Lock()
	_, ok := c.adapters["plexd0"]
	c.mu.Unlock()
	if !ok {
		t.Error("no adapter recorded after the lookup resolved")
	}
	if calls != 3 {
		t.Errorf("lookup called %d times, want 3", calls)
	}

	out := buf.String()
	for _, want := range []string{"wintun adapter visible after wait", "interface=plexd0", "waited="} {
		if !strings.Contains(out, want) {
			t.Errorf("log output %q missing %q", out, want)
		}
	}
}

func TestWindowsController_CreateInterface_AdapterNeverVisible(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)

	lookupErr := errors.New("no such network interface")
	c.lookup = func(string) (*net.Interface, error) { return nil, lookupErr }
	c.visibleTimeout = 50 * time.Millisecond
	key := mustKey(t)

	err := c.CreateInterface("plexd0", key[:], 0)
	const want = "wireguard: create interface: adapter plexd0 not visible to the IP stack within 50ms"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CreateInterface = %v, want an error containing %q", err, want)
	}
	if !errors.Is(err, lookupErr) {
		t.Errorf("error = %v, want it to wrap the lookup error", err)
	}
	if !tuns.only(t).closed.Load() {
		t.Error("the tun device was left open after the adapter stayed invisible")
	}
	assertNoAdapter(t, c)

	// Nothing was recorded, so releasing the name afterwards is still a no-op.
	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Errorf("DeleteInterface = %v, want nil after a create that never recorded the adapter", err)
	}
}

// The wait for the IP stack runs after the adapter is recorded and outside the
// controller's lock, so every other method stays callable while it polls.
// Holding the lock for up to visibleTimeout would stall the ConfigureAddress
// and SetMTU of unrelated interfaces, and the DeleteInterface a teardown makes.
func TestWindowsController_CreateInterface_WaitRunsWithoutTheLock(t *testing.T) {
	c, _, _ := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	entered := make(chan struct{})
	release := make(chan struct{})
	c.lookup = func(name string) (*net.Interface, error) {
		if name == "plexd1" {
			close(entered)
			<-release
		}
		return &net.Interface{Name: name}, nil
	}

	key := mustKey(t)
	created := make(chan error, 1)
	go func() { created <- c.CreateInterface("plexd1", key[:], 0) }()
	<-entered

	mtu := make(chan error, 1)
	go func() { mtu <- c.SetMTU("plexd0", 1380) }()

	blocked := false
	select {
	case err := <-mtu:
		if err != nil {
			t.Errorf("SetMTU during the visibility wait = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		blocked = true
	}

	close(release)
	if err := <-created; err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	if blocked {
		<-mtu
		t.Error("SetMTU blocked until CreateInterface finished waiting for the IP stack")
	}
}

func TestWindowsController_ConfigureAddress(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ConfigureAddress("plexd0", "10.0.0.5/16"); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}

	want := addressCall{luid: testLUID, prefix: netip.MustParsePrefix("10.0.0.5/16")}
	if got := ipcfg.addressCalls(); len(got) != 1 || got[0] != want {
		t.Errorf("address calls = %v, want one %v", got, want)
	}
}

func TestWindowsController_ConfigureAddress_AlreadyExists(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	ipcfg.stubAdd(windows.ERROR_OBJECT_ALREADY_EXISTS)

	if err := c.ConfigureAddress("plexd0", "10.0.0.5/16"); err != nil {
		t.Errorf("ConfigureAddress = %v, want nil for an address already on the adapter", err)
	}
}

func TestWindowsController_ConfigureAddress_AddError(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	ipcfg.stubAdd(errors.New("nope"))

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	if err == nil || err.Error() != "wireguard: configure address: add 10.0.0.5/16: nope" {
		t.Errorf("ConfigureAddress = %v, want the add error", err)
	}
}

func TestWindowsController_ConfigureAddress_Unknown(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ConfigureAddress = %v, want os.ErrNotExist", err)
	}
	if !strings.HasPrefix(err.Error(), "wireguard: configure address:") {
		t.Errorf("error = %q, want the configure address prefix", err)
	}
	if got := ipcfg.addressCalls(); len(got) != 0 {
		t.Errorf("address calls = %v, want none for an unknown interface", got)
	}
}

func TestWindowsController_ConfigureAddress_InvalidPrefix(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	for _, address := range []string{"not-a-prefix", ""} {
		err := c.ConfigureAddress("plexd0", address)
		if err == nil {
			t.Fatalf("ConfigureAddress(%q) = nil, want a parse error", address)
		}
		if want := `wireguard: configure address: parse "` + address + `":`; !strings.HasPrefix(err.Error(), want) {
			t.Errorf("error = %q, want the prefix %q", err, want)
		}
	}
	if got := ipcfg.addressCalls(); len(got) != 0 {
		t.Errorf("address calls = %v, want none for an unparseable address", got)
	}
}

func TestWindowsController_ReplaceAddress(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16"); err != nil {
		t.Fatalf("ReplaceAddress: %v", err)
	}

	// The new address goes on before the old one comes off, so the adapter
	// is never without an address.
	want := []string{"add 10.0.0.9/16", "delete 10.0.0.1/16"}
	if got := ipcfg.addressSequence(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("address calls = %v, want %v", got, want)
	}
	if got := ipcfg.addressCalls(); len(got) != 1 || got[0].luid != testLUID {
		t.Errorf("add calls = %v, want one on LUID %d", got, testLUID)
	}
	if got := ipcfg.deleteCalls(); len(got) != 1 || got[0].luid != testLUID {
		t.Errorf("delete calls = %v, want one on LUID %d", got, testLUID)
	}
}

// A repeat of a call that failed halfway finds the new address there and the
// old one gone, which a delete answers with ERROR_INVALID_PARAMETER on the
// Windows runner.
func TestWindowsController_ReplaceAddress_ToleratesARepeat(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	ipcfg.stubAdd(windows.ERROR_OBJECT_ALREADY_EXISTS)
	ipcfg.stubDelete(windows.ERROR_INVALID_PARAMETER)

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16"); err != nil {
		t.Errorf("ReplaceAddress = %v, want nil when both steps are already done", err)
	}
	want := []string{"add 10.0.0.9/16", "delete 10.0.0.1/16"}
	if got := ipcfg.addressSequence(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("address calls = %v, want %v", got, want)
	}
}

func TestWindowsController_ReplaceAddress_AddError(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	// ERROR_NOT_FOUND is no answer an add tolerates.
	ipcfg.stubAdd(windows.ERROR_NOT_FOUND)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	if !errors.Is(err, windows.ERROR_NOT_FOUND) || !strings.HasPrefix(err.Error(), "wireguard: replace address: add 10.0.0.9/16:") {
		t.Errorf("ReplaceAddress = %v, want the add error", err)
	}
	// The old address stays when the new one could not go on.
	if got := ipcfg.deleteCalls(); len(got) != 0 {
		t.Errorf("delete calls = %v, want none after a failed add", got)
	}
}

func TestWindowsController_ReplaceAddress_DeleteError(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	// ERROR_OBJECT_ALREADY_EXISTS is no answer a delete tolerates.
	ipcfg.stubDelete(windows.ERROR_OBJECT_ALREADY_EXISTS)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	if !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || !strings.HasPrefix(err.Error(), "wireguard: replace address: delete 10.0.0.1/16:") {
		t.Errorf("ReplaceAddress = %v, want the delete error", err)
	}
}

func TestWindowsController_ReplaceAddress_Unknown(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReplaceAddress = %v, want os.ErrNotExist", err)
	}
	if !strings.HasPrefix(err.Error(), "wireguard: replace address:") {
		t.Errorf("error = %q, want the replace address prefix", err)
	}
	if got := ipcfg.addressSequence(); len(got) != 0 {
		t.Errorf("address calls = %v, want none for an unknown interface", got)
	}
}

func TestWindowsController_ReplaceAddress_InvalidArguments(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	tests := []struct {
		oldCIDR, newCIDR string
		want             string
	}{
		{"not-a-cidr", "10.0.0.9/16", `wireguard: replace address: parse "not-a-cidr":`},
		{"10.0.0.1/16", "10.0.0.9", `wireguard: replace address: parse "10.0.0.9":`},
		{"10.0.0.1/16", "10.0.0.9/24", "wireguard: replace address: 10.0.0.1/16 and 10.0.0.9/24 are not of one length"},
		{"fd00::1/64", "fd00::9/64", "wireguard: replace address: fd00::1/64 is not an IPv4 CIDR"},
	}
	for _, tt := range tests {
		err := c.ReplaceAddress("plexd0", tt.oldCIDR, tt.newCIDR)
		if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
			t.Errorf("ReplaceAddress(%q, %q) = %v, want the prefix %q", tt.oldCIDR, tt.newCIDR, err, tt.want)
		}
	}
	if got := ipcfg.addressSequence(); len(got) != 0 {
		t.Errorf("address calls = %v, want none for refused arguments", got)
	}
}

// Deleting the old address of a pair that names one address would delete the
// new one, so nothing is programmed.
func TestWindowsController_ReplaceAddress_SameAddress(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.1/16"); err != nil {
		t.Errorf("ReplaceAddress = %v, want nil", err)
	}
	if got := ipcfg.addressSequence(); len(got) != 0 {
		t.Errorf("address calls = %v, want none", got)
	}
}

func TestWindowsController_SetMTU(t *testing.T) {
	c, tuns, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.SetMTU("plexd0", 1380); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}

	// The create-time call programs 1420, this one 1380.
	want := []mtuCall{{luid: testLUID, mtu: 1420}, {luid: testLUID, mtu: 1380}}
	got := ipcfg.mtuCalls()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("MTU calls = %v, want %v", got, want)
	}

	// The running device hears about it only from the controller.
	if forced := tuns.only(t).forced(); len(forced) != 1 || forced[0] != 1380 {
		t.Errorf("ForceMTU calls = %v, want [1380]", forced)
	}
}

func TestWindowsController_SetMTU_Unknown(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)

	err := c.SetMTU("plexd0", 1380)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SetMTU = %v, want os.ErrNotExist", err)
	}
	if !strings.HasPrefix(err.Error(), "wireguard: set mtu:") {
		t.Errorf("error = %q, want the set mtu prefix", err)
	}
	if got := ipcfg.mtuCalls(); len(got) != 0 {
		t.Errorf("MTU calls = %v, want none for an unknown interface", got)
	}
}

func TestWindowsController_SetMTU_Error(t *testing.T) {
	c, tuns, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	ipcfg.stubMTU(errors.New("nope"))

	err := c.SetMTU("plexd0", 1380)
	if err == nil || err.Error() != "wireguard: set mtu: nope" {
		t.Errorf("SetMTU = %v, want the set mtu error", err)
	}
	if forced := tuns.only(t).forced(); len(forced) != 0 {
		t.Errorf("ForceMTU calls = %v, want none when the interface refused the MTU", forced)
	}
}

func TestWindowsController_SetInterfaceUp(t *testing.T) {
	c, _, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.SetInterfaceUp("plexd0"); err != nil {
		t.Errorf("SetInterfaceUp = %v, want nil", err)
	}
	// A Wintun adapter is connected from its session start, so nothing is
	// programmed to raise it.
	if got := ipcfg.mtuCalls(); len(got) != 1 {
		t.Errorf("MTU calls = %v, want only the create-time one", got)
	}
	if got := ipcfg.addressCalls(); len(got) != 0 {
		t.Errorf("address calls = %v, want none", got)
	}
}

func TestWindowsController_SetInterfaceUp_Unknown(t *testing.T) {
	c, _, _ := newTestWindowsController(t)

	err := c.SetInterfaceUp("plexd0")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SetInterfaceUp = %v, want os.ErrNotExist", err)
	}
	if !strings.HasPrefix(err.Error(), "wireguard: set interface up:") {
		t.Errorf("error = %q, want the set interface up prefix", err)
	}
}

func TestWindowsController_DeleteInterface_Unknown(t *testing.T) {
	c, _, _ := newTestWindowsController(t)

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Errorf("DeleteInterface = %v, want nil for an interface that does not exist", err)
	}
}

func TestWindowsController_DeleteInterface_ReleasesAdapter(t *testing.T) {
	c, tuns, _ := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}

	if !tuns.only(t).closed.Load() {
		t.Error("the tun device is still open after DeleteInterface")
	}
	assertNoAdapter(t, c)

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Errorf("second DeleteInterface = %v, want nil", err)
	}
}

func TestWindowsController_PeerOperationsDelegate(t *testing.T) {
	c, _, _ := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	peerKey := mustKey(t)
	if err := c.AddPeer("plexd0", PeerConfig{
		PublicKey:  pubBytes(peerKey),
		AllowedIPs: []string{"10.0.0.2/32"},
	}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if dump := ipcGet(t, c.backend, "plexd0"); !strings.Contains(dump, "public_key=") {
		t.Errorf("uapi dump = %q, want the peer present", dump)
	}

	stats, err := c.PeerStats("plexd0")
	if err != nil {
		t.Fatalf("PeerStats: %v", err)
	}
	assertPeerStats(t, stats, []PeerStat{{
		PublicKey:  peerKey.PublicKey(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
	}})

	before := privateKeyHex(ipcGet(t, c.backend, "plexd0"))
	newKey := mustKey(t)
	if err := c.SetPrivateKey("plexd0", newKey[:]); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	if after := privateKeyHex(ipcGet(t, c.backend, "plexd0")); after == before {
		t.Error("private key unchanged after SetPrivateKey")
	}

	if err := c.RemovePeer("plexd0", pubBytes(peerKey)); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if dump := ipcGet(t, c.backend, "plexd0"); strings.Contains(dump, "public_key=") {
		t.Errorf("uapi dump = %q, want the peer gone", dump)
	}
}

func TestWindowsController_PeerOperations_Unknown(t *testing.T) {
	c, _, _ := newTestWindowsController(t)
	key := mustKey(t)

	if err := c.AddPeer("plexd0", PeerConfig{PublicKey: pubBytes(key)}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("AddPeer = %v, want os.ErrNotExist", err)
	}
	if err := c.RemovePeer("plexd0", pubBytes(key)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("RemovePeer = %v, want os.ErrNotExist", err)
	}
	if err := c.SetPrivateKey("plexd0", key[:]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SetPrivateKey = %v, want os.ErrNotExist", err)
	}
	if _, err := c.PeerStats("plexd0"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("PeerStats = %v, want os.ErrNotExist", err)
	}
}

// meshRewriterAddrs is the addrs seam of the rewriter tests: fake adapters are
// no interfaces of the host.
func meshRewriterAddrs() func(string) ([]netip.Prefix, error) {
	return fakeAddrs(map[string][]netip.Prefix{
		"plexd0":         {netip.MustParsePrefix("10.255.241.1/24")},
		"wg-ua-a0a0a0e1": {netip.MustParsePrefix("10.255.242.1/24")},
	})
}

func TestWindowsController_SetMeshRewriter(t *testing.T) {
	r := NewMeshRewriter(discardLogger())
	r.addrs = meshRewriterAddrs()
	c, tuns, ipcfg := newTestWindowsController(t)
	c.SetMeshRewriter(r)

	createTestInterface(t, c, "plexd0")
	createTestInterface(t, c, "wg-ua-a0a0a0e1")

	if err := r.AddMeshSourceRewrite("wg-ua-a0a0a0e1", "plexd0"); err != nil {
		t.Fatalf("AddMeshSourceRewrite between two interfaces of the controller = %v, want nil", err)
	}

	tuns.mu.Lock()
	mesh, access := tuns.tuns[0], tuns.tuns[1]
	tuns.mu.Unlock()

	// The LUID and the MTU hook are the raw adapter's, not the wrapper's.
	if err := c.SetMTU("plexd0", 1380); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}
	want := []mtuCall{{luid: testLUID, mtu: 1420}, {luid: testLUID, mtu: 1420}, {luid: testLUID, mtu: 1380}}
	if got := ipcfg.mtuCalls(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("MTU calls = %v, want %v", got, want)
	}
	if forced := mesh.forced(); len(forced) != 1 || forced[0] != 1380 {
		t.Errorf("ForceMTU calls on the mesh adapter = %v, want [1380]", forced)
	}

	// Deleting the provider's interface closes the wrapper and the adapter's
	// tun, and the rewriter forgets the device and its rewrite.
	if err := c.DeleteInterface("wg-ua-a0a0a0e1"); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}
	if !access.closed.Load() {
		t.Error("the adapter's tun is still open after DeleteInterface")
	}
	if r.nat.known("wg-ua-a0a0a0e1") || r.nat.involved("plexd0") {
		t.Error("the rewriter still knows the deleted interface or its rewrite")
	}
}

func TestWindowsController_WithoutMeshRewriter(t *testing.T) {
	r := NewMeshRewriter(discardLogger())
	r.addrs = meshRewriterAddrs()
	c, _, _ := newTestWindowsController(t)

	createTestInterface(t, c, "plexd0")
	createTestInterface(t, c, "wg-ua-a0a0a0e1")

	err := r.AddMeshSourceRewrite("wg-ua-a0a0a0e1", "plexd0")
	const want = "the mesh interface is no device of this process"
	if err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Errorf("AddMeshSourceRewrite between interfaces of a controller without a rewriter = %v, want an error ending in %q", err, want)
	}
}

// windowsClamp returns the MSS clamp of the adapter the controller recorded
// for name, and whether it recorded one.
func windowsClamp(c *WindowsController, name string) (*mssClampTUN, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ad, ok := c.adapters[name]
	if !ok || ad.clamp == nil {
		return nil, false
	}
	return ad.clamp, true
}

func TestWindowsController_ClampMSS(t *testing.T) {
	c, tuns, ipcfg := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")

	clamp, ok := windowsClamp(c, "plexd0")
	if !ok {
		t.Fatal("CreateInterface recorded no MSS clamp")
	}
	// Without a rewriter the clamp wraps the adapter's tun itself.
	if clamp.Device != tun.Device(tuns.only(t)) {
		t.Errorf("the clamp wraps %T, want the device createTUN returned", clamp.Device)
	}
	if got := clamp.mss.Load(); got != 0 {
		t.Errorf("mss after CreateInterface = %d, want 0", got)
	}

	if err := c.ClampMSS("plexd0", 1332); err != nil {
		t.Fatalf("ClampMSS(1332) = %v, want nil", err)
	}
	if got := clamp.mss.Load(); got != 1332 {
		t.Errorf("mss after ClampMSS(1332) = %d, want 1332", got)
	}
	if err := c.ClampMSS("plexd0", 1380); err != nil {
		t.Fatalf("ClampMSS(1380) = %v, want nil", err)
	}
	if got := clamp.mss.Load(); got != 1380 {
		t.Errorf("mss after a second ClampMSS(1380) = %d, want 1380", got)
	}

	if err := c.UnclampMSS("plexd0"); err != nil {
		t.Fatalf("UnclampMSS = %v, want nil", err)
	}
	if got := clamp.mss.Load(); got != 0 {
		t.Errorf("mss after UnclampMSS = %d, want 0", got)
	}
	if err := c.UnclampMSS("plexd0"); err != nil {
		t.Errorf("second UnclampMSS = %v, want nil", err)
	}

	// The clamp is in process, so the IP Helper API sees only the
	// create-time MTU.
	if got := ipcfg.mtuCalls(); len(got) != 1 {
		t.Errorf("MTU calls = %v, want only the create-time one", got)
	}
	if got := ipcfg.addressCalls(); len(got) != 0 {
		t.Errorf("address calls = %v, want none", got)
	}
}

func TestWindowsController_ClampMSS_Unknown(t *testing.T) {
	c, _, _ := newTestWindowsController(t)

	err := c.ClampMSS("plexd0", 1332)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ClampMSS = %v, want os.ErrNotExist", err)
	}
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: clamp mss: ") {
		t.Errorf("error = %v, want the clamp mss prefix", err)
	}

	if err := c.UnclampMSS("plexd0"); err != nil {
		t.Errorf("UnclampMSS of an unknown name = %v, want nil", err)
	}
}

func TestWindowsController_ClampMSS_Invalid(t *testing.T) {
	c, _, _ := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	if err := c.ClampMSS("plexd0", 1332); err != nil {
		t.Fatalf("ClampMSS(1332) = %v, want nil", err)
	}
	clamp, _ := windowsClamp(c, "plexd0")

	for _, mss := range []int{0, -1, 65536} {
		err := c.ClampMSS("plexd0", mss)
		if want := fmt.Sprintf("wireguard: clamp mss: invalid mss %d", mss); err == nil || err.Error() != want {
			t.Errorf("ClampMSS(%d) = %v, want %q", mss, err, want)
		}
		if got := clamp.mss.Load(); got != 1332 {
			t.Errorf("mss after ClampMSS(%d) = %d, want 1332 kept", mss, got)
		}
	}

	// The value is checked before the name.
	if err := c.ClampMSS("plexd9", 0); err == nil || err.Error() != "wireguard: clamp mss: invalid mss 0" {
		t.Errorf("ClampMSS of an unknown name with 0 = %v, want the invalid mss error", err)
	}
}

func TestWindowsController_DeleteInterface_ForgetsClamp(t *testing.T) {
	c, _, _ := newTestWindowsController(t)
	createTestInterface(t, c, "plexd0")
	if err := c.ClampMSS("plexd0", 1332); err != nil {
		t.Fatalf("ClampMSS = %v, want nil", err)
	}

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}
	if _, ok := windowsClamp(c, "plexd0"); ok {
		t.Error("the MSS clamp is still recorded after DeleteInterface")
	}
	if err := c.ClampMSS("plexd0", 1332); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ClampMSS after DeleteInterface = %v, want os.ErrNotExist", err)
	}
	if err := c.UnclampMSS("plexd0"); err != nil {
		t.Errorf("UnclampMSS after DeleteInterface = %v, want nil", err)
	}
}

// With a rewriter the clamp wraps the rewriter's wrapper, so it also sees the
// packets the rewriter translates, which never pass the adapter's tun.
func TestWindowsController_ClampWrapsMeshRewriter(t *testing.T) {
	r := NewMeshRewriter(discardLogger())
	r.addrs = meshRewriterAddrs()
	c, tuns, _ := newTestWindowsController(t)
	c.SetMeshRewriter(r)
	createTestInterface(t, c, "plexd0")

	clamp, ok := windowsClamp(c, "plexd0")
	if !ok {
		t.Fatal("CreateInterface recorded no MSS clamp")
	}
	rewriter, ok := clamp.Device.(*meshTUN)
	if !ok {
		t.Fatalf("the clamp wraps %T, want the rewriter's *meshTUN", clamp.Device)
	}
	if rewriter.dev != tun.Device(tuns.only(t)) {
		t.Errorf("the rewriter's wrapper wraps %T, want the device createTUN returned", rewriter.dev)
	}

	if err := c.ClampMSS("plexd0", 1332); err != nil {
		t.Fatalf("ClampMSS = %v, want nil", err)
	}
	if got := clamp.mss.Load(); got != 1332 {
		t.Errorf("mss after ClampMSS(1332) = %d, want 1332", got)
	}
}

func TestAdapterGUID_Deterministic(t *testing.T) {
	first := adapterGUID("plexd0")
	if second := adapterGUID("plexd0"); *first != *second {
		t.Errorf("adapterGUID(%q) = %v then %v, want one stable value", "plexd0", first, second)
	}
	if other := adapterGUID("wg-access"); *first == *other {
		t.Error("adapterGUID returns the same GUID for different interface names")
	}
}

// TestWindowsController_RealWintun drives the production seams against Windows:
// the embedded driver written beside the test binary, a real Wintun adapter,
// the real IP Helper API and the real UAPI named pipe. It is the only test that
// proves the calls the fakes above assert are the ones Windows accepts.
//
// The gate is an environment variable rather than elevation, because the CI
// runner is already elevated and this must not run inside the ordinary
// unprivileged test step. CI runs it as its own step on the Windows runner.
func TestWindowsController_RealWintun(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WINTUN") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WINTUN=1 to create a real Wintun adapter")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter needs Administrator")
	}

	const (
		name    = "plexd-citest"
		address = "10.255.253.1/30"
		mtu     = 1380
	)

	c := NewWindowsController(discardLogger())
	key := mustKey(t)

	if err := c.CreateInterface(name, key[:], 0); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			_ = c.DeleteInterface(name)
		}
	})

	// The adapter carries the configured name, which is what the readiness
	// check resolves. Windows settles the IP stack a moment after the adapter
	// appears, so the assertions poll.
	waitForInterface(t, name, func(link *net.Interface) error {
		if link.Flags&net.FlagUp == 0 {
			return errors.New("interface is down")
		}
		if link.MTU != 1420 {
			return fmt.Errorf("MTU = %d, want the 1420 default", link.MTU)
		}
		return nil
	})

	if err := c.ConfigureAddress(name, address); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}
	waitForInterface(t, name, func(link *net.Interface) error {
		if !hasAddr(t, link, "10.255.253.1") {
			return errors.New("address not assigned yet")
		}
		return nil
	})

	if err := c.SetMTU(name, mtu); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}
	waitForInterface(t, name, func(link *net.Interface) error {
		if link.MTU != mtu {
			return fmt.Errorf("MTU = %d, want %d", link.MTU, mtu)
		}
		return nil
	})

	if err := c.SetInterfaceUp(name); err != nil {
		t.Fatalf("SetInterfaceUp: %v", err)
	}

	pipe := uapiPipePrefix + name
	dump := uapiGet(t, pipe)
	if !strings.Contains(dump, "listen_port=") {
		t.Errorf("uapi dump = %q, want a listen_port= line", dump)
	}
	if !strings.Contains(dump, "errno=0") {
		t.Errorf("uapi dump = %q, want it to end with errno=0", dump)
	}

	if err := c.DeleteInterface(name); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}
	deleted = true

	if _, err := net.InterfaceByName(name); err == nil {
		t.Errorf("%s still exists after DeleteInterface", name)
	}
	if _, err := (&namedpipe.DialConfig{}).DialTimeout(pipe, time.Second); err == nil {
		t.Errorf("the UAPI pipe for %s still answers after DeleteInterface", name)
	}
}

// TestWindowsController_RealReplaceAddress swaps the address of a real Wintun
// adapter through the production seams. It is the only proof of what
// ReplaceAddress relies on about Windows: that the on-link route of the
// prefix and a route through the adapter stay when the old address goes, and
// that deleting an address the adapter does not hold answers
// ERROR_INVALID_PARAMETER, which the repeated call meets.
//
// It adds a route, so it asks for PLEXD_TEST_REAL_ROUTES besides
// PLEXD_TEST_REAL_WINTUN, as TestPeerRoutes_RealWintun does. CI runs it in the
// step "Run real Wintun tests" beside the bridge package's tests, so its
// prefixes are ones no other test of the step uses.
func TestWindowsController_RealReplaceAddress(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WINTUN") != "1" || os.Getenv("PLEXD_TEST_REAL_ROUTES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WINTUN=1 and PLEXD_TEST_REAL_ROUTES=1 to create a real Wintun adapter and route over it")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter needs Administrator")
	}

	const (
		name       = "plexd-readdress"
		oldAddress = "10.255.248.1/24"
		newAddress = "10.255.248.9/24"
	)
	var (
		onLink = netip.MustParsePrefix("10.255.248.0/24")
		// routed stands for a peer's routed subnet.
		routed = netip.MustParsePrefix("10.255.238.0/24")
	)

	c := NewWindowsController(discardLogger())
	key := mustKey(t)

	if err := c.CreateInterface(name, key[:], 0); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	// Windows removes the adapter with its addresses and routes.
	t.Cleanup(func() { _ = c.DeleteInterface(name) })

	if err := c.ConfigureAddress(name, oldAddress); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}
	waitForInterface(t, name, func(link *net.Interface) error {
		if !hasAddr(t, link, "10.255.248.1") {
			return errors.New("address not assigned yet")
		}
		return nil
	})

	ad, err := c.adapter(name, "replace address test")
	if err != nil {
		t.Fatal(err)
	}
	luid := winipcfg.LUID(ad.luid)
	if err := luid.AddRoute(routed, netip.IPv4Unspecified(), 0); err != nil {
		t.Fatalf("route %s through %s: %v", routed, name, err)
	}

	// Windows settles an adapter a moment after the call that changed it
	// returns, so the check polls, as the other checks of this file do.
	check := func(when string) {
		t.Helper()
		waitForInterface(t, name, func(*net.Interface) error {
			addrs, err := adapterIPv4(luid)
			if err != nil {
				return err
			}
			if fmt.Sprint(addrs) != "[10.255.248.9/24]" {
				return fmt.Errorf("%s: %s holds %v, want 10.255.248.9/24 alone", when, name, addrs)
			}
			for _, p := range []netip.Prefix{onLink, routed} {
				if _, err := luid.Route(p, netip.IPv4Unspecified()); err != nil {
					return fmt.Errorf("%s: route %s through %s: %w, want it kept", when, p, name, err)
				}
			}
			return nil
		})
	}

	if err := c.ReplaceAddress(name, oldAddress, newAddress); err != nil {
		t.Fatalf("ReplaceAddress: %v", err)
	}
	check("after the call")

	if err := c.ReplaceAddress(name, oldAddress, newAddress); err != nil {
		t.Errorf("repeated ReplaceAddress = %v, want nil", err)
	}
	check("after the repeated call")
}

// adapterIPv4 returns the IPv4 addresses of the adapter with their on-link
// prefix lengths, read from the host's unicast table. An autoconfiguration
// address, which Windows may give the adapter meanwhile, is left out.
func adapterIPv4(luid winipcfg.LUID) ([]string, error) {
	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for i := range rows {
		addr := rows[i].Address.Addr()
		if rows[i].InterfaceLUID == luid && !addr.IsLinkLocalUnicast() {
			addrs = append(addrs, netip.PrefixFrom(addr, int(rows[i].OnLinkPrefixLength)).String())
		}
	}
	return addrs, nil
}

// waitForInterface polls the named interface until check passes, because
// Windows finishes wiring an adapter's IP stack a moment after the call that
// changed it returns.
func waitForInterface(t *testing.T, name string, check func(*net.Interface) error) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var last error
	for {
		link, err := net.InterfaceByName(name)
		if err == nil {
			if last = check(link); last == nil {
				return
			}
		} else {
			last = err
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("interface %s did not settle within 10s: %v", name, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// hasAddr reports whether the interface carries an address containing want.
func hasAddr(t *testing.T, link *net.Interface, want string) bool {
	t.Helper()

	addrs, err := link.Addrs()
	if err != nil {
		t.Fatalf("Addrs(): %v", err)
	}
	for _, addr := range addrs {
		if strings.Contains(addr.String(), want) {
			return true
		}
	}
	return false
}

// uapiGet reads the device's UAPI dump over its named pipe, the way wg(8) does.
// It dials without an owner expectation: wgctrl's own dial requires the pipe to
// be owned by LocalSystem, which holds for the service but not for a test that
// created it as an Administrator.
func uapiGet(t *testing.T, path string) string {
	t.Helper()

	conn, err := (&namedpipe.DialConfig{}).DialTimeout(path, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("get=1\n\n")); err != nil {
		t.Fatalf("write get: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read uapi: %v", err)
	}
	return string(buf[:n])
}
