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
)

// Compile-time check that WindowsController is a controller the manager can
// drive. It deliberately does not implement OSInterfaceNamer: the Wintun
// adapter carries the configured name, which TestWindowsController_
// NoOSInterfaceNamer pins.
var _ WGController = (*WindowsController)(nil)

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
// without touching the host.
type fakeIPConfig struct {
	mu        sync.Mutex
	addresses []addressCall
	mtus      []mtuCall
	addErr    error
	mtuErr    error
}

func (f *fakeIPConfig) AddIPAddress(luid uint64, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addresses = append(f.addresses, addressCall{luid: luid, prefix: prefix})
	return f.addErr
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
