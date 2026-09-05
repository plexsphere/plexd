//go:build darwin

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// Compile-time checks that DarwinController is a controller the manager can
// drive and that the readiness check can resolve a kernel name through.
var (
	_ WGController     = (*DarwinController)(nil)
	_ OSInterfaceNamer = (*DarwinController)(nil)
)

// namedTUN is a trackedTUN that reports a fixed name, standing in for the
// utunN name the kernel assigns. trackedTUN alone reports loopbackTun1.
type namedTUN struct {
	*trackedTUN
	name string
}

func (t *namedTUN) Name() (string, error) { return t.name, nil }

// tunRequest is one recorded call to the fake createTUN.
type tunRequest struct {
	name string
	mtu  int
}

// tunRequests records what the controller asked of createTUN and hands out the
// fake devices, so a test can assert the requested name and MTU and whether
// the tun was closed.
type tunRequests struct {
	mu      sync.Mutex
	calls   []tunRequest
	tuns    []*namedTUN
	err     error  // returned instead of a device when set
	tunName string // the name every handed-out device reports
}

// create is the fake createTUN. It never returns (nil, nil): the controller
// calls Name() on a device it got without an error, which is what
// tun.CreateTUN guarantees in production.
func (r *tunRequests) create(name string, mtu int) (tun.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, tunRequest{name: name, mtu: mtu})
	if r.err != nil {
		return nil, r.err
	}

	tdev := &namedTUN{trackedTUN: newTrackedTUN(), name: r.tunName}
	r.tuns = append(r.tuns, tdev)
	return tdev, nil
}

func (r *tunRequests) requests() []tunRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]tunRequest(nil), r.calls...)
}

// only returns the single device handed out, failing when the count differs.
func (r *tunRequests) only(t *testing.T) *namedTUN {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.tuns) != 1 {
		t.Fatalf("handed out %d tun devices, want 1", len(r.tuns))
	}
	return r.tuns[0]
}

// fakeResult is the stubbed outcome of one command line.
type fakeResult struct {
	out []byte
	err error
}

// fakeRunner records the commands the controller runs and returns stubbed
// results, so the exact ifconfig and route arguments are asserted without
// touching the host.
type fakeRunner struct {
	mu        sync.Mutex
	calls     [][]string
	deadlines []bool
	results   map[string]fakeResult
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{results: make(map[string]fakeResult)}
}

// stub makes the command line argv return out and err.
func (r *fakeRunner) stub(argv, out string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results[argv] = fakeResult{out: []byte(out), err: err}
}

func (r *fakeRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	argv := append([]string{name}, args...)
	r.calls = append(r.calls, argv)
	_, hasDeadline := ctx.Deadline()
	r.deadlines = append(r.deadlines, hasDeadline)

	res := r.results[strings.Join(argv, " ")]
	return res.out, res.err
}

// argv returns every recorded command line, each joined by single spaces.
func (r *fakeRunner) argv() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	lines := make([]string, 0, len(r.calls))
	for _, call := range r.calls {
		lines = append(lines, strings.Join(call, " "))
	}
	return lines
}

// allDeadlined reports whether every recorded call carried a context deadline.
func (r *fakeRunner) allDeadlined() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, ok := range r.deadlines {
		if !ok {
			return false
		}
	}
	return true
}

// newTestDarwinController returns a controller whose tun and command runner
// are fakes and whose UAPI endpoint is a loopback TCP listener, so it needs no
// privileges. Every interface it creates is deleted on cleanup, which the
// package's goleak TestMain requires.
func newTestDarwinController(t *testing.T) (*DarwinController, *fakeRunner, *tunRequests) {
	t.Helper()

	runner := newFakeRunner()
	tuns := &tunRequests{tunName: "utun9"}

	c := NewDarwinController(discardLogger())
	c.createTUN = tuns.create
	c.run = runner.run
	c.backend.uapiListen = func(string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}

	t.Cleanup(func() {
		c.mu.Lock()
		names := make([]string, 0, len(c.utuns))
		for name := range c.utuns {
			names = append(names, name)
		}
		c.mu.Unlock()
		for _, name := range names {
			_ = c.DeleteInterface(name)
		}
	})

	return c, runner, tuns
}

// createTestInterface brings up an interface the test then operates on.
func createTestInterface(t *testing.T, c *DarwinController, name string) {
	t.Helper()
	key := mustKey(t)
	if err := c.CreateInterface(name, key[:], 0); err != nil {
		t.Fatalf("CreateInterface(%q): %v", name, err)
	}
}

// assertArgv compares the runner's recorded command lines with want.
func assertArgv(t *testing.T, r *fakeRunner, want ...string) {
	t.Helper()

	got := r.argv()
	if len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d:\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDarwinController_CreateInterface_AssignsUTUN(t *testing.T) {
	c, runner, tuns := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	want := []tunRequest{{name: "utun", mtu: 1420}}
	if got := tuns.requests(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("createTUN calls = %v, want %v", got, want)
	}

	osName, ok := c.OSInterfaceName("plexd0")
	if !ok || osName != "utun9" {
		t.Errorf("OSInterfaceName() = (%q, %v), want (\"utun9\", true)", osName, ok)
	}

	if dump := ipcGet(t, c.backend, "plexd0"); !strings.Contains(dump, "listen_port=") {
		t.Errorf("uapi dump = %q, want a listen_port= line", dump)
	}

	// Addressing, MTU and the interface flag are separate calls; creating the
	// interface runs no host command.
	assertArgv(t, runner)
}

func TestDarwinController_CreateInterface_ExplicitUTUNName(t *testing.T) {
	c, _, tuns := newTestDarwinController(t)
	createTestInterface(t, c, "utun7")

	got := tuns.requests()
	if len(got) != 1 || got[0].name != "utun7" {
		t.Fatalf("createTUN calls = %v, want a single request for utun7", got)
	}
}

func TestDarwinController_CreateInterface_Duplicate(t *testing.T) {
	c, _, tuns := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	key := mustKey(t)
	err := c.CreateInterface("plexd0", key[:], 0)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want os.ErrExist", err)
	}
	if got := tuns.requests(); len(got) != 1 {
		t.Errorf("createTUN called %d times, want 1", len(got))
	}

	// The first device survives.
	if _, err := c.backend.device("plexd0"); err != nil {
		t.Errorf("device(plexd0) after duplicate create: %v", err)
	}
}

func TestDarwinController_CreateInterface_PermissionDenied(t *testing.T) {
	c, _, tuns := newTestDarwinController(t)
	tuns.err = unix.EPERM

	key := mustKey(t)
	err := c.CreateInterface("plexd0", key[:], 0)
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("err = %v, want it to wrap unix.EPERM", err)
	}
	assertPrefix(t, err, "wireguard: create interface: create utun: operation not permitted")
	if !strings.Contains(err.Error(), "creating a utun device requires root") {
		t.Errorf("err = %q, want the root hint", err)
	}

	if _, ok := c.OSInterfaceName("plexd0"); ok {
		t.Error("interface mapped despite the failure")
	}
	if _, err := c.backend.device("plexd0"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("backend device(plexd0) = %v, want os.ErrNotExist", err)
	}
}

func TestDarwinController_CreateInterface_CreateTUNError(t *testing.T) {
	c, _, tuns := newTestDarwinController(t)
	tuns.err = errors.New("boom")

	key := mustKey(t)
	err := c.CreateInterface("plexd0", key[:], 0)
	if err == nil || err.Error() != "wireguard: create interface: create utun: boom" {
		t.Fatalf("err = %v, want the bare create error", err)
	}
	if strings.Contains(err.Error(), "requires root") {
		t.Error("root hint added to an error that is not EPERM")
	}
}

func TestDarwinController_CreateInterface_NilKey(t *testing.T) {
	c, _, tuns := newTestDarwinController(t)

	// The backend rejects the key and, owning the tun by then, closes it.
	err := c.CreateInterface("plexd0", nil, 0)
	assertPrefix(t, err, "wireguard: create interface: parse private key:")

	if !tuns.only(t).closed.Load() {
		t.Error("tun not closed after the backend rejected the key")
	}
	if _, ok := c.OSInterfaceName("plexd0"); ok {
		t.Error("interface mapped despite the failure")
	}
}

func TestDarwinController_ConfigureAddress_IPv4(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ConfigureAddress("plexd0", "10.0.0.5/16"); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}

	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.5/16 10.0.0.5 alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
	)
	if !runner.allDeadlined() {
		t.Error("a command ran without a context deadline")
	}
}

func TestDarwinController_ConfigureAddress_HostPrefix(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	// The alias installs the host route itself, so no route command follows.
	if err := c.ConfigureAddress("plexd0", "10.0.0.5/32"); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}

	assertArgv(t, runner, "/sbin/ifconfig utun9 inet 10.0.0.5/32 10.0.0.5 alias")
}

func TestDarwinController_ConfigureAddress_IPv6(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ConfigureAddress("plexd0", "fd00::5/64"); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}

	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet6 fd00::5/64 alias",
		"/sbin/route -n add -inet6 fd00::/64 -interface utun9",
	)
}

func TestDarwinController_ConfigureAddress_Unknown(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
	assertPrefix(t, err, "wireguard: configure address:")
	assertArgv(t, runner)
}

func TestDarwinController_ConfigureAddress_InvalidPrefix(t *testing.T) {
	// The interface must exist, or the mapping lookup would fail first and the
	// test would assert the wrong error.
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	for _, address := range []string{"not-a-prefix", "", "10.0.0.5"} {
		err := c.ConfigureAddress("plexd0", address)
		assertPrefix(t, err, fmt.Sprintf("wireguard: configure address: parse %q:", address))
	}
	assertArgv(t, runner)
}

func TestDarwinController_ConfigureAddress_IfconfigFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/ifconfig utun9 inet 10.0.0.5/16 10.0.0.5 alias",
		"ifconfig: ioctl (SIOCAIFADDR): permission denied",
		errors.New("exit status 1"),
	)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	want := "wireguard: configure address: /sbin/ifconfig utun9 inet 10.0.0.5/16 10.0.0.5 alias: " +
		"exit status 1: ifconfig: ioctl (SIOCAIFADDR): permission denied"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}

	// The route is not attempted once the address failed.
	assertArgv(t, runner, "/sbin/ifconfig utun9 inet 10.0.0.5/16 10.0.0.5 alias")
}

func TestDarwinController_ConfigureAddress_RouteExists(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists\nadd net 10.0.0.0: gateway utun9: File exists",
		errors.New("exit status 1"),
	)
	runner.stub("/sbin/route -n get -inet 10.0.0.0/16", routeGetOutput("utun9"), nil)

	if err := c.ConfigureAddress("plexd0", "10.0.0.5/16"); err != nil {
		t.Fatalf("ConfigureAddress: %v, want an existing route to be success", err)
	}

	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.5/16 10.0.0.5 alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"/sbin/route -n get -inet 10.0.0.0/16",
	)
}

// routeGetOutput is what route(8) prints for a "get" that found a route.
func routeGetOutput(iface string) string {
	return "   route to: 10.0.0.0\ndestination: 10.0.0.0\n       mask: 255.255.0.0\n" +
		"  interface: " + iface + "\n      flags: <UP,DONE,STATIC>\n"
}

// "File exists" names neither the prefix's owner nor a next hop. A mesh CIDR
// that overlaps a prefix another interface holds must not be accepted as the
// idempotent case: every mesh packet would leave through that interface in the
// clear.
func TestDarwinController_ConfigureAddress_RouteExistsOtherInterface(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists\nadd net 10.0.0.0: gateway utun9: File exists",
		errors.New("exit status 1"),
	)
	runner.stub("/sbin/route -n get -inet 10.0.0.0/16", routeGetOutput("en0"), nil)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	want := `wireguard: configure address: 10.0.0.0/16 is already routed via "en0", not via utun9`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// route(8) answers a "get" for a prefix with no route of its own with the
// default route, which carries no interface the add can be matched against.
func TestDarwinController_ConfigureAddress_RouteExistsOwnerUnknown(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists",
		nil,
	)
	runner.stub("/sbin/route -n get -inet 10.0.0.0/16", "   route to: 10.0.0.0\n", nil)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	want := `wireguard: configure address: 10.0.0.0/16 is already routed via "", not via utun9`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// The "get" is refused the way every route(8) call is: with a message in the
// output and a zero exit status. Nothing proved the route belongs to this
// utun, so the add is not success.
func TestDarwinController_ConfigureAddress_RouteExistsGetFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists",
		nil,
	)
	runner.stub(
		"/sbin/route -n get -inet 10.0.0.0/16",
		"route: writing to routing socket: not in table",
		nil,
	)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	want := "wireguard: configure address: /sbin/route -n get -inet 10.0.0.0/16: not in table"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestDarwinController_ConfigureAddress_RouteFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: Network is unreachable",
		errors.New("exit status 1"),
	)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	assertPrefix(t, err, "wireguard: configure address: /sbin/route -n add -inet 10.0.0.0/16 -interface utun9: exit status 1:")
}

// route(8) reports every routing-socket failure in its output and still exits
// 0, so a zero exit alone must not be read as "the route went in": the mesh
// prefix would then be left on the default route with nothing recording it.
func TestDarwinController_ConfigureAddress_RouteFailsWithExitZero(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: Network is unreachable\nadd net 10.0.0.0: gateway utun9: Network is unreachable",
		nil,
	)

	err := c.ConfigureAddress("plexd0", "10.0.0.5/16")
	want := "wireguard: configure address: /sbin/route -n add -inet 10.0.0.0/16 -interface utun9: Network is unreachable"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// The same zero exit carries "File exists", which stays idempotent success.
func TestDarwinController_ConfigureAddress_RouteExistsWithExitZero(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists\nadd net 10.0.0.0: gateway utun9: File exists",
		nil,
	)
	runner.stub("/sbin/route -n get -inet 10.0.0.0/16", routeGetOutput("utun9"), nil)

	if err := c.ConfigureAddress("plexd0", "10.0.0.5/16"); err != nil {
		t.Fatalf("ConfigureAddress: %v, want an existing route to be success", err)
	}
}

func TestRouteSocketError(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		wantMsg string
		wantOK  bool
	}{
		{
			name:    "two lines",
			out:     "route: writing to routing socket: Network is unreachable\nadd net 10.0.0.0: gateway utun9: Network is unreachable",
			wantMsg: "Network is unreachable",
			wantOK:  true,
		},
		{
			name:    "single line",
			out:     "route: writing to routing socket: File exists",
			wantMsg: "File exists",
			wantOK:  true,
		},
		{
			name: "success output",
			out:  "add net 10.0.0.0: gateway utun9",
		},
		{
			name: "empty output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, ok := routeSocketError([]byte(tt.out))
			if msg != tt.wantMsg || ok != tt.wantOK {
				t.Errorf("routeSocketError(%q) = (%q, %v), want (%q, %v)", tt.out, msg, ok, tt.wantMsg, tt.wantOK)
			}
		})
	}
}

func TestDarwinController_SetMTU(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.SetMTU("plexd0", 1380); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}
	assertArgv(t, runner, "/sbin/ifconfig utun9 mtu 1380")
}

func TestDarwinController_SetMTU_Unknown(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)

	err := c.SetMTU("plexd0", 1380)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
	assertPrefix(t, err, "wireguard: set mtu:")
	assertArgv(t, runner)
}

func TestDarwinController_SetMTU_Fails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub("/sbin/ifconfig utun9 mtu 1380", "ifconfig: bad value", errors.New("exit status 1"))

	err := c.SetMTU("plexd0", 1380)
	assertPrefix(t, err, "wireguard: set mtu: /sbin/ifconfig utun9 mtu 1380: exit status 1:")
}

func TestDarwinController_SetInterfaceUp(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.SetInterfaceUp("plexd0"); err != nil {
		t.Fatalf("SetInterfaceUp: %v", err)
	}
	assertArgv(t, runner, "/sbin/ifconfig utun9 up")
}

func TestDarwinController_SetInterfaceUp_Unknown(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)

	err := c.SetInterfaceUp("plexd0")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
	assertPrefix(t, err, "wireguard: set interface up:")
	assertArgv(t, runner)
}

func TestDarwinController_SetInterfaceUp_Fails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub("/sbin/ifconfig utun9 up", "ifconfig: interface utun9 does not exist", errors.New("exit status 1"))

	err := c.SetInterfaceUp("plexd0")
	assertPrefix(t, err, "wireguard: set interface up: /sbin/ifconfig utun9 up: exit status 1:")
}

func TestDarwinController_DeleteInterface_Unknown(t *testing.T) {
	c, _, _ := newTestDarwinController(t)

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Fatalf("DeleteInterface of an unknown name = %v, want nil", err)
	}
}

func TestDarwinController_DeleteInterface_ReleasesUTUN(t *testing.T) {
	c, runner, tuns := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}

	if !tuns.only(t).closed.Load() {
		t.Error("tun not closed by DeleteInterface")
	}
	if _, err := c.backend.device("plexd0"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("backend device(plexd0) = %v, want os.ErrNotExist", err)
	}
	if osName, ok := c.OSInterfaceName("plexd0"); ok {
		t.Errorf("OSInterfaceName() = (%q, true), want the mapping gone", osName)
	}

	// Idempotent, and the kernel releases the utun with its addresses and
	// routes, so no host command is run.
	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Errorf("second DeleteInterface = %v, want nil", err)
	}
	assertArgv(t, runner)
}

func TestDarwinController_PeerOperationsDelegate(t *testing.T) {
	c, _, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	peerKey := mustKey(t)
	if err := c.AddPeer("plexd0", PeerConfig{
		PublicKey:  pubBytes(peerKey),
		AllowedIPs: []string{"10.0.0.2/32"},
	}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if dump := ipcGet(t, c.backend, "plexd0"); !strings.Contains(dump, "public_key=") {
		t.Fatalf("uapi dump = %q, want the peer", dump)
	}

	rotated := mustKey(t)
	before := privateKeyHex(ipcGet(t, c.backend, "plexd0"))
	if err := c.SetPrivateKey("plexd0", rotated[:]); err != nil {
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

func TestDarwinController_PeerOperations_Unknown(t *testing.T) {
	c, _, _ := newTestDarwinController(t)
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

// TestDarwinController_RealUTUN drives the production seams against the
// kernel: a real utun, real ifconfig and route calls, and the real UAPI socket.
// It is the only test that proves the command lines the fakes above assert are
// the ones macOS accepts.
//
// CI runs it as a separate privileged step on the macOS runner.
func TestDarwinController_RealUTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun needs root; run with sudo")
	}

	const (
		name    = "plexd-roottest"
		address = "10.255.254.1/30"
		mtu     = 1380
	)

	c := NewDarwinController(discardLogger())
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

	osName, ok := c.OSInterfaceName(name)
	if !ok {
		t.Fatal("no utun name recorded after CreateInterface")
	}
	if !utunNameRE.MatchString(osName) {
		t.Fatalf("kernel name = %q, want utunN", osName)
	}

	if err := c.ConfigureAddress(name, address); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}
	if err := c.SetMTU(name, mtu); err != nil {
		t.Fatalf("SetMTU: %v", err)
	}
	if err := c.SetInterfaceUp(name); err != nil {
		t.Fatalf("SetInterfaceUp: %v", err)
	}

	link, err := net.InterfaceByName(osName)
	if err != nil {
		t.Fatalf("InterfaceByName(%q): %v", osName, err)
	}
	if link.Flags&net.FlagUp == 0 {
		t.Errorf("%s is down, want up", osName)
	}
	if link.MTU != mtu {
		t.Errorf("%s MTU = %d, want %d", osName, link.MTU, mtu)
	}
	if !hasAddr(t, link, "10.255.254.1") {
		t.Errorf("%s does not carry 10.255.254.1", osName)
	}

	// netstat abbreviates a prefix (10.255.254/30), so match the interface and
	// the prefix length rather than the CIDR string.
	if !routeLine(t, osName, "/30") {
		t.Errorf("no /30 route via %s in netstat -rn -f inet", osName)
	}

	sock := "/var/run/wireguard/" + name + ".sock"
	dump := uapiGet(t, sock)
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

	if _, err := net.InterfaceByName(osName); err == nil {
		t.Errorf("%s still exists after DeleteInterface", osName)
	}
	if routeLine(t, osName, "") {
		t.Errorf("a route via %s survived DeleteInterface", osName)
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat %s = %v, want it removed", sock, err)
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

// routeLine reports whether the IPv4 routing table has a line naming iface and
// containing want. An empty want matches any line naming the interface.
func routeLine(t *testing.T, iface, want string) bool {
	t.Helper()

	out, err := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").CombinedOutput()
	if err != nil {
		t.Fatalf("netstat: %v: %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, iface) && strings.Contains(line, want) {
			return true
		}
	}
	return false
}

// uapiGet reads the device's UAPI dump over its Unix socket, the way wg(8)
// does.
func uapiGet(t *testing.T, path string) string {
	t.Helper()

	conn, err := net.DialTimeout("unix", path, 5*time.Second)
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
