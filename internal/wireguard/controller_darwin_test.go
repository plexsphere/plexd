//go:build darwin

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// Compile-time checks that DarwinController is a controller the manager can
// drive and swap the mesh address through, that the readiness check can
// resolve a kernel name through, and that the handshake report and tunnel
// metrics can read peer state from.
var (
	_ WGController     = (*DarwinController)(nil)
	_ OSInterfaceNamer = (*DarwinController)(nil)
	_ PeerStatsReader  = (*DarwinController)(nil)
	_ AddressReplacer  = (*DarwinController)(nil)
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
	c.routes = func(string) ([]utunRoute, error) { return nil, nil }
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

func TestDarwinController_ReplaceAddress(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16"); err != nil {
		t.Fatalf("ReplaceAddress: %v", err)
	}

	// The new alias goes on before the old one comes off, so the utun is
	// never without an address.
	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
	)
	if !runner.allDeadlined() {
		t.Error("a command ran without a context deadline")
	}
}

func TestDarwinController_ReplaceAddress_HostPrefix(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	// The alias installs the host route itself, so no route command follows.
	if err := c.ReplaceAddress("plexd0", "10.0.0.1/32", "10.0.0.9/32"); err != nil {
		t.Fatalf("ReplaceAddress: %v", err)
	}

	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/32 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
	)
}

// A repeat of a call that failed after the removal finds the old alias gone,
// which ifconfig(8) reports with exit status 1.
func TestDarwinController_ReplaceAddress_AliasGone(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"ifconfig: ioctl (SIOCDIFADDR): Can't assign requested address",
		errors.New("exit status 1"),
	)
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists",
		errors.New("exit status 1"),
	)
	runner.stub("/sbin/route -n get -inet 10.0.0.0/16", routeGetOutput("utun9"), nil)

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16"); err != nil {
		t.Fatalf("ReplaceAddress: %v, want a missing old alias to be success", err)
	}

	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"/sbin/route -n get -inet 10.0.0.0/16",
	)
}

func TestDarwinController_ReplaceAddress_AddFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"ifconfig: ioctl (SIOCAIFADDR): permission denied",
		errors.New("exit status 1"),
	)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	want := "wireguard: replace address: /sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias: " +
		"exit status 1: ifconfig: ioctl (SIOCAIFADDR): permission denied"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}

	// The old alias stays when the new one could not go on.
	assertArgv(t, runner, "/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias")
}

func TestDarwinController_ReplaceAddress_RemoveFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"ifconfig: ioctl (SIOCDIFADDR): Operation not permitted",
		errors.New("exit status 1"),
	)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	assertPrefix(t, err, "wireguard: replace address: /sbin/ifconfig utun9 inet 10.0.0.1 -alias: exit status 1:")

	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
	)
}

func TestDarwinController_ReplaceAddress_RouteFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: Network is unreachable",
		nil,
	)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	want := "wireguard: replace address: /sbin/route -n add -inet 10.0.0.0/16 -interface utun9: Network is unreachable"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// The on-link route of the new prefix is held by another interface, which
// the replace reports under its own name.
func TestDarwinController_ReplaceAddress_RouteExistsOtherInterface(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	runner.stub(
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"route: writing to routing socket: File exists",
		errors.New("exit status 1"),
	)
	runner.stub("/sbin/route -n get -inet 10.0.0.0/16", routeGetOutput("en0"), nil)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	want := `wireguard: replace address: 10.0.0.0/16 is already routed via "en0", not via utun9`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestDarwinController_ReplaceAddress_Unknown(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
	assertPrefix(t, err, "wireguard: replace address:")
	assertArgv(t, runner)
}

func TestDarwinController_ReplaceAddress_InvalidArguments(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
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
		assertPrefix(t, err, tt.want)
	}
	assertArgv(t, runner)
}

// Every route through the utun that names the old address is pointed at the
// new one: a route plexd added is changed in place, a host route the kernel
// cloned is deleted, and a route on any other address is left alone.
func TestDarwinController_ReplaceAddress_RepointsRoutes(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	old := netip.MustParseAddr("10.0.0.1")
	var asked []string
	c.routes = func(osName string) ([]utunRoute, error) {
		asked = append(asked, osName)
		return []utunRoute{
			{dst: netip.MustParsePrefix("10.0.0.0/16"), ifa: old},
			{dst: netip.MustParsePrefix("10.0.0.77/32"), host: true, cloned: true, ifa: old},
			{dst: netip.MustParsePrefix("10.9.0.0/24"), ifa: old},
			{dst: netip.MustParsePrefix("10.8.0.5/32"), host: true, ifa: old},
			{dst: netip.MustParsePrefix("10.7.0.0/24"), ifa: netip.MustParseAddr("10.0.0.9")},
			{dst: netip.MustParsePrefix("10.6.0.0/24"), ifa: netip.MustParseAddr("10.0.0.3")},
		}, nil
	}

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16"); err != nil {
		t.Fatalf("ReplaceAddress: %v", err)
	}

	if !slices.Equal(asked, []string{"utun9"}) {
		t.Errorf("routes read for %v, want [utun9]", asked)
	}
	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"/sbin/route -n change -inet 10.0.0.0/16 -interface utun9 -ifa 10.0.0.9",
		"/sbin/route -n delete -inet -host 10.0.0.77",
		"/sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9",
		"/sbin/route -n change -inet -host 10.8.0.5 -interface utun9 -ifa 10.0.0.9",
	)
	if !runner.allDeadlined() {
		t.Error("a command ran without a context deadline")
	}
}

// A route that went away between the read and the call is done, whichever
// exit status route(8) reports it with, and the next route still follows.
func TestDarwinController_ReplaceAddress_RouteGoneMeanwhile(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	old := netip.MustParseAddr("10.0.0.1")
	c.routes = func(string) ([]utunRoute, error) {
		return []utunRoute{
			{dst: netip.MustParsePrefix("10.0.0.77/32"), host: true, cloned: true, ifa: old},
			{dst: netip.MustParsePrefix("10.8.0.5/32"), host: true, ifa: old},
			{dst: netip.MustParsePrefix("10.9.0.0/24"), ifa: old},
		}, nil
	}
	runner.stub(
		"/sbin/route -n delete -inet -host 10.0.0.77",
		"route: writing to routing socket: not in table",
		errors.New("exit status 1"),
	)
	runner.stub(
		"/sbin/route -n change -inet -host 10.8.0.5 -interface utun9 -ifa 10.0.0.9",
		"route: writing to routing socket: not in table\nchange host 10.8.0.5: gateway utun9: not in table",
		nil,
	)

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16"); err != nil {
		t.Fatalf("ReplaceAddress: %v, want a route gone meanwhile to be success", err)
	}
	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"/sbin/route -n delete -inet -host 10.0.0.77",
		"/sbin/route -n change -inet -host 10.8.0.5 -interface utun9 -ifa 10.0.0.9",
		"/sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9",
	)
}

// route(8) exits 0 after a refused change, so the output reports it.
func TestDarwinController_ReplaceAddress_RepointRefused(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	old := netip.MustParseAddr("10.0.0.1")
	c.routes = func(string) ([]utunRoute, error) {
		return []utunRoute{
			{dst: netip.MustParsePrefix("10.9.0.0/24"), ifa: old},
			{dst: netip.MustParsePrefix("10.8.0.0/24"), ifa: old},
		}, nil
	}
	runner.stub(
		"/sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9",
		"route: writing to routing socket: Network is unreachable",
		nil,
	)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	want := "wireguard: replace address: /sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9: Network is unreachable"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	// The refusal stops the call, so a repeat starts from the first route
	// still on the old address.
	assertArgv(t, runner,
		"/sbin/ifconfig utun9 inet 10.0.0.9/16 10.0.0.9 alias",
		"/sbin/ifconfig utun9 inet 10.0.0.1 -alias",
		"/sbin/route -n add -inet 10.0.0.0/16 -interface utun9",
		"/sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9",
	)
}

func TestDarwinController_ReplaceAddress_RepointFails(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	c.routes = func(string) ([]utunRoute, error) {
		return []utunRoute{{dst: netip.MustParsePrefix("10.9.0.0/24"), ifa: netip.MustParseAddr("10.0.0.1")}}, nil
	}
	runner.stub(
		"/sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9",
		"route: must be root to alter routing table",
		errors.New("exit status 1"),
	)

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	want := "wireguard: replace address: /sbin/route -n change -inet 10.9.0.0/24 -interface utun9 -ifa 10.0.0.9: " +
		"exit status 1: route: must be root to alter routing table"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestDarwinController_ReplaceAddress_ReadRoutesFails(t *testing.T) {
	c, _, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	c.routes = func(string) ([]utunRoute, error) {
		return nil, errors.New("sysctl: operation not permitted")
	}

	err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.9/16")
	want := "wireguard: replace address: read the routes via utun9: sysctl: operation not permitted"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

func TestParseUTUNRoute(t *testing.T) {
	inet4 := func(s string) *route.Inet4Addr {
		return &route.Inet4Addr{IP: netip.MustParseAddr(s).As4()}
	}
	link := &route.LinkAddr{Index: 9, Name: "utun9"}

	tests := []struct {
		name   string
		flags  int
		addrs  []route.Addr
		want   utunRoute
		wantOK bool
	}{
		{
			name:   "network route",
			flags:  unix.RTF_UP | unix.RTF_STATIC,
			addrs:  []route.Addr{inet4("10.9.0.0"), link, inet4("255.255.255.0"), nil, link, inet4("10.0.0.1")},
			want:   utunRoute{dst: netip.MustParsePrefix("10.9.0.0/24"), ifa: netip.MustParseAddr("10.0.0.1")},
			wantOK: true,
		},
		{
			name:   "host route",
			flags:  unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC,
			addrs:  []route.Addr{inet4("10.8.0.5"), link, nil, nil, link, inet4("10.0.0.1")},
			want:   utunRoute{dst: netip.MustParsePrefix("10.8.0.5/32"), host: true, ifa: netip.MustParseAddr("10.0.0.1")},
			wantOK: true,
		},
		{
			name:   "cloned host route",
			flags:  unix.RTF_UP | unix.RTF_HOST | unix.RTF_WASCLONED,
			addrs:  []route.Addr{inet4("10.0.0.77"), link, nil, nil, link, inet4("10.0.0.1")},
			want:   utunRoute{dst: netip.MustParsePrefix("10.0.0.77/32"), host: true, cloned: true, ifa: netip.MustParseAddr("10.0.0.1")},
			wantOK: true,
		},
		{
			name:  "no interface address",
			flags: unix.RTF_UP | unix.RTF_STATIC,
			addrs: []route.Addr{inet4("10.9.0.0"), link, inet4("255.255.255.0")},
		},
		{
			name:  "network route without a netmask",
			flags: unix.RTF_UP | unix.RTF_STATIC,
			addrs: []route.Addr{inet4("10.9.0.0"), link, nil, nil, link, inet4("10.0.0.1")},
		},
		{
			name:  "netmask with a hole",
			flags: unix.RTF_UP | unix.RTF_STATIC,
			addrs: []route.Addr{inet4("10.9.0.0"), link, inet4("255.0.255.0"), nil, link, inet4("10.0.0.1")},
		},
		{
			name:  "IPv6 destination",
			flags: unix.RTF_UP | unix.RTF_HOST,
			addrs: []route.Addr{&route.Inet6Addr{IP: netip.MustParseAddr("fd00::5").As16()}, link, nil, nil, link, inet4("10.0.0.1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseUTUNRoute(&route.RouteMessage{Flags: tt.flags, Index: 9, Addrs: tt.addrs})
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseUTUNRoute = %+v, %v, want %+v, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// Removing the old alias of a pair that names one address would remove the
// new one, so nothing runs.
func TestDarwinController_ReplaceAddress_SameAddress(t *testing.T) {
	c, runner, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	if err := c.ReplaceAddress("plexd0", "10.0.0.1/16", "10.0.0.1/16"); err != nil {
		t.Fatalf("ReplaceAddress = %v, want nil", err)
	}
	assertArgv(t, runner)
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

	stats, err := c.PeerStats("plexd0")
	if err != nil {
		t.Fatalf("PeerStats: %v", err)
	}
	assertPeerStats(t, stats, []PeerStat{{
		PublicKey:  peerKey.PublicKey(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
	}})

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
	if _, err := c.PeerStats("plexd0"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("PeerStats = %v, want os.ErrNotExist", err)
	}
}

// darwinClamp returns the MSS clamp the controller recorded for name, and
// whether it recorded one.
func darwinClamp(c *DarwinController, name string) (*mssClampTUN, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	clamp, ok := c.clamps[name]
	return clamp, ok
}

func TestDarwinController_ClampMSS(t *testing.T) {
	c, runner, tuns := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")

	clamp, ok := darwinClamp(c, "plexd0")
	if !ok {
		t.Fatal("CreateInterface recorded no MSS clamp")
	}
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

	// The clamp is in process, so no host command runs.
	assertArgv(t, runner)
}

func TestDarwinController_ClampMSS_Unknown(t *testing.T) {
	c, _, _ := newTestDarwinController(t)

	err := c.ClampMSS("plexd0", 1332)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ClampMSS = %v, want os.ErrNotExist", err)
	}
	assertPrefix(t, err, "wireguard: clamp mss: ")

	if err := c.UnclampMSS("plexd0"); err != nil {
		t.Errorf("UnclampMSS of an unknown name = %v, want nil", err)
	}
}

func TestDarwinController_ClampMSS_Invalid(t *testing.T) {
	c, _, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	if err := c.ClampMSS("plexd0", 1332); err != nil {
		t.Fatalf("ClampMSS(1332) = %v, want nil", err)
	}
	clamp, _ := darwinClamp(c, "plexd0")

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

func TestDarwinController_CreateInterface_FailureRecordsNoClamp(t *testing.T) {
	c, _, _ := newTestDarwinController(t)

	if err := c.CreateInterface("plexd0", nil, 0); err == nil {
		t.Fatal("CreateInterface with a nil key = nil, want an error")
	}
	if _, ok := darwinClamp(c, "plexd0"); ok {
		t.Error("an MSS clamp recorded despite the failure")
	}
}

func TestDarwinController_DeleteInterface_ForgetsClamp(t *testing.T) {
	c, _, _ := newTestDarwinController(t)
	createTestInterface(t, c, "plexd0")
	if err := c.ClampMSS("plexd0", 1332); err != nil {
		t.Fatalf("ClampMSS = %v, want nil", err)
	}

	if err := c.DeleteInterface("plexd0"); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}
	if _, ok := darwinClamp(c, "plexd0"); ok {
		t.Error("the MSS clamp is still recorded after DeleteInterface")
	}
	if err := c.ClampMSS("plexd0", 1332); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ClampMSS after DeleteInterface = %v, want os.ErrNotExist", err)
	}
	if err := c.UnclampMSS("plexd0"); err != nil {
		t.Errorf("UnclampMSS after DeleteInterface = %v, want nil", err)
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

	// The round-trip probe's default listen binds UDP port RTTProbePort of
	// the mesh IP and sets IP_BOUND_IF to the utun, which only the kernel can
	// accept or refuse.
	mgr := NewManager(c, Config{InterfaceName: name}, discardLogger())
	mgr.meshIP = netip.MustParseAddr("10.255.254.1")
	if conn, err := mgr.listenRTT(); err != nil {
		t.Errorf("listenRTT on %s: %v, want the probe socket bound to the utun", osName, err)
	} else {
		_ = conn.Close()
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

// TestDarwinController_RealReplaceAddress swaps the address of a real utun
// through the production seams. It is the only proof of what ReplaceAddress
// relies on about macOS: that ifconfig removes one IPv4 alias with -alias,
// that adding an alias the utun already holds succeeds, that ifconfig reports
// an alias the utun does not hold with the message ReplaceAddress tolerates,
// and that once the routes through the utun are pointed at the new address,
// the on-link route of the prefix, a route through the utun and the host
// routes a connect cloned from them give a socket the new address as its
// source. The repeated call meets the two middle cases.
//
// CI runs it beside TestDarwinController_RealUTUN in the privileged macOS
// step, which runs packages side by side, so its prefixes are ones no other
// test of the step uses.
func TestDarwinController_RealReplaceAddress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun needs root; run with sudo")
	}

	const (
		name       = "plexd-readdress"
		oldAddress = "10.255.248.1/24"
		newAddress = "10.255.248.9/24"
		// routed stands for a peer's routed subnet.
		routed = "10.255.238.0/24"
	)

	c := NewDarwinController(discardLogger())
	key := mustKey(t)

	if err := c.CreateInterface(name, key[:], 0); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	// The kernel destroys the utun with its addresses and routes.
	t.Cleanup(func() { _ = c.DeleteInterface(name) })

	osName, ok := c.OSInterfaceName(name)
	if !ok {
		t.Fatal("no utun name recorded after CreateInterface")
	}
	if err := c.ConfigureAddress(name, oldAddress); err != nil {
		t.Fatalf("ConfigureAddress: %v", err)
	}
	if err := c.SetInterfaceUp(name); err != nil {
		t.Fatalf("SetInterfaceUp: %v", err)
	}

	out, err := exec.Command(routePath, "-n", "add", "-inet", routed, "-interface", osName).CombinedOutput()
	if err != nil {
		t.Fatalf("route add %s via %s: %v: %s", routed, osName, err, out)
	}
	if msg, ok := routeSocketError(out); ok {
		t.Fatalf("route add %s via %s: %s", routed, osName, msg)
	}

	check := func(when string) {
		t.Helper()
		link, err := net.InterfaceByName(osName)
		if err != nil {
			t.Fatalf("InterfaceByName(%q): %v", osName, err)
		}
		if got := ipv4Addrs(t, link); !slices.Equal(got, []string{"10.255.248.9"}) {
			t.Errorf("%s: %s holds %v, want 10.255.248.9 alone", when, osName, got)
		}
		// A host inside each prefix resolves through the route that covers
		// it, or through the default route when that route is gone.
		for _, dst := range []string{"10.255.248.77", "10.255.238.77"} {
			if got := routeGetInterface(t, dst); got != osName {
				t.Errorf("%s: %s resolves through %q, want %s", when, dst, got, osName)
			}
			// A BSD route keeps the interface address it was added with, and
			// a socket takes its source from it, so a route that still names
			// the removed alias resolves through the utun all the same.
			// Connecting a UDP socket picks the source and sends nothing.
			conn, err := net.Dial("udp4", net.JoinHostPort(dst, "9"))
			if err != nil {
				t.Errorf("%s: dial udp4 %s: %v", when, dst, err)
				continue
			}
			src := conn.LocalAddr().String()
			_ = conn.Close()
			if host, _, _ := net.SplitHostPort(src); host != "10.255.248.9" {
				t.Errorf("%s: a socket to %s leaves from %s, want 10.255.248.9", when, dst, src)
			}
		}
	}

	// A node has sent to its peers before its address moves. Connecting a
	// UDP socket looks its route up, and on macOS that clones a host route
	// with the interface address of the route it came from, so the call
	// meets such clones.
	for _, dst := range []string{"10.255.248.77", "10.255.238.77"} {
		conn, err := net.Dial("udp4", net.JoinHostPort(dst, "9"))
		if err != nil {
			t.Fatalf("dial udp4 %s before the call: %v", dst, err)
		}
		_ = conn.Close()
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

// ipv4Addrs returns the IPv4 addresses the interface carries.
func ipv4Addrs(t *testing.T, link *net.Interface) []string {
	t.Helper()

	addrs, err := link.Addrs()
	if err != nil {
		t.Fatalf("Addrs(): %v", err)
	}
	var got []string
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			got = append(got, ip4.String())
		}
	}
	return got
}

// routeGetInterface returns the interface route(8) resolves dst through, or
// "" when its answer names none.
func routeGetInterface(t *testing.T, dst string) string {
	t.Helper()

	out, err := exec.Command(routePath, "-n", "get", "-inet", dst).CombinedOutput()
	if err != nil {
		t.Fatalf("route get %s: %v: %s", dst, err, out)
	}
	name, _ := routeInterface(out)
	return name
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
