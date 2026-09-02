//go:build darwin

package bridge

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Compile-time check that DarwinRouteController implements RouteController.
var _ RouteController = (*DarwinRouteController)(nil)

// netstatPath is only needed to observe the kernel's routing table in the
// root-gated test; the controller itself never runs netstat.
const netstatPath = "/usr/sbin/netstat"

func newTestDarwinRouteController(t *testing.T) (*DarwinRouteController, *mockCommandExecutor) {
	t.Helper()

	runner := newMockCommandExecutor()
	ctrl := NewDarwinRouteController(discardLogger(), nil)
	ctrl.exec = runner
	return ctrl, runner
}

// runCalls flattens the recorded Run invocations into name-plus-arguments
// slices, which is how the assertions below spell a command line.
func runCalls(t *testing.T, runner *mockCommandExecutor) [][]string {
	t.Helper()

	var got [][]string
	for _, call := range runner.execCallsFor("Run") {
		got = append(got, append([]string{call.Name}, call.Args...))
	}
	return got
}

func wantCalls(t *testing.T, runner *mockCommandExecutor, want [][]string) {
	t.Helper()

	got := runCalls(t, runner)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("commands = %v, want %v", got, want)
	}
}

// deadlineExecutor records whether each Run carried a context deadline.
type deadlineExecutor struct {
	*mockCommandExecutor

	mu        sync.Mutex
	deadlines []bool
}

func (e *deadlineExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	_, ok := ctx.Deadline()
	e.mu.Lock()
	e.deadlines = append(e.deadlines, ok)
	e.mu.Unlock()
	return e.mockCommandExecutor.Run(ctx, name, args...)
}

func TestDarwinRouteController_CommandsCarryDeadline(t *testing.T) {
	runner := &deadlineExecutor{mockCommandExecutor: newMockCommandExecutor()}
	runner.runOutputs[commandKey(sysctlPath, "-n", forwardingSysctl)] = []byte("0\n")

	ctrl := NewDarwinRouteController(discardLogger(), nil)
	ctrl.exec = runner

	if err := ctrl.AddRoute("10.1.0.0/24", "en1"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.deadlines) != 3 {
		t.Fatalf("recorded %d commands, want 3", len(runner.deadlines))
	}
	for i, ok := range runner.deadlines {
		if !ok {
			t.Errorf("command %d ran without a context deadline", i)
		}
	}
}

func TestDarwinRouteController_AddRoute_IPv4(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.AddRoute("10.1.0.0/24", "en1"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{routePath, "-n", "add", "-inet", "10.1.0.0/24", "-interface", "en1"},
	})
}

func TestDarwinRouteController_AddRoute_IPv6(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.AddRoute("fd00:1::/64", "en1"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{routePath, "-n", "add", "-inet6", "fd00:1::/64", "-interface", "en1"},
	})
}

func TestDarwinRouteController_AddRoute_MasksHostBits(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.AddRoute("10.1.0.5/24", "en1"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{routePath, "-n", "add", "-inet", "10.1.0.0/24", "-interface", "en1"},
	})
}

func TestDarwinRouteController_AddRoute_InvalidCIDR(t *testing.T) {
	for _, subnet := range []string{"not-a-cidr", ""} {
		ctrl, runner := newTestDarwinRouteController(t)

		err := ctrl.AddRoute(subnet, "en1")
		if err == nil {
			t.Fatalf("AddRoute(%q) = nil, want an error", subnet)
		}
		want := `bridge: add route: parse CIDR "` + subnet + `":`
		if !strings.HasPrefix(err.Error(), want) {
			t.Errorf("AddRoute(%q) error = %q, want prefix %q", subnet, err, want)
		}
		wantCalls(t, runner, nil)
	}
}

func TestDarwinRouteController_AddRoute_EmptyInterface(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	err := ctrl.AddRoute("10.1.0.0/24", "")
	if err == nil {
		t.Fatal("AddRoute with an empty interface = nil, want an error")
	}
	if got, want := err.Error(), "bridge: add route: interface name is empty"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
	wantCalls(t, runner, nil)
}

func TestDarwinRouteController_RemoveRoute_EmptyInterface(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	err := ctrl.RemoveRoute("10.1.0.0/24", "")
	if err == nil {
		t.Fatal("RemoveRoute with an empty interface = nil, want an error")
	}
	if got, want := err.Error(), "bridge: remove route: interface name is empty"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
	wantCalls(t, runner, nil)
}

func TestDarwinRouteController_AddRoute_Exists(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	key := commandKey(routePath, "-n", "add", "-inet", "10.1.0.0/24", "-interface", "en1")
	runner.runOutputs[key] = []byte("route: writing to routing socket: File exists\nadd net 10.1.0.0: gateway en1: File exists")
	runner.runErrors[key] = errors.New("exit status 1")

	if err := ctrl.AddRoute("10.1.0.0/24", "en1"); err != nil {
		t.Fatalf("AddRoute over an existing route = %v, want nil", err)
	}
}

func TestDarwinRouteController_AddRoute_Fails(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	key := commandKey(routePath, "-n", "add", "-inet", "10.1.0.0/24", "-interface", "en99")
	runner.runOutputs[key] = []byte("route: bad address: en99")
	runner.runErrors[key] = errors.New("exit status 68")

	err := ctrl.AddRoute("10.1.0.0/24", "en99")
	if err == nil {
		t.Fatal("AddRoute = nil, want an error")
	}
	want := `bridge: add route "10.1.0.0/24" via "en99": /sbin/route -n add -inet 10.1.0.0/24 -interface en99: exit status 68: route: bad address: en99`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestDarwinRouteController_AddRoute_NotRoot(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	key := commandKey(routePath, "-n", "add", "-inet", "10.1.0.0/24", "-interface", "en1")
	runner.runOutputs[key] = []byte("route: must be root to alter routing table")
	runner.runErrors[key] = errors.New("exit status 77")

	err := ctrl.AddRoute("10.1.0.0/24", "en1")
	if err == nil {
		t.Fatal("AddRoute = nil, want an error")
	}
	want := "exit status 77: route: must be root to alter routing table (bridge mode on macOS requires root)"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
}

func TestDarwinRouteController_AddRoute_FailsWithoutOutput(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	key := commandKey(routePath, "-n", "add", "-inet", "10.1.0.0/24", "-interface", "en1")
	runner.runErrors[key] = errors.New("exit status 1")

	err := ctrl.AddRoute("10.1.0.0/24", "en1")
	if err == nil {
		t.Fatal("AddRoute = nil, want an error")
	}
	want := `bridge: add route "10.1.0.0/24" via "en1": /sbin/route -n add -inet 10.1.0.0/24 -interface en1: exit status 1`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestDarwinRouteController_RemoveRoute(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.RemoveRoute("10.1.0.0/24", "en1"); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{routePath, "-n", "delete", "-inet", "10.1.0.0/24"},
	})
}

func TestDarwinRouteController_RemoveRoute_IPv6(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.RemoveRoute("fd00:1::/64", "en1"); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{routePath, "-n", "delete", "-inet6", "fd00:1::/64"},
	})
}

func TestDarwinRouteController_RemoveRoute_InvalidCIDR(t *testing.T) {
	for _, subnet := range []string{"not-a-cidr", ""} {
		ctrl, runner := newTestDarwinRouteController(t)

		err := ctrl.RemoveRoute(subnet, "en1")
		if err == nil {
			t.Fatalf("RemoveRoute(%q) = nil, want an error", subnet)
		}
		want := `bridge: remove route: parse CIDR "` + subnet + `":`
		if !strings.HasPrefix(err.Error(), want) {
			t.Errorf("RemoveRoute(%q) error = %q, want prefix %q", subnet, err, want)
		}
		wantCalls(t, runner, nil)
	}
}

func TestDarwinRouteController_RemoveRoute_NotInTable(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	key := commandKey(routePath, "-n", "delete", "-inet", "10.1.0.0/24")
	runner.runOutputs[key] = []byte("route: writing to routing socket: not in table\ndelete net 10.1.0.0: not in table")
	runner.runErrors[key] = errors.New("exit status 1")

	if err := ctrl.RemoveRoute("10.1.0.0/24", "en1"); err != nil {
		t.Fatalf("RemoveRoute of a missing route = %v, want nil", err)
	}
}

func TestDarwinRouteController_RemoveRoute_Fails(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	key := commandKey(routePath, "-n", "delete", "-inet", "10.1.0.0/24")
	runner.runOutputs[key] = []byte("route: writing to routing socket: Operation not supported")
	runner.runErrors[key] = errors.New("exit status 1")

	err := ctrl.RemoveRoute("10.1.0.0/24", "en1")
	if err == nil {
		t.Fatal("RemoveRoute = nil, want an error")
	}
	want := `bridge: remove route "10.1.0.0/24" via "en1": /sbin/route -n delete -inet 10.1.0.0/24: exit status 1:`
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
}

// readKey and writeKey name the two sysctl command lines the forwarding tests
// map results onto.
func readKey() string          { return commandKey(sysctlPath, "-n", forwardingSysctl) }
func writeKey(v string) string { return commandKey(sysctlPath, "-w", forwardingSysctl+"="+v) }

func TestDarwinRouteController_EnableForwarding_FirstCall(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{sysctlPath, "-n", forwardingSysctl},
		{sysctlPath, "-w", forwardingSysctl + "=1"},
	})
}

func TestDarwinRouteController_EnableForwarding_Repeat(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("first EnableForwarding: %v", err)
	}
	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("second EnableForwarding: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{sysctlPath, "-n", forwardingSysctl},
		{sysctlPath, "-w", forwardingSysctl + "=1"},
		{sysctlPath, "-w", forwardingSysctl + "=1"},
	})
}

func TestDarwinRouteController_EnableForwarding_SecondPair(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding for the bridge: %v", err)
	}
	if err := ctrl.EnableForwarding("wg-access", "en1"); err != nil {
		t.Fatalf("EnableForwarding for user access: %v", err)
	}

	wantCalls(t, runner, [][]string{
		{sysctlPath, "-n", forwardingSysctl},
		{sysctlPath, "-w", forwardingSysctl + "=1"},
		{sysctlPath, "-w", forwardingSysctl + "=1"},
	})
}

func TestDarwinRouteController_EnableForwarding_ReadFails(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runErrors[readKey()] = errors.New("exit status 1")

	err := ctrl.EnableForwarding("plexd0", "en1")
	if err == nil {
		t.Fatal("EnableForwarding = nil, want an error")
	}
	want := "bridge: enable forwarding: /usr/sbin/sysctl -n net.inet.ip.forwarding: exit status 1"
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	wantCalls(t, runner, [][]string{
		{sysctlPath, "-n", forwardingSysctl},
	})

	// A failed enable recorded no holder, so the matching disable is a no-op.
	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("DisableForwarding after a failed enable = %v, want nil", err)
	}
	wantCalls(t, runner, [][]string{
		{sysctlPath, "-n", forwardingSysctl},
	})
}

func TestDarwinRouteController_EnableForwarding_ReadUnexpected(t *testing.T) {
	for _, value := range []string{"garbage", ""} {
		ctrl, runner := newTestDarwinRouteController(t)
		runner.runOutputs[readKey()] = []byte(value)

		err := ctrl.EnableForwarding("plexd0", "en1")
		if err == nil {
			t.Fatalf("EnableForwarding with sysctl reporting %q = nil, want an error", value)
		}
		want := `bridge: enable forwarding: unexpected net.inet.ip.forwarding value "` + value + `"`
		if err.Error() != want {
			t.Errorf("error = %q, want %q", err, want)
		}
		wantCalls(t, runner, [][]string{
			{sysctlPath, "-n", forwardingSysctl},
		})
	}
}

func TestDarwinRouteController_EnableForwarding_WriteFails(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")
	runner.runOutputs[writeKey("1")] = []byte("sysctl: net.inet.ip.forwarding=1: Operation not permitted")
	runner.runErrors[writeKey("1")] = errors.New("exit status 1")

	err := ctrl.EnableForwarding("plexd0", "en1")
	if err == nil {
		t.Fatal("EnableForwarding = nil, want an error")
	}
	want := "bridge: enable forwarding: /usr/sbin/sysctl -w net.inet.ip.forwarding=1: exit status 1: sysctl: net.inet.ip.forwarding=1: Operation not permitted (bridge mode on macOS requires root)"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}

	before := len(runCalls(t, runner))
	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("DisableForwarding after a failed enable = %v, want nil", err)
	}
	if got := len(runCalls(t, runner)); got != before {
		t.Errorf("DisableForwarding ran %d commands after a failed enable, want none", got-before)
	}
}

func TestDarwinRouteController_DisableForwarding_RestoresZero(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("DisableForwarding: %v", err)
	}

	calls := runCalls(t, runner)
	want := []string{sysctlPath, "-w", forwardingSysctl + "=0"}
	if got := calls[len(calls)-1]; !reflect.DeepEqual(got, want) {
		t.Errorf("last command = %v, want %v", got, want)
	}
}

func TestDarwinRouteController_DisableForwarding_RestoresOne(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	// The host already forwarded before plexd started; teardown must leave it
	// that way.
	runner.runOutputs[readKey()] = []byte("1\n")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("DisableForwarding: %v", err)
	}

	calls := runCalls(t, runner)
	want := []string{sysctlPath, "-w", forwardingSysctl + "=1"}
	if got := calls[len(calls)-1]; !reflect.DeepEqual(got, want) {
		t.Errorf("last command = %v, want %v", got, want)
	}
}

func TestDarwinRouteController_DisableForwarding_LastHolderOnly(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding for the bridge: %v", err)
	}
	if err := ctrl.EnableForwarding("wg-access", "en1"); err != nil {
		t.Fatalf("EnableForwarding for user access: %v", err)
	}

	before := len(runCalls(t, runner))
	if err := ctrl.DisableForwarding("wg-access", "en1"); err != nil {
		t.Fatalf("DisableForwarding for user access: %v", err)
	}
	if got := len(runCalls(t, runner)); got != before {
		t.Errorf("DisableForwarding ran %d commands while the bridge still forwards, want none", got-before)
	}

	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("DisableForwarding for the bridge: %v", err)
	}
	calls := runCalls(t, runner)
	want := []string{sysctlPath, "-w", forwardingSysctl + "=0"}
	if got := calls[len(calls)-1]; !reflect.DeepEqual(got, want) {
		t.Errorf("last command = %v, want %v", got, want)
	}
}

func TestDarwinRouteController_DisableForwarding_Unknown(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("DisableForwarding without an enable = %v, want nil", err)
	}
	wantCalls(t, runner, nil)
}

func TestDarwinRouteController_DisableForwarding_WriteFails(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)
	runner.runOutputs[readKey()] = []byte("0\n")
	runner.runErrors[writeKey("0")] = errors.New("exit status 1")

	if err := ctrl.EnableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}

	err := ctrl.DisableForwarding("plexd0", "en1")
	if err == nil {
		t.Fatal("DisableForwarding = nil, want an error")
	}
	want := "bridge: disable forwarding: /usr/sbin/sysctl -w net.inet.ip.forwarding=0:"
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}

	// The pair was released before the write, so teardown does not retry.
	before := len(runCalls(t, runner))
	if err := ctrl.DisableForwarding("plexd0", "en1"); err != nil {
		t.Fatalf("second DisableForwarding = %v, want nil", err)
	}
	if got := len(runCalls(t, runner)); got != before {
		t.Errorf("second DisableForwarding ran %d commands, want none", got-before)
	}
}

func TestDarwinRouteController_AddNATMasquerade_NoBackend(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	err := ctrl.AddNATMasquerade("en1")
	if err == nil {
		t.Fatal("AddNATMasquerade without a backend = nil, want an error")
	}
	if !errors.Is(err, ErrNATUnavailable) {
		t.Errorf("error = %q, want it to wrap ErrNATUnavailable", err)
	}
	want := `bridge: add NAT masquerade on "en1": NAT masquerade is not available on this platform; set bridge.enable_nat: false to run the bridge without NAT`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	wantCalls(t, runner, nil)
}

func TestDarwinRouteController_RemoveNATMasquerade_NoBackend(t *testing.T) {
	ctrl, runner := newTestDarwinRouteController(t)

	if err := ctrl.RemoveNATMasquerade("en1"); err != nil {
		t.Fatalf("RemoveNATMasquerade without a backend = %v, want nil", err)
	}
	wantCalls(t, runner, nil)
}

func TestDarwinRouteController_NATDelegates(t *testing.T) {
	nat := &mockRouteController{}
	ctrl := NewDarwinRouteController(discardLogger(), nat)
	ctrl.exec = newMockCommandExecutor()

	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade: %v", err)
	}
	if err := ctrl.RemoveNATMasquerade("en1"); err != nil {
		t.Fatalf("RemoveNATMasquerade: %v", err)
	}

	for _, method := range []string{"AddNATMasquerade", "RemoveNATMasquerade"} {
		calls := nat.callsFor(method)
		if len(calls) != 1 {
			t.Fatalf("%s reached the backend %d times, want 1", method, len(calls))
		}
		if calls[0].Args[0] != "en1" {
			t.Errorf("%s interface = %v, want en1", method, calls[0].Args[0])
		}
	}

	addErr := errors.New("pf anchor busy")
	removeErr := errors.New("pf anchor missing")
	nat.addNATMasqueradeErr = addErr
	nat.removeNATMasqueradeErr = removeErr

	if err := ctrl.AddNATMasquerade("en1"); !errors.Is(err, addErr) {
		t.Errorf("AddNATMasquerade error = %v, want the backend's %v", err, addErr)
	}
	if err := ctrl.RemoveNATMasquerade("en1"); !errors.Is(err, removeErr) {
		t.Errorf("RemoveNATMasquerade error = %v, want the backend's %v", err, removeErr)
	}
}

// TestDarwinRouteController_Real drives the real route(8) and sysctl(8)
// against the kernel, which needs root. CI runs it in its own privileged step
// on the macOS runner.
func TestDarwinRouteController_Real(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("altering routes and sysctls needs root; run with sudo")
	}

	const (
		subnet = "10.255.252.0/30"
		iface  = "lo0"
	)

	ctrl := NewDarwinRouteController(discardLogger(), nil)
	before := readForwardingSysctl(t)

	t.Cleanup(func() {
		_ = ctrl.RemoveRoute(subnet, iface)
		if err := exec.Command(sysctlPath, "-w", forwardingSysctl+"="+before).Run(); err != nil {
			t.Errorf("restoring %s to %q: %v", forwardingSysctl, before, err)
		}
	})

	if err := ctrl.AddRoute(subnet, iface); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if !routeInTable(t, iface) {
		t.Error("netstat shows no route for the subnet after AddRoute")
	}
	if err := ctrl.AddRoute(subnet, iface); err != nil {
		t.Errorf("second AddRoute = %v, want nil", err)
	}

	if err := ctrl.RemoveRoute(subnet, iface); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}
	if routeInTable(t, iface) {
		t.Error("netstat still shows the route after RemoveRoute")
	}
	if err := ctrl.RemoveRoute(subnet, iface); err != nil {
		t.Errorf("second RemoveRoute = %v, want nil", err)
	}

	if err := ctrl.EnableForwarding(iface, iface); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	if got := readForwardingSysctl(t); got != "1" {
		t.Errorf("%s = %q after EnableForwarding, want \"1\"", forwardingSysctl, got)
	}

	if err := ctrl.DisableForwarding(iface, iface); err != nil {
		t.Fatalf("DisableForwarding: %v", err)
	}
	if got := readForwardingSysctl(t); got != before {
		t.Errorf("%s = %q after DisableForwarding, want the prior %q", forwardingSysctl, got, before)
	}
}

func readForwardingSysctl(t *testing.T) string {
	t.Helper()

	out, err := exec.Command(sysctlPath, "-n", forwardingSysctl).Output()
	if err != nil {
		t.Fatalf("reading %s: %v", forwardingSysctl, err)
	}
	return strings.TrimSpace(string(out))
}

// routeInTable reports whether the routing table holds the test's /30 via
// iface. netstat drops trailing zero octets from a network address, printing
// 10.255.252/30 rather than 10.255.252.0/30.
func routeInTable(t *testing.T, iface string) bool {
	t.Helper()

	out, err := exec.Command(netstatPath, "-rn", "-f", "inet").Output()
	if err != nil {
		t.Fatalf("netstat: %v", err)
	}
	re := regexp.MustCompile(`(?m)^10\.255\.252(\.0)?/30\s.*\b` + regexp.QuoteMeta(iface) + `\b`)
	return re.Match(out)
}
