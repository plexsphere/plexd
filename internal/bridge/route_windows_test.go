//go:build windows

package bridge

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Compile-time checks that the controller and the production router satisfy
// their interfaces.
var (
	_ RouteController = (*WindowsRouteController)(nil)
	_ ipRouter        = winipcfgRouter{}
)

// routeCall records one AddRoute or DeleteRoute invocation.
type routeCall struct {
	luid   uint64
	prefix netip.Prefix
}

// forwardSet records one SetForwarding invocation.
type forwardSet struct {
	luid    uint64
	enabled bool
}

// fakeIPRouter stands in for the IP Helper API.
type fakeIPRouter struct {
	mu sync.Mutex

	luids      map[string]uint64
	forwarding map[uint64]bool

	lookupErr error
	addErr    error
	deleteErr error
	readErr   error
	setErr    error
	// setErrFor fails only for one interface, which is how a failure partway
	// through EnableForwarding is exercised.
	setErrFor map[uint64]error

	adds    []routeCall
	deletes []routeCall
	reads   []uint64
	sets    []forwardSet
}

func (f *fakeIPRouter) LookupLUID(iface string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.lookupErr != nil {
		return 0, f.lookupErr
	}
	luid, ok := f.luids[iface]
	if !ok {
		// What net.InterfaceByName reports for a name that is not there.
		return 0, errors.New("no such network interface")
	}
	return luid, nil
}

func (f *fakeIPRouter) AddRoute(luid uint64, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.adds = append(f.adds, routeCall{luid: luid, prefix: prefix})
	return f.addErr
}

func (f *fakeIPRouter) DeleteRoute(luid uint64, prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.deletes = append(f.deletes, routeCall{luid: luid, prefix: prefix})
	return f.deleteErr
}

func (f *fakeIPRouter) Forwarding(luid uint64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reads = append(f.reads, luid)
	if f.readErr != nil {
		return false, f.readErr
	}
	return f.forwarding[luid], nil
}

func (f *fakeIPRouter) SetForwarding(luid uint64, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err, ok := f.setErrFor[luid]; ok {
		return err
	}
	if f.setErr != nil {
		return f.setErr
	}
	f.sets = append(f.sets, forwardSet{luid: luid, enabled: enabled})
	f.forwarding[luid] = enabled
	return nil
}

func (f *fakeIPRouter) recorded() ([]routeCall, []routeCall, []uint64, []forwardSet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.deletes, f.reads, f.sets
}

func newTestWindowsRouteController(t *testing.T) (*WindowsRouteController, *fakeIPRouter) {
	t.Helper()

	router := &fakeIPRouter{
		luids:      map[string]uint64{"plexd0": 42, "Ethernet": 7, "wg-access": 9},
		forwarding: map[uint64]bool{42: false, 7: false, 9: false},
	}
	ctrl := NewWindowsRouteController(discardLogger(), nil)
	ctrl.ip = router
	return ctrl, router
}

func wantAdds(t *testing.T, router *fakeIPRouter, want []routeCall) {
	t.Helper()

	adds, _, _, _ := router.recorded()
	if !reflect.DeepEqual(adds, want) {
		t.Errorf("AddRoute calls = %v, want %v", adds, want)
	}
}

func wantSets(t *testing.T, router *fakeIPRouter, want []forwardSet) {
	t.Helper()

	_, _, _, sets := router.recorded()
	if !reflect.DeepEqual(sets, want) {
		t.Errorf("SetForwarding calls = %v, want %v", sets, want)
	}
}

func wantReads(t *testing.T, router *fakeIPRouter, want []uint64) {
	t.Helper()

	_, _, reads, _ := router.recorded()
	if !reflect.DeepEqual(reads, want) {
		t.Errorf("Forwarding reads = %v, want %v", reads, want)
	}
}

func TestWindowsRouteController_AddRoute(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.AddRoute("10.1.0.0/24", "Ethernet"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	wantAdds(t, router, []routeCall{{luid: 7, prefix: netip.MustParsePrefix("10.1.0.0/24")}})
}

func TestWindowsRouteController_AddRoute_IPv6(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.AddRoute("fd00:1::/64", "Ethernet"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	wantAdds(t, router, []routeCall{{luid: 7, prefix: netip.MustParsePrefix("fd00:1::/64")}})
}

func TestWindowsRouteController_AddRoute_MasksHostBits(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.AddRoute("10.1.0.5/24", "Ethernet"); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	wantAdds(t, router, []routeCall{{luid: 7, prefix: netip.MustParsePrefix("10.1.0.0/24")}})
}

func TestWindowsRouteController_AddRoute_InvalidCIDR(t *testing.T) {
	for _, subnet := range []string{"not-a-cidr", ""} {
		ctrl, router := newTestWindowsRouteController(t)

		err := ctrl.AddRoute(subnet, "Ethernet")
		if err == nil {
			t.Fatalf("AddRoute(%q) = nil, want an error", subnet)
		}
		want := `bridge: add route: parse CIDR "` + subnet + `":`
		if !strings.HasPrefix(err.Error(), want) {
			t.Errorf("AddRoute(%q) error = %q, want prefix %q", subnet, err, want)
		}
		wantAdds(t, router, nil)
		wantReads(t, router, nil)
	}
}

func TestWindowsRouteController_AddRoute_UnknownInterface(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	err := ctrl.AddRoute("10.1.0.0/24", "en99")
	if err == nil {
		t.Fatal("AddRoute over an unknown interface = nil, want an error")
	}
	want := `bridge: add route: lookup interface "en99":`
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	if !strings.HasSuffix(err.Error(), "no such network interface") {
		t.Errorf("error = %q, want it to end with the lookup failure", err)
	}
	wantAdds(t, router, nil)

	// The empty name fails the same way: Go rejects it before it reaches the
	// interface table.
	ctrl, router = newTestWindowsRouteController(t)
	router.lookupErr = errors.New("invalid network interface name")

	err = ctrl.AddRoute("10.1.0.0/24", "")
	if err == nil {
		t.Fatal("AddRoute with an empty interface = nil, want an error")
	}
	if want := `bridge: add route: lookup interface "":`; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	wantAdds(t, router, nil)
}

func TestWindowsRouteController_AddRoute_Exists(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.addErr = windows.ERROR_OBJECT_ALREADY_EXISTS

	if err := ctrl.AddRoute("10.1.0.0/24", "Ethernet"); err != nil {
		t.Fatalf("AddRoute over an existing route = %v, want nil", err)
	}
}

func TestWindowsRouteController_AddRoute_AccessDenied(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.addErr = windows.ERROR_ACCESS_DENIED

	err := ctrl.AddRoute("10.1.0.0/24", "Ethernet")
	if err == nil {
		t.Fatal("AddRoute = nil, want an error")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("error = %q, want it to wrap ERROR_ACCESS_DENIED", err)
	}
	if want := `bridge: add route "10.1.0.0/24" via "Ethernet":`; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	if want := "(bridge mode on Windows requires Administrator)"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
}

func TestWindowsRouteController_AddRoute_Fails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.addErr = errors.New("boom")

	err := ctrl.AddRoute("10.1.0.0/24", "Ethernet")
	if err == nil {
		t.Fatal("AddRoute = nil, want an error")
	}
	want := `bridge: add route "10.1.0.0/24" via "Ethernet": boom`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestWindowsRouteController_RemoveRoute(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.RemoveRoute("10.1.0.0/24", "Ethernet"); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}

	_, deletes, _, _ := router.recorded()
	want := []routeCall{{luid: 7, prefix: netip.MustParsePrefix("10.1.0.0/24")}}
	if !reflect.DeepEqual(deletes, want) {
		t.Errorf("DeleteRoute calls = %v, want %v", deletes, want)
	}
}

func TestWindowsRouteController_RemoveRoute_NotFound(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.deleteErr = windows.ERROR_NOT_FOUND

	if err := ctrl.RemoveRoute("10.1.0.0/24", "Ethernet"); err != nil {
		t.Fatalf("RemoveRoute of a missing route = %v, want nil", err)
	}
}

func TestWindowsRouteController_RemoveRoute_InvalidCIDR(t *testing.T) {
	for _, subnet := range []string{"not-a-cidr", ""} {
		ctrl, router := newTestWindowsRouteController(t)

		err := ctrl.RemoveRoute(subnet, "Ethernet")
		if err == nil {
			t.Fatalf("RemoveRoute(%q) = nil, want an error", subnet)
		}
		want := `bridge: remove route: parse CIDR "` + subnet + `":`
		if !strings.HasPrefix(err.Error(), want) {
			t.Errorf("RemoveRoute(%q) error = %q, want prefix %q", subnet, err, want)
		}

		_, deletes, _, _ := router.recorded()
		if deletes != nil {
			t.Errorf("DeleteRoute calls = %v, want none", deletes)
		}
	}
}

func TestWindowsRouteController_RemoveRoute_UnknownInterface(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	err := ctrl.RemoveRoute("10.1.0.0/24", "en99")
	if err == nil {
		t.Fatal("RemoveRoute over an unknown interface = nil, want an error")
	}
	if want := `bridge: remove route: lookup interface "en99":`; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}

	_, deletes, _, _ := router.recorded()
	if deletes != nil {
		t.Errorf("DeleteRoute calls = %v, want none", deletes)
	}
}

func TestWindowsRouteController_RemoveRoute_Fails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.deleteErr = errors.New("boom")

	err := ctrl.RemoveRoute("10.1.0.0/24", "Ethernet")
	if err == nil {
		t.Fatal("RemoveRoute = nil, want an error")
	}
	want := `bridge: remove route "10.1.0.0/24" via "Ethernet": boom`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestWindowsRouteController_EnableForwarding(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}

	wantReads(t, router, []uint64{42, 7})
	wantSets(t, router, []forwardSet{{luid: 42, enabled: true}, {luid: 7, enabled: true}})
}

func TestWindowsRouteController_EnableForwarding_Repeat(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("first EnableForwarding: %v", err)
	}
	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("second EnableForwarding: %v", err)
	}

	// The flags are re-asserted, but nothing is read again: the saved state
	// must stay the one the first call found.
	wantReads(t, router, []uint64{42, 7})
	wantSets(t, router, []forwardSet{
		{luid: 42, enabled: true},
		{luid: 7, enabled: true},
		{luid: 42, enabled: true},
		{luid: 7, enabled: true},
	})
}

func TestWindowsRouteController_EnableForwarding_SharedInterface(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding for the bridge: %v", err)
	}
	if err := ctrl.EnableForwarding("wg-access", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding for user access: %v", err)
	}

	wantReads(t, router, []uint64{42, 7, 9})
	wantSets(t, router, []forwardSet{
		{luid: 42, enabled: true},
		{luid: 7, enabled: true},
		{luid: 9, enabled: true},
		{luid: 7, enabled: true},
	})
}

func TestWindowsRouteController_EnableForwarding_SameName(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.luids["lo"] = 1
	router.forwarding[1] = false

	if err := ctrl.EnableForwarding("lo", "lo"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}

	wantReads(t, router, []uint64{1})
	wantSets(t, router, []forwardSet{{luid: 1, enabled: true}, {luid: 1, enabled: true}})
}

func TestWindowsRouteController_EnableForwarding_LookupFails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.lookupErr = errors.New("boom")

	err := ctrl.EnableForwarding("plexd0", "Ethernet")
	if err == nil {
		t.Fatal("EnableForwarding = nil, want an error")
	}
	if want := `bridge: enable forwarding: lookup interface "plexd0":`; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	wantReads(t, router, nil)
	wantSets(t, router, nil)
}

func TestWindowsRouteController_EnableForwarding_ReadFails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.readErr = errors.New("boom")

	err := ctrl.EnableForwarding("plexd0", "Ethernet")
	if err == nil {
		t.Fatal("EnableForwarding = nil, want an error")
	}
	want := `bridge: enable forwarding: read forwarding on "plexd0": boom`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	wantSets(t, router, nil)

	// Nothing was recorded, so teardown writes nothing.
	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding after a failed enable = %v, want nil", err)
	}
	wantSets(t, router, nil)
}

func TestWindowsRouteController_EnableForwarding_SetFails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.setErr = windows.ERROR_ACCESS_DENIED

	err := ctrl.EnableForwarding("plexd0", "Ethernet")
	if err == nil {
		t.Fatal("EnableForwarding = nil, want an error")
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("error = %q, want it to wrap ERROR_ACCESS_DENIED", err)
	}
	if want := `bridge: enable forwarding: set forwarding on "plexd0":`; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	if want := "requires Administrator"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}

	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding after a failed enable = %v, want nil", err)
	}
	wantSets(t, router, nil)
}

func TestWindowsRouteController_EnableForwarding_SecondSetFails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	router.setErrFor = map[uint64]error{7: errors.New("boom")}

	err := ctrl.EnableForwarding("plexd0", "Ethernet")
	if err == nil {
		t.Fatal("EnableForwarding = nil, want an error")
	}
	if want := `bridge: enable forwarding: set forwarding on "Ethernet":`; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want prefix %q", err, want)
	}
	// The mesh interface was already switched on and recorded.
	wantSets(t, router, []forwardSet{{luid: 42, enabled: true}})

	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding: %v", err)
	}
	wantSets(t, router, []forwardSet{{luid: 42, enabled: true}, {luid: 42, enabled: false}})
}

func TestWindowsRouteController_DisableForwarding_RestoresPrior(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)
	// The access adapter already forwarded before plexd started; teardown must
	// leave it that way.
	router.forwarding[7] = true

	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding: %v", err)
	}

	wantSets(t, router, []forwardSet{
		{luid: 42, enabled: true},
		{luid: 7, enabled: true},
		{luid: 42, enabled: false},
		{luid: 7, enabled: true},
	})
}

func TestWindowsRouteController_DisableForwarding_SharedInterface(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding for the bridge: %v", err)
	}
	if err := ctrl.EnableForwarding("wg-access", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding for user access: %v", err)
	}

	if err := ctrl.DisableForwarding("wg-access", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding for user access: %v", err)
	}
	wantSets(t, router, []forwardSet{
		{luid: 42, enabled: true},
		{luid: 7, enabled: true},
		{luid: 9, enabled: true},
		{luid: 7, enabled: true},
		{luid: 9, enabled: false},
	})

	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding for the bridge: %v", err)
	}
	wantSets(t, router, []forwardSet{
		{luid: 42, enabled: true},
		{luid: 7, enabled: true},
		{luid: 9, enabled: true},
		{luid: 7, enabled: true},
		{luid: 9, enabled: false},
		{luid: 42, enabled: false},
		{luid: 7, enabled: false},
	})
}

func TestWindowsRouteController_DisableForwarding_Unknown(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("DisableForwarding without an enable = %v, want nil", err)
	}
	wantReads(t, router, nil)
	wantSets(t, router, nil)
}

func TestWindowsRouteController_DisableForwarding_SetFails(t *testing.T) {
	ctrl, router := newTestWindowsRouteController(t)

	if err := ctrl.EnableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	router.setErr = errors.New("boom")

	err := ctrl.DisableForwarding("plexd0", "Ethernet")
	if err == nil {
		t.Fatal("DisableForwarding = nil, want an error")
	}
	for _, want := range []string{
		`bridge: disable forwarding: set forwarding on "plexd0":`,
		`bridge: disable forwarding: set forwarding on "Ethernet":`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}

	// Both interfaces were released before their writes, so teardown does not
	// retry.
	router.setErr = nil
	_, _, _, sets := router.recorded()
	before := len(sets)
	if err := ctrl.DisableForwarding("plexd0", "Ethernet"); err != nil {
		t.Fatalf("second DisableForwarding = %v, want nil", err)
	}
	if _, _, _, sets = router.recorded(); len(sets) != before {
		t.Errorf("second DisableForwarding wrote %d flags, want none", len(sets)-before)
	}
}

func TestWindowsRouteController_AddNATMasquerade_NoBackend(t *testing.T) {
	ctrl, _ := newTestWindowsRouteController(t)

	err := ctrl.AddNATMasquerade("Ethernet")
	if err == nil {
		t.Fatal("AddNATMasquerade without a backend = nil, want an error")
	}
	if !errors.Is(err, ErrNATUnavailable) {
		t.Errorf("error = %q, want it to wrap ErrNATUnavailable", err)
	}
	want := `bridge: add NAT masquerade on "Ethernet": NAT masquerade is not available on this platform; set bridge.enable_nat: false to run the bridge without NAT`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestWindowsRouteController_RemoveNATMasquerade_NoBackend(t *testing.T) {
	ctrl, _ := newTestWindowsRouteController(t)

	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("RemoveNATMasquerade without a backend = %v, want nil", err)
	}
}

func TestWindowsRouteController_NATDelegates(t *testing.T) {
	nat := &mockRouteController{}
	ctrl := NewWindowsRouteController(discardLogger(), nat)

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade: %v", err)
	}
	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("RemoveNATMasquerade: %v", err)
	}

	for _, method := range []string{"AddNATMasquerade", "RemoveNATMasquerade"} {
		calls := nat.callsFor(method)
		if len(calls) != 1 {
			t.Fatalf("%s reached the backend %d times, want 1", method, len(calls))
		}
		if calls[0].Args[0] != "Ethernet" {
			t.Errorf("%s interface = %v, want Ethernet", method, calls[0].Args[0])
		}
	}

	addErr := errors.New("WFP filter rejected")
	removeErr := errors.New("WFP filter missing")
	nat.addNATMasqueradeErr = addErr
	nat.removeNATMasqueradeErr = removeErr

	if err := ctrl.AddNATMasquerade("Ethernet"); !errors.Is(err, addErr) {
		t.Errorf("AddNATMasquerade error = %v, want the backend's %v", err, addErr)
	}
	if err := ctrl.RemoveNATMasquerade("Ethernet"); !errors.Is(err, removeErr) {
		t.Errorf("RemoveNATMasquerade error = %v, want the backend's %v", err, removeErr)
	}
}

// TestWindowsRouteController_Real drives the real IP Helper API against the
// host's routing table, which needs Administrator. The Windows CI runner is
// already elevated, so the gate is the environment variable: without one the
// test would alter the routing table inside the ordinary test step.
func TestWindowsRouteController_Real(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_ROUTES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_ROUTES=1 in an elevated shell to alter the routing table")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("altering routes needs Administrator")
	}

	const subnet = "10.255.252.0/30"
	prefix := netip.MustParsePrefix(subnet)

	name := firstRoutableInterface(t)
	ctrl := NewWindowsRouteController(discardLogger(), nil)

	luid, err := winipcfgRouter{}.LookupLUID(name)
	if err != nil {
		t.Fatalf("resolving the LUID of %q: %v", name, err)
	}

	before, err := winipcfgRouter{}.Forwarding(luid)
	if err != nil {
		t.Fatalf("reading the forwarding flag of %q: %v", name, err)
	}

	t.Cleanup(func() {
		_ = ctrl.RemoveRoute(subnet, name)
		if err := (winipcfgRouter{}).SetForwarding(luid, before); err != nil {
			t.Errorf("restoring the forwarding flag of %q: %v", name, err)
		}
	})

	if err := ctrl.AddRoute(subnet, name); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if _, err := winipcfg.LUID(luid).Route(prefix, netip.IPv4Unspecified()); err != nil {
		t.Errorf("the route is not in the table after AddRoute: %v", err)
	}
	if err := ctrl.AddRoute(subnet, name); err != nil {
		t.Errorf("second AddRoute = %v, want nil", err)
	}

	if err := ctrl.RemoveRoute(subnet, name); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}
	if _, err := winipcfg.LUID(luid).Route(prefix, netip.IPv4Unspecified()); !errors.Is(err, windows.ERROR_NOT_FOUND) {
		t.Errorf("looking the route up after RemoveRoute = %v, want ERROR_NOT_FOUND", err)
	}
	if err := ctrl.RemoveRoute(subnet, name); err != nil {
		t.Errorf("second RemoveRoute = %v, want nil", err)
	}

	if err := ctrl.EnableForwarding(name, name); err != nil {
		t.Fatalf("EnableForwarding: %v", err)
	}
	if got, err := (winipcfgRouter{}).Forwarding(luid); err != nil || !got {
		t.Errorf("forwarding = %v (err %v) after EnableForwarding, want true", got, err)
	}

	if err := ctrl.DisableForwarding(name, name); err != nil {
		t.Fatalf("DisableForwarding: %v", err)
	}
	if got, err := (winipcfgRouter{}).Forwarding(luid); err != nil || got != before {
		t.Errorf("forwarding = %v (err %v) after DisableForwarding, want the prior %v", got, err, before)
	}
}

// firstRoutableInterface returns the name of an up, non-loopback interface
// carrying an IPv4 address, which is what the runner's routing table accepts a
// route on.
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
