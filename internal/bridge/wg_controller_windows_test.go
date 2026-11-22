//go:build windows

package bridge

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/wireguard"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// uapiPipePrefix is where the userspace backend listens for a device, the
// place wg(8) and any wgctrl reader look. The wireguard package spells it the
// same way; the test reaches the pipe from outside that package.
const uapiPipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`

// TestWGControllers_RealWintun drives WGVPNController and WGAccessController
// against Windows: a real Wintun adapter from WindowsController, the real IP
// Helper API and the real UAPI named pipe. The fake-based tests pin which
// calls the controllers make; this is the only test that proves Windows
// accepts them.
//
// It checks the two assumptions the bridge rests on here: the adapter is
// visible to the IP stack the moment CreateTunnelInterface returns, and an
// on-link route by LUID installs on an adapter that carries no address, which
// macOS refuses.
//
// The gate is an environment variable rather than elevation, because the CI
// runner is already elevated and this must not run inside the ordinary
// unprivileged test step. CI runs it as its own step on the Windows runner.
func TestWGControllers_RealWintun(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WINTUN") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WINTUN=1 to create a real Wintun adapter")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter needs Administrator")
	}

	// The prefix belongs to this test alone, so a parallel run of the other
	// gated tests cannot collide with its route.
	const tunnelSubnet = "10.255.250.0/30"
	prefix := netip.MustParsePrefix(tunnelSubnet)

	t.Run("tunnel", func(t *testing.T) {
		const name = "plexd-s2sci"

		ctrl := NewWGVPNController(wireguard.NewWindowsController(discardLogger()), "", discardLogger())
		if err := ctrl.CreateTunnelInterface(name, testPrivateKey(t), 0); err != nil {
			t.Fatalf("CreateTunnelInterface: %v", err)
		}
		removed := false
		t.Cleanup(func() {
			if !removed {
				_ = ctrl.RemoveTunnelInterface(name)
			}
		})

		// CreateInterface returns only once the adapter answers a lookup, so
		// this one call has to resolve. Polling here would hide a create that
		// hands back an adapter the IP stack does not know yet.
		if _, err := net.InterfaceByName(name); err != nil {
			t.Fatalf("InterfaceByName(%q) right after CreateTunnelInterface: %v", name, err)
		}

		// The adapter carries the configured name, so that is the name the
		// operating system knows it by.
		if osName, ok := ctrl.OSInterfaceName(name); osName != name || !ok {
			t.Errorf("OSInterfaceName(%q) = (%q, %v), want (%q, true)", name, osName, ok, name)
		}

		luid, err := winipcfgRouter{}.LookupLUID(name)
		if err != nil {
			t.Fatalf("resolving the LUID of %q: %v", name, err)
		}

		routes := NewWindowsRouteController(discardLogger(), nil)
		t.Cleanup(func() { _ = routes.RemoveRoute(tunnelSubnet, name) })

		// The adapter has no address. Windows installs the on-link route by
		// LUID anyway, which is why the Windows bridge leaves a site-to-site
		// adapter unnumbered.
		if err := routes.AddRoute(tunnelSubnet, name); err != nil {
			t.Fatalf("AddRoute over the unnumbered %s: %v", name, err)
		}
		if _, err := winipcfg.LUID(luid).Route(prefix, netip.IPv4Unspecified()); err != nil {
			t.Errorf("the route is not in the table after AddRoute: %v", err)
		}

		if err := routes.RemoveRoute(tunnelSubnet, name); err != nil {
			t.Fatalf("RemoveRoute: %v", err)
		}
		if _, err := winipcfg.LUID(luid).Route(prefix, netip.IPv4Unspecified()); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			t.Errorf("looking the route up after RemoveRoute = %v, want ERROR_NOT_FOUND", err)
		}

		// The pair restores what it found, and the adapter is deleted below in
		// any case, so nothing has to be put back by hand.
		if err := routes.EnableForwarding(name, name); err != nil {
			t.Fatalf("EnableForwarding: %v", err)
		}
		if err := routes.DisableForwarding(name, name); err != nil {
			t.Fatalf("DisableForwarding: %v", err)
		}

		publicKey, raw := testPeerKey(t)
		if err := ctrl.ConfigureTunnelPeer(name, publicKey, []string{tunnelSubnet}, "127.0.0.1:51999", ""); err != nil {
			t.Fatalf("ConfigureTunnelPeer: %v", err)
		}

		pipe := uapiPipePrefix + name
		dump := uapiDump(t, pipe)
		if want := "public_key=" + hex.EncodeToString(raw); !strings.Contains(dump, want) {
			t.Errorf("uapi dump = %q, want it to carry %q", dump, want)
		}
		if want := "allowed_ip=" + tunnelSubnet; !strings.Contains(dump, want) {
			t.Errorf("uapi dump = %q, want it to carry %q", dump, want)
		}

		if err := ctrl.RemoveTunnelPeer(name, publicKey); err != nil {
			t.Fatalf("RemoveTunnelPeer: %v", err)
		}
		if dump := uapiDump(t, pipe); strings.Contains(dump, "public_key=") {
			t.Errorf("uapi dump = %q, want the peer gone", dump)
		}

		if err := ctrl.RemoveTunnelInterface(name); err != nil {
			t.Fatalf("RemoveTunnelInterface: %v", err)
		}
		removed = true

		if _, err := net.InterfaceByName(name); err == nil {
			t.Errorf("%s still exists after RemoveTunnelInterface", name)
		}
		if _, err := (&namedpipe.DialConfig{}).DialTimeout(pipe, time.Second); err == nil {
			t.Errorf("the UAPI pipe for %s still answers after RemoveTunnelInterface", name)
		}
		if err := ctrl.RemoveTunnelInterface(name); err != nil {
			t.Errorf("second RemoveTunnelInterface = %v, want nil", err)
		}
	})

	t.Run("access", func(t *testing.T) {
		const name = "plexd-accci"

		ctrl := NewWGAccessController(wireguard.NewWindowsController(discardLogger()), discardLogger())
		if err := ctrl.CreateInterface(name, testPrivateKey(t), 0, ""); err != nil {
			t.Fatalf("CreateInterface: %v", err)
		}
		removed := false
		t.Cleanup(func() {
			if !removed {
				_ = ctrl.RemoveInterface(name)
			}
		})

		if _, err := net.InterfaceByName(name); err != nil {
			t.Fatalf("InterfaceByName(%q) right after CreateInterface: %v", name, err)
		}

		// wireguard-go binds the port as it brings the device up, so a second
		// adapter cannot take the port the first one's device holds. Windows
		// reports that bind as WSAEADDRINUSE, which has to read as
		// ErrListenPortInUse for the managers to report bind_failed.
		const taken = "plexd-acctaken"
		port := uapiListenPort(t, uapiDump(t, uapiPipePrefix+name))
		err := ctrl.CreateInterface(taken, testPrivateKey(t), port, "")
		t.Cleanup(func() { _ = ctrl.RemoveInterface(taken) })
		if !errors.Is(err, ErrListenPortInUse) {
			t.Errorf("CreateInterface(%q) on port %d, which %s holds = %v, want an error wrapping ErrListenPortInUse", taken, port, name, err)
		}

		// A user-access peer dials the node, so it carries no endpoint.
		publicKey, _ := testPeerKey(t)
		if err := ctrl.ConfigurePeer(name, publicKey, []string{tunnelSubnet}, ""); err != nil {
			t.Fatalf("ConfigurePeer: %v", err)
		}
		if err := ctrl.RemovePeer(name, publicKey); err != nil {
			t.Fatalf("RemovePeer: %v", err)
		}

		if err := ctrl.RemoveInterface(name); err != nil {
			t.Fatalf("RemoveInterface: %v", err)
		}
		removed = true

		if err := ctrl.RemoveInterface(name); err != nil {
			t.Errorf("second RemoveInterface = %v, want nil", err)
		}
	})
}

// The mesh and the peer of TestPeerRoutes_RealWintun. No other test that runs
// against Windows uses these prefixes, so the routes cannot collide.
const (
	peerRoutesInterface = "plexd-peerrt"
	peerRoutesMeshIP    = "10.99.0.1"
	peerRoutesMeshCIDR  = "10.99.0.0/24"
	peerRoutesPeerIP    = "10.99.0.2"
	peerRoutesSubnet    = "10.20.0.0/16"
)

// TestPeerRoutes_RealWintun proves the peer routes on Windows without
// traffic: a wireguard.Manager over a real WindowsController, with a
// WindowsRouteController as its PeerRouter, programs the routed subnet of a
// peer as one of its allowed IPs on the mesh adapter and routes the subnet
// through that adapter, and takes both away once the peer drops the subnet.
// The fake-based tests in package wireguard pin which calls the manager
// makes; this is the only test that proves Windows accepts them.
//
// It reads the route by the adapter's LUID, as TestWindowsRouteController_Real
// does. It creates an adapter and alters the routing table, so it runs only
// when both PLEXD_TEST_REAL_WINTUN and PLEXD_TEST_REAL_ROUTES are set. CI runs
// it in the Wintun step, which fails unless it passed.
//
// The manager listens on a port from freeUDPPort. A fixed one, 51994, was
// refused once on a windows-latest runner, with the error a bind gets inside
// a UDP port reservation.
func TestPeerRoutes_RealWintun(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WINTUN") != "1" || os.Getenv("PLEXD_TEST_REAL_ROUTES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WINTUN=1 and PLEXD_TEST_REAL_ROUTES=1 to create a real Wintun adapter and route over it")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter and altering routes need Administrator")
	}
	ctx := context.Background()
	prefix := netip.MustParsePrefix(peerRoutesSubnet)

	ctrl := wireguard.NewWindowsController(discardLogger())
	listenPort := freeUDPPort(t)
	mgr := wireguard.NewManager(ctrl, wireguard.Config{InterfaceName: peerRoutesInterface, ListenPort: listenPort}, discardLogger())
	mgr.SetPeerRouter(NewWindowsRouteController(discardLogger(), nil))
	identity := &registration.NodeIdentity{
		NodeID:         "node-peer-routes",
		MeshIP:         peerRoutesMeshIP,
		DomainMeshCIDR: peerRoutesMeshCIDR,
		PrivateKey:     testPrivateKey(t),
	}
	if err := mgr.Setup(ctx, identity); err != nil {
		t.Fatalf("Setup on listen port %d: %v", listenPort, err)
	}
	// Teardown removes the peer route the test leaves behind, then the
	// adapter.
	t.Cleanup(func() { _ = mgr.Teardown() })

	luid, err := winipcfgRouter{}.LookupLUID(mgr.OSInterfaceName())
	if err != nil {
		t.Fatalf("resolving the LUID of %q: %v", mgr.OSInterfaceName(), err)
	}

	publicKey, raw := testPeerKey(t)
	peer := api.SnapshotPeer{
		NodeID:        "peer-routes",
		MeshIP:        peerRoutesPeerIP,
		PublicKey:     publicKey,
		RoutedSubnets: []string{peerRoutesSubnet},
	}
	handler := wireguard.ReconcileHandler(mgr, nil)
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToAdd: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("handler with the routed subnet: %v", err)
	}

	if got, want := meshPeerAllowedIPs(t, ctrl, raw), []string{peerRoutesSubnet, peerRoutesPeerIP + "/32"}; !slices.Equal(got, want) {
		t.Errorf("allowed IPs = %v, want %v", got, want)
	}
	if _, err := winipcfg.LUID(luid).Route(prefix, netip.IPv4Unspecified()); err != nil {
		t.Errorf("no route for %s on the mesh adapter: %v", peerRoutesSubnet, err)
	}

	peer.RoutedSubnets = nil
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("handler without the routed subnet: %v", err)
	}

	if got, want := meshPeerAllowedIPs(t, ctrl, raw), []string{peerRoutesPeerIP + "/32"}; !slices.Equal(got, want) {
		t.Errorf("allowed IPs after the member is gone = %v, want %v", got, want)
	}
	if _, err := winipcfg.LUID(luid).Route(prefix, netip.IPv4Unspecified()); !errors.Is(err, windows.ERROR_NOT_FOUND) {
		t.Errorf("looking the route for %s up after the member is gone = %v, want ERROR_NOT_FOUND", peerRoutesSubnet, err)
	}
}

// meshPeerAllowedIPs returns the allowed IPs the mesh adapter of
// TestPeerRoutes_RealWintun holds for the peer whose public key is raw,
// sorted, and fails the test when the adapter does not hold the peer.
func meshPeerAllowedIPs(t *testing.T, reader wireguard.PeerStatsReader, raw []byte) []string {
	t.Helper()

	stats, err := reader.PeerStats(peerRoutesInterface)
	if err != nil {
		t.Fatalf("PeerStats(%q): %v", peerRoutesInterface, err)
	}
	for _, s := range stats {
		if s.PublicKey != [32]byte(raw) {
			continue
		}
		allowed := make([]string, 0, len(s.AllowedIPs))
		for _, p := range s.AllowedIPs {
			allowed = append(allowed, p.String())
		}
		slices.Sort(allowed)
		return allowed
	}
	t.Fatalf("the mesh adapter holds no peer with the test's key: %+v", stats)
	return nil
}

// uapiDump reads the device's UAPI dump over its named pipe, the way wg(8)
// does. It dials without an owner expectation: wgctrl's own dial requires the
// pipe to be owned by LocalSystem, which holds for the service but not for a
// test that created it as an Administrator.
func uapiDump(t *testing.T, path string) string {
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

// uapiListenPort returns the listen port a UAPI dump reports, and fails the
// test when it reports none.
func uapiListenPort(t *testing.T, dump string) int {
	t.Helper()

	for _, line := range strings.Split(dump, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.Atoi(value)
			if err != nil {
				t.Fatalf("listen_port=%q in the uapi dump: %v", value, err)
			}
			return port
		}
	}
	t.Fatalf("uapi dump = %q, want a listen_port line", dump)
	return 0
}

// freeUDPPort returns a UDP port the kernel hands out on port 0, taken for
// IPv4 on every address, as wireguard-go takes its own on a listen port of 0,
// and released again. The test cannot pass 0 on: NewManager reads it as the
// default port. On port 0 Windows leaves out the ports the host reserved for
// UDP and those in use, so the number binds again unless another process
// takes that one port of the 16384 dynamic ones before the caller does.
func freeUDPPort(t *testing.T) int {
	t.Helper()

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("ListenUDP on port 0: %v", err)
	}
	defer func() { _ = udp.Close() }()
	return udp.LocalAddr().(*net.UDPAddr).Port
}

// reservedUDPPorts is how many neighbouring ports reserveUDPPorts reserves.
// The windows-latest runner boots with reservations of that size, two side by
// side for UDP on most boots, at a place that differs from boot to boot.
const reservedUDPPorts = 100

// reserveUDPPorts makes a persistent UDP port reservation of reservedUDPPorts
// neighbouring dynamic ports and returns the first of them. The test's
// cleanup deletes it. A bind of a reserved port for UDP fails with WSAEACCES
// for everyone but the holder of the reservation's token. It takes the ports
// from 51900 when they and the port before them bind, which holds 51994, the
// port TestPeerRoutes_RealWintun listened on until a runner refused it.
func reserveUDPPorts(t *testing.T) int {
	t.Helper()

	free := func(first int) bool {
		for port := first - 1; port < first+reservedUDPPorts; port++ {
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
			if err != nil {
				return false
			}
			_ = udp.Close()
		}
		return true
	}
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	// Both calls take the first port in network byte order.
	htons := func(port int) uintptr { return uintptr(uint16(port)<<8 | uint16(port)>>8) }
	for first := 51900; first < 64000; first += 2 * reservedUDPPorts {
		if !free(first) {
			continue
		}
		var token uint64
		if rc, _, _ := iphlpapi.NewProc("CreatePersistentUdpPortReservation").Call(htons(first), reservedUDPPorts, uintptr(unsafe.Pointer(&token))); rc != 0 {
			t.Fatalf("CreatePersistentUdpPortReservation(%d, %d) = %v", first, reservedUDPPorts, syscall.Errno(rc))
		}
		t.Cleanup(func() {
			if rc, _, _ := iphlpapi.NewProc("DeletePersistentUdpPortReservation").Call(htons(first), reservedUDPPorts); rc != 0 {
				t.Errorf("DeletePersistentUdpPortReservation(%d, %d) = %v", first, reservedUDPPorts, syscall.Errno(rc))
			}
		})
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: first})
		if !errors.Is(err, windows.WSAEACCES) {
			if err == nil {
				_ = udp.Close()
			}
			t.Fatalf("ListenUDP on the reserved port %d = %v, want an error wrapping %v", first, err, error(windows.WSAEACCES))
		}
		return first
	}
	t.Fatalf("no %d neighbouring ports between 51900 and 64000 are free for UDP", reservedUDPPorts)
	return 0
}

// windUDPPickBefore takes UDP ports from the kernel until it has handed out
// the port before the reserved ports that start at first, so the next UDP
// bind on port 0 is the one that meets them. It fails the test when the
// kernel hands out a reserved port.
func windUDPPickBefore(t *testing.T, first int) {
	t.Helper()

	// Two laps of the 16384 dynamic ports.
	for range 2 * 16384 {
		switch port := freeUDPPort(t); {
		case port >= first && port < first+reservedUDPPorts:
			t.Fatalf("the kernel handed out UDP port %d, one of the reserved ports %d to %d", port, first, first+reservedUDPPorts-1)
		case port == first-1:
			return
		}
	}
	t.Fatalf("the kernel's UDP pick never reached %d, the port before the reserved ports", first-1)
}

// TestPeerRoutes_RealWintunAtReservedUDPPorts pins that
// TestPeerRoutes_RealWintun gets a listen port while the host holds ports
// reserved for UDP and the kernel's UDP pick has reached them. The
// windows-latest runner boots with such reservations, and the test failed
// there on its fixed port 51994 with "wireguard: setup: wireguard: create
// interface: up: An attempt was made to access a socket in a way forbidden
// by its access permissions."
//
// It reserves ports of the host, and a reservation outlives a killed test and
// a reboot, so it needs PLEXD_TEST_REAL_PORT_RESERVATION=1 on top of the
// gates of TestPeerRoutes_RealWintun. It moves the kernel's UDP pick, which
// every process of the host shares, so no other test may run beside it: CI
// runs it in the port reservation step.
func TestPeerRoutes_RealWintunAtReservedUDPPorts(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_PORT_RESERVATION") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PORT_RESERVATION=1 to reserve UDP ports on this host")
	}
	if os.Getenv("PLEXD_TEST_REAL_WINTUN") != "1" || os.Getenv("PLEXD_TEST_REAL_ROUTES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WINTUN=1 and PLEXD_TEST_REAL_ROUTES=1 to create a real Wintun adapter and route over it")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("reserving UDP ports, creating a Wintun adapter and altering routes need Administrator")
	}
	windUDPPickBefore(t, reserveUDPPorts(t))
	t.Run("peer routes", TestPeerRoutes_RealWintun)
}
