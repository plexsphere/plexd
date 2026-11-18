//go:build darwin

package bridge

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// utunNameRE matches the kernel name macOS hands a utun device, which is what
// OSInterfaceName reports for an interface created under a configured name.
var utunNameRE = regexp.MustCompile(`^utun[0-9]+$`)

// TestWGControllers_RealUTUN drives WGVPNController and WGAccessController
// against the kernel: a real utun from DarwinController, real ifconfig and
// route(8) calls and the real UAPI socket. The fake-based tests pin which
// calls the controllers make; this is the only test that proves macOS accepts
// them.
//
// The unnumbered subtest records the reason plexd up puts an address on a
// site-to-site utun: route(8) refuses an on-link route over a utun that has
// none.
//
// CI runs it in its own privileged step on the macOS runner.
func TestWGControllers_RealUTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun needs root; run with sudo")
	}

	// Both prefixes belong to this test alone, so a parallel run of the other
	// root-gated tests cannot collide with its routes.
	const (
		tunnelSubnet = "10.255.250.0/30"
		meshAddress  = "10.255.251.1/32"
	)

	t.Run("unnumbered", func(t *testing.T) {
		const name = "plexd-s2sroot0"

		ctrl := NewWGVPNController(wireguard.NewDarwinController(discardLogger()), "", discardLogger())
		if err := ctrl.CreateTunnelInterface(name, 0); err != nil {
			t.Fatalf("CreateTunnelInterface: %v", err)
		}
		t.Cleanup(func() { _ = ctrl.RemoveTunnelInterface(name) })

		osName, ok := ctrl.OSInterfaceName(name)
		if !ok {
			t.Fatal("no utun name recorded after CreateTunnelInterface")
		}
		if !utunNameRE.MatchString(osName) {
			t.Fatalf("kernel name = %q, want utunN", osName)
		}

		link, err := net.InterfaceByName(osName)
		if err != nil {
			t.Fatalf("InterfaceByName(%q): %v", osName, err)
		}
		if link.Flags&net.FlagUp == 0 {
			t.Errorf("%s is down, want up", osName)
		}

		routes := NewDarwinRouteController(discardLogger(), nil)
		// Should the kernel accept the route after all, the cleanup takes it
		// back out of the table.
		t.Cleanup(func() { _ = routes.RemoveRoute(tunnelSubnet, osName) })

		// A utun without an IPv4 address has no local address the kernel can
		// route from, so route(8) writes "Network is unreachable" to its
		// output and still exits 0. Reading that output is what
		// DarwinRouteController.AddRoute does, and this call is where the
		// kernel confirms it.
		err = routes.AddRoute(tunnelSubnet, osName)
		if err == nil {
			t.Fatalf("AddRoute over the unnumbered %s = nil, want the kernel to refuse it", osName)
		}
		if !strings.Contains(err.Error(), "Network is unreachable") {
			t.Errorf("AddRoute error = %q, want it to carry \"Network is unreachable\"", err)
		}
	})

	t.Run("addressed", func(t *testing.T) {
		const name = "plexd-s2sroot1"

		ctrl := NewWGVPNController(wireguard.NewDarwinController(discardLogger()), meshAddress, discardLogger())
		if err := ctrl.CreateTunnelInterface(name, 0); err != nil {
			t.Fatalf("CreateTunnelInterface: %v", err)
		}
		removed := false
		t.Cleanup(func() {
			if !removed {
				_ = ctrl.RemoveTunnelInterface(name)
			}
		})

		osName, ok := ctrl.OSInterfaceName(name)
		if !ok {
			t.Fatal("no utun name recorded after CreateTunnelInterface")
		}

		link, err := net.InterfaceByName(osName)
		if err != nil {
			t.Fatalf("InterfaceByName(%q): %v", osName, err)
		}
		if !hasAddr(t, link, "10.255.251.1") {
			t.Errorf("%s does not carry 10.255.251.1", osName)
		}

		routes := NewDarwinRouteController(discardLogger(), nil)
		t.Cleanup(func() { _ = routes.RemoveRoute(tunnelSubnet, osName) })

		// The same call the unnumbered subtest saw refused, now over a utun
		// that carries the mesh address.
		if err := routes.AddRoute(tunnelSubnet, osName); err != nil {
			t.Fatalf("AddRoute over the addressed %s: %v", osName, err)
		}
		if !routeTableHas(t, osName, tunnelPrefixRE) {
			t.Errorf("no %s route via %s in netstat -rn -f inet", tunnelSubnet, osName)
		}

		if err := routes.RemoveRoute(tunnelSubnet, osName); err != nil {
			t.Fatalf("RemoveRoute: %v", err)
		}
		if routeTableHas(t, osName, tunnelPrefixRE) {
			t.Errorf("the %s route via %s survived RemoveRoute", tunnelSubnet, osName)
		}

		publicKey, raw := testPeerKey(t)
		if err := ctrl.ConfigureTunnelPeer(name, publicKey, []string{tunnelSubnet}, "127.0.0.1:51999", ""); err != nil {
			t.Fatalf("ConfigureTunnelPeer: %v", err)
		}

		// The device is reached under the configured name, not the utun name:
		// the UAPI socket carries the name plexd asked for.
		sock := "/var/run/wireguard/" + name + ".sock"
		dump := uapiDump(t, sock)
		if want := "public_key=" + hex.EncodeToString(raw); !strings.Contains(dump, want) {
			t.Errorf("uapi dump = %q, want it to carry %q", dump, want)
		}
		if want := "allowed_ip=" + tunnelSubnet; !strings.Contains(dump, want) {
			t.Errorf("uapi dump = %q, want it to carry %q", dump, want)
		}

		if err := ctrl.RemoveTunnelPeer(name, publicKey); err != nil {
			t.Fatalf("RemoveTunnelPeer: %v", err)
		}
		if dump := uapiDump(t, sock); strings.Contains(dump, "public_key=") {
			t.Errorf("uapi dump = %q, want the peer gone", dump)
		}

		if err := ctrl.RemoveTunnelInterface(name); err != nil {
			t.Fatalf("RemoveTunnelInterface: %v", err)
		}
		removed = true

		if _, err := net.InterfaceByName(osName); err == nil {
			t.Errorf("%s still exists after RemoveTunnelInterface", osName)
		}
		if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stat %s = %v, want the socket removed", sock, err)
		}
		if err := ctrl.RemoveTunnelInterface(name); err != nil {
			t.Errorf("second RemoveTunnelInterface = %v, want nil", err)
		}
	})

	t.Run("access", func(t *testing.T) {
		const name = "plexd-accroot"

		wg := wireguard.NewDarwinController(discardLogger())
		ctrl := NewWGAccessController(wg, discardLogger())
		if err := ctrl.CreateInterface(name, testPrivateKey(t), 0, ""); err != nil {
			t.Fatalf("CreateInterface: %v", err)
		}
		removed := false
		t.Cleanup(func() {
			if !removed {
				_ = ctrl.RemoveInterface(name)
			}
		})

		// The access controller exposes no name mapping of its own: nothing
		// hands the access interface back to the operating system on macOS.
		// The utun the create made is asserted through the controller it wraps.
		osName, ok := wg.OSInterfaceName(name)
		if !ok || !utunNameRE.MatchString(osName) {
			t.Fatalf("OSInterfaceName(%q) = (%q, %v), want a utunN name", name, osName, ok)
		}
		if _, err := net.InterfaceByName(osName); err != nil {
			t.Fatalf("InterfaceByName(%q): %v", osName, err)
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

// The mesh and the peer of TestPeerRoutes_RealUTUN. No other test that runs
// against the kernel uses these prefixes, so the routes cannot collide.
const (
	peerRoutesInterface  = "plexd-peerrt"
	peerRoutesListenPort = 51994
	peerRoutesMeshIP     = "10.99.0.1"
	peerRoutesMeshCIDR   = "10.99.0.0/24"
	peerRoutesPeerIP     = "10.99.0.2"
	peerRoutesSubnet     = "10.20.0.0/16"
	peerRoutesProbe      = "10.20.0.1"
)

// TestPeerRoutes_RealUTUN proves the peer routes on macOS without traffic: a
// wireguard.Manager over a real DarwinController, with a
// DarwinRouteController as its PeerRouter, programs the routed subnet of a
// peer as one of its allowed IPs on the mesh device and routes the subnet
// through the mesh utun, and takes both away once the peer drops the subnet.
// The fake-based tests in package wireguard pin which calls the manager
// makes; this is the only test that proves macOS accepts them.
//
// CI runs it in the privileged macOS step, which fails unless it passed.
func TestPeerRoutes_RealUTUN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and routing over it need root; run with sudo")
	}
	ctx := context.Background()

	ctrl := wireguard.NewDarwinController(discardLogger())
	mgr := wireguard.NewManager(ctrl, wireguard.Config{InterfaceName: peerRoutesInterface, ListenPort: peerRoutesListenPort}, discardLogger())
	mgr.SetPeerRouter(NewDarwinRouteController(discardLogger(), nil))
	identity := &registration.NodeIdentity{
		NodeID:         "node-peer-routes",
		MeshIP:         peerRoutesMeshIP,
		DomainMeshCIDR: peerRoutesMeshCIDR,
		PrivateKey:     testPrivateKey(t),
	}
	if err := mgr.Setup(ctx, identity); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Teardown removes the peer route the test leaves behind, then the utun.
	t.Cleanup(func() { _ = mgr.Teardown() })

	osName := mgr.OSInterfaceName()
	if !utunNameRE.MatchString(osName) {
		t.Fatalf("OSInterfaceName() = %q, want utunN", osName)
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
	if iface, ok := routeGetInterface(t, peerRoutesProbe); !ok || iface != osName {
		t.Errorf("route -n get %s names interface %q (found %v), want %s", peerRoutesProbe, iface, ok, osName)
	}

	peer.RoutedSubnets = nil
	if err := handler(ctx, nil, reconcile.StateDiff{PeersToUpdate: []api.SnapshotPeer{peer}}); err != nil {
		t.Fatalf("handler without the routed subnet: %v", err)
	}

	if got, want := meshPeerAllowedIPs(t, ctrl, raw), []string{peerRoutesPeerIP + "/32"}; !slices.Equal(got, want) {
		t.Errorf("allowed IPs after the member is gone = %v, want %v", got, want)
	}
	if iface, ok := routeGetInterface(t, peerRoutesProbe); ok && iface == osName {
		t.Errorf("route -n get %s still names %s after the member is gone", peerRoutesProbe, osName)
	}
}

// meshPeerAllowedIPs returns the allowed IPs the mesh device of
// TestPeerRoutes_RealUTUN holds for the peer whose public key is raw, sorted,
// and fails the test when the device does not hold the peer.
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
	t.Fatalf("the mesh device holds no peer with the test's key: %+v", stats)
	return nil
}

// routeGetInterface returns the interface route(8) names for the route the
// kernel picks to dst, and false when it names none, as when no route covers
// dst.
func routeGetInterface(t *testing.T, dst string) (string, bool) {
	t.Helper()

	// route(8) exits non-zero when no route covers dst, which is an answer
	// here, so only the output decides.
	out, _ := exec.Command(routePath, "-n", "get", dst).CombinedOutput()
	return routeInterface(out)
}

// tunnelPrefixRE matches the destination netstat prints for the test's /30. It
// drops trailing zero octets from a network address, so the table reads
// 10.255.250/30 rather than 10.255.250.0/30.
const tunnelPrefixRE = `10\.255\.250(\.0)?/30`

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

// routeTableHas reports whether the IPv4 routing table holds a route whose
// destination matches prefixRE and whose line names iface.
func routeTableHas(t *testing.T, iface, prefixRE string) bool {
	t.Helper()

	out, err := exec.Command(netstatPath, "-rn", "-f", "inet").Output()
	if err != nil {
		t.Fatalf("netstat: %v", err)
	}
	re := regexp.MustCompile(`(?m)^` + prefixRE + `\s.*\b` + regexp.QuoteMeta(iface) + `\b`)
	return re.Match(out)
}

// uapiDump reads the device's UAPI dump over its Unix socket, the way wg(8)
// does.
func uapiDump(t *testing.T, path string) string {
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
