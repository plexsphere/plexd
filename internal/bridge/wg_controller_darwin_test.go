//go:build darwin

package bridge

import (
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

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
		if err := ctrl.CreateInterface(name, 0); err != nil {
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
