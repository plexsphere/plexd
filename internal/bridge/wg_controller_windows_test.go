//go:build windows

package bridge

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

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
		if err := ctrl.CreateTunnelInterface(name, 0); err != nil {
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
		if err := ctrl.CreateInterface(name, 0); err != nil {
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
