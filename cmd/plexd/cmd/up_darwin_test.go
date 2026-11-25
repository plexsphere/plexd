//go:build darwin

package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/tunnel"
	"github.com/plexsphere/plexd/internal/wireguard"
)

func TestNewWGController_Darwin(t *testing.T) {
	logger := discardLogger()

	ctrl := newWGController(logger)
	if ctrl == nil {
		t.Fatal("newWGController() = nil, want the utun controller on macOS")
	}
	if _, ok := ctrl.(*wireguard.DarwinController); !ok {
		t.Errorf("newWGController() = %T, want *wireguard.DarwinController", ctrl)
	}

	// The readiness poller resolves the kernel name through this interface.
	if _, ok := ctrl.(wireguard.OSInterfaceNamer); !ok {
		t.Errorf("%T does not implement wireguard.OSInterfaceNamer", ctrl)
	}
}

func TestNewFirewallController_Darwin(t *testing.T) {
	logger := discardLogger()

	ctrl := newFirewallController(logger, "plexd0")
	if ctrl == nil {
		t.Fatal("newFirewallController() = nil, want the pf controller on macOS")
	}
	if _, ok := ctrl.(*policy.PFController); !ok {
		t.Errorf("newFirewallController() = %T, want *policy.PFController", ctrl)
	}

	// The route controller takes this instance as its NAT backend, because pf
	// keeps the translation rule in the same anchor as the policy chains.
	if _, ok := ctrl.(bridge.NATController); !ok {
		t.Errorf("%T does not implement bridge.NATController", ctrl)
	}
}

func TestNewRouteController_Darwin(t *testing.T) {
	logger := discardLogger()

	ctrl := newRouteController(logger, newFirewallController(logger, "plexd0"))
	if ctrl == nil {
		t.Fatal("newRouteController() = nil, want the route(8) controller on macOS")
	}
	if _, ok := ctrl.(*bridge.DarwinRouteController); !ok {
		t.Errorf("newRouteController() = %T, want *bridge.DarwinRouteController", ctrl)
	}
}

// TestNewRouteController_Darwin_NilFirewall covers the caller that has no
// firewall controller: the NAT type assertion has to yield a nil backend
// rather than panic, leaving a route controller that only lacks NAT.
func TestNewRouteController_Darwin_NilFirewall(t *testing.T) {
	ctrl := newRouteController(discardLogger(), nil)
	if ctrl == nil {
		t.Fatal("newRouteController() = nil, want the route(8) controller without a NAT backend")
	}
	if _, ok := ctrl.(*bridge.DarwinRouteController); !ok {
		t.Errorf("newRouteController() = %T, want *bridge.DarwinRouteController", ctrl)
	}
}

// TestNewMeshSourceRewriter_Darwin pins the pf controller as the mesh source
// rewriter on macOS, and an untyped nil without a firewall controller, which
// serves no user access provider and no site-to-site tunnel. The in-process
// rewriter changes neither.
func TestNewMeshSourceRewriter_Darwin(t *testing.T) {
	logger := discardLogger()
	fw := policy.NewPFController(logger)
	routes := newRouteController(logger, fw)

	if got, ok := newMeshSourceRewriter(routes, fw, nil).(*policy.PFController); !ok || got != fw {
		t.Errorf("newMeshSourceRewriter(routes, fw, nil) = %T %p, want the pf controller %p itself", got, got, fw)
	}
	if got, ok := newMeshSourceRewriter(routes, fw, wireguard.NewMeshRewriter(logger)).(*policy.PFController); !ok || got != fw {
		t.Errorf("newMeshSourceRewriter(routes, fw, rewriter) = %T %p, want the pf controller %p itself", got, got, fw)
	}
	if got := newMeshSourceRewriter(routes, nil, nil); got != nil {
		t.Errorf("newMeshSourceRewriter(routes, nil, nil) = %#v, want an untyped nil", got)
	}
}

// TestNewMeshRewriter_Darwin pins that macOS builds no in-process rewriter,
// even for a bridge that serves: pf rewrites in the kernel.
func TestNewMeshRewriter_Darwin(t *testing.T) {
	if got := newMeshRewriter(true, discardLogger()); got != nil {
		t.Errorf("newMeshRewriter(true) = %p, want nil on macOS", got)
	}
}

// TestNewNATExempter_Darwin pins that macOS exempts no tunnel's link from the
// bridge NAT, which translates only what leaves the access interface.
func TestNewNATExempter_Darwin(t *testing.T) {
	if got := newNATExempter(nil); got != nil {
		t.Errorf("newNATExempter(nil) = %#v, want nil on macOS", got)
	}
	if got := newNATExempter(policy.NewPFController(discardLogger())); got != nil {
		t.Errorf("newNATExempter(fw) = %#v, want nil on macOS", got)
	}
}

// TestNewTunnelProviders_Darwin pins that macOS builds no ipsec and no
// openvpn provider: their links are Linux kernel features, so such a tunnel
// reads kind_not_served.
func TestNewTunnelProviders_Darwin(t *testing.T) {
	if got := newTunnelProviders(t.TempDir(), discardLogger()); len(got) != 0 {
		t.Errorf("newTunnelProviders() = %v, want no provider on macOS", got)
	}
}

func TestNewSystemReader_Darwin(t *testing.T) {
	reader := newSystemReader(discardLogger())
	if reader == nil {
		t.Fatal("newSystemReader() = nil, want the sysctl and Mach reader on macOS")
	}
	if _, ok := reader.(*metrics.DarwinSystemReader); !ok {
		t.Errorf("newSystemReader() = %T, want *metrics.DarwinSystemReader", reader)
	}
}

func TestNewSystemLogSource_Darwin(t *testing.T) {
	src := newSystemLogSource("host", discardLogger())
	if src == nil {
		t.Fatal("newSystemLogSource() = nil, want the daemon log source on macOS")
	}
	if _, ok := src.(*logfwd.DaemonLogSource); !ok {
		t.Errorf("newSystemLogSource() = %T, want *logfwd.DaemonLogSource", src)
	}
}

func TestNewAccessController_Darwin(t *testing.T) {
	ctrl := newAccessController(discardLogger(), nil)
	if ctrl == nil {
		t.Fatal("newAccessController() = nil, want the utun-backed access controller on macOS")
	}
	if _, ok := ctrl.(*bridge.WGAccessController); !ok {
		t.Errorf("newAccessController() = %T, want *bridge.WGAccessController", ctrl)
	}
}

func TestNewVPNController_Darwin(t *testing.T) {
	logger := discardLogger()

	ctrl := newVPNController(logger, "10.42.0.5", nil)
	if ctrl == nil {
		t.Fatal("newVPNController() = nil, want the utun-backed tunnel controller on macOS")
	}
	if _, ok := ctrl.(*bridge.WGVPNController); !ok {
		t.Errorf("newVPNController() = %T, want *bridge.WGVPNController", ctrl)
	}

	// The site-to-site manager resolves utunN through this interface, so the
	// route to the remote subnet names the device the kernel created.
	if _, ok := ctrl.(wireguard.OSInterfaceNamer); !ok {
		t.Errorf("%T does not implement wireguard.OSInterfaceNamer", ctrl)
	}

	// An identity without a mesh IP leaves the utun unnumbered instead of
	// leaving the node without a tunnel controller.
	if c := newVPNController(logger, "", nil); c == nil {
		t.Fatal(`newVPNController(logger, "", nil) = nil, want a controller that leaves the utun unnumbered`)
	}
}

// The address the controller is built with is what route(8) needs to accept a
// route over the tunnel utun, and it is unreachable from here once the
// controller exists, so the derivation is asserted on its own. A mesh IP that
// lost its /32 fails every AddRoute with "Network is unreachable"; an empty
// one turned into "/32" fails ConfigureAddress and deletes the interface the
// create just made.
func TestTunnelAddress_Darwin(t *testing.T) {
	tests := []struct {
		name   string
		meshIP string
		want   string
	}{
		{name: "mesh ip becomes a host prefix", meshIP: "10.42.0.5", want: "10.42.0.5/32"},
		{name: "no mesh ip leaves the utun unnumbered", meshIP: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tunnelAddress(tt.meshIP); got != tt.want {
				t.Errorf("tunnelAddress(%q) = %q, want %q", tt.meshIP, got, tt.want)
			}
		})
	}
}

// addressRecordingWGController brings an interface "up" as statsWGController
// does and records the address each ConfigureAddress call assigns.
type addressRecordingWGController struct {
	statsWGController

	addrMu    sync.Mutex
	addresses []string
}

func (c *addressRecordingWGController) ConfigureAddress(_, address string) error {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	c.addresses = append(c.addresses, address)
	return nil
}

func (c *addressRecordingWGController) configured() []string {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	return append([]string(nil), c.addresses...)
}

// A move of a macOS bridge gives the site-to-site controller the new mesh
// address as the host prefix every tunnel utun carries, and has the manager
// build its tunnels again, so the next utun carries the new address. A
// controller that cannot change its address gets no follower.
func TestNewVPNReaddresser_Darwin(t *testing.T) {
	moved := netip.MustParseAddr("10.42.0.9")
	key := bytes.Repeat([]byte{0x44}, 32)

	t.Run("the next tunnel utun carries the new address", func(t *testing.T) {
		wg := &addressRecordingWGController{}
		vpn := bridge.NewWGVPNController(wg, tunnelAddress("10.42.0.5"), discardLogger())
		move := newVPNReaddresser(vpn, nil)
		if move == nil {
			t.Fatal("newVPNReaddresser(WGVPNController, nil) = nil, want the site-to-site follower")
		}
		if err := move(context.Background(), moved); err != nil {
			t.Fatalf("move: %v", err)
		}
		if err := vpn.CreateTunnelInterface("s2s-test0", key, 0); err != nil {
			t.Fatalf("CreateTunnelInterface: %v", err)
		}
		if got, want := wg.configured(), []string{"10.42.0.9/32"}; !slices.Equal(got, want) {
			t.Errorf("addresses configured = %v, want %v", got, want)
		}
	})

	t.Run("the manager builds its tunnels again", func(t *testing.T) {
		vpn := bridge.NewWGVPNController(&addressRecordingWGController{}, tunnelAddress("10.42.0.5"), discardLogger())
		s2s := bridge.NewSiteToSiteManager(bridge.SiteToSiteDeps{VPN: vpn, Logger: discardLogger()})
		move := newVPNReaddresser(vpn, s2s)
		if move == nil {
			t.Fatal("newVPNReaddresser(WGVPNController, manager) = nil, want the site-to-site follower")
		}
		if err := move(context.Background(), moved); err != nil {
			t.Fatalf("move: %v", err)
		}
		// Rebuild signals ReportChanged whether or not a tunnel is up.
		select {
		case <-s2s.ReportChanged():
		default:
			t.Error("ReportChanged did not signal, want the move to call Rebuild")
		}
	})

	t.Run("a controller without SetAddress gets no follower", func(t *testing.T) {
		vpn := bridge.NewWGVPNController(&addressRecordingWGController{}, "", discardLogger())
		if move := newVPNReaddresser(struct{ bridge.VPNController }{vpn}, nil); move != nil {
			t.Error("newVPNReaddresser(a controller without SetAddress) != nil, want nil")
		}
		if move := newVPNReaddresser(nil, nil); move != nil {
			t.Error("newVPNReaddresser(nil) != nil, want nil")
		}
	})
}

// macOS serves ssh sessions through the child session helper, so plexd up
// wires a launcher there.
func TestNewSessionLauncher_Darwin(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	launcher := newSessionLauncher(api.NewEd25519Verifier("kid", pub), discardLogger())
	if launcher == nil {
		t.Fatal("newSessionLauncher() = nil, want the child session helper client on macOS")
	}
	if _, ok := launcher.(*tunnel.SessionHelperClient); !ok {
		t.Errorf("newSessionLauncher() = %T, want *tunnel.SessionHelperClient", launcher)
	}
}
