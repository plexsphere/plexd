//go:build windows

package cmd

import (
	"testing"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
	"github.com/plexsphere/plexd/internal/wireguard"
)

func TestNewWGController_Windows(t *testing.T) {
	logger := discardLogger()

	ctrl := newWGController(logger)
	if ctrl == nil {
		t.Fatal("newWGController() = nil, want the Wintun controller on Windows")
	}
	if _, ok := ctrl.(*wireguard.WindowsController); !ok {
		t.Errorf("newWGController() = %T, want *wireguard.WindowsController", ctrl)
	}

	// The Wintun adapter carries the configured name, so the readiness check
	// resolves it directly and no kernel-name indirection is wired up.
	if _, ok := ctrl.(wireguard.OSInterfaceNamer); ok {
		t.Errorf("%T implements wireguard.OSInterfaceNamer, want the configured name used directly", ctrl)
	}
}

func TestNewFirewallController_Windows(t *testing.T) {
	logger := discardLogger()

	ctrl := newFirewallController(logger, "plexd0")
	if ctrl == nil {
		t.Fatal("newFirewallController() = nil, want the WFP controller on Windows")
	}
	if _, ok := ctrl.(*policy.WFPController); !ok {
		t.Errorf("newFirewallController() = %T, want *policy.WFPController", ctrl)
	}

	// The route controller takes this instance as its NAT backend, because the
	// same controller owns the WinNAT instance for the mesh prefix.
	if _, ok := ctrl.(bridge.NATController); !ok {
		t.Errorf("%T does not implement bridge.NATController", ctrl)
	}
}

func TestNewRouteController_Windows(t *testing.T) {
	logger := discardLogger()

	ctrl := newRouteController(logger, newFirewallController(logger, "plexd0"))
	if ctrl == nil {
		t.Fatal("newRouteController() = nil, want the IP Helper controller on Windows")
	}
	if _, ok := ctrl.(*bridge.WindowsRouteController); !ok {
		t.Errorf("newRouteController() = %T, want *bridge.WindowsRouteController", ctrl)
	}
}

// TestNewRouteController_Windows_NilFirewall covers the caller that has no
// firewall controller: the NAT type assertion has to yield a nil backend
// rather than panic, leaving a route controller that only lacks NAT.
func TestNewRouteController_Windows_NilFirewall(t *testing.T) {
	ctrl := newRouteController(discardLogger(), nil)
	if ctrl == nil {
		t.Fatal("newRouteController() = nil, want the IP Helper controller without a NAT backend")
	}
	if _, ok := ctrl.(*bridge.WindowsRouteController); !ok {
		t.Errorf("newRouteController() = %T, want *bridge.WindowsRouteController", ctrl)
	}
}

func TestNewSystemReader_Windows(t *testing.T) {
	reader := newSystemReader(discardLogger())
	if reader == nil {
		t.Fatal("newSystemReader() = nil, want the kernel32 and IP Helper reader on Windows")
	}
	if _, ok := reader.(*metrics.WindowsSystemReader); !ok {
		t.Errorf("newSystemReader() = %T, want *metrics.WindowsSystemReader", reader)
	}
}

func TestNewSystemLogSource_Windows(t *testing.T) {
	src := newSystemLogSource("host", discardLogger())
	if src == nil {
		t.Fatal("newSystemLogSource() = nil, want the Event Log source on Windows")
	}
	if _, ok := src.(*logfwd.EventLogSource); !ok {
		t.Errorf("newSystemLogSource() = %T, want *logfwd.EventLogSource", src)
	}
}

// TestNewMeshRewriter_Windows pins that a Windows bridge that serves user
// access or site-to-site gets the in-process rewriter, and every other
// Windows node none, so it pays no wrapper's copy per packet.
func TestNewMeshRewriter_Windows(t *testing.T) {
	logger := discardLogger()
	if got := newMeshRewriter(true, logger); got == nil {
		t.Error("newMeshRewriter(true) = nil, want the in-process rewriter on a Windows bridge that serves")
	}
	if got := newMeshRewriter(false, logger); got != nil {
		t.Errorf("newMeshRewriter(false) = %p, want nil", got)
	}
}

// TestNewMeshSourceRewriter_Windows pins the in-process rewriter as the mesh
// source rewriter on Windows, which serves user access providers and
// wireguard site-to-site tunnels, and an untyped nil without one, which
// serves neither.
func TestNewMeshSourceRewriter_Windows(t *testing.T) {
	logger := discardLogger()
	fw := newFirewallController(logger, "plexd0")
	routes := newRouteController(logger, fw)
	rewriter := wireguard.NewMeshRewriter(logger)

	if got, ok := newMeshSourceRewriter(routes, fw, rewriter).(*wireguard.MeshRewriter); !ok || got != rewriter {
		t.Errorf("newMeshSourceRewriter(routes, fw, rewriter) = %T %p, want the rewriter %p itself", got, got, rewriter)
	}
	if got := newMeshSourceRewriter(routes, fw, nil); got != nil {
		t.Errorf("newMeshSourceRewriter(routes, fw, nil) = %#v, want an untyped nil", got)
	}
}

// TestNewNATExempter_Windows pins the WFP controller as the exempter of a
// tunnel's adapter from the bridge NAT, and an untyped nil without a
// firewall controller.
func TestNewNATExempter_Windows(t *testing.T) {
	fw := newFirewallController(discardLogger(), "plexd0")

	if got, ok := newNATExempter(fw).(*policy.WFPController); !ok || got != fw {
		t.Errorf("newNATExempter(fw) = %T %p, want the WFP controller %p itself", got, got, fw)
	}
	if got := newNATExempter(nil); got != nil {
		t.Errorf("newNATExempter(nil) = %#v, want an untyped nil", got)
	}
}

// TestNewTunnelProviders_Windows pins that Windows builds no ipsec and no
// openvpn provider, as macOS does: their links are Linux kernel features, so
// such a tunnel reads kind_not_served.
func TestNewTunnelProviders_Windows(t *testing.T) {
	if got := newTunnelProviders(t.TempDir(), discardLogger()); len(got) != 0 {
		t.Errorf("newTunnelProviders() = %v, want no ipsec and no openvpn provider on Windows", got)
	}
}

// TestNewAccessController_Windows pins the Wintun-backed access controller
// with the rewriter of a bridge that serves and without one.
func TestNewAccessController_Windows(t *testing.T) {
	logger := discardLogger()

	for _, tt := range []struct {
		name     string
		rewriter *wireguard.MeshRewriter
	}{
		{name: "with a rewriter", rewriter: wireguard.NewMeshRewriter(logger)},
		{name: "without a rewriter"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := newAccessController(logger, tt.rewriter)
			if ctrl == nil {
				t.Fatal("newAccessController() = nil, want the Wintun-backed access controller on Windows")
			}
			if _, ok := ctrl.(*bridge.WGAccessController); !ok {
				t.Errorf("newAccessController() = %T, want *bridge.WGAccessController", ctrl)
			}
		})
	}
}

func TestNewVPNController_Windows(t *testing.T) {
	logger := discardLogger()

	for _, tt := range []struct {
		name     string
		rewriter *wireguard.MeshRewriter
	}{
		{name: "with a rewriter", rewriter: wireguard.NewMeshRewriter(logger)},
		{name: "without a rewriter"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := newVPNController(logger, "10.42.0.5", tt.rewriter)
			if ctrl == nil {
				t.Fatal("newVPNController() = nil, want the Wintun-backed tunnel controller on Windows")
			}
			if _, ok := ctrl.(*bridge.WGVPNController); !ok {
				t.Errorf("newVPNController() = %T, want *bridge.WGVPNController", ctrl)
			}

			// The site-to-site manager asks for a kernel name through this
			// interface. A Wintun adapter keeps the configured name, so the
			// controller reports no mapping and the manager routes over the
			// configured name.
			if _, ok := ctrl.(wireguard.OSInterfaceNamer); !ok {
				t.Errorf("%T does not implement wireguard.OSInterfaceNamer", ctrl)
			}

			// The mesh IP is unused on Windows: an identity without one
			// yields the same unnumbered adapter.
			if c := newVPNController(logger, "", tt.rewriter); c == nil {
				t.Fatal(`newVPNController(logger, "", rewriter) = nil, want the unnumbered tunnel controller`)
			}
		})
	}
}
