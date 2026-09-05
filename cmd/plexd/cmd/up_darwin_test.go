//go:build darwin

package cmd

import (
	"testing"

	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/logfwd"
	"github.com/plexsphere/plexd/internal/metrics"
	"github.com/plexsphere/plexd/internal/policy"
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
	ctrl := newAccessController(discardLogger())
	if ctrl == nil {
		t.Fatal("newAccessController() = nil, want the utun-backed access controller on macOS")
	}
	if _, ok := ctrl.(*bridge.WGAccessController); !ok {
		t.Errorf("newAccessController() = %T, want *bridge.WGAccessController", ctrl)
	}
}

func TestNewVPNController_Darwin(t *testing.T) {
	logger := discardLogger()

	ctrl := newVPNController(logger, "10.42.0.5")
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
	if c := newVPNController(logger, ""); c == nil {
		t.Fatal(`newVPNController(logger, "") = nil, want a controller that leaves the utun unnumbered`)
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
