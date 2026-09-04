//go:build darwin

package cmd

import (
	"testing"

	"github.com/plexsphere/plexd/internal/bridge"
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

// TestNewControllers_DarwinStubs pins the subsystems macOS does not have yet,
// so the sibling that implements one has to flip its stub deliberately.
func TestNewControllers_DarwinStubs(t *testing.T) {
	logger := discardLogger()

	if r := newJournalReader(logger); r != nil {
		t.Errorf("newJournalReader() = %v, want nil until #14", r)
	}
	if c := newAccessController(logger); c != nil {
		t.Errorf("newAccessController() = %v, want nil until #12", c)
	}
	if c := newVPNController(logger); c != nil {
		t.Errorf("newVPNController() = %v, want nil until #12", c)
	}
}
