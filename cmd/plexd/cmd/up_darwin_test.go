//go:build darwin

package cmd

import (
	"testing"

	"github.com/plexsphere/plexd/internal/bridge"
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

func TestNewRouteController_Darwin(t *testing.T) {
	logger := discardLogger()

	ctrl := newRouteController(logger)
	if ctrl == nil {
		t.Fatal("newRouteController() = nil, want the route(8) controller on macOS")
	}
	if _, ok := ctrl.(*bridge.DarwinRouteController); !ok {
		t.Errorf("newRouteController() = %T, want *bridge.DarwinRouteController", ctrl)
	}
}

// TestNewControllers_DarwinStubs pins the subsystems macOS does not have yet,
// so the sibling that implements one has to flip its stub deliberately.
func TestNewControllers_DarwinStubs(t *testing.T) {
	logger := discardLogger()

	if r := newSystemReader(); r != nil {
		t.Errorf("newSystemReader() = %v, want nil until #13", r)
	}
	if r := newJournalReader(logger); r != nil {
		t.Errorf("newJournalReader() = %v, want nil until #14", r)
	}
	if c := newFirewallController(logger); c != nil {
		t.Errorf("newFirewallController() = %v, want nil until #11", c)
	}
	if c := newAccessController(logger); c != nil {
		t.Errorf("newAccessController() = %v, want nil until #12", c)
	}
	if c := newVPNController(logger); c != nil {
		t.Errorf("newVPNController() = %v, want nil until #12", c)
	}
}
