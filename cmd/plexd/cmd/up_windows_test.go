//go:build windows

package cmd

import (
	"testing"

	"github.com/plexsphere/plexd/internal/bridge"
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

func TestNewRouteController_Windows(t *testing.T) {
	logger := discardLogger()

	ctrl := newRouteController(logger)
	if ctrl == nil {
		t.Fatal("newRouteController() = nil, want the IP Helper controller on Windows")
	}
	if _, ok := ctrl.(*bridge.WindowsRouteController); !ok {
		t.Errorf("newRouteController() = %T, want *bridge.WindowsRouteController", ctrl)
	}
}

// TestNewControllers_WindowsStubs pins the subsystems Windows does not have
// yet, so the sibling that implements one has to flip its stub deliberately.
func TestNewControllers_WindowsStubs(t *testing.T) {
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
