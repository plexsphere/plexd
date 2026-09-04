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

// TestNewControllers_WindowsStubs pins the bridge subsystems Windows does not
// have yet (#12), so the sibling that implements one has to flip its stub
// deliberately.
func TestNewControllers_WindowsStubs(t *testing.T) {
	logger := discardLogger()

	if c := newAccessController(logger); c != nil {
		t.Errorf("newAccessController() = %v, want nil until #12", c)
	}
	if c := newVPNController(logger); c != nil {
		t.Errorf("newVPNController() = %v, want nil until #12", c)
	}
}
