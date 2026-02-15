//go:build linux

package bridge

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func discardLoggerRoute() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Compile-time check that NetlinkRouteController implements RouteController.
var _ RouteController = (*NetlinkRouteController)(nil)

func TestNewNetlinkRouteController(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())
	if ctrl == nil {
		t.Fatal("NewNetlinkRouteController returned nil")
	}
	if ctrl.logger == nil {
		t.Fatal("logger field is nil")
	}
}

func TestAddRouteInvalidCIDR(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.AddRoute("not-a-cidr", "lo")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}

	expected := "bridge: add route: parse CIDR"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveRouteInvalidCIDR(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.RemoveRoute("not-a-cidr", "lo")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}

	expected := "bridge: remove route: parse CIDR"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestAddRouteNonExistentInterface(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.AddRoute("10.99.0.0/24", "plexd-nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "bridge: add route: lookup interface"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveRouteNonExistentInterface(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.RemoveRoute("10.99.0.0/24", "plexd-nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "bridge: remove route: lookup interface"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestEnableForwardingRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.EnableForwarding("lo", "lo")
	if err == nil {
		// Succeeded — running as root. Restore.
		_ = ctrl.DisableForwarding("lo", "lo")
		return
	}

	expected := "bridge: enable forwarding:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestDisableForwardingRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.DisableForwarding("lo", "lo")
	if err == nil {
		return
	}

	expected := "bridge: disable forwarding:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestAddNATMasqueradeRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.AddNATMasquerade("lo")
	if err == nil {
		// Succeeded — running as root. Clean up.
		_ = ctrl.RemoveNATMasquerade("lo")
		return
	}

	expected := "bridge: add NAT masquerade"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveNATMasqueradeRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	err := ctrl.RemoveNATMasquerade("lo")
	if err == nil {
		return
	}

	expected := "bridge: remove NAT masquerade"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestIfaceNameBytes(t *testing.T) {
	tests := []struct {
		name string
		want int // expected length including null terminator
	}{
		{"lo", 3},
		{"eth0", 5},
		{"plexd0", 7},
	}

	for _, tt := range tests {
		got := ifaceNameBytes(tt.name)
		if len(got) != tt.want {
			t.Errorf("ifaceNameBytes(%q) length = %d, want %d", tt.name, len(got), tt.want)
		}
		// Verify null terminator.
		if got[len(got)-1] != 0 {
			t.Errorf("ifaceNameBytes(%q) missing null terminator", tt.name)
		}
		// Verify the name content matches.
		if string(got[:len(got)-1]) != tt.name {
			t.Errorf("ifaceNameBytes(%q) content = %q, want %q", tt.name, got[:len(got)-1], tt.name)
		}
	}
}

func TestValidateIfaceName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"wg0", false},
		{"eth0", false},
		{"plexd-mesh", false},
		{"../etc/passwd", true},
		{"/dev/null", true},
		{"wg0\x00", true},
		{"", true},
		{"lo", false},
	}

	for _, tt := range tests {
		err := validateIfaceName(tt.name)
		if tt.wantErr && err == nil {
			t.Errorf("validateIfaceName(%q) expected error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("validateIfaceName(%q) unexpected error: %v", tt.name, err)
		}
	}
}


func TestAddRouteRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	// Adding a route via the loopback — requires CAP_NET_ADMIN.
	err := ctrl.AddRoute("10.99.0.0/24", "lo")
	if err == nil {
		// Succeeded — running as root. Clean up.
		_ = ctrl.RemoveRoute("10.99.0.0/24", "lo")
		return
	}

	expected := "bridge: add route"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestRemoveRouteNonExistentRouteIdempotent(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	// Removing a non-existent route via loopback.
	err := ctrl.RemoveRoute("10.99.99.0/24", "lo")
	if err == nil {
		// Idempotent success on root.
		return
	}

	// On non-root, we may get permission errors for the interface lookup
	// or ESRCH for the route — both are acceptable.
	expected := "bridge: remove route"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestAddAndRemoveRouteRoundTrip(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	subnet := "10.88.0.0/24"

	if err := ctrl.AddRoute(subnet, "lo"); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}

	// Adding again should be idempotent.
	if err := ctrl.AddRoute(subnet, "lo"); err != nil {
		t.Fatalf("second AddRoute failed: %v", err)
	}

	if err := ctrl.RemoveRoute(subnet, "lo"); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	// Removing again should be idempotent.
	if err := ctrl.RemoveRoute(subnet, "lo"); err != nil {
		t.Fatalf("second RemoveRoute failed: %v", err)
	}
}

func TestAddAndRemoveNATMasqueradeRoundTrip(t *testing.T) {
	ctrl := NewNetlinkRouteController(discardLoggerRoute())

	if err := ctrl.AddNATMasquerade("lo"); err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}

	// Adding again should be idempotent (table/chain/rules are re-applied).
	if err := ctrl.AddNATMasquerade("lo"); err != nil {
		t.Fatalf("second AddNATMasquerade failed: %v", err)
	}

	if err := ctrl.RemoveNATMasquerade("lo"); err != nil {
		t.Fatalf("RemoveNATMasquerade failed: %v", err)
	}

	// Removing again should be idempotent.
	if err := ctrl.RemoveNATMasquerade("lo"); err != nil {
		t.Fatalf("second RemoveNATMasquerade failed: %v", err)
	}
}
