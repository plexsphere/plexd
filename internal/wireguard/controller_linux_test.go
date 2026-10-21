//go:build linux

package wireguard

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

type nopWriterLinux struct{}

func (nopWriterLinux) Write(p []byte) (int, error) { return len(p), nil }

func discardLoggerLinux() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriterLinux{}, nil))
}

// Compile-time checks that NetlinkController implements WGController and that
// the handshake report and tunnel metrics can read peer state from it.
var (
	_ WGController    = (*NetlinkController)(nil)
	_ PeerStatsReader = (*NetlinkController)(nil)
)

func TestNewNetlinkController(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())
	if ctrl == nil {
		t.Fatal("NewNetlinkController returned nil")
	}
	if ctrl.logger == nil {
		t.Fatal("logger field is nil")
	}
}

func TestDeleteInterfaceNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	// Deleting a non-existent interface should be idempotent and return nil.
	// This may require root/CAP_NET_ADMIN; skip if we get a permission error.
	err := ctrl.DeleteInterface("wg-nonexistent-test")
	if err != nil {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
}

func TestPeerStatsNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	// Reading a device needs CAP_NET_ADMIN once the kernel's WireGuard family
	// is registered: unprivileged, netlink answers EPERM, which says nothing
	// about this method. A privileged read validates the name first and
	// refuses one longer than IFNAMSIZ-1 (15 bytes) with EINVAL before any
	// lookup, so this name proves only the error prefix. Without the family
	// wgctrl falls back to its userspace lookup, which finds no socket and
	// reports ErrNotExist.
	_, err := ctrl.PeerStats("wg-nonexistent-test")
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: peer stats:"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}

	// The missing-device mapping is checked on a name the kernel accepts.
	_, err = ctrl.PeerStats("wg-nonexist0")
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("skipping: requires elevated privileges: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want it to wrap os.ErrNotExist", err)
	}
}

func TestCreateInterfaceRequiresPrivileges(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	// Creating an interface without root should fail; verify the error is wrapped.
	err := ctrl.CreateInterface("wg-test-priv", make([]byte, 32), 51820)
	if err == nil {
		// Cleanup if we somehow succeeded (running as root in CI).
		_ = ctrl.DeleteInterface("wg-test-priv")
		return
	}

	// Verify error wrapping format.
	expected := "wireguard: create interface:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestSetInterfaceUpNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.SetInterfaceUp("wg-nonexistent-test")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: set interface up:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestConfigureAddressNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.ConfigureAddress("wg-nonexistent-test", "10.0.0.1/32")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: configure address:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestSetMTUNonExistent(t *testing.T) {
	ctrl := NewNetlinkController(discardLoggerLinux())

	err := ctrl.SetMTU("wg-nonexistent-test", 1420)
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}

	expected := "wireguard: set mtu:"
	if len(err.Error()) < len(expected) || err.Error()[:len(expected)] != expected {
		t.Errorf("expected error prefix %q, got %q", expected, err.Error())
	}
}

func TestNetlinkPeerConfig_Keepalive(t *testing.T) {
	key := make([]byte, 32)
	for _, tt := range []struct {
		keepalive int
		want      time.Duration
	}{
		{0, 0},
		{25, 25 * time.Second},
	} {
		cfg, err := netlinkPeerConfig(PeerConfig{PublicKey: key, PersistentKeepalive: tt.keepalive})
		if err != nil {
			t.Fatalf("netlinkPeerConfig(%d): %v", tt.keepalive, err)
		}
		// A nil interval would leave the device's keepalive as it is, so a 0 must
		// arrive as a pointer to clear one an earlier run programmed.
		if cfg.PersistentKeepaliveInterval == nil {
			t.Fatalf("PersistentKeepaliveInterval = nil for %d, want a pointer to %v", tt.keepalive, tt.want)
		}
		if got := *cfg.PersistentKeepaliveInterval; got != tt.want {
			t.Errorf("PersistentKeepaliveInterval = %v for %d, want %v", got, tt.keepalive, tt.want)
		}
	}
}

func TestNetlinkPeerConfig_ParseErrors(t *testing.T) {
	key := make([]byte, 32)
	tests := []struct {
		name string
		cfg  PeerConfig
		want string
	}{
		{"bad public key", PeerConfig{PublicKey: []byte{1, 2, 3}}, "wireguard: add peer: parse public key:"},
		{"bad endpoint", PeerConfig{PublicKey: key, Endpoint: "not-an-endpoint"}, "wireguard: add peer: resolve endpoint:"},
		{"bad allowed IP", PeerConfig{PublicKey: key, AllowedIPs: []string{"10.0.0.2"}}, `wireguard: add peer: parse allowed IP "10.0.0.2":`},
		{"bad psk", PeerConfig{PublicKey: key, PSK: []byte{1, 2, 3}}, "wireguard: add peer: parse psk:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := netlinkPeerConfig(tt.cfg)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("netlinkPeerConfig() error = %v, want prefix %q", err, tt.want)
			}
		})
	}
}
