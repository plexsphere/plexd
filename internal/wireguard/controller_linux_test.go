//go:build linux

package wireguard

import (
	"log/slog"
	"testing"
)

type nopWriterLinux struct{}

func (nopWriterLinux) Write(p []byte) (int, error) { return len(p), nil }

func discardLoggerLinux() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriterLinux{}, nil))
}

// Compile-time check that NetlinkController implements WGController.
var _ WGController = (*NetlinkController)(nil)

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
