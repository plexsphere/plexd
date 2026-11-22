//go:build windows

package bridge

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// windowsBindErr returns what the wrapped CreateInterface fails with when
// wireguard-go's bind of the listen port fails with errno on Windows: the
// errno inside the *os.SyscallError and *net.OpError the net package builds,
// wrapped once more by the controller. errors.Is has to unwrap all three.
func windowsBindErr(errno syscall.Errno) error {
	bind := &net.OpError{Op: "listen", Net: "udp4", Err: os.NewSyscallError("bind", errno)}
	return fmt.Errorf("wireguard: create interface: up: %w", bind)
}

// TestWGControllers_WindowsTakenPort checks that a listen port another socket
// holds, which Windows reports as WSAEADDRINUSE, fails the create of both
// controllers with an error wrapping ErrListenPortInUse and its cause, so the
// managers report bind_failed. A port inside one of Windows' reserved ranges
// fails with WSAEACCES, which stays a plain failure.
func TestWGControllers_WindowsTakenPort(t *testing.T) {
	controllers := []struct {
		name   string
		prefix string
		create func(wg *fakeWGController) error
	}{
		{"access", "bridge: access: create interface wg-access: ", func(wg *fakeWGController) error {
			return NewWGAccessController(wg, discardLogger()).CreateInterface(testAccessIface, testPrivateKey(t), testAccessPort, testAccessAddress)
		}},
		{"vpn", "bridge: vpn: create interface wg-s2s-0: ", func(wg *fakeWGController) error {
			return NewWGVPNController(wg, testVPNAddress, discardLogger()).CreateTunnelInterface(testVPNIface, testPrivateKey(t), testVPNPort)
		}},
	}
	for _, c := range controllers {
		t.Run(c.name+" WSAEADDRINUSE", func(t *testing.T) {
			wg := &fakeWGController{createInterfaceErr: windowsBindErr(windows.WSAEADDRINUSE)}
			err := c.create(wg)
			wantWGErrPrefix(t, err, c.prefix+"listen port in use:")
			if !errors.Is(err, ErrListenPortInUse) {
				t.Errorf("errors.Is(err, ErrListenPortInUse) = false for %v, want true", err)
			}
			if !errors.Is(err, windows.WSAEADDRINUSE) {
				t.Errorf("errors.Is(err, windows.WSAEADDRINUSE) = false for %v, want the cause kept", err)
			}
		})

		t.Run(c.name+" WSAEACCES", func(t *testing.T) {
			wg := &fakeWGController{createInterfaceErr: windowsBindErr(windows.WSAEACCES)}
			err := c.create(wg)
			wantWGErrPrefix(t, err, c.prefix)
			if errors.Is(err, ErrListenPortInUse) {
				t.Errorf("errors.Is(err, ErrListenPortInUse) = true for %v, want false: a reserved port is no taken port", err)
			}
			if !errors.Is(err, windows.WSAEACCES) {
				t.Errorf("errors.Is(err, windows.WSAEACCES) = false for %v, want the cause kept", err)
			}
		})
	}
}

// TestIsAddrInUse_Windows checks which errors isAddrInUse takes for a taken
// port on Windows.
func TestIsAddrInUse_Windows(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"WSAEADDRINUSE", windowsBindErr(windows.WSAEADDRINUSE), true},
		{"syscall.EADDRINUSE", windowsBindErr(syscall.EADDRINUSE), true},
		{"WSAEACCES", windowsBindErr(windows.WSAEACCES), false},
		{"another error", errors.New("wg failed"), false},
	}
	for _, tt := range tests {
		if got := isAddrInUse(tt.err); got != tt.want {
			t.Errorf("isAddrInUse(%s: %v) = %v, want %v", tt.name, tt.err, got, tt.want)
		}
	}
}
