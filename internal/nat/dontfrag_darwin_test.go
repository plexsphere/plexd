//go:build darwin

package nat

import (
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// dontFragmentOption reads the socket option setDontFragment sets back from
// c, and returns it with the value setDontFragment sets it to.
func dontFragmentOption(c syscall.RawConn) (got, want int, err error) {
	var optErr error
	if err := c.Control(func(fd uintptr) {
		got, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG)
	}); err != nil {
		return 0, 0, fmt.Errorf("control: %w", err)
	}
	if optErr != nil {
		return 0, 0, fmt.Errorf("getsockopt IP_DONTFRAG: %w", optErr)
	}
	return got, 1, nil
}

func TestSetDontFragment(t *testing.T) {
	// Dialing UDP sends nothing; the listener only gives the dial a target.
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer target.Close()

	dialer := net.Dialer{Control: setDontFragment}
	conn, err := dialer.Dial("udp4", target.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial with setDontFragment: %v", err)
	}
	defer conn.Close()

	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	got, want, err := dontFragmentOption(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("IP_DONTFRAG = %d, want %d", got, want)
	}
}
