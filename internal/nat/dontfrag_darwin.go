//go:build darwin

package nat

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setDontFragment is a net.Dialer Control function that sets the
// don't-fragment bit on every datagram the socket sends. macOS has no
// IP_MTU_DISCOVER; IP_DONTFRAG is its switch for DF on a datagram socket.
func setDontFragment(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
	})
	if err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("nat: mtu probe: set don't-fragment: %w", sockErr)
	}
	return nil
}
