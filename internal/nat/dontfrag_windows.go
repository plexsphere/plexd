//go:build windows

package nat

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

// setDontFragment is a net.Dialer Control function that sets the
// don't-fragment bit on every datagram the socket sends.
//
// Windows takes the Linux option and value: IP_PMTUDISC_PROBE sets DF and
// ignores the path MTU cached for the destination, so a round measures the
// path again instead of failing locally against what an earlier round's ICMP
// left behind.
func setDontFragment(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MTU_DISCOVER, windows.IP_PMTUDISC_PROBE)
	})
	if err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("nat: mtu probe: set don't-fragment: %w", sockErr)
	}
	return nil
}
