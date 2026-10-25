//go:build linux

package nat

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setDontFragment is a net.Dialer Control function that sets the
// don't-fragment bit on every datagram the socket sends.
//
// IP_PMTUDISC_PROBE sets DF as IP_PMTUDISC_DO does, but ignores the path MTU
// the kernel cached for the destination. Under DO, a size an earlier round
// found too large would fail locally against the value its ICMP left behind,
// which the kernel keeps for 10 minutes, and the round would measure that
// cache instead of the path. A datagram larger than the local link's MTU
// still fails on write with EMSGSIZE, so a node whose own link is the
// bottleneck is measured too.
func setDontFragment(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
	})
	if err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("nat: mtu probe: set don't-fragment: %w", sockErr)
	}
	return nil
}
