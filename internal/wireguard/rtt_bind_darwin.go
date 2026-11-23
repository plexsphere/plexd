//go:build darwin

package wireguard

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// rttBindToInterface returns the socket control that binds the round-trip
// probe's socket to iface with IP_BOUND_IF, so the kernel delivers to it only
// what arrives on iface and sends what it writes through iface. iface is the
// kernel's name of the utun device. The DECISION is at listenRTT.
func rttBindToInterface(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("bind to interface %s: %w", iface, err)
		}
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
		}); err != nil {
			return err
		}
		if bindErr != nil {
			return fmt.Errorf("bind to interface %s: %w", iface, bindErr)
		}
		return nil
	}
}
