//go:build linux

package wireguard

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// rttBindToInterface returns the socket control that binds the round-trip
// probe's socket to iface with SO_BINDTODEVICE, so the kernel delivers to it
// only what arrives on iface and sends what it writes through iface. Since
// Linux 5.7 a socket that is not yet bound to a device needs no capability
// for it; an older kernel asks for CAP_NET_RAW. The DECISION is at listenRTT.
func rttBindToInterface(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		if bindErr != nil {
			return fmt.Errorf("bind to interface %s: %w", iface, bindErr)
		}
		return nil
	}
}
