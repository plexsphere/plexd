//go:build linux

package ifbind

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Control returns the net.ListenConfig control that binds a socket to
// iface: SO_BINDTODEVICE on Linux; on macOS IP_BOUND_IF, or IPV6_BOUND_IF
// when network ends in "6". It returns nil for an empty iface, and on
// every other system, so the socket is bound to its address alone.
//
// An unknown iface or a refused option fails the listen with the kernel's
// error wrapped as "bind to interface <iface>: <error>". Since Linux 5.7 a
// socket that is not yet bound to a device needs no capability for
// SO_BINDTODEVICE; an older kernel asks for CAP_NET_RAW.
func Control(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
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
