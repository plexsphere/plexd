//go:build darwin

package ifbind

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Control returns the net.ListenConfig control that binds a socket to
// iface: IP_BOUND_IF at IPPROTO_IP, or IPV6_BOUND_IF at IPPROTO_IPV6 when
// network ends in "6". It returns nil for an empty iface, so the socket is
// bound to its address alone. The control looks up the index of iface when
// it runs, not when Control is called. An unknown iface or a refused option
// fails the listen with the error wrapped as
// "bind to interface <iface>: <error>".
//
// On macOS the option confines what the socket sends to iface. It does not
// filter what the socket receives: on a host that forwards, a socket bound
// to iface still receives what arrives for its address on another
// interface, and its answers leave through iface. IPV6_BOUND_IF is the
// counterpart from netinet6/in6.h that Tailscale's netns_darwin.go sets for
// IPv6 sockets. Nothing beyond the unit test measures it here.
func Control(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, _ string, c syscall.RawConn) error {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("bind to interface %s: %w", iface, err)
		}
		level, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if strings.HasSuffix(network, "6") {
			level, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		var bindErr error
		if err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptInt(int(fd), level, opt, ifi.Index)
		}); err != nil {
			return err
		}
		if bindErr != nil {
			return fmt.Errorf("bind to interface %s: %w", iface, bindErr)
		}
		return nil
	}
}
