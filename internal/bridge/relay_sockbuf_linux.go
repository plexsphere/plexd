//go:build linux

package bridge

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// forceRelayBuffers sets both buffers of conn to relaySocketBuffer with
// SO_RCVBUFFORCE and SO_SNDBUFFORCE. SetReadBuffer and SetWriteBuffer stop at
// net.core.rmem_max and wmem_max, a few hundred kilobytes on most hosts, and
// the FORCE options pass those limits for a process with CAP_NET_ADMIN, which
// plexd holds. wireguard-go forces its own sockets the same way. Without the
// capability both calls fail with EPERM and the socket keeps the capped size,
// so the caller ignores the error.
func forceRelayBuffers(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = errors.Join(
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, relaySocketBuffer),
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, relaySocketBuffer),
		)
	}); err != nil {
		return err
	}
	return sockErr
}
