//go:build unix

package bridge

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// relayBufferSizes reads the receive and send buffer sizes of conn back from
// the kernel, which may have granted less than was asked. Linux reports twice
// the size set, because it counts its own bookkeeping against the buffer, so
// a socket forced to relaySocketBuffer reads 14,680,064 each way there.
func relayBufferSizes(conn *net.UDPConn) (receive, send int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var receiveErr, sendErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		receive, receiveErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		send, sendErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); ctlErr != nil {
		return 0, 0, ctlErr
	}
	if err := errors.Join(receiveErr, sendErr); err != nil {
		return 0, 0, err
	}
	return receive, send, nil
}
