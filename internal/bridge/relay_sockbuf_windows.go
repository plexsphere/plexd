//go:build windows

package bridge

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// relayBufferSizes reads the receive and send buffer sizes of conn back from
// Winsock, which may have granted less than was asked.
func relayBufferSizes(conn *net.UDPConn) (receive, send int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var receiveErr, sendErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		receive, receiveErr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
		send, sendErr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
	}); ctlErr != nil {
		return 0, 0, ctlErr
	}
	if err := errors.Join(receiveErr, sendErr); err != nil {
		return 0, 0, err
	}
	return receive, send, nil
}
