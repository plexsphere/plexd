//go:build windows

package bridge

import "golang.org/x/sys/windows"

// errConnRefused is the errno a TCP dial fails with when nothing listens on
// the port. Winsock reports WSAECONNREFUSED, which Go returns as a plain
// syscall.Errno whose text is not syscall.ECONNREFUSED's.
var errConnRefused error = windows.WSAECONNREFUSED

// errNetUnreachable is the errno a send fails with when no route reaches the
// target's network. Winsock reports WSAENETUNREACH, which Go returns as a
// plain syscall.Errno whose text is not syscall.ENETUNREACH's.
var errNetUnreachable error = windows.WSAENETUNREACH
