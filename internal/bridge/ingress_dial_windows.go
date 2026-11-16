//go:build windows

package bridge

import "golang.org/x/sys/windows"

// The errnos a failed TCP dial is classified by. Winsock reports its own
// errnos, which Go returns as plain syscall.Errno values that match neither
// the syscall names of the other platforms nor, for WSAETIMEDOUT, a net.Error
// timeout.
var (
	dialErrnoRefused     = []error{windows.WSAECONNREFUSED}
	dialErrnoUnreachable = []error{windows.WSAEHOSTUNREACH, windows.WSAENETUNREACH}
	dialErrnoTimeout     = []error{windows.WSAETIMEDOUT}
)
