//go:build windows

package meshdns

import "golang.org/x/sys/windows"

// errAddrInUse is the errno a bind fails with when another socket holds the
// address and port. Winsock reports WSAEADDRINUSE, which Go returns as a
// plain syscall.Errno that does not match syscall.EADDRINUSE.
var errAddrInUse error = windows.WSAEADDRINUSE
