//go:build !windows

package meshdns

import "syscall"

// errAddrInUse is the errno a bind fails with when another socket holds the
// address and port.
var errAddrInUse error = syscall.EADDRINUSE
