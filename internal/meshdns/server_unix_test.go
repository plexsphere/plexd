//go:build !windows

package meshdns

import "syscall"

// errAddrInUse is the errno a bind fails with when another socket holds the
// address and port.
var errAddrInUse error = syscall.EADDRINUSE

// errConnRefused is the errno a TCP dial fails with when nothing listens on
// the port.
var errConnRefused error = syscall.ECONNREFUSED
