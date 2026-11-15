//go:build !windows

package bridge

import "syscall"

// errConnRefused is the errno a TCP dial fails with when nothing listens on
// the port.
var errConnRefused error = syscall.ECONNREFUSED
