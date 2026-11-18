//go:build !windows

package bridge

import "syscall"

// errConnRefused is the errno a TCP dial fails with when nothing listens on
// the port.
var errConnRefused error = syscall.ECONNREFUSED

// errNetUnreachable is the errno a send fails with when no route reaches the
// target's network.
var errNetUnreachable error = syscall.ENETUNREACH
