//go:build !windows

package bridge

import "syscall"

// The errnos a failed TCP dial is classified by. A connect that times out in
// the kernel fails with ETIMEDOUT, which a net.Error reports as a timeout
// already, so dialErrnoTimeout is empty here.
var (
	dialErrnoRefused     = []error{syscall.ECONNREFUSED}
	dialErrnoUnreachable = []error{syscall.EHOSTUNREACH, syscall.ENETUNREACH}
	dialErrnoTimeout     []error
)
