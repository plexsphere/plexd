//go:build !windows

package bridge

import (
	"errors"
	"syscall"
)

// isAddrInUse reports whether err says that another socket holds the listen
// port: the bind's EADDRINUSE, wrapped.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
