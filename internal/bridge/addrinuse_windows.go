//go:build windows

package bridge

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// isAddrInUse reports whether err says that another socket holds the listen
// port. Windows reports a held UDP port as WSAEADDRINUSE, which Go does not
// equate with syscall.EADDRINUSE, so both are asked for. A port inside one of
// Windows' reserved ranges fails with WSAEACCES instead, which is no taken
// port.
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, syscall.EADDRINUSE)
}
