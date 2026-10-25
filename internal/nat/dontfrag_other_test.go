//go:build !linux && !darwin && !windows

package nat

import (
	"errors"
	"syscall"
)

// dontFragmentOption has no option to read back on the remaining platforms,
// where setDontFragment fails.
func dontFragmentOption(syscall.RawConn) (got, want int, err error) {
	return 0, 0, errors.New("don't-fragment is not supported on this platform")
}
