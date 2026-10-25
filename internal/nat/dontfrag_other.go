//go:build !linux && !darwin && !windows

package nat

import (
	"errors"
	"syscall"
)

// setDontFragment fails on the remaining platforms, so every probe socket's
// dial fails and ProbePathMTU reports the round inconclusive rather than
// measuring with packets a router could fragment. plexd has no WireGuard
// controller there (cmd/plexd/cmd/up_other.go), so no mesh MTU depends on it.
func setDontFragment(network, address string, c syscall.RawConn) error {
	return errors.New("nat: mtu probe: don't-fragment is not supported on this platform")
}
