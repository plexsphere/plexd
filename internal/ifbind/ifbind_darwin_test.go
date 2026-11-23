//go:build darwin

package ifbind

import (
	"net"
	"testing"
)

// boundDevice returns false: reading IP_BOUND_IF or IPV6_BOUND_IF back from
// a socket on lo0 is not measured, so on macOS TestControl_BindsLoopback
// proves only that a listener with the control accepts a local dial.
func boundDevice(*testing.T, net.Listener) (string, bool) {
	return "", false
}

// checkNoDevice checks nothing: on macOS the control fails in
// net.InterfaceByName before it sets an option, so the error carries no
// errno from the kernel.
func checkNoDevice(*testing.T, string, error) {}
