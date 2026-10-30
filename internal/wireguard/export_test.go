package wireguard

import "testing"

// NewLoopbackUserspaceBackend returns a backend for the tests of package
// wireguard_test. Each device it creates binds a UDP socket of its own, so
// devices reach each other over loopback, and its UAPI endpoint is a loopback
// TCP listener (see newTestBackend). Every device it holds is deleted on
// cleanup.
func NewLoopbackUserspaceBackend(t *testing.T) *UserspaceBackend {
	t.Helper()
	b := newTestBackend(t, newDefaultBind())
	// newTestBackend hands every device the one bind it was given, but each
	// device needs its own socket.
	b.newBind = newDefaultBind
	return b
}
