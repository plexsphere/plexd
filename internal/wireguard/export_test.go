package wireguard

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// NewLoopbackUserspaceBackend returns a backend for the tests of package
// wireguard_test. Each device it creates binds a UDP socket of its own, so
// devices reach each other over loopback, and its UAPI endpoint is a loopback
// TCP listener (see newTestBackend). Every device it holds is deleted on
// cleanup.
func NewLoopbackUserspaceBackend(t *testing.T) *UserspaceBackend {
	t.Helper()
	b := newTestBackend(t, conn.NewDefaultBind())
	// newTestBackend hands every device the one bind it was given, but each
	// device needs its own socket.
	b.newBind = conn.NewDefaultBind
	return b
}
