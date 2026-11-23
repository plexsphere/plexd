//go:build !darwin

package wireguard

import (
	"net"
	"testing"
)

// TestRTTMeshOnly_OtherSystemsKeepTheSocket shows that rttMeshOnly hands back
// the socket it was given outside macOS: Linux confines the socket with
// SO_BINDTODEVICE, and Windows receives on the strong host model.
func TestRTTMeshOnly_OtherSystemsKeepTheSocket(t *testing.T) {
	conn := listenLoopback(t)
	got, err := rttMeshOnly(conn, "plexd0", discardLogger())
	if got != net.PacketConn(conn) || err != nil {
		t.Errorf("rttMeshOnly(socket on %s, plexd0) = %T %p, %v; want the socket %p and a nil error",
			conn.LocalAddr(), got, got, err, conn)
	}
}
