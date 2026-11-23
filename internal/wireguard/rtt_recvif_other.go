//go:build !darwin

package wireguard

import (
	"log/slog"
	"net"
)

// rttMeshOnly returns conn wrapped so that ReadFrom hands over only the
// datagrams that arrived on iface, and conn itself where the kernel
// already confines the socket.
//
// Outside macOS it returns conn itself and a nil error: Linux confines the
// socket with SO_BINDTODEVICE (ifbind.Control), and Windows receives on the
// strong host model.
func rttMeshOnly(conn net.PacketConn, _ string, _ *slog.Logger) (net.PacketConn, error) {
	return conn, nil
}
