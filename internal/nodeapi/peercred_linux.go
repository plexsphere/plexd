//go:build linux

package nodeapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// GetPeerCredentials extracts peer credentials from a Unix socket connection
// using the SO_PEERCRED socket option. Returns an error if the connection
// is not a Unix socket or the credentials cannot be retrieved.
func GetPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("nodeapi: auth: not a Unix socket connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("nodeapi: auth: get syscall conn: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return nil, fmt.Errorf("nodeapi: auth: control: %w", err)
	}
	if credErr != nil {
		return nil, fmt.Errorf("nodeapi: auth: getsockopt SO_PEERCRED: %w", credErr)
	}
	return &PeerCredentials{
		PID: uint32(cred.Pid),
		UID: uint32(cred.Uid),
		GID: uint32(cred.Gid),
	}, nil
}
