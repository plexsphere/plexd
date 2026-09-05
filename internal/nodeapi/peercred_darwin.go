//go:build darwin

package nodeapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// GetPeerCredentials extracts peer credentials from a Unix socket connection
// using the LOCAL_PEERCRED and LOCAL_PEERPID socket options, which yield the
// same uid, gid and pid Linux gets from SO_PEERCRED. Returns an error if the
// connection is not a Unix socket or the credentials cannot be retrieved.
func GetPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("nodeapi: auth: not a Unix socket connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("nodeapi: auth: get syscall conn: %w", err)
	}
	var (
		xucred  *unix.Xucred
		credErr error
		pid     int
		pidErr  error
	)
	err = raw.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return
		}
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return nil, fmt.Errorf("nodeapi: auth: control: %w", err)
	}
	if credErr != nil {
		return nil, fmt.Errorf("nodeapi: auth: getsockopt LOCAL_PEERCRED: %w", credErr)
	}
	if pidErr != nil {
		return nil, fmt.Errorf("nodeapi: auth: getsockopt LOCAL_PEERPID: %w", pidErr)
	}
	// A misreported credential must never read as group 0.
	if xucred.Ngroups == 0 {
		return nil, fmt.Errorf("nodeapi: auth: LOCAL_PEERCRED returned no groups")
	}
	return &PeerCredentials{
		PID: uint32(pid),
		UID: xucred.Uid,
		// The effective group is first in cr_groups.
		GID: xucred.Groups[0],
	}, nil
}
