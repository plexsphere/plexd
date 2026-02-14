//go:build linux

package nodeapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// GroupChecker checks group membership for a given user.
type GroupChecker interface {
	// IsInGroup reports whether the user identified by uid belongs to the
	// named group, or if the user's primary group (gid) matches the group.
	IsInGroup(uid, gid uint32, groupName string) bool
}

// OSGroupChecker checks group membership using the OS user/group database.
type OSGroupChecker struct{}

func (OSGroupChecker) IsInGroup(uid, gid uint32, groupName string) bool {
	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return false
	}
	groupGID, err := strconv.ParseUint(grp.Gid, 10, 32)
	if err != nil {
		return false
	}
	// Check if primary GID matches.
	if gid == uint32(groupGID) {
		return true
	}
	// Check if user is in the group's member list.
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	groupIDs, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, g := range groupIDs {
		if g == grp.Gid {
			return true
		}
	}
	return false
}

// PeerCredentials holds the peer credentials extracted from a Unix socket connection.
type PeerCredentials struct {
	PID uint32
	UID uint32
	GID uint32
}

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

// PeerCredGetter extracts peer credentials from an HTTP request's
// underlying connection.
type PeerCredGetter interface {
	GetPeerCredentials(r *http.Request) (*PeerCredentials, error)
}

// SetSocketPermissions sets ownership and permissions on the Unix socket file.
// If the plexd group exists, the socket is chowned to root:plexd with mode 0660.
// If the group does not exist, the socket gets mode 0666 and a warning is logged.
func SetSocketPermissions(socketPath string, logger *slog.Logger) error {
	grp, err := user.LookupGroup("plexd")
	if err != nil {
		logger.Warn("plexd group not found, using permissive socket permissions",
			"error", err,
		)
		return os.Chmod(socketPath, 0666)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("nodeapi: auth: parse gid: %w", err)
	}
	if err := os.Chown(socketPath, 0, gid); err != nil {
		return fmt.Errorf("nodeapi: auth: chown socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0660); err != nil {
		return fmt.Errorf("nodeapi: auth: chmod socket: %w", err)
	}
	return nil
}

// SecretAuthMiddleware returns HTTP middleware that restricts access to secret
// endpoints. Access is granted to root (UID 0) or processes whose user is a
// member of the plexd-secrets group.
//
// The middleware extracts peer credentials from the request's underlying
// connection using a PeerCredGetter. In production, this is backed by
// SO_PEERCRED; in tests, a mock can be injected.
func SecretAuthMiddleware(checker GroupChecker, getter PeerCredGetter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cred, err := getter.GetPeerCredentials(r)
			if err != nil {
				logger.Error("failed to get peer credentials", "error", err)
				writeSecretAuthError(w)
				return
			}
			// Root always has access.
			if cred.UID == 0 {
				next.ServeHTTP(w, r)
				return
			}
			// Check plexd-secrets group membership.
			if checker.IsInGroup(cred.UID, cred.GID, "plexd-secrets") {
				next.ServeHTTP(w, r)
				return
			}
			logger.Warn("secret access denied",
				"uid", cred.UID,
				"gid", cred.GID,
				"path", r.URL.Path,
			)
			writeSecretAuthError(w)
		})
	}
}

func writeSecretAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: insufficient privileges for secret access"})
}
