//go:build unix

package nodeapi

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
)

// PeerCredentials holds the peer credentials extracted from a Unix socket connection.
type PeerCredentials struct {
	PID uint32
	UID uint32
	GID uint32
}

// logAttrs returns the attributes the secrets middleware logs when it denies
// a peer.
func (c *PeerCredentials) logAttrs() []any {
	return []any{"pid", c.PID, "uid", c.UID, "gid", c.GID}
}

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

// SetSocketPermissions sets ownership and permissions on the Unix socket file.
// If the plexd group exists and the daemon may hand the socket to it, the
// socket is chowned to root:plexd with mode 0660. Otherwise the socket is
// narrowed to mode 0600 and a warning is logged.
//
// The fallback narrows rather than widens because opening the socket is
// the whole authorization for every route but the secret ones: the mux serves
// POST /v1/actions/run, POST /v1/hooks/reload and the report writes to any
// peer that connects, and the daemon runs those as root. Only deploy/install.sh
// creates the group, and only on Linux, so the fallback is the default state
// on every other install path.
func SetSocketPermissions(socketPath string, logger *slog.Logger) error {
	grp, err := user.LookupGroup("plexd")
	if err != nil {
		logger.Warn("plexd group not found, restricting the socket to its owner",
			"error", err,
		)
		return os.Chmod(socketPath, 0600)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("nodeapi: auth: parse gid: %w", err)
	}
	return setSocketGroup(socketPath, gid, logger)
}

// setSocketGroup hands the socket to the plexd group, or narrows it to its
// owner when the daemon may not change the socket's group.
//
// Denied is the ordinary case rather than an exotic one: chown(2) lets a caller
// without CAP_CHOWN set a file's group only to a group it belongs to itself,
// the systemd unit `plexd install` writes bounds the daemon to CAP_NET_ADMIN
// and CAP_NET_RAW, and `groupadd --system plexd` creates the group empty.
// Aborting there would take the local API down on every systemd install, so
// this falls back to the owner-only mode a missing group produces.
func setSocketGroup(socketPath string, gid int, logger *slog.Logger) error {
	if err := os.Chown(socketPath, 0, gid); err != nil {
		logger.Warn("cannot hand the socket to the plexd group, restricting it to its owner",
			"error", err,
		)
		return os.Chmod(socketPath, 0600)
	}
	if err := os.Chmod(socketPath, 0660); err != nil {
		return fmt.Errorf("nodeapi: auth: chmod socket: %w", err)
	}
	return nil
}

// unixSecretPolicy is the Linux and macOS policy: root, or a member of the
// plexd-secrets group, may read secrets.
type unixSecretPolicy struct {
	groups GroupChecker
}

func (p unixSecretPolicy) AllowSecrets(cred *PeerCredentials) bool {
	return cred.UID == 0 || p.groups.IsInGroup(cred.UID, cred.GID, "plexd-secrets")
}

// newSecretPolicy returns the secret policy this platform enforces on the
// local API.
func newSecretPolicy() SecretPolicy {
	return unixSecretPolicy{groups: OSGroupChecker{}}
}
