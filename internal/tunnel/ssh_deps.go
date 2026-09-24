package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/api"
)

// ErrSSHSessionsDisabled is returned by CreateSession for an ssh entry when the
// node refuses ssh sessions (tunnel.ssh_sessions_enabled: false). Like
// ErrTunnelingDisabled it holds for the life of the process, so the dispatcher
// settles the entry instead of retrying it.
var ErrSSHSessionsDisabled = errors.New("tunnel: ssh sessions are disabled on this node")

// ErrSSHSessionsUnsupported is returned by CreateSession for an ssh entry on a
// platform without an ssh session listener.
var ErrSSHSessionsUnsupported = errors.New("tunnel: ssh sessions are not supported on this platform")

// DefaultSessionHelperSocket is where plexd-session-helper.socket listens.
// plexd starts ssh processes through it whenever it exists.
const DefaultSessionHelperSocket = "/run/plexd-session-helper.sock"

// SSHCommandReporter posts the command rows of an ssh session: one when an
// exec request is about to run, and one when it exited. Both return the post's
// error: a command runs only once its started row was accepted.
type SSHCommandReporter interface {
	ReportSSHCommandStarted(ctx context.Context, sessionID, command string, startedAt time.Time) error
	ReportSSHCommandExited(ctx context.Context, sessionID, command string, exitCode int, startedAt, completedAt time.Time) error
}

// SessionLauncher starts one shell or command of an ssh session and waits for
// it. files are the process's standard streams: the pty slave alone when
// req.PTY is set, else stdin, stdout and stderr. Launch closes every file in
// files once it has handed them on, on every path, so the caller's ends of the
// pty and the pipes reach EOF when the process is done. Cancelling ctx stops the
// process.
type SessionLauncher interface {
	Launch(ctx context.Context, req LaunchRequest, files []*os.File) (exitStatus int, err error)
}

// SSHSessionDeps is what the SessionManager needs to serve ssh sessions: the
// host key the listener presents, the keys session tokens verify against, the
// reporter for command rows, and the launcher that starts processes. ssh
// entries are not provisioned until every member is set.
type SSHSessionDeps struct {
	HostKey  ssh.Signer
	Keys     SigningKeySource
	Commands SSHCommandReporter
	Launcher SessionLauncher
}

// complete reports whether every member is set.
func (d SSHSessionDeps) complete() bool {
	return d.HostKey != nil && d.Keys != nil && d.Commands != nil && d.Launcher != nil
}

// The modes of a LaunchRequest.
const (
	// LaunchModeShell starts the user's login shell.
	LaunchModeShell = "shell"
	// LaunchModeExec runs one command through the user's shell.
	LaunchModeExec = "exec"
)

// LaunchRequest is what plexd asks the session helper to start. It travels as
// one JSON line, with the process's file descriptors as SCM_RIGHTS ancillary
// data. Token is the session token the client logged in with; the helper
// verifies it again and takes the allowed commands from it, so a request plexd
// made up is refused.
type LaunchRequest struct {
	Version   int    `json:"v"`
	SessionID string `json:"session_id"`
	User      string `json:"user"`
	Token     string `json:"token"`
	Mode      string `json:"mode"`
	Command   string `json:"command,omitempty"`
	Term      string `json:"term,omitempty"`
	PTY       bool   `json:"pty"`
}

// sshSessionParams carries what newSSHSession builds an ssh session from.
type sshSessionParams struct {
	entry     api.NodeStateSession
	meshIP    string
	expiresAt time.Time
	deps      SSHSessionDeps
	logger    *slog.Logger
}
