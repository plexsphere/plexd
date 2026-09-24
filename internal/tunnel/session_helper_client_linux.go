//go:build linux

package tunnel

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrSessionHelperRefused wraps the reason the session helper gave for not
// starting a process.
var ErrSessionHelperRefused = errors.New("tunnel: session helper refused")

// The size caps of the helper protocol. A request is one JSON line with a
// token of at most 8 KiB and a command of at most 1 KiB; a response is one
// short JSON line.
const (
	maxLaunchRequestBytes  = 16 << 10
	maxLaunchResponseBytes = 4 << 10
)

// SessionHelperClient is the SessionLauncher plexd starts ssh processes
// through. It reaches the root session helper through its socket, or runs the
// helper as its own child where no socket exists.
//
// The protocol is one request and one response per connection. plexd writes
// the LaunchRequest as one JSON line, in a single sendmsg that carries the
// process's file descriptors as SCM_RIGHTS: the pty slave alone with a pty,
// else stdin, stdout and stderr. The helper answers with one JSON line,
// {"exit_status":N} or {"error":"<reason>"}, and closes. plexd shutting down
// its sending side before the answer means "stop the process"; the answer
// follows once the process is gone.
type SessionHelperClient struct {
	socketPath string
	child      func(keys []ed25519.PublicKey) *exec.Cmd
	keys       SigningKeySource
	logger     *slog.Logger
}

var _ SessionLauncher = (*SessionHelperClient)(nil)

// NewSessionHelperClient returns a client that dials socketPath when it is a
// Unix socket, and otherwise starts child(keys) with one end of a socketpair as
// its fd 3.
func NewSessionHelperClient(socketPath string, child func(keys []ed25519.PublicKey) *exec.Cmd, keys SigningKeySource, logger *slog.Logger) *SessionHelperClient {
	return &SessionHelperClient{
		socketPath: socketPath,
		child:      child,
		keys:       keys,
		logger:     logger.With("component", "tunnel"),
	}
}

// fileCount is how many descriptors travel with r: the pty slave alone with a
// pty, else stdin, stdout and stderr.
func (r LaunchRequest) fileCount() int {
	if r.PTY {
		return 1
	}
	return 3
}

// helperResponse is the helper's answer: exactly one member is set.
type helperResponse struct {
	ExitStatus *int   `json:"exit_status,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Launch sends req and files to the session helper and waits for its answer.
// Every file in files is closed before Launch returns, and right after the
// send on the path that reaches it.
func (c *SessionHelperClient) Launch(ctx context.Context, req LaunchRequest, files []*os.File) (int, error) {
	defer closeFiles(files)

	if want := req.fileCount(); len(files) != want {
		return 0, fmt.Errorf("tunnel: session helper: %d files for a request that takes %d", len(files), want)
	}
	line, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("tunnel: session helper: encode request: %w", err)
	}
	line = append(line, '\n')
	if len(line) > maxLaunchRequestBytes {
		return 0, fmt.Errorf("tunnel: session helper: request exceeds %d bytes", maxLaunchRequestBytes)
	}

	conn, waitChild, err := c.connect()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	oob := syscall.UnixRights(fds...)
	n, oobn, err := conn.WriteMsgUnix(line, oob, nil)
	// The helper holds its own copies now, so the process's streams reach EOF
	// once it and its descendants are done with them.
	closeFiles(files)
	if err == nil && (n != len(line) || oobn != len(oob)) {
		err = io.ErrShortWrite
	}
	if err != nil {
		conn.Close()
		waitChild(drainTimeout)
		return 0, fmt.Errorf("tunnel: session helper: send request: %w", err)
	}

	stop := context.AfterFunc(ctx, func() {
		// A half-close is the stop signal: the helper reads EOF and stops the
		// process, and its answer still arrives. Waiting for it keeps the
		// channel's slot taken while the helper runs, so plexd's own limits
		// bound the helpers as well.
		_ = conn.CloseWrite()
		_ = conn.SetReadDeadline(time.Now().Add(sessionHelperKillGrace + drainTimeout))
	})
	defer stop()

	resp, err := bufio.NewReader(io.LimitReader(conn, maxLaunchResponseBytes)).ReadBytes('\n')
	if ctx.Err() != nil {
		// The helper escalates from SIGHUP to SIGKILL after
		// sessionHelperKillGrace; the child is given that long to finish.
		waitChild(sessionHelperKillGrace + drainTimeout)
		// The helper answers once the process is gone; its status (a trap's
		// own, 129 after SIGHUP, 137 after SIGKILL) is what the exit row
		// records.
		var answer helperResponse
		if err == nil && json.Unmarshal(resp, &answer) == nil && answer.ExitStatus != nil {
			return *answer.ExitStatus, nil
		}
		return 0, fmt.Errorf("tunnel: session helper: %w", ctx.Err())
	}
	waitChild(drainTimeout)
	if len(resp) == 0 {
		return 0, fmt.Errorf("tunnel: session helper: no response: %w", err)
	}

	var answer helperResponse
	if err := json.Unmarshal(resp, &answer); err != nil {
		return 0, fmt.Errorf("tunnel: session helper: malformed response: %w", err)
	}
	switch {
	case answer.Error != "":
		return 0, fmt.Errorf("%w: %s", ErrSessionHelperRefused, answer.Error)
	case answer.ExitStatus != nil:
		return *answer.ExitStatus, nil
	default:
		return 0, fmt.Errorf("tunnel: session helper: malformed response: %w", errors.New("neither exit_status nor error"))
	}
}

// connect reaches the helper. waitChild waits at most the given time for a
// child helper to exit, and kills it after that; it does nothing for the
// socket.
//
// DECISION: plexd uses plexd-session-helper.socket whenever that socket exists,
// and a dial it refuses is an error, never a reason to fall back to the child:
// the child runs inside plexd's own sandbox, so falling back would silently
// start shells that cannot switch users. A path whose state cannot be read is
// an error for the same reason. Without the socket (OpenWrt, containers, a host
// installed before the helper units) the child helper runs with plexd's own
// privileges, which is no boundary; it trusts the keys plexd passes it and
// pins nothing.
func (c *SessionHelperClient) connect() (*net.UnixConn, func(time.Duration), error) {
	noChild := func(time.Duration) {}

	info, err := os.Stat(c.socketPath)
	switch {
	case err == nil && info.Mode()&os.ModeSocket != 0:
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.socketPath, Net: "unix"})
		if err != nil {
			return nil, nil, fmt.Errorf("tunnel: session helper: dial %s: %w", c.socketPath, err)
		}
		return conn, noChild, nil
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, nil, fmt.Errorf("tunnel: session helper: stat %s: %w", c.socketPath, err)
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel: session helper: socketpair: %w", err)
	}
	local := os.NewFile(uintptr(pair[0]), "plexd-session-helper")
	remote := os.NewFile(uintptr(pair[1]), "plexd-session-helper-child")

	cmd := c.child(c.keys.TrustedKeys(time.Now()))
	cmd.ExtraFiles = []*os.File{remote}
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	remote.Close()
	if err != nil {
		local.Close()
		return nil, nil, fmt.Errorf("tunnel: session helper: start child: %w", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	waitChild := func(grace time.Duration) {
		select {
		case <-exited:
		case <-time.After(grace):
			c.logger.Warn("session helper child did not exit; killing it", "pid", cmd.Process.Pid)
			_ = cmd.Process.Kill()
			<-exited
		}
	}

	fc, err := net.FileConn(local)
	local.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		<-exited
		return nil, nil, fmt.Errorf("tunnel: session helper: wrap the socketpair: %w", err)
	}
	return fc.(*net.UnixConn), waitChild, nil
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}
