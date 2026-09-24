//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/api"
)

// sshSessionsSupported is true on Linux, the one platform with a session
// helper that can start processes as the login user.
const sshSessionsSupported = true

// DECISION: one listener per ssh session, on an ephemeral port of the mesh
// address, the way a tcp session binds one. The mesh SSHServer
// (tunnel.ssh_listen_addr) is left as it is: it serves direct-tcpip, which the
// session contract refuses, and takes its token from the public-key blob.
//
// DECISION: the listener presents the node's existing host key, whose
// fingerprint the capability manifest already carries. Clients do not pin it
// (contract §d): the session token is what authenticates the pair.
//
// DECISION: the limits below keep one session from exhausting the node. Channels
// are counted while they are open, so a multiplexed connection can run commands
// one after another. A command is capped at the control plane's cap on the
// command column of an activity row. Three password attempts leave a client
// room to retry after a stale token while bounding the token checks one
// connection costs.
const (
	sshMaxConnsPerSession = 4
	sshMaxChannelsPerConn = 10
	sshHandshakeTimeout   = 30 * time.Second
	sshMaxAuthTries       = 3
	maxSSHCommandBytes    = 1024
)

// sshCommandReportTimeout bounds each command row. It matches
// sessionStartedReportTimeout for the same reason: the post covers connect,
// handshake, request and response, and must clear the API client's own connect
// timeout.
const sshCommandReportTimeout = sessionStartedReportTimeout

// launchRequestVersion is the only version of LaunchRequest there is.
const launchRequestVersion = 1

// The permission keys under which the password callback hands the token and
// the allowed-command list to the connection.
const (
	sshExtToken           = "plexd-session-token"
	sshExtAllowedCommands = "plexd-allowed-commands"
)

var errSSHLoginUser = errors.New("tunnel: ssh: login user does not match the session")

// sshSession serves one mediated ssh session: an SSH-2 listener that admits the
// session's user with the session token as password, and starts a shell or one
// command per session channel through the SessionLauncher.
type sshSession struct {
	entry     api.NodeStateSession
	meshIP    string
	expiresAt time.Time
	startTime time.Time
	deps      SSHSessionDeps
	logger    *slog.Logger
	config    *ssh.ServerConfig

	// idleTimeout and onIdle are set by the manager before start.
	idleTimeout time.Duration
	onIdle      func()
	// activityClock holds the last byte on any connection.
	activityClock

	listener net.Listener
	cancel   context.CancelFunc

	mu     sync.Mutex
	closed bool
	// conns holds the raw connections, so Close can end one mid-handshake.
	conns map[net.Conn]struct{}
	// wg tracks every goroutine serving the session. Each Add happens on a
	// goroutine that itself holds a count, so it never races Close's Wait.
	wg sync.WaitGroup
}

var _ managedSession = (*sshSession)(nil)

func newSSHSession(p sshSessionParams) (managedSession, error) {
	s := &sshSession{
		entry:     p.entry,
		meshIP:    p.meshIP,
		expiresAt: p.expiresAt,
		startTime: time.Now(),
		deps:      p.deps,
		logger:    p.logger.With("session_id", p.entry.SessionID),
		conns:     make(map[net.Conn]struct{}),
	}
	s.config = &ssh.ServerConfig{
		ServerVersion:    "SSH-2.0-plexd",
		MaxAuthTries:     sshMaxAuthTries,
		PasswordCallback: s.checkPassword,
	}
	s.config.AddHostKey(p.deps.HostKey)
	return s, nil
}

func (s *sshSession) setIdle(timeout time.Duration, onIdle func()) {
	s.idleTimeout = timeout
	s.onIdle = onIdle
}

func (s *sshSession) expiry() time.Time { return s.expiresAt }

func (s *sshSession) started() time.Time { return s.startTime }

func (s *sshSession) closedInfo() ClosedSessionInfo {
	return ClosedSessionInfo{Kind: api.SessionKindSSH}
}

// Start binds the listener on an ephemeral port of the mesh address and serves
// it on a child of ctx that Close cancels.
func (s *sshSession) Start(ctx context.Context) (string, error) {
	ctx, s.cancel = context.WithCancel(ctx)

	addr := net.JoinHostPort(s.meshIP, "0")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.cancel()
		return "", fmt.Errorf("tunnel: listen on %s: %w", addr, err)
	}
	s.listener = ln
	// The bind is the first activity, as for a tcp session.
	s.stamp()
	context.AfterFunc(ctx, func() { ln.Close() })

	s.logger.Info("ssh session started",
		"listen_addr", ln.Addr().String(),
		"user", s.entry.Target.SSH.User,
	)

	s.wg.Add(1)
	go s.acceptLoop(ctx)

	// The monitor is not tracked in wg: it calls onIdle, which closes the
	// session and waits for wg. It returns once ctx is cancelled.
	if s.idleTimeout > 0 {
		go runIdleMonitor(ctx, s.idleTimeout, s.idleFor, s.onIdle)
	}
	return ln.Addr().String(), nil
}

func (s *sshSession) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return // The listener was closed.
		}
		if !s.register(raw) {
			raw.Close()
			s.logger.Debug("ssh connection refused: session connection limit reached",
				"remote_addr", raw.RemoteAddr().String(),
			)
			continue
		}
		s.wg.Add(1)
		go s.handleConn(ctx, raw)
	}
}

// register records raw as a live connection unless the session is closed or
// at its connection limit.
func (s *sshSession) register(raw net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= sshMaxConnsPerSession {
		return false
	}
	s.conns[raw] = struct{}{}
	return true
}

func (s *sshSession) unregister(raw net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, raw)
}

// sshActivityConn stamps the session's activity on every byte it carries, so a
// session in use never idles out.
type sshActivityConn struct {
	net.Conn
	session *sshSession
}

func (c *sshActivityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.session.stamp()
	}
	return n, err
}

func (c *sshActivityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.session.stamp()
	}
	return n, err
}

func (s *sshSession) handleConn(ctx context.Context, raw net.Conn) {
	defer s.wg.Done()
	defer s.unregister(raw)
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()

	_ = raw.SetDeadline(time.Now().Add(sshHandshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(&sshActivityConn{Conn: raw, session: s}, s.config)
	if err != nil {
		s.logger.Debug("ssh handshake failed", "remote_addr", raw.RemoteAddr().String(), "error", err)
		return
	}
	defer conn.Close()
	_ = raw.SetDeadline(time.Time{})

	// Global requests, tcpip-forward among them, are all refused.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ssh.DiscardRequests(reqs)
	}()

	allowed, ok := conn.Permissions.ExtraData[sshExtAllowedCommands].([]string)
	if !ok {
		s.logger.Warn("ssh connection carries no allowed-command list; closing it")
		return
	}

	var open atomic.Int32
	var channels sync.WaitGroup
	for newCh := range chans {
		// direct-tcpip, x11 and auth-agent@openssh.com all land here.
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.Prohibited, "only session channels are served")
			continue
		}
		if open.Load() >= sshMaxChannelsPerConn {
			_ = newCh.Reject(ssh.ResourceShortage, "too many open session channels")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		open.Add(1)
		channels.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer channels.Done()
			defer open.Add(-1)
			s.serveChannel(ctx, conn, allowed, ch, chReqs)
		}()
	}
	// The connection keeps its slot until its channels' processes are gone, so
	// a client that hangs up cannot start more processes than the limits allow.
	channels.Wait()
}

// checkPassword admits the session's user with a token VerifySessionToken
// accepts, and hands the token and its allowed-command list to the connection.
// Neither the token nor any part of it is logged.
func (s *sshSession) checkPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	refuse := func(err error) (*ssh.Permissions, error) {
		s.logger.Warn("ssh login refused",
			"remote_addr", conn.RemoteAddr().String(),
			"user", conn.User(),
			"error", err,
		)
		return nil, err
	}
	if conn.User() != s.entry.Target.SSH.User {
		return refuse(errSSHLoginUser)
	}
	now := time.Now()
	claims, err := VerifySessionToken(string(password), s.deps.Keys.TrustedKeys(now), s.entry.SessionID, conn.User(), now)
	if err != nil {
		return refuse(err)
	}
	s.logger.Info("ssh login accepted",
		"remote_addr", conn.RemoteAddr().String(),
		"user", conn.User(),
	)
	// DECISION: allowed_commands comes from the verified token's target claim,
	// not from the pull entry, so the list plexd pre-checks is the list the
	// session helper enforces.
	return &ssh.Permissions{
		Extensions: map[string]string{sshExtToken: string(password)},
		ExtraData:  map[any]any{sshExtAllowedCommands: claims.AllowedCommands},
	}, nil
}

// channelState is what the requests of one session channel set up before its
// process starts.
type channelState struct {
	master, slave *os.File
	term          string
	started       bool
}

// serveChannel answers the requests of one session channel. The loop keeps
// running while the process runs, so window-change requests reach the pty.
// When the channel ends, the process is stopped and waited for.
func (s *sshSession) serveChannel(ctx context.Context, conn *ssh.ServerConn, allowed []string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	ctx, cancel := context.WithCancel(ctx)
	var st channelState
	var proc sync.WaitGroup
	defer func() {
		cancel()
		proc.Wait()
		// A process owns the pty and closes it; without one it is closed here.
		if !st.started && st.master != nil {
			st.master.Close()
			st.slave.Close()
		}
		ch.Close()
	}()

	refuse := func(req *ssh.Request, reason string) {
		s.logger.Info("ssh request refused", "request", req.Type, "reason", reason)
		_ = req.Reply(false, nil)
	}
	run := func(req *ssh.Request, mode, command string) {
		st.started = true
		_ = req.Reply(true, nil)
		state := st
		proc.Add(1)
		go func() {
			defer proc.Done()
			s.runProcess(ctx, conn, ch, mode, command, state)
		}()
	}

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term                      string
				Cols, Rows, Width, Height uint32
				Modes                     string
			}
			switch {
			case ssh.Unmarshal(req.Payload, &p) != nil:
				refuse(req, "malformed pty-req")
			case st.started:
				refuse(req, "a process already started")
			case st.master != nil:
				refuse(req, "the channel already has a pty")
			default:
				master, slave, err := ptyOpener()
				if err == nil {
					if err = setWinsize(master, p.Rows, p.Cols); err != nil {
						master.Close()
						slave.Close()
					}
				}
				if err != nil {
					s.logger.Warn("ssh pty allocation failed", "error", err)
					_ = req.Reply(false, nil)
					continue
				}
				// Terminal modes are ignored; the kernel's tty defaults apply.
				st.master, st.slave, st.term = master, slave, p.Term
				_ = req.Reply(true, nil)
			}

		case "window-change":
			var p struct{ Cols, Rows, Width, Height uint32 }
			if st.master == nil || ssh.Unmarshal(req.Payload, &p) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(setWinsize(st.master, p.Rows, p.Cols) == nil, nil)

		case "shell":
			switch {
			case st.started:
				refuse(req, "a process already started")
			case len(allowed) > 0:
				refuse(req, "interactive shell is not allowed for this session")
			default:
				run(req, LaunchModeShell, "")
			}

		case "exec":
			var p struct{ Command string }
			switch {
			case ssh.Unmarshal(req.Payload, &p) != nil:
				refuse(req, "malformed exec")
			case st.started:
				refuse(req, "a process already started")
			case p.Command == "":
				refuse(req, "empty command")
			case len(p.Command) > maxSSHCommandBytes:
				refuse(req, fmt.Sprintf("command exceeds %d bytes", maxSSHCommandBytes))
			case len(allowed) > 0 && !slices.Contains(allowed, p.Command):
				refuse(req, "command is not in this session's allowed-command list")
			default:
				run(req, LaunchModeExec, p.Command)
			}

		default:
			// env, subsystem (sftp), x11-req, auth-agent-req@openssh.com,
			// signal and anything else are not served.
			s.logger.Debug("ssh request not served", "request", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

// runProcess starts the channel's process through the launcher, carries its
// streams, and reports its exit to the client and, for exec, to the control
// plane. It owns the channel's pty and closes the channel when done.
func (s *sshSession) runProcess(ctx context.Context, conn *ssh.ServerConn, ch ssh.Channel, mode, command string, st channelState) {
	if st.master != nil {
		defer st.master.Close()
	}
	exec := mode == LaunchModeExec
	startedAt := time.Now()

	// exec fails closed: a command runs only once the control plane accepted its
	// command_executed row.
	if exec {
		reportCtx, cancel := context.WithTimeout(ctx, sshCommandReportTimeout)
		err := s.deps.Commands.ReportSSHCommandStarted(reportCtx, s.entry.SessionID, command, startedAt)
		cancel()
		if err != nil {
			fmt.Fprintf(ch.Stderr(), "plexd: the control plane did not record this command; it was not run: %v\r\n", err)
			sendExitStatus(ch, 1)
			ch.Close()
			if st.slave != nil {
				st.slave.Close()
			}
			s.logger.Warn("ssh command not recorded by the control plane; refusing to run it",
				"command", command,
				"error", err,
			)
			if api.IsSessionRevokedOrExpired(err) {
				s.logger.Info("ssh session revoked or expired server-side; closing the connection")
				conn.Close()
			}
			return
		}
	}

	status, launchErr := s.launch(ctx, conn, ch, mode, command, st)
	if launchErr != nil {
		fmt.Fprintf(ch.Stderr(), "plexd: %v\r\n", launchErr)
		status = 1
		s.logger.Warn("ssh session launch failed", "mode", mode, "error", launchErr)
	}

	_ = ch.CloseWrite()
	sendExitStatus(ch, status)
	if exec {
		// DECISION: the exit row is detached from the session's cancellation, so
		// a command that ran is recorded even when the session closes under it.
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sshCommandReportTimeout)
		err := s.deps.Commands.ReportSSHCommandExited(reportCtx, s.entry.SessionID, command, status, startedAt, time.Now())
		cancel()
		if err != nil {
			s.logger.Warn("ssh command exit not recorded",
				"command", command,
				"exit_code", status,
				"error", err,
			)
		}
	}
	ch.Close()

	// The status is logged as a number, never as a signal name: the systemd e2e
	// suite treats SIGKILL in plexd's journal as a crash.
	s.logger.Info("ssh process exited", "mode", mode, "exit_status", status)
}

// launch builds the process's standard streams, wires them to the channel, and
// runs the launcher. Once it returns, the output has been carried to the
// channel, or drainTimeout has passed trying.
func (s *sshSession) launch(ctx context.Context, conn *ssh.ServerConn, ch ssh.Channel, mode, command string, st channelState) (int, error) {
	var (
		files   []*os.File
		outputs []*os.File // plexd's ends the output copies read from
		copies  sync.WaitGroup
	)
	copyOut := func(dst io.Writer, src *os.File) {
		outputs = append(outputs, src)
		copies.Add(1)
		go func() {
			defer copies.Done()
			_, _ = io.Copy(dst, src)
		}()
	}

	if st.slave != nil {
		files = []*os.File{st.slave}
		// The input copy ends when the channel does; it is not waited for.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_, _ = io.Copy(st.master, ch)
		}()
		copyOut(ch, st.master)
	} else {
		pipes, err := newStdioPipes()
		if err != nil {
			return 1, err
		}
		files = []*os.File{pipes.stdinR, pipes.stdoutW, pipes.stderrW}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_, _ = io.Copy(pipes.stdinW, ch)
			pipes.stdinW.Close()
		}()
		copyOut(ch, pipes.stdoutR)
		copyOut(ch.Stderr(), pipes.stderrR)
		defer pipes.stdoutR.Close()
		defer pipes.stderrR.Close()
	}

	status, err := s.deps.Launcher.Launch(ctx, LaunchRequest{
		Version:   launchRequestVersion,
		SessionID: s.entry.SessionID,
		User:      conn.User(),
		Token:     conn.Permissions.Extensions[sshExtToken],
		Mode:      mode,
		Command:   command,
		Term:      st.term,
		PTY:       st.slave != nil,
	}, files)
	// The launcher closes files; closing them again is harmless and keeps a
	// launcher that failed before taking them from leaving the copies waiting.
	for _, f := range files {
		f.Close()
	}

	drained := make(chan struct{})
	go func() {
		copies.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(drainTimeout):
		// Something outside the process still holds a write end. Closing plexd's
		// read ends ends the copies.
		for _, f := range outputs {
			f.Close()
		}
		<-drained
	}
	return status, err
}

// stdioPipes are the three pipes of a process without a pty. The child's ends
// are stdinR, stdoutW and stderrW.
type stdioPipes struct {
	stdinR, stdinW   *os.File
	stdoutR, stdoutW *os.File
	stderrR, stderrW *os.File
}

func newStdioPipes() (*stdioPipes, error) {
	var p stdioPipes
	var made []*os.File
	for _, pair := range []struct{ r, w **os.File }{
		{&p.stdinR, &p.stdinW},
		{&p.stdoutR, &p.stdoutW},
		{&p.stderrR, &p.stderrW},
	} {
		r, w, err := os.Pipe()
		if err != nil {
			for _, f := range made {
				f.Close()
			}
			return nil, fmt.Errorf("tunnel: ssh: create pipe: %w", err)
		}
		*pair.r, *pair.w = r, w
		made = append(made, r, w)
	}
	return &p, nil
}

// sendExitStatus sends the RFC 4254 §6.10 exit-status request.
func sendExitStatus(ch ssh.Channel, status int) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
}

// Close ends the session idempotently: it cancels everything the session runs,
// closes the listener and every connection, and waits at most drainTimeout for
// the handlers.
func (s *sshSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	for _, c := range conns {
		c.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		s.logger.Warn("timed out waiting for ssh handlers to drain")
	}
	s.logger.Info("ssh session closed", "duration", time.Since(s.startTime).String())
	return nil
}
