//go:build linux || darwin

package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/plexsphere/plexd/internal/api"
)

// syncBuffer is a log sink the session's goroutines may write concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// sessionToken mints a valid token for sessionID and user, with the given
// allowed-command list when it is non-nil.
func sessionToken(t testing.TB, priv ed25519.PrivateKey, sessionID, user string, allowed []string) string {
	t.Helper()
	claims := validSSHClaims(sessionID, user, time.Now())
	if allowed != nil {
		claims["target"] = map[string]any{"kind": "ssh", "user": user, "allowed_commands": allowed}
	}
	return mintSessionToken(t, priv, sessionTokenHeaderFields(), claims)
}

// commands returns the ssh command rows recorded so far.
func (r *mockReporter) commands() []commandCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]commandCall(nil), r.commandCalls...)
}

// launches returns the launch requests recorded so far.
func (l *fakeLauncher) launches() []launchCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]launchCall(nil), l.calls...)
}

// sshHarness is one provisioned ssh session on a manager with a fake launcher
// and a recording reporter.
type sshHarness struct {
	mgr      *SessionManager
	reporter *mockReporter
	launcher *fakeLauncher
	logs     *syncBuffer
	priv     ed25519.PrivateKey
	entry    api.NodeStateSession
	// conns numbers the connections dial opens, for their connection ids.
	conns atomic.Int32
}

const sshTestUser = "ops"

func startSSHHarness(t *testing.T, launcher *fakeLauncher, setup func(*api.NodeStateSession)) *sshHarness {
	t.Helper()
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr := NewSessionManager(Config{}, "127.0.0.1", logger)
	t.Cleanup(func() { mgr.Shutdown() })

	reporter := &mockReporter{}
	deps, priv := newSSHTestDeps(t, reporter, launcher)
	mgr.SetSSHSessionDeps(deps)

	entry := sshEntry("sess-ssh", sshTestUser, time.Now().Add(5*time.Minute))
	if setup != nil {
		setup(&entry)
	}
	if _, err := mgr.CreateSession(context.Background(), entry); err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	return &sshHarness{mgr: mgr, reporter: reporter, launcher: launcher, logs: logs, priv: priv, entry: entry}
}

// token mints a valid token for the harness's session and user.
func (h *sshHarness) token(t *testing.T, allowed []string) string {
	t.Helper()
	return sessionToken(t, h.priv, h.entry.SessionID, sshTestUser, allowed)
}

// dial asks the session for a connection the way a session_connect event
// does, with a loopback TCP pair standing in for the WebSocket to the control
// plane, and logs in over the client's end.
func (h *sshHarness) dial(user, password string) (*ssh.Client, error) {
	var client net.Conn
	connectionID := fmt.Sprintf("conn-%d", h.conns.Add(1))
	err := h.mgr.ConnectSSHSession(h.entry.SessionID, connectionID, func(context.Context) (net.Conn, error) {
		server, c, err := connPair()
		client = c
		return server, err
	})
	if err != nil {
		return nil, err
	}
	return sshClientOver(client, user, password)
}

// connPair returns the two ends of a loopback TCP connection. net.Pipe does
// not stand in for one here: it buffers nothing, and both ends of an SSH
// handshake write their version line before either reads.
func connPair() (server, client net.Conn, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	server, err = ln.Accept()
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return server, client, nil
}

// sshClientOver logs in as user with password over conn, which it closes when
// the handshake fails.
func sshClientOver(conn net.Conn, user, password string) (*ssh.Client, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, "plexd", &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// login dials as the session's user with a fresh token and closes the client
// on cleanup.
func (h *sshHarness) login(t *testing.T, allowed []string) *ssh.Client {
	t.Helper()
	client, err := h.dial(sshTestUser, h.token(t, allowed))
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func newSSHChannel(t *testing.T, client *ssh.Client) *ssh.Session {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func exitStatus(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %v, want an exit status", err)
	}
	return exitErr.ExitStatus()
}

func TestSSHSession_AcceptsTokenLogin(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)
	token := h.token(t, nil)

	client, err := h.dial(sshTestUser, token)
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
	defer client.Close()

	if got := string(client.ServerVersion()); got != "SSH-2.0-plexd" {
		t.Errorf("server version = %q, want SSH-2.0-plexd", got)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "ssh login accepted") {
		t.Errorf("logs lack the accepted login:\n%s", logs)
	}
	// The connection's peer is always the control plane, so the line names the
	// connection the session_connect event asked for instead.
	if !strings.Contains(logs, "connection_id=conn-1") || strings.Contains(logs, "remote_addr") {
		t.Errorf("logs do not name the connection by its connection_id:\n%s", logs)
	}
	if strings.Contains(logs, token) {
		t.Error("the logs carry the session token")
	}
}

func TestSSHSession_RefusesBadLogins(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)
	now := time.Now()

	expiredClaims := validSSHClaims(h.entry.SessionID, sshTestUser, now)
	expiredClaims["nbf"] = now.Add(-time.Hour).Unix()
	expiredClaims["exp"] = now.Add(-time.Minute).Unix()

	for _, tc := range []struct {
		name, user, password string
	}{
		{"another user", "root", h.token(t, nil)},
		{"empty password", sshTestUser, ""},
		{"token for another session", sshTestUser, sessionToken(t, h.priv, "sess-other", sshTestUser, nil)},
		{"expired token", sshTestUser, mintSessionToken(t, h.priv, sessionTokenHeaderFields(), expiredClaims)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := h.dial(tc.user, tc.password)
			if err == nil {
				client.Close()
				t.Fatal("the handshake succeeded, want it refused")
			}
			if tc.password == "" {
				return
			}
			if strings.Contains(h.logs.String(), tc.password) {
				t.Error("the logs carry the refused token")
			}
		})
	}
	if n := strings.Count(h.logs.String(), `msg="ssh login refused"`); n < 4 {
		t.Errorf("logged %d refused logins, want at least 4", n)
	}
}

func TestSSHSession_RefusesForwarding(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)
	client := h.login(t, nil)

	_, err := client.Dial("tcp", "127.0.0.1:22")
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.Prohibited {
		t.Errorf("direct-tcpip error = %v, want an OpenChannelError with Prohibited", err)
	}

	ok, _, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"127.0.0.1", 0}))
	if err != nil {
		t.Fatalf("tcpip-forward: %v", err)
	}
	if ok {
		t.Error("tcpip-forward was granted, want refused")
	}
}

func TestSSHSession_RefusesUnservedRequests(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	client := h.login(t, nil)

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"subsystem", ssh.Marshal(struct{ Name string }{"sftp"})},
		{"env", ssh.Marshal(struct{ Name, Value string }{"LANG", "C"})},
		{"x11-req", ssh.Marshal(struct {
			Single           bool
			Protocol, Cookie string
			Screen           uint32
		}{false, "MIT-MAGIC-COOKIE-1", "00", 0})},
		{"auth-agent-req@openssh.com", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := newSSHChannel(t, client)
			ok, err := session.SendRequest(tc.name, true, tc.payload)
			if err != nil {
				t.Fatalf("SendRequest() error: %v", err)
			}
			if ok {
				t.Errorf("%s was granted, want refused", tc.name)
			}
		})
	}
	if n := len(launcher.launches()); n != 0 {
		t.Errorf("launcher called %d times, want 0", n)
	}
}

func TestSSHSession_AllowedCommands(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	client := h.login(t, []string{"uptime"})

	if err := newSSHChannel(t, client).Shell(); err == nil {
		t.Error("shell was started under an allowed-command list, want refused")
	}
	if err := newSSHChannel(t, client).Run("uptime"); err != nil {
		t.Errorf("exec uptime: %v", err)
	}
	err := newSSHChannel(t, client).Run("uptime ")
	var exitErr *ssh.ExitError
	if err == nil || errors.As(err, &exitErr) {
		t.Errorf("exec %q: error = %v, want the request refused", "uptime ", err)
	}

	launches := launcher.launches()
	if len(launches) != 1 {
		t.Fatalf("launcher called %d times, want 1", len(launches))
	}
	if got := launches[0].req; got.Mode != LaunchModeExec || got.Command != "uptime" || got.PTY || launches[0].files != 3 {
		t.Errorf("launch = %+v with %d files, want exec uptime without a pty and 3 files", got, launches[0].files)
	}
	if got := launches[0].req; got.Version != 1 || got.SessionID != h.entry.SessionID || got.User != sshTestUser || got.Token == "" {
		t.Errorf("launch request = %+v, want version 1, the session, its user and the token", got)
	}
}

// Without an allowed-command list, the listener's own checks refuse an empty or
// oversized command before a command row is posted.
func TestSSHSession_RefusesEmptyAndOversizedCommands(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	client := h.login(t, nil)

	for _, cmd := range []string{"", strings.Repeat("x", maxSSHCommandBytes+1)} {
		err := newSSHChannel(t, client).Run(cmd)
		var exitErr *ssh.ExitError
		if err == nil || errors.As(err, &exitErr) {
			t.Errorf("exec %.20q: error = %v, want the request refused", cmd, err)
		}
	}
	if rows := h.reporter.commands(); len(rows) != 0 {
		t.Errorf("command rows = %+v, want none", rows)
	}
	if n := len(launcher.launches()); n != 0 {
		t.Errorf("launcher called %d times, want 0", n)
	}
}

func TestSSHSession_PTYShell(t *testing.T) {
	winsize := make(chan string, 1)
	launcher := &fakeLauncher{run: func(ctx context.Context, _ LaunchRequest, files []*os.File) (int, error) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			ws, err := unix.IoctlGetWinsize(int(files[0].Fd()), unix.TIOCGWINSZ)
			if err == nil && ws.Row == 40 && ws.Col == 100 {
				winsize <- fmt.Sprintf("Row %d, Col %d", ws.Row, ws.Col)
				return 0, nil
			}
			time.Sleep(10 * time.Millisecond)
		}
		return 1, errors.New("the window-change never reached the pty")
	}}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	if err := session.WindowChange(40, 100); err != nil {
		t.Fatalf("WindowChange() error: %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
	select {
	case got := <-winsize:
		if got != "Row 40, Col 100" {
			t.Errorf("winsize = %s, want Row 40, Col 100", got)
		}
	default:
		t.Fatal("the launcher never saw the window-change")
	}

	launches := launcher.launches()
	if len(launches) != 1 {
		t.Fatalf("launcher called %d times, want 1", len(launches))
	}
	got := launches[0]
	if !got.req.PTY || got.req.Term != "xterm-256color" || got.req.Mode != LaunchModeShell || got.files != 1 {
		t.Errorf("launch = %+v with %d files, want a pty shell for xterm-256color and 1 file", got.req, got.files)
	}
}

func TestSSHSession_PTYExec(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	if err := session.Run("uptime"); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	launches := launcher.launches()
	if len(launches) != 1 {
		t.Fatalf("launcher called %d times, want 1", len(launches))
	}
	if got := launches[0]; !got.req.PTY || got.req.Mode != LaunchModeExec || got.req.Command != "uptime" || got.files != 1 {
		t.Errorf("launch = %+v with %d files, want exec uptime on a pty and 1 file", got.req, got.files)
	}
}

// One channel starts one process: a second pty-req, and a shell or an exec
// once the process started, are refused, and window-change needs a pty.
func TestSSHSession_OneProcessPerChannel(t *testing.T) {
	release := make(chan struct{})
	launcher := &fakeLauncher{run: func(ctx context.Context, _ LaunchRequest, _ []*os.File) (int, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return 0, nil
	}}
	h := startSSHHarness(t, launcher, nil)
	client := h.login(t, nil)
	session := newSSHChannel(t, client)

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Error("a second pty-req was granted, want refused")
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	for _, req := range []struct {
		name    string
		payload []byte
	}{
		{"exec", ssh.Marshal(struct{ Command string }{"id"})},
		{"shell", nil},
	} {
		if ok, err := session.SendRequest(req.name, true, req.payload); err != nil || ok {
			t.Errorf("%s once the process started = %v, %v; want refused", req.name, ok, err)
		}
	}
	close(release)
	if err := session.Wait(); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
	if n := len(launcher.launches()); n != 1 {
		t.Errorf("launcher called %d times, want 1", n)
	}

	windowChange := ssh.Marshal(struct{ Cols, Rows, Width, Height uint32 }{80, 24, 0, 0})
	if ok, err := newSSHChannel(t, client).SendRequest("window-change", true, windowChange); err != nil || ok {
		t.Errorf("window-change without a pty = %v, %v; want refused", ok, err)
	}
}

func TestSSHSession_PTYAllocationFailure(t *testing.T) {
	prev := ptyOpener
	ptyOpener = func() (*os.File, *os.File, error) { return nil, nil, errors.New("no pty") }
	t.Cleanup(func() { ptyOpener = prev })

	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("RequestPty() succeeded, want it refused")
	}
	if !strings.Contains(h.logs.String(), `msg="ssh pty allocation failed"`) {
		t.Error("the failed allocation was not warned about")
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
	launches := launcher.launches()
	if len(launches) != 1 || launches[0].req.PTY || launches[0].files != 3 {
		t.Errorf("launches = %+v, want one shell without a pty and 3 files", launches)
	}
}

func TestSSHSession_ExecPipes(t *testing.T) {
	launcher := &fakeLauncher{run: func(_ context.Context, _ LaunchRequest, files []*os.File) (int, error) {
		in, err := io.ReadAll(files[0])
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(files[1], "out:%s", in)
		fmt.Fprint(files[2], "err:stderr")
		return 0, nil
	}}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	var stdout, stderr bytes.Buffer
	session.Stdin = strings.NewReader("ping")
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Run("cat"); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if stdout.String() != "out:ping" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "out:ping")
	}
	if stderr.String() != "err:stderr" {
		t.Errorf("stderr = %q, want %q", stderr.String(), "err:stderr")
	}
	launches := launcher.launches()
	if len(launches) != 1 || launches[0].req.PTY || launches[0].files != 3 {
		t.Errorf("launches = %+v, want one exec without a pty and 3 files", launches)
	}
}

func TestSSHSession_ExecFailsClosed(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	h.reporter.mu.Lock()
	h.reporter.commandStartedErr = errors.New("control plane unreachable")
	h.reporter.mu.Unlock()

	session := newSSHChannel(t, h.login(t, nil))
	var stderr bytes.Buffer
	session.Stderr = &stderr
	err := session.Run("uptime")

	if got := exitStatus(t, err); got != 1 {
		t.Errorf("exit status = %d, want 1", got)
	}
	const prefix = "plexd: the control plane did not record this command; it was not run:"
	if !strings.HasPrefix(stderr.String(), prefix) {
		t.Errorf("stderr = %q, want prefix %q", stderr.String(), prefix)
	}
	if n := len(launcher.launches()); n != 0 {
		t.Errorf("launcher called %d times, want 0", n)
	}
	if !strings.Contains(h.logs.String(), `level=WARN msg="ssh command not recorded by the control plane; refusing to run it"`) {
		t.Error("the refusal was not warned about")
	}
}

func TestSSHSession_RevokedStartClosesConnection(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	h.reporter.mu.Lock()
	h.reporter.commandStartedErr = fmt.Errorf("report command: %w", &api.APIError{StatusCode: 409, Code: "session_already_revoked"})
	h.reporter.mu.Unlock()

	client := h.login(t, nil)
	session := newSSHChannel(t, client)
	_ = session.Run("uptime")

	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection stayed open after the session was revoked")
	}
	if n := len(launcher.launches()); n != 0 {
		t.Errorf("launcher called %d times, want 0", n)
	}
}

func TestSSHSession_ExitStatusAndRows(t *testing.T) {
	launcher := &fakeLauncher{run: func(context.Context, LaunchRequest, []*os.File) (int, error) { return 7, nil }}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	if got := exitStatus(t, session.Run("uptime")); got != 7 {
		t.Errorf("exit status = %d, want 7", got)
	}
	rows := h.reporter.commands()
	if len(rows) != 2 {
		t.Fatalf("command rows = %+v, want a started and an exited row", rows)
	}
	started, exited := rows[0], rows[1]
	if started.Exited || started.Command != "uptime" || started.SessionID != h.entry.SessionID {
		t.Errorf("first row = %+v, want the started row of uptime", started)
	}
	if !exited.Exited || exited.Command != "uptime" || exited.ExitCode != 7 {
		t.Errorf("second row = %+v, want uptime exited with 7", exited)
	}
	if !exited.StartedAt.Equal(started.StartedAt) || exited.CompletedAt.Before(exited.StartedAt) {
		t.Errorf("exited row times started=%v completed=%v, want the started row's start and a later completion", exited.StartedAt, exited.CompletedAt)
	}
}

func TestSSHSession_ExitRowFailureKeepsStatus(t *testing.T) {
	launcher := &fakeLauncher{run: func(context.Context, LaunchRequest, []*os.File) (int, error) { return 7, nil }}
	h := startSSHHarness(t, launcher, nil)
	h.reporter.mu.Lock()
	h.reporter.commandExitedErr = errors.New("control plane unreachable")
	h.reporter.mu.Unlock()

	session := newSSHChannel(t, h.login(t, nil))
	if got := exitStatus(t, session.Run("uptime")); got != 7 {
		t.Errorf("exit status = %d, want 7", got)
	}
	if !strings.Contains(h.logs.String(), `msg="ssh command exit not recorded"`) {
		t.Error("the lost exit row was not warned about")
	}
}

// sleepingLauncher runs a process that lasts until its context is cancelled and
// then reports 129, the status of a death by SIGHUP. started closes when it
// began, returned when it returned.
func sleepingLauncher() (launcher *fakeLauncher, started, returned <-chan struct{}) {
	s, r := make(chan struct{}), make(chan struct{})
	return &fakeLauncher{run: func(ctx context.Context, _ LaunchRequest, _ []*os.File) (int, error) {
		close(s)
		<-ctx.Done()
		close(r)
		return 129, nil
	}}, s, r
}

// awaitClosed fails the test unless ch closes within d.
func awaitClosed(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("%s did not happen within %v", what, d)
	}
}

func TestSSHSession_ChannelCloseStopsProcess(t *testing.T) {
	launcher, started, returned := sleepingLauncher()
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	if err := session.Start("sleep"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	awaitClosed(t, started, 5*time.Second, "the launch")
	session.Close()
	awaitClosed(t, returned, drainTimeout, "stopping the process of a closed channel")
}

// A command that ran is recorded even when the session closes under it.
func TestSSHSession_CloseMidCommandPostsExitRow(t *testing.T) {
	launcher, started, _ := sleepingLauncher()
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	if err := session.Start("sleep"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	awaitClosed(t, started, 5*time.Second, "the launch")
	h.mgr.CloseSession(h.entry.SessionID, reasonDrained)
	waitForCondition(t, drainTimeout, func() bool {
		for _, row := range h.reporter.commands() {
			if row.Exited && row.Command == "sleep" && row.ExitCode == 129 {
				return true
			}
		}
		return false
	})
}

// A write end of the output that outlives the process, here a descriptor the
// launcher duplicated, ends the command after drainTimeout rather than never.
func TestSSHSession_LeftoverWriteEndDoesNotHangTheCommand(t *testing.T) {
	launcher := &fakeLauncher{run: func(_ context.Context, _ LaunchRequest, files []*os.File) (int, error) {
		fd, err := unix.Dup(int(files[1].Fd()))
		if err != nil {
			return 1, err
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return 0, nil
	}}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))

	done := make(chan error, 1)
	go func() { done <- session.Run("x") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error: %v", err)
		}
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("the command never ended while a write end of its output stayed open")
	}
}

func TestSSHSession_LaunchErrorOnStderr(t *testing.T) {
	launcher := &fakeLauncher{run: func(context.Context, LaunchRequest, []*os.File) (int, error) {
		return 0, errors.New("tunnel: session helper refused: token refused: tunnel: session token: expired")
	}}
	h := startSSHHarness(t, launcher, nil)
	session := newSSHChannel(t, h.login(t, nil))
	var stderr bytes.Buffer
	session.Stderr = &stderr

	if got := exitStatus(t, session.Run("uptime")); got != 1 {
		t.Errorf("exit status = %d, want 1", got)
	}
	if !strings.HasPrefix(stderr.String(), "plexd: tunnel: session helper refused:") {
		t.Errorf("stderr = %q, want the launcher's error", stderr.String())
	}
}

func TestSSHSession_ConnectionAndChannelLimits(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)

	var first *ssh.Client
	for i := 0; i < sshMaxConnsPerSession; i++ {
		client := h.login(t, nil)
		if first == nil {
			first = client
		}
	}
	dialed := false
	err := h.mgr.ConnectSSHSession(h.entry.SessionID, "fifth", func(context.Context) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dialed")
	})
	if !errors.Is(err, ErrSSHConnectionLimit) || dialed {
		t.Errorf("a fifth connection: error = %v, dialed = %v, want ErrSSHConnectionLimit before any dial", err, dialed)
	}

	for i := 0; i < sshMaxChannelsPerConn; i++ {
		newSSHChannel(t, first)
	}
	_, err = first.NewSession()
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.ResourceShortage {
		t.Errorf("eleventh channel error = %v, want an OpenChannelError with ResourceShortage", err)
	}
}

// Closing a channel or a connection frees its slot: one connection runs more
// commands one after another than it may hold channels open, and a closed
// connection makes room for the next.
func TestSSHSession_ClosingFreesSlots(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)

	clients := make([]*ssh.Client, sshMaxConnsPerSession)
	for i := range clients {
		clients[i] = h.login(t, nil)
	}
	for i := 0; i <= sshMaxChannelsPerConn; i++ {
		if err := newSSHChannel(t, clients[0]).Run("uptime"); err != nil {
			t.Fatalf("command %d on one connection: %v", i+1, err)
		}
	}

	clients[1].Close()
	var replacement *ssh.Client
	waitForCondition(t, 3*time.Second, func() bool {
		client, err := h.dial(sshTestUser, h.token(t, nil))
		if err != nil {
			return false
		}
		replacement = client
		return true
	})
	replacement.Close()
}

// A connection keeps its slot until the processes of its channels are gone, so
// a client that hangs up while a process is still stopping cannot take the
// slot again and start more.
func TestSSHSession_HangUpKeepsSlotUntilProcessesEnd(t *testing.T) {
	started, stopping, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	free := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(free)
	launcher := &fakeLauncher{run: func(ctx context.Context, _ LaunchRequest, _ []*os.File) (int, error) {
		close(started)
		<-ctx.Done()
		close(stopping)
		<-release
		return 129, nil
	}}
	h := startSSHHarness(t, launcher, nil)

	clients := make([]*ssh.Client, sshMaxConnsPerSession)
	for i := range clients {
		clients[i] = h.login(t, nil)
	}
	if err := newSSHChannel(t, clients[0]).Start("sleep"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	awaitClosed(t, started, 5*time.Second, "the launch")
	clients[0].Close()
	awaitClosed(t, stopping, 5*time.Second, "stopping the process of a hung-up connection")

	for i := 0; i < 10; i++ {
		if client, err := h.dial(sshTestUser, h.token(t, nil)); err == nil {
			client.Close()
			t.Fatal("a connection took the slot of one whose process was still stopping")
		}
		time.Sleep(20 * time.Millisecond)
	}
	free()
	waitForCondition(t, 3*time.Second, func() bool {
		client, err := h.dial(sshTestUser, h.token(t, nil))
		if err != nil {
			return false
		}
		client.Close()
		return true
	})
}

func TestSSHSession_CloseDropsClients(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)
	clients := []*ssh.Client{h.login(t, nil), h.login(t, nil)}

	var wg sync.WaitGroup
	returned := make([]time.Duration, len(clients))
	start := time.Now()
	for i, client := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = client.Wait()
			returned[i] = time.Since(start)
		}()
	}
	h.mgr.CloseSession(h.entry.SessionID, reasonDrained)
	wg.Wait()

	for i, took := range returned {
		if took > drainTimeout {
			t.Errorf("client %d stayed connected for %v after CloseSession, want at most %v", i, took, drainTimeout)
		}
	}
}

func TestSSHSession_IdleTimeout(t *testing.T) {
	t.Run("no traffic", func(t *testing.T) {
		h := startSSHHarness(t, &fakeLauncher{}, func(e *api.NodeStateSession) { e.IdleTimeoutSeconds = 1 })
		mu, records := recordCloses(h.mgr)
		waitForCondition(t, 3*time.Second, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(*records) == 1
		})
		mu.Lock()
		defer mu.Unlock()
		if got := TerminatedByFromReason((*records)[0].reason); got != api.TerminatedByIdleTimeout {
			t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByIdleTimeout)
		}
	})

	t.Run("steady traffic", func(t *testing.T) {
		h := startSSHHarness(t, &fakeLauncher{}, func(e *api.NodeStateSession) { e.IdleTimeoutSeconds = 1 })
		client := h.login(t, nil)
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				t.Fatalf("keepalive: %v", err)
			}
			time.Sleep(300 * time.Millisecond)
		}
		if h.mgr.ActiveCount() != 1 {
			t.Errorf("the session idled out while the client kept writing, ActiveCount()=%d", h.mgr.ActiveCount())
		}
	})
}

// An ssh session binds nothing, so neither an empty mesh address nor a wildcard
// keeps a node from serving one, while a tcp session there is still refused.
func TestSessionManager_SSHSessionNeedsNoMeshAddress(t *testing.T) {
	echoAddr := startEchoServer(t)
	for _, meshIP := range []string{"", "0.0.0.0"} {
		t.Run(fmt.Sprintf("mesh ip %q", meshIP), func(t *testing.T) {
			mgr := NewSessionManager(Config{}, meshIP, slog.Default())
			t.Cleanup(mgr.Shutdown)
			deps, _ := newSSHTestDeps(t, &mockReporter{}, &fakeLauncher{})
			mgr.SetSSHSessionDeps(deps)

			addr, err := mgr.CreateSession(context.Background(), sshEntry("sess-ssh", sshTestUser, time.Now().Add(5*time.Minute)))
			if err != nil || addr != "" {
				t.Fatalf("CreateSession(ssh) = %q, %v, want an empty address and no error", addr, err)
			}
			_, err = mgr.CreateSession(context.Background(), echoSession(t, "sess-tcp", echoAddr))
			if err == nil || !strings.Contains(err.Error(), "is not a bindable unicast address") {
				t.Errorf("CreateSession(tcp) error = %v, want the mesh address refused", err)
			}
		})
	}
}

// Every refusal of ConnectSSHSession comes before it opens anything.
func TestSessionManager_ConnectSSHSessionRefusals(t *testing.T) {
	echoAddr := startEchoServer(t)
	off := false
	for _, tt := range []struct {
		name      string
		cfg       Config
		sessionID string
		want      error
	}{
		{"unknown id", Config{}, "sess-unknown", ErrSessionNotLive},
		{"empty id", Config{}, "", ErrSessionNotLive},
		{"tcp session", Config{}, "sess-tcp", ErrNotSSHSession},
		{"ssh sessions disabled", Config{Enabled: true, MaxSessions: 10, DefaultTimeout: 5 * time.Minute, SSHSessionsEnabled: &off}, "sess-ssh", ErrSSHSessionsDisabled},
		{"tunneling disabled", Config{Enabled: false, MaxSessions: 10, DefaultTimeout: 5 * time.Minute}, "sess-ssh", ErrTunnelingDisabled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewSessionManager(tt.cfg, "127.0.0.1", slog.Default())
			t.Cleanup(mgr.Shutdown)
			deps, _ := newSSHTestDeps(t, &mockReporter{}, &fakeLauncher{})
			mgr.SetSSHSessionDeps(deps)
			// Under the disabled configurations these are refused too; the
			// refusal under test does not depend on them.
			_, _ = mgr.CreateSession(context.Background(), sshEntry("sess-ssh", sshTestUser, time.Now().Add(5*time.Minute)))
			_, _ = mgr.CreateSession(context.Background(), echoSession(t, "sess-tcp", echoAddr))

			dialed := false
			err := mgr.ConnectSSHSession(tt.sessionID, "conn-1", func(context.Context) (net.Conn, error) {
				dialed = true
				return nil, errors.New("dialed")
			})
			if !errors.Is(err, tt.want) {
				t.Errorf("ConnectSSHSession() error = %v, want %v", err, tt.want)
			}
			if dialed {
				t.Error("ConnectSSHSession dialed before refusing")
			}
		})
	}
}

// pendingDials reads how many connections of the harness's session are still
// being opened (white-box).
func pendingDials(h *sshHarness) int {
	h.mgr.mu.Lock()
	s := h.mgr.sessions[h.entry.SessionID].(*sshSession)
	h.mgr.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

// A connection being opened holds its slot, so a burst of events cannot open
// more connections than the limit while their dials are in flight.
func TestSSHSession_ConnectionLimitCountsDialsInFlight(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)

	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < sshMaxConnsPerSession; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.mgr.ConnectSSHSession(h.entry.SessionID, fmt.Sprintf("blocked-%d", i), func(context.Context) (net.Conn, error) {
				<-release
				return nil, errors.New("control plane unreachable")
			})
		}()
	}
	waitForCondition(t, 3*time.Second, func() bool { return pendingDials(h) == sshMaxConnsPerSession })

	dialed := false
	err := h.mgr.ConnectSSHSession(h.entry.SessionID, "fifth", func(context.Context) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dialed")
	})
	close(release)
	wg.Wait()
	if !errors.Is(err, ErrSSHConnectionLimit) || dialed {
		t.Errorf("a fifth connection while four dial: error = %v, dialed = %v, want ErrSSHConnectionLimit before any dial", err, dialed)
	}
}

// A dial that fails gives its slot back and reports why.
func TestSSHSession_FailedDialFreesItsSlot(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)

	err := h.mgr.ConnectSSHSession(h.entry.SessionID, "failing", func(context.Context) (net.Conn, error) {
		return nil, errors.New("control plane unreachable")
	})
	if err == nil || err.Error() != "tunnel: open session connection: control plane unreachable" {
		t.Fatalf("ConnectSSHSession() error = %v, want the dial's error wrapped", err)
	}
	for i := 0; i < sshMaxConnsPerSession; i++ {
		h.login(t, nil)
	}
}

// Closing the session cancels a dial in flight, and nothing it started is left
// running.
func TestSSHSession_CloseCancelsDialInFlight(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	h := startSSHHarness(t, &fakeLauncher{}, nil)

	dialing := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		returned <- h.mgr.ConnectSSHSession(h.entry.SessionID, "in-flight", func(ctx context.Context) (net.Conn, error) {
			close(dialing)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	awaitClosed(t, dialing, 3*time.Second, "the dial")
	h.mgr.CloseSession(h.entry.SessionID, reasonDrained)

	select {
	case err := <-returned:
		if !errors.Is(err, errSessionClosedWhileConnecting) {
			t.Errorf("ConnectSSHSession() error = %v, want errSessionClosedWhileConnecting", err)
		}
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("ConnectSSHSession did not return after the session closed")
	}
}

// A connection that opens after the session closed is closed again instead of
// being served.
func TestSSHSession_ConnectionOpenedAfterCloseIsClosed(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)

	var client net.Conn
	dialing := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		returned <- h.mgr.ConnectSSHSession(h.entry.SessionID, "late", func(ctx context.Context) (net.Conn, error) {
			close(dialing)
			<-ctx.Done()
			server, c, err := connPair()
			client = c
			return server, err
		})
	}()
	awaitClosed(t, dialing, 3*time.Second, "the dial")
	h.mgr.CloseSession(h.entry.SessionID, reasonDrained)

	if err := <-returned; !errors.Is(err, errSessionClosedWhileConnecting) {
		t.Fatalf("ConnectSSHSession() error = %v, want errSessionClosedWhileConnecting", err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("read from the late connection = %v, want io.EOF: the session closed it", err)
	}
}

// wsControlPlane is a stand-in for the control plane's node connection route.
// serve runs on every connection it accepts; the connections close when the
// test ends.
func wsControlPlane(t *testing.T, serve func(ctx context.Context, c *websocket.Conn)) *api.ControlPlane {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = c.CloseNow() }()
			serve(ctx, c)
		}()
	}))
	t.Cleanup(func() {
		cancel()
		wg.Wait()
		srv.Close()
	})
	cp, err := api.NewControlPlane(api.Config{BaseURL: srv.URL}, "1.0.0-test", slog.Default())
	if err != nil {
		t.Fatalf("NewControlPlane() error: %v", err)
	}
	return cp
}

func connectOverWebSocket(t *testing.T, h *sshHarness, cp *api.ControlPlane, connectionID string) {
	t.Helper()
	err := h.mgr.ConnectSSHSession(h.entry.SessionID, connectionID, func(ctx context.Context) (net.Conn, error) {
		return cp.OpenSessionConnection(ctx, "node-1", h.entry.SessionID, connectionID)
	})
	if err != nil {
		t.Fatalf("ConnectSSHSession() error: %v", err)
	}
}

// Closing a session does not wait on a control plane that never answers the
// WebSocket close: the session's handlers drain within drainTimeout.
func TestSSHSession_CloseDoesNotWaitForTheControlPlane(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, nil)
	// The control plane's end never reads, so it never answers a close frame.
	cp := wsControlPlane(t, func(ctx context.Context, _ *websocket.Conn) { <-ctx.Done() })
	connectOverWebSocket(t, h, cp, "silent")
	client := h.login(t, nil)
	waitForCondition(t, 3*time.Second, func() bool { return strings.Contains(h.logs.String(), "ssh login accepted") })

	start := time.Now()
	h.mgr.CloseSession(h.entry.SessionID, reasonDrained)
	if took := time.Since(start); took > drainTimeout+time.Second {
		t.Errorf("CloseSession took %v, want at most %v", took, drainTimeout+time.Second)
	}
	if strings.Contains(h.logs.String(), "timed out waiting for ssh handlers to drain") {
		t.Error("the handlers waited on the control plane's close past drainTimeout")
	}
	waited := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(waited)
	}()
	awaitClosed(t, waited, time.Second, "the other client's disconnect")
}

// The control plane's WebSocket pings keep its socket alive, not the session:
// a connection that carries only pings idles out.
func TestSSHSession_PingsDoNotHoldAnIdleSessionOpen(t *testing.T) {
	h := startSSHHarness(t, &fakeLauncher{}, func(e *api.NodeStateSession) { e.IdleTimeoutSeconds = 1 })
	mu, records := recordCloses(h.mgr)

	var pongs atomic.Int32
	cp := wsControlPlane(t, func(ctx context.Context, c *websocket.Conn) {
		// A ping completes only once its pong is read, so the control plane
		// reads, and discards the node's SSH version line, while it pings.
		go func() {
			for {
				if _, _, err := c.Read(ctx); err != nil {
					return
				}
			}
		}()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.Ping(ctx); err != nil {
					return
				}
				pongs.Add(1)
			}
		}
	})
	connectOverWebSocket(t, h, cp, "pinged")

	waitForCondition(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*records) == 1
	})
	mu.Lock()
	reason := (*records)[0].reason
	mu.Unlock()
	if got := TerminatedByFromReason(reason); got != api.TerminatedByIdleTimeout {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByIdleTimeout)
	}
	if n := pongs.Load(); n < 3 {
		t.Errorf("the connection answered %d pings before the session idled out, want at least 3", n)
	}
}
