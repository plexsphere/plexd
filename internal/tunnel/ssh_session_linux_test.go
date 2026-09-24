//go:build linux

package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	addr     string
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
	addr, err := mgr.CreateSession(context.Background(), entry)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	return &sshHarness{mgr: mgr, reporter: reporter, launcher: launcher, logs: logs, priv: priv, entry: entry, addr: addr}
}

// token mints a valid token for the harness's session and user.
func (h *sshHarness) token(t *testing.T, allowed []string) string {
	t.Helper()
	return sessionToken(t, h.priv, h.entry.SessionID, sshTestUser, allowed)
}

func (h *sshHarness) dial(user, password string) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
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

// countFDs counts this process's descriptors whose target match accepts.
// Counting only the targets a test is about keeps descriptors other tests
// close in the background, a garbage-collected file among them, out of it.
func countFDs(t *testing.T, match func(target string) bool) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && match(target) {
			n++
		}
	}
	return n
}

// A pty exec the control plane did not record never runs, and its pty is closed
// with the refusal.
func TestSSHSession_RefusedPTYExecClosesThePTY(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	h.reporter.mu.Lock()
	h.reporter.commandStartedErr = errors.New("control plane unreachable")
	h.reporter.mu.Unlock()
	client := h.login(t, nil)

	isPTY := func(target string) bool { return target == "/dev/ptmx" || strings.HasPrefix(target, "/dev/pts/") }
	before := countFDs(t, isPTY)
	for i := 0; i < 3; i++ {
		session := newSSHChannel(t, client)
		if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
			t.Fatalf("RequestPty() error: %v", err)
		}
		if got := exitStatus(t, session.Run("uptime")); got != 1 {
			t.Errorf("exit status = %d, want 1", got)
		}
	}
	waitForCondition(t, 2*time.Second, func() bool { return countFDs(t, isPTY) <= before })
	if n := len(launcher.launches()); n != 0 {
		t.Errorf("launcher called %d times, want 0", n)
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
	if !strings.Contains(h.logs.String(), "ssh command not recorded by the control plane; refusing to run it") {
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
	if client, err := h.dial(sshTestUser, h.token(t, nil)); err == nil {
		client.Close()
		t.Error("a fifth concurrent connection completed its handshake, want it closed")
	}

	for i := 0; i < sshMaxChannelsPerConn; i++ {
		newSSHChannel(t, first)
	}
	_, err := first.NewSession()
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
