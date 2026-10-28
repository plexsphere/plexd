//go:build linux || darwin

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/api"
)

// nodeConnector binds api.ControlPlane.OpenSessionConnection to one node id,
// the way plexd up's controlPlaneSessionConnector does.
type nodeConnector struct {
	cp     *api.ControlPlane
	nodeID string
}

func (c nodeConnector) OpenSessionConnection(ctx context.Context, sessionID, connectionID string) (net.Conn, error) {
	return c.cp.OpenSessionConnection(ctx, c.nodeID, sessionID, connectionID)
}

// TestIntegration_SSHSessionEndToEnd drives a mediated ssh session through the
// production wiring: the dispatcher provisions the entry, a session_connect
// event makes the node open a WebSocket to a stand-in control plane through the
// real API client, a real SSH client logs in with the session token on the
// control plane's end of that socket, and the command runs through the child
// session helper as the current user. The block draining ends the session.
func TestIntegration_SSHSessionEndToEnd(t *testing.T) {
	passwd := usePasswdFixture(t, "/bin/sh")
	pub, priv := newSigningKey(t)
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	d, mgr, reporter := newIntegrationDispatcher(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: time.Minute,
	})
	// No helper socket exists at this path, so the client starts the test
	// binary as its child helper.
	launcher := NewSessionHelperClient(filepath.Join(t.TempDir(), "absent.sock"), testHelperChild(passwd), staticKeys{pub}, slog.Default())
	mgr.SetSSHSessionDeps(SSHSessionDeps{HostKey: hostKey, Keys: staticKeys{pub}, Commands: reporter, Launcher: launcher})

	entry := api.NodeStateSession{
		SessionID: "integ-ssh",
		JTI:       "integ-ssh",
		Kind:      api.SessionKindSSH,
		Target:    api.SessionTarget{SSH: &api.SessionTargetSSH{User: helperUser}},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	d.Handle(context.Background(), sessionsSnapshot(entry))

	started := startedRows(reporter, "integ-ssh")
	if len(started) != 1 || started[0].Kind != api.SessionKindSSH || started[0].ListenerEndpoint != "" {
		t.Fatalf("started rows = %+v, want one ssh row without an endpoint", started)
	}

	// The control plane's node connection route: it records the path and hands
	// the accepted socket to the client that attached.
	accepted := make(chan net.Conn, 1)
	paths := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	}))
	t.Cleanup(srv.Close)
	cp, err := api.NewControlPlane(api.Config{BaseURL: srv.URL}, "1.0.0-test", slog.Default())
	if err != nil {
		t.Fatalf("NewControlPlane() error: %v", err)
	}
	cp.SetAuthToken("test-token")

	payload, _ := json.Marshal(api.SessionConnectRequest{SessionID: "integ-ssh", ConnectionID: "conn-integ", ExpiresAt: time.Now().Add(10 * time.Second)})
	handler := d.SessionConnectHandler(nodeConnector{cp: cp, nodeID: "node-integ"})
	if err := handler(context.Background(), api.Envelope{ID: "evt-connect", Type: api.EventSessionConnect, Payload: payload}); err != nil {
		t.Fatalf("session_connect handler error: %v", err)
	}

	var cpConn net.Conn
	select {
	case cpConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the node opened no connection within 5s of the event")
	}
	t.Cleanup(func() { cpConn.Close() })
	if path := <-paths; path != "/v1/nodes/node-integ/sessions/integ-ssh/connections/conn-integ" {
		t.Errorf("connection path = %q, want the node connection route of conn-integ", path)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(cpConn, "plexd", &ssh.ClientConfig{
		User:            helperUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sessionToken(t, priv, "integ-ssh", helperUser, nil))},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	})
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	out, err := session.Output("echo hi")
	if err != nil {
		t.Fatalf("exec echo hi: %v", err)
	}
	if string(out) != "hi\n" {
		t.Errorf("stdout = %q, want %q", out, "hi\n")
	}

	rows := reporter.commands()
	if len(rows) != 2 || rows[0].Exited || rows[0].Command != "echo hi" || !rows[1].Exited || rows[1].ExitCode != 0 {
		t.Errorf("command rows = %+v, want command_executed then command_exited with exit_code 0", rows)
	}

	// The drain closes the session and the client's connection.
	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()
	d.Handle(context.Background(), sessionsSnapshot())
	select {
	case <-closed:
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("the drain left the client connected")
	}

	ended := endedRows(reporter, "integ-ssh")
	if len(ended) != 1 {
		t.Fatalf("ended rows = %+v, want 1", ended)
	}
	if ended[0].Kind != api.SessionKindSSH || ended[0].TerminatedBy != api.TerminatedByPlexdClose {
		t.Errorf("ended row = %+v, want kind ssh closed by plexd_close", ended[0])
	}
}

// integShellOutput collects what an interactive channel prints, so a test can
// match it while it arrives. The shell on the other end is a real /bin/sh on a
// real pty: it prints prompts and the tty echoes input, so the output is
// matched with patterns, never compared whole.
type integShellOutput struct {
	mu    sync.Mutex
	buf   []byte
	ended bool
	// changed is closed and replaced whenever buf or ended changes.
	changed chan struct{}
}

// collectIntegShellOutput reads r until it ends.
func collectIntegShellOutput(r io.Reader) *integShellOutput {
	o := &integShellOutput{changed: make(chan struct{})}
	go func() {
		b := make([]byte, 32<<10)
		for {
			n, err := r.Read(b)
			o.mu.Lock()
			o.buf = append(o.buf, b[:n]...)
			o.ended = err != nil
			close(o.changed)
			o.changed = make(chan struct{})
			o.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return o
}

// mark returns how many bytes arrived so far.
func (o *integShellOutput) mark() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.buf)
}

// await waits at most timeout for re to match the bytes that arrived after
// the first from, and returns the match and its submatches.
func (o *integShellOutput) await(t *testing.T, from int, re *regexp.Regexp, timeout time.Duration) []string {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		o.mu.Lock()
		out := string(o.buf[from:])
		ended, changed := o.ended, o.changed
		o.mu.Unlock()
		if m := re.FindStringSubmatch(out); m != nil {
			return m
		}
		if ended {
			t.Fatalf("the channel ended without printing %q; after byte %d it printed %q", re, from, out)
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("no %q within %v; after byte %d the channel printed %q", re, timeout, from, out)
		}
	}
}

// integGlobalRequests records the global requests a client received, in
// place of ssh.NewClient's discarding default, and answers each one that
// wants a reply with false.
type integGlobalRequests struct {
	mu   sync.Mutex
	reqs []*ssh.Request
	// ended is closed once the connection ended and no request can follow.
	ended chan struct{}
}

func watchIntegGlobalRequests(in <-chan *ssh.Request) *integGlobalRequests {
	w := &integGlobalRequests{ended: make(chan struct{})}
	go func() {
		defer close(w.ended)
		for req := range in {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			w.mu.Lock()
			w.reqs = append(w.reqs, req)
			w.mu.Unlock()
		}
	}()
	return w
}

func (w *integGlobalRequests) received() []*ssh.Request {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*ssh.Request(nil), w.reqs...)
}

// TestIntegration_SSHSessionKeptShell drives the kept shell through the
// production wiring: an interactive /bin/sh on a real pty, started by the
// child session helper, served on connections the node opens to a stand-in
// control plane over a real WebSocket, one session_connect event each.
// Connection 1 starts the shell; connection 2 reattaches once connection 1's
// control-plane end closed, and finds the shell's output replayed and the same
// process; connection 3 takes the shell over from connection 2; the block
// draining ends the session and the shell's process with it.
func TestIntegration_SSHSessionKeptShell(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("no pty on this host: %v", err)
	}
	master.Close()
	slave.Close()

	passwd := usePasswdFixture(t, "/bin/sh")
	pub, priv := newSigningKey(t)
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatalf("GenerateHostKey() error: %v", err)
	}

	d, mgr, reporter := newIntegrationDispatcher(t, Config{
		Enabled:        true,
		MaxSessions:    10,
		DefaultTimeout: time.Minute,
	})
	// No helper socket exists at this path, so the client starts the test
	// binary as its child helper.
	launcher := NewSessionHelperClient(filepath.Join(t.TempDir(), "absent.sock"), testHelperChild(passwd), staticKeys{pub}, slog.Default())
	mgr.SetSSHSessionDeps(SSHSessionDeps{HostKey: hostKey, Keys: staticKeys{pub}, Commands: reporter, Launcher: launcher})

	const sessionID = "integ-kept"
	d.Handle(context.Background(), sessionsSnapshot(api.NodeStateSession{
		SessionID: sessionID,
		JTI:       sessionID,
		Kind:      api.SessionKindSSH,
		Target:    api.SessionTarget{SSH: &api.SessionTargetSSH{User: helperUser}},
		ExpiresAt: time.Now().Add(time.Minute),
	}))

	// The control plane's node connection route: it records the path and hands
	// each accepted socket to the test.
	accepted := make(chan net.Conn, 3)
	paths := make(chan string, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	}))
	t.Cleanup(srv.Close)
	cp, err := api.NewControlPlane(api.Config{BaseURL: srv.URL}, "1.0.0-test", slog.Default())
	if err != nil {
		t.Fatalf("NewControlPlane() error: %v", err)
	}
	cp.SetAuthToken("test-token")
	handler := d.SessionConnectHandler(nodeConnector{cp: cp, nodeID: "node-integ"})
	token := sessionToken(t, priv, sessionID, helperUser, nil)

	// step bounds every blocking step that has no bound of its own.
	const step = 10 * time.Second
	kept42 := regexp.MustCompile(`kept-42\r?\n`)
	pidLine := regexp.MustCompile(`pid-([0-9]+)\r?\n`)

	// within runs op and fails the test when it fails or takes longer than
	// timeout. A timeout closes cpConn, the transport op waits on, so op
	// returns and the test fails rather than hangs.
	within := func(cpConn net.Conn, timeout time.Duration, what string, op func() error) {
		t.Helper()
		timer := time.AfterFunc(timeout, func() { cpConn.Close() })
		err := op()
		if !timer.Stop() {
			t.Fatalf("%s took longer than %v", what, timeout)
		}
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	// connect fires one session_connect for connectionID and returns the
	// control plane's end of the connection the node opened for it.
	connect := func(connectionID string) net.Conn {
		t.Helper()
		payload, _ := json.Marshal(api.SessionConnectRequest{SessionID: sessionID, ConnectionID: connectionID, ExpiresAt: time.Now().Add(10 * time.Second)})
		if err := handler(context.Background(), api.Envelope{ID: "evt-" + connectionID, Type: api.EventSessionConnect, Payload: payload}); err != nil {
			t.Fatalf("session_connect handler error for %s: %v", connectionID, err)
		}
		var cpConn net.Conn
		select {
		case cpConn = <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatalf("the node opened no connection within 5s of the session_connect for %s", connectionID)
		}
		t.Cleanup(func() { cpConn.Close() })
		want := "/v1/nodes/node-integ/sessions/" + sessionID + "/connections/" + connectionID
		if path := <-paths; path != want {
			t.Errorf("connection path = %q, want %q", path, want)
		}
		return cpConn
	}

	// login logs in on cpConn with the session token. With watch set, the
	// connection's global requests reach the returned watcher; without it the
	// client refuses them, as ssh.NewClient does.
	login := func(cpConn net.Conn, watch bool) (*ssh.Client, *integGlobalRequests) {
		t.Helper()
		var (
			conn  ssh.Conn
			chans <-chan ssh.NewChannel
			reqs  <-chan *ssh.Request
		)
		within(cpConn, step, "ssh login", func() (err error) {
			conn, chans, reqs, err = ssh.NewClientConn(cpConn, "plexd", &ssh.ClientConfig{
				User:            helperUser,
				Auth:            []ssh.AuthMethod{ssh.Password(token)},
				HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
			})
			return err
		})
		var watched *integGlobalRequests
		if watch {
			watched = watchIntegGlobalRequests(reqs)
			// The client's own handler gets a closed channel and returns.
			none := make(chan *ssh.Request)
			close(none)
			reqs = none
		}
		client := ssh.NewClient(conn, chans, reqs)
		t.Cleanup(func() { client.Close() })
		return client, watched
	}

	// shell opens a channel on client, requests a rows x cols pty and an
	// interactive shell, and returns the channel's input and output. Its output
	// is collected from before the shell request, so a replay sent ahead of
	// the answer is kept.
	shell := func(cpConn net.Conn, client *ssh.Client, rows, cols int) (io.Writer, *integShellOutput) {
		t.Helper()
		var session *ssh.Session
		within(cpConn, step, "NewSession", func() (err error) {
			session, err = client.NewSession()
			return err
		})
		t.Cleanup(func() { session.Close() })
		within(cpConn, step, "pty-req", func() error {
			return session.RequestPty("xterm", rows, cols, ssh.TerminalModes{})
		})
		stdin, err := session.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe() error: %v", err)
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatalf("StdoutPipe() error: %v", err)
		}
		out := collectIntegShellOutput(stdout)
		within(cpConn, step, "shell", session.Shell)
		return stdin, out
	}

	// send types line into the shell.
	send := func(cpConn net.Conn, stdin io.Writer, line string) {
		t.Helper()
		within(cpConn, step, "send "+line, func() error {
			_, err := io.WriteString(stdin, line+"\n")
			return err
		})
	}

	// shellState asks client's connection for its shell state, and returns the
	// state plexd answered, or "" when it refused.
	shellState := func(cpConn net.Conn, client *ssh.Client) string {
		t.Helper()
		var (
			ok      bool
			payload []byte
		)
		within(cpConn, step, "shell-state request", func() (err error) {
			ok, payload, err = client.SendRequest("shell-state@plexsphere.com", true, nil)
			return err
		})
		if !ok {
			return ""
		}
		// ssh.Unmarshal refuses trailing bytes, so the payload is exactly one
		// string.
		var answer struct{ State string }
		if err := ssh.Unmarshal(payload, &answer); err != nil {
			t.Fatalf("shell-state payload %q: %v", payload, err)
		}
		return answer.State
	}

	// whenEnded returns a channel closed once client's connection ended.
	whenEnded := func(client *ssh.Client) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			_ = client.Wait()
			close(done)
		}()
		return done
	}

	// 1. Connection 1 starts the kept shell.
	cp1 := connect("conn-1")
	client1, _ := login(cp1, false)
	in1, out1 := shell(cp1, client1, 24, 80)
	send(cp1, in1, "echo pid-$$; echo kept-$((6*7))")
	out1.await(t, 0, kept42, step)
	pid, err := strconv.Atoi(out1.await(t, 0, pidLine, step)[1])
	if err != nil {
		t.Fatalf("shell pid: %v", err)
	}
	if state := shellState(cp1, client1); state != "started" {
		t.Fatalf("shell-state on connection 1 = %q, want started", state)
	}

	// 2. Connection 1's control-plane end closes; the shell runs on, and
	// connection 2 reattaches to it.
	ended1 := whenEnded(client1)
	cp1.Close()
	select {
	case <-ended1:
	case <-time.After(step):
		t.Fatalf("connection 1's client still connected %v after its control-plane end closed", step)
	}

	cp2 := connect("conn-2")
	client2, global2 := login(cp2, true)
	in2, out2 := shell(cp2, client2, 30, 100)
	// Connection 2 has sent nothing yet, so this came from the replay.
	out2.await(t, 0, kept42, step)
	if state := shellState(cp2, client2); state != "reattached" {
		t.Fatalf("shell-state on connection 2 = %q, want reattached", state)
	}
	from := out2.mark()
	send(cp2, in2, "stty size")
	out2.await(t, from, regexp.MustCompile(`\b30 100\r?\n`), step)
	from = out2.mark()
	send(cp2, in2, "echo pid-$$")
	if got := out2.await(t, from, pidLine, step)[1]; got != strconv.Itoa(pid) {
		t.Fatalf("pid after the reattach = %s, want %d, the shell connection 1 started", got, pid)
	}

	// 3. Connection 3 takes the shell over while connection 2 is attached.
	ended2 := whenEnded(client2)
	cp3 := connect("conn-3")
	client3, _ := login(cp3, false)
	shell(cp3, client3, 24, 80)
	select {
	case <-global2.ended:
	case <-time.After(drainTimeout):
		t.Fatalf("connection 2 still open %v after connection 3 took the shell over", drainTimeout)
	}
	select {
	case <-ended2:
	case <-time.After(drainTimeout):
		t.Fatalf("connection 2's client still connected %v after connection 3 took the shell over", drainTimeout)
	}
	reqs := global2.received()
	if len(reqs) != 1 {
		t.Fatalf("connection 2 received %d global requests, want exactly shell-taken-over@plexsphere.com", len(reqs))
	}
	if reqs[0].Type != "shell-taken-over@plexsphere.com" || reqs[0].WantReply || len(reqs[0].Payload) != 0 {
		t.Errorf("connection 2 received %q (want_reply %v, payload %q), want shell-taken-over@plexsphere.com without want_reply and with an empty payload",
			reqs[0].Type, reqs[0].WantReply, reqs[0].Payload)
	}
	if state := shellState(cp3, client3); state != "reattached" {
		t.Fatalf("shell-state on connection 3 = %q, want reattached", state)
	}

	// 4. The block drains: the session closes, connection 3 with it, and the
	// helper stops the shell's process.
	ended3 := whenEnded(client3)
	drained := time.Now()
	d.Handle(context.Background(), sessionsSnapshot())
	select {
	case <-ended3:
	case <-time.After(time.Until(drained.Add(drainTimeout + time.Second))):
		t.Fatalf("connection 3's client still connected %v after the drain", drainTimeout+time.Second)
	}
	waitForCondition(t, time.Until(drained.Add(sessionHelperKillGrace+drainTimeout)), func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	})

	ended := endedRows(reporter, sessionID)
	if len(ended) != 1 {
		t.Fatalf("ended rows = %+v, want 1", ended)
	}
	if ended[0].Kind != api.SessionKindSSH || ended[0].TerminatedBy != api.TerminatedByPlexdClose {
		t.Errorf("ended row = %+v, want kind ssh closed by plexd_close", ended[0])
	}
}
