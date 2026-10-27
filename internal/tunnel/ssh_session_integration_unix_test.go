//go:build linux || darwin

package tunnel

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
