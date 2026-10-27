//go:build linux || darwin

package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The lines the session_connect handler logs.
const (
	connectOpenedMsg  = "session connection opened"
	connectNoLiveMsg  = "session_connect names no live ssh session; not connecting"
	connectRefusedMsg = "session_connect cannot be served on this node; not connecting"
	connectFailedMsg  = "session connection to the control plane failed"
)

// connectSessionUser is the login user of the ssh session the handler tests
// provision.
const connectSessionUser = "ops"

// fakeConnector is a SessionConnector that records every open and answers it
// with open.
type fakeConnector struct {
	mu    sync.Mutex
	calls [][2]string
	open  func(ctx context.Context) (net.Conn, error)
}

func (f *fakeConnector) OpenSessionConnection(ctx context.Context, sessionID, connectionID string) (net.Conn, error) {
	f.mu.Lock()
	f.calls = append(f.calls, [2]string{sessionID, connectionID})
	open := f.open
	f.mu.Unlock()
	return open(ctx)
}

func (f *fakeConnector) opened() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.calls...)
}

// connectEnvelope builds a session_connect envelope carrying payload verbatim
// as its raw payload; an empty payload leaves the field absent.
func connectEnvelope(payload string) api.Envelope {
	env := api.Envelope{ID: "evt-session-connect", Type: api.EventSessionConnect}
	if payload != "" {
		env.Payload = json.RawMessage(payload)
	}
	return env
}

func connectPayload(t *testing.T, sessionID, connectionID string) string {
	t.Helper()
	data, err := json.Marshal(api.SessionConnectRequest{
		SessionID:    sessionID,
		ConnectionID: connectionID,
		ExpiresAt:    time.Now().Add(10 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// newConnectTestDispatcher wires a dispatcher with ssh sessions and provisions
// one live ssh session, sess-ssh, and one live tcp session, sess-tcp.
func newConnectTestDispatcher(t *testing.T) (*Dispatcher, *SessionManager, *countingHandler, ed25519.PrivateKey) {
	t.Helper()
	d, mgr, reporter, logs := newTestDispatcher(t, Config{})
	deps, priv := newSSHTestDeps(t, reporter, &fakeLauncher{})
	mgr.SetSSHSessionDeps(deps)
	d.Handle(context.Background(), sessionsSnapshot(
		sshEntry("sess-ssh", connectSessionUser, time.Now().Add(5*time.Minute)),
		echoSession(t, "sess-tcp", startEchoServer(t)),
	))
	if mgr.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount()=2, got %d", mgr.ActiveCount())
	}
	return d, mgr, logs, priv
}

func waitForLog(t *testing.T, logs *countingHandler, msg string) {
	t.Helper()
	waitForCondition(t, 3*time.Second, func() bool { return logs.count(msg) == 1 })
}

// A valid event for a live ssh session opens its connection and serves the
// session's login on it.
func TestSessionConnectHandler_ServesTheSessionOnTheConnection(t *testing.T) {
	d, _, logs, priv := newConnectTestDispatcher(t)
	clients := make(chan net.Conn, 1)
	connector := &fakeConnector{open: func(context.Context) (net.Conn, error) {
		server, client, err := connPair()
		if err == nil {
			clients <- client
		}
		return server, err
	}}

	if err := d.SessionConnectHandler(connector)(context.Background(), connectEnvelope(connectPayload(t, "sess-ssh", "conn-1"))); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	waitForLog(t, logs, connectOpenedMsg)
	if got := connector.opened(); len(got) != 1 || got[0] != [2]string{"sess-ssh", "conn-1"} {
		t.Errorf("connector opened %v, want one connection conn-1 for sess-ssh", got)
	}
	if logs.attr(connectOpenedMsg, "session_id") != "sess-ssh" || logs.attr(connectOpenedMsg, "connection_id") != "conn-1" {
		t.Errorf("%q does not name the session and the connection", connectOpenedMsg)
	}

	client, err := sshClientOver(<-clients, connectSessionUser, sessionToken(t, priv, "sess-ssh", connectSessionUser, nil))
	if err != nil {
		t.Fatalf("ssh login over the opened connection: %v", err)
	}
	client.Close()
}

// The open blocks on the control plane, so the handler returns before it does
// and the event stream keeps dispatching.
func TestSessionConnectHandler_DoesNotBlockTheEventStream(t *testing.T) {
	d, _, logs, _ := newConnectTestDispatcher(t)
	release := make(chan struct{})
	connector := &fakeConnector{open: func(context.Context) (net.Conn, error) {
		<-release
		return nil, errors.New("control plane unreachable")
	}}

	returned := make(chan error, 1)
	go func() {
		returned <- d.SessionConnectHandler(connector)(context.Background(), connectEnvelope(connectPayload(t, "sess-ssh", "conn-1")))
	}()
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("handler error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the handler waited for the open")
	}
	close(release)
	waitForLog(t, logs, connectFailedMsg)
}

// A payload that does not decode, or names no connection, opens nothing.
func TestSessionConnectHandler_RefusesUnusablePayloads(t *testing.T) {
	d, _, _, _ := newConnectTestDispatcher(t)
	connector := &fakeConnector{open: func(context.Context) (net.Conn, error) {
		return nil, errors.New("opened")
	}}
	handler := d.SessionConnectHandler(connector)

	for _, tt := range []struct {
		name    string
		payload string
		check   func(error) bool
	}{
		{"not json", `{"session_id":`, func(err error) bool {
			return err != nil && strings.HasPrefix(err.Error(), "tunnel: session_connect payload:")
		}},
		{"absent", "", func(err error) bool {
			return err != nil && strings.HasPrefix(err.Error(), "tunnel: session_connect payload:")
		}},
		{"null", "null", func(err error) bool { return errors.Is(err, errSessionConnectUnnamed) }},
		{"empty session_id", connectPayload(t, "", "conn-1"), func(err error) bool { return errors.Is(err, errSessionConnectUnnamed) }},
		{"empty connection_id", connectPayload(t, "sess-ssh", ""), func(err error) bool { return errors.Is(err, errSessionConnectUnnamed) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := handler(context.Background(), connectEnvelope(tt.payload)); !tt.check(err) {
				t.Errorf("handler error = %v", err)
			}
		})
	}
	// The refusals return before the goroutine that would open anything.
	if got := connector.opened(); len(got) != 0 {
		t.Errorf("connector opened %v, want nothing", got)
	}
}

// A session that is not live here, or is not an ssh session, opens nothing.
func TestSessionConnectHandler_OpensNothingForSessionsItCannotServe(t *testing.T) {
	d, _, logs, _ := newConnectTestDispatcher(t)
	connector := &fakeConnector{open: func(context.Context) (net.Conn, error) {
		return nil, errors.New("opened")
	}}
	handler := d.SessionConnectHandler(connector)

	if err := handler(context.Background(), connectEnvelope(connectPayload(t, "sess-gone", "conn-1"))); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	waitForLog(t, logs, connectNoLiveMsg)
	if logs.level(connectNoLiveMsg) != slog.LevelInfo {
		t.Errorf("%q logged at %v, want Info", connectNoLiveMsg, logs.level(connectNoLiveMsg))
	}

	if err := handler(context.Background(), connectEnvelope(connectPayload(t, "sess-tcp", "conn-2"))); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	waitForLog(t, logs, connectRefusedMsg)
	if logs.level(connectRefusedMsg) != slog.LevelWarn || !strings.Contains(logs.attr(connectRefusedMsg, "error"), ErrNotSSHSession.Error()) {
		t.Errorf("%q = %v %q, want a Warn carrying ErrNotSSHSession", connectRefusedMsg, logs.level(connectRefusedMsg), logs.attr(connectRefusedMsg, "error"))
	}

	if got := connector.opened(); len(got) != 0 {
		t.Errorf("connector opened %v, want nothing", got)
	}
}

// A refused open is logged with the control plane's answer, and its slot is
// free again.
func TestSessionConnectHandler_LogsAFailedOpen(t *testing.T) {
	d, mgr, logs, _ := newConnectTestDispatcher(t)
	refusal := &api.APIError{StatusCode: 404, Code: "session_connection_not_found", Message: "no such connection"}
	connector := &fakeConnector{open: func(context.Context) (net.Conn, error) {
		return nil, refusal
	}}

	if err := d.SessionConnectHandler(connector)(context.Background(), connectEnvelope(connectPayload(t, "sess-ssh", "conn-1"))); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	waitForLog(t, logs, connectFailedMsg)
	if logs.level(connectFailedMsg) != slog.LevelWarn || !strings.Contains(logs.attr(connectFailedMsg, "error"), refusal.Error()) {
		t.Errorf("%q = %v %q, want a Warn carrying the 404", connectFailedMsg, logs.level(connectFailedMsg), logs.attr(connectFailedMsg, "error"))
	}

	for i := 0; i < sshMaxConnsPerSession; i++ {
		err := mgr.ConnectSSHSession("sess-ssh", "after", func(context.Context) (net.Conn, error) {
			server, client, err := connPair()
			if err == nil {
				t.Cleanup(func() { client.Close() })
			}
			return server, err
		})
		if err != nil {
			t.Fatalf("connection %d after the failed open: %v", i+1, err)
		}
	}
}
