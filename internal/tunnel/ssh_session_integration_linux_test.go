//go:build linux

package tunnel

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/plexsphere/plexd/internal/api"
)

// TestIntegration_SSHSessionEndToEnd drives a mediated ssh session through the
// production wiring: the dispatcher provisions the entry, the manager starts
// the listener, a real SSH client logs in with the session token, and the
// command runs through the child session helper as the current user. The block
// draining ends the session.
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
	if len(started) != 1 || started[0].Kind != api.SessionKindSSH {
		t.Fatalf("started rows = %+v, want one ssh row", started)
	}

	client, err := ssh.Dial("tcp", started[0].ListenerEndpoint, &ssh.ClientConfig{
		User:            helperUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sessionToken(t, priv, "integ-ssh", helperUser, nil))},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
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

	// The drain closes the listener and the client's connection.
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
