//go:build unix

package nodeapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestListenLocal_SocketFileLifecycle(t *testing.T) {
	path := shortSocketPath(t)

	ln, err := ListenLocal(path, discardLogger())
	if err != nil {
		t.Fatalf("ListenLocal: %v", err)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		ln.Close()
		t.Fatalf("Lstat while listening: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		ln.Close()
		t.Fatalf("mode = %v, want a socket", fi.Mode())
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	removeLocal(path)

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("Lstat after removeLocal = %v, want a not-exist error", err)
	}
}

func TestListenLocal_StaleSocketReplaced(t *testing.T) {
	path := shortSocketPath(t)
	if err := os.WriteFile(path, []byte("stale"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ln, err := ListenLocal(path, discardLogger())
	if err != nil {
		t.Fatalf("ListenLocal over a stale file: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		accepts <- accepted{conn: conn, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := DialLocal(ctx, path)
	if err != nil {
		t.Fatalf("DialLocal: %v", err)
	}
	defer client.Close()

	select {
	case a := <-accepts:
		if a.err != nil {
			t.Fatalf("Accept: %v", a.err)
		}
		if a.conn == nil {
			t.Fatal("Accept returned a nil connection")
		}
		a.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not see the dialed connection")
	}
}

func TestListenLocal_DirCreateFails(t *testing.T) {
	// A regular file where the socket directory belongs makes MkdirAll fail.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ln, err := ListenLocal(filepath.Join(file, "api.sock"), discardLogger())
	if err == nil {
		ln.Close()
		t.Fatal("ListenLocal() = nil error, want the directory to fail")
	}
	if !strings.HasPrefix(err.Error(), "nodeapi: create socket dir:") {
		t.Errorf("error = %q, want it to start with %q", err, "nodeapi: create socket dir:")
	}
}

func TestListenLocal_ListenFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root binds in a directory it has no write permission on")
	}

	// os.MkdirTemp rather than t.TempDir: the test name would push the socket
	// path past the 104-byte sun_path limit, and bind would fail for that
	// reason instead of the directory mode.
	dir, err := os.MkdirTemp("", "plexd-ro-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0700)
		_ = os.RemoveAll(dir)
	})
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	ln, err := ListenLocal(filepath.Join(dir, "api.sock"), discardLogger())
	if err == nil {
		ln.Close()
		t.Fatal("ListenLocal() = nil error, want bind to fail")
	}
	if !strings.HasPrefix(err.Error(), "nodeapi: listen unix") {
		t.Errorf("error = %q, want it to start with %q", err, "nodeapi: listen unix")
	}
}

func TestListenLocal_PermissionFailureAborts(t *testing.T) {
	path := shortSocketPath(t)

	// Only an injected failure reaches this path: as the socket's owner the
	// test process can always chmod it.
	restore := setSocketPermissions
	setSocketPermissions = func(string, *slog.Logger) error {
		return errors.New("no plexd group and no chmod either")
	}
	t.Cleanup(func() { setSocketPermissions = restore })

	ln, err := ListenLocal(path, discardLogger())
	if err == nil {
		ln.Close()
		t.Fatal("ListenLocal() = nil error, want the permission failure to abort the listener")
	}
	if !strings.HasPrefix(err.Error(), "nodeapi: set socket permissions:") {
		t.Errorf("error = %q, want it to start with %q", err, "nodeapi: set socket permissions:")
	}

	// The failed call never established the socket's mode. Serving it would
	// authorize the action, hook and report routes on a socket nobody vouched
	// for, so the socket must be gone.
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("Lstat after the aborted listen = %v, want a not-exist error", err)
	}
}

func TestListenLocal_BindsNarrowerThanTheUmask(t *testing.T) {
	// A permissive umask is what makes the window between bind and
	// setSocketPermissions exploitable: the socket is connectable from the
	// moment net.Listen returns, and a peer that gets in there is served in
	// full afterwards.
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })

	path := shortSocketPath(t)

	var atBind os.FileMode
	restore := setSocketPermissions
	setSocketPermissions = func(p string, _ *slog.Logger) error {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		atBind = fi.Mode().Perm()
		return nil
	}
	t.Cleanup(func() { setSocketPermissions = restore })

	ln, err := ListenLocal(path, discardLogger())
	if err != nil {
		t.Fatalf("ListenLocal: %v", err)
	}
	defer ln.Close()

	if atBind != 0600 {
		t.Errorf("socket permission before setSocketPermissions = %04o, want 0600", atBind)
	}
}

func TestSetSocketPermissions_NoPlexdGroup(t *testing.T) {
	path := shortSocketPath(t)

	// A socket file to set permissions on.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Neither CI runner has a plexd group, so the fallback mode applies. It
	// must fail closed: the action, hook and report routes are authorized by
	// nothing but the ability to open the socket, so a missing group leaves
	// the socket to its owner rather than to everyone.
	if err := SetSocketPermissions(path, discardLogger()); err != nil {
		t.Fatalf("SetSocketPermissions: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("socket should exist: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("socket permission = %04o, want 0600", got)
	}
}

func TestSetSocketGroup_ChgrpDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root carries CAP_CHOWN here, so the denied chgrp this test needs succeeds")
	}

	path := shortSocketPath(t)

	// A socket file to set permissions on.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Handing the socket to a group the daemon does not belong to needs
	// CAP_CHOWN, which the systemd unit `plexd install` writes masks, so the
	// chown is denied on every systemd install. That must not take the local
	// API down: it narrows to the owner, exactly as a missing group does, and
	// root still reaches the API.
	if err := setSocketGroup(path, os.Getgid(), discardLogger()); err != nil {
		t.Fatalf("setSocketGroup: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("socket should exist: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("socket permission = %04o, want 0600", got)
	}
}

// currentPeerIsPrivileged reports what the secrets policy says about this test
// process when it connects to itself.
func currentPeerIsPrivileged() bool {
	return os.Geteuid() == 0
}
