//go:build unix

package nodeapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
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
