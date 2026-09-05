//go:build unix

package nodeapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// setSocketPermissions is a variable so the tests can drive the failure path.
// No unprivileged process can provoke it through the OS: the socket belongs to
// the caller, so its own chmod always succeeds.
var setSocketPermissions = SetSocketPermissions

// ListenLocal opens the local node API listener: a Unix domain socket at path.
// It drops a socket file an earlier run left behind, creates the socket
// directory, and applies the platform's socket ownership and mode.
func ListenLocal(path string, logger *slog.Logger) (net.Listener, error) {
	// Remove stale socket.
	os.Remove(path)

	// Ensure socket directory exists.
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("nodeapi: create socket dir: %w", err)
	}

	// Bind under a umask that leaves the socket to its owner. net.Listen
	// creates it at the umask-derived mode and it is connectable from that
	// moment on, so a peer that connects before the ownership and mode below
	// are applied keeps a connection the mux then serves in full -- and
	// applying them opens with an NSS group lookup, which a remote directory
	// service can stall for seconds.
	oldMask := syscall.Umask(0177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(oldMask)
	if err != nil {
		return nil, fmt.Errorf("nodeapi: listen unix %s: %w", path, err)
	}

	// Set socket ownership and mode: root:plexd 0660 when the plexd group
	// exists and the daemon may hand the socket to it, else 0600. A failure
	// aborts the listener rather than warning: the socket's mode was never
	// established then, and opening the socket is the whole authorization for
	// every route but the secret ones, so serving it anyway would hand the
	// action, hook and report routes to whoever can reach it. Close unlinks
	// the socket it created, and no second unlink follows it: that one would
	// race a listener that has meanwhile bound the same path.
	if err := setSocketPermissions(path, logger); err != nil {
		ln.Close()
		return nil, fmt.Errorf("nodeapi: set socket permissions: %w", err)
	}

	return ln, nil
}

// DialLocal connects to the local node API listener at path.
func DialLocal(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

// removeLocal deletes the listener's socket file. The error is ignored: a
// caller reaches here on paths where the file may already be gone.
func removeLocal(path string) {
	os.Remove(path)
}

// validateSocketPath accepts any path on Unix. An empty one is rejected by
// bind when ListenLocal runs.
func validateSocketPath(_ string) error {
	return nil
}
