//go:build windows

package nodeapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// pipeSecurityDescriptor guards the local node API pipe with a protected DACL
// that grants full access to LocalSystem and Administrators and to nobody else.
//
// Opening the pipe is the whole authorization for every route but the secret
// ones: the mux serves POST /v1/actions/run, POST /v1/hooks/reload and the
// report writes to any peer that gets a connection, and the Windows service
// runs those as LocalSystem. An Authenticated Users ACE would hand that to
// every signed-in account, so the pipe stays at the Linux posture, where the
// socket is root:plexd 0660 and an unprivileged user reaches no route at all.
// A generic-write grant reaches further than it reads: FILE_GENERIC_WRITE
// carries FILE_APPEND_DATA, which on a pipe object is FILE_CREATE_PIPE_INSTANCE,
// so the grantee could add an instance of this pipe name and answer connections
// the CLI believes it made to plexd.
//
// It carries no owner clause, for the reason uapiSecurityDescriptor records: an
// O:SY clause names LocalSystem as the owner, and a process may only name an
// owner its own token carries, so the clause fails with ERROR_INVALID_OWNER
// when an elevated Administrator starts plexd by hand. Leaving it out makes the
// creator the owner, which is LocalSystem when plexd runs as the service.
//
// It carries no mandatory label either. The UAPI pipe's S:(ML;;NWNRNX;;;HI)
// would add nothing here: BA already resolves to the deny-only Administrators
// SID of a filtered token, so a non-elevated shell is refused by the DACL.
const pipeSecurityDescriptor = `D:P(A;;GA;;;SY)(A;;GA;;;BA)`

// ListenLocal opens the local node API listener: the named pipe called path.
// The logger is unused on Windows, where the pipe's access control is fixed by
// pipeSecurityDescriptor at creation rather than applied afterwards.
func ListenLocal(path string, _ *slog.Logger) (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSecurityDescriptor)
	if err != nil {
		return nil, fmt.Errorf("nodeapi: pipe security descriptor: %w", err)
	}
	ln, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
	if err != nil {
		return nil, fmt.Errorf("nodeapi: listen pipe %s: %w", path, err)
	}
	return ln, nil
}

// DialLocal connects to the local node API listener at path.
func DialLocal(ctx context.Context, path string) (net.Conn, error) {
	return namedpipe.DialContext(ctx, path)
}

// removeLocal does nothing on Windows: a pipe name is not a file, and the
// kernel drops the pipe when its last handle closes.
func removeLocal(_ string) {}

// validateSocketPath requires a Windows named pipe name. A config.yaml or a
// PLEXD_NODE_API_SOCKET that still holds a file path fails at config load with
// this message instead of inside NtCreateNamedPipeFile.
func validateSocketPath(path string) error {
	if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) {
		return errors.New("nodeapi: config: SocketPath must name a Windows named pipe (\\\\.\\pipe\\<name>)")
	}
	return nil
}
