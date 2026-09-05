//go:build windows

package nodeapi

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// PeerCredentials holds the peer credentials extracted from the pipe client's
// process token.
type PeerCredentials struct {
	PID         uint32
	Elevated    bool
	LocalSystem bool
}

// logAttrs returns the attributes the secrets middleware logs when it denies
// a peer.
func (c *PeerCredentials) logAttrs() []any {
	return []any{"pid", c.PID, "elevated", c.Elevated, "local_system", c.LocalSystem}
}

// GetPeerCredentials extracts peer credentials from a named pipe connection.
// It asks the pipe for the client's process id and reads that process's token.
//
// The pid is a recorded value, not a reference: an open pipe instance holds the
// pipe object, not the client's process object, so a client that exits frees the
// number for another process and OpenProcess may land on that one instead. What
// bounds the consequence is pipeSecurityDescriptor, which admits only
// LocalSystem and Administrators, the two identities windowsSecretPolicy already
// grants — so the check confirms an identity rather than establishing one.
func GetPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	pipe, ok := conn.(interface{ Handle() windows.Handle })
	if !ok {
		return nil, fmt.Errorf("nodeapi: auth: not a named pipe connection")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe.Handle(), &pid); err != nil {
		return nil, fmt.Errorf("nodeapi: auth: GetNamedPipeClientProcessId: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("nodeapi: auth: open client process %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()

	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("nodeapi: auth: open client token: %w", err)
	}
	defer tok.Close()

	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("nodeapi: auth: client token user: %w", err)
	}
	return &PeerCredentials{
		PID:         pid,
		Elevated:    tok.IsElevated(),
		LocalSystem: user.User.Sid.IsWellKnown(windows.WinLocalSystemSid),
	}, nil
}

// windowsSecretPolicy is the Windows policy: an elevated Administrator or
// LocalSystem may read secrets. A filtered Administrator token in a
// non-elevated shell reports Elevated == false and is denied, which is the
// Windows reading of "not root".
type windowsSecretPolicy struct{}

func (windowsSecretPolicy) AllowSecrets(cred *PeerCredentials) bool {
	return cred.LocalSystem || cred.Elevated
}

// newSecretPolicy returns the secret policy this platform enforces on the
// local API.
func newSecretPolicy() SecretPolicy {
	return windowsSecretPolicy{}
}
