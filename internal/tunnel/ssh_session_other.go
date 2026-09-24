//go:build !linux

package tunnel

// sshSessionsSupported is false off Linux: the dispatcher settles ssh entries
// as unsupported, and CreateSession refuses them.
const sshSessionsSupported = false

func newSSHSession(sshSessionParams) (managedSession, error) {
	return nil, ErrSSHSessionsUnsupported
}
