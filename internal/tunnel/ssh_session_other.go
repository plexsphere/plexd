//go:build !linux && !darwin

package tunnel

// sshSessionsSupported is false off Linux and macOS: the dispatcher settles
// ssh entries as unsupported, and CreateSession refuses them.
const sshSessionsSupported = false

func newSSHSession(sshSessionParams) (managedSession, error) {
	return nil, ErrSSHSessionsUnsupported
}
