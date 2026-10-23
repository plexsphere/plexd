//go:build darwin

package cmd

import (
	"crypto/ed25519"
	"errors"
	"log/slog"
)

// sessionHelperKeys returns the keys plexd passed the child helper. macOS has
// no helper socket and no trust anchor of its own: plexd runs as root under
// launchd with no sandbox, so a helper with a key plexd cannot write would
// guard nothing.
func sessionHelperKeys(_ *slog.Logger) ([]ed25519.PublicKey, error) {
	if !sessionHelperChild {
		return nil, errors.New("plexd session-helper: plexd starts it as its own child (--child); macOS has no helper socket")
	}
	if len(sessionHelperTrustedKeys) == 0 {
		return nil, errors.New("--child needs at least one --trusted-key")
	}
	return parseTrustedKeys(sessionHelperTrustedKeys)
}
