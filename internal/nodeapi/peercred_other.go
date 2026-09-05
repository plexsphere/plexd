//go:build unix && !linux && !darwin

package nodeapi

import (
	"fmt"
	"net"
	"runtime"
)

// GetPeerCredentials has no implementation on the remaining Unix platforms.
// With SecretAuthEnabled the secret routes therefore answer 403 there, which
// fails closed, as Linux does for a connection without credentials.
func GetPeerCredentials(_ net.Conn) (*PeerCredentials, error) {
	return nil, fmt.Errorf("nodeapi: auth: peer credentials not supported on %s", runtime.GOOS)
}
