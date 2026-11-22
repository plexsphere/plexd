package bridge

import (
	"errors"
	"time"
)

// ErrListenPortInUse reports that CreateInterface could not bind the listen
// port because another socket holds it. A caller tells a taken port from any
// other failure with errors.Is; the error that wraps it also wraps the cause
// the kernel reported.
var ErrListenPortInUse = errors.New("listen port in use")

// AccessController abstracts WireGuard interface operations for user access testability.
// Every method except CreateInterface must be idempotent: repeating an
// operation that is already applied returns nil.
type AccessController interface {
	// CreateInterface creates a WireGuard interface with the given name,
	// configures privateKey (32 raw bytes) and listenPort on it, assigns
	// address (a CIDR such as 10.98.0.1/24; empty leaves the interface
	// unnumbered) and brings it up. The caller owns the key, so an interface
	// created again under the same key keeps its public key.
	//
	// A failure after the interface exists removes it again. A listen port
	// another socket holds fails with an error wrapping ErrListenPortInUse
	// where the implementation can tell: NetlinkAccessController does, and
	// WGAccessController does over the utun controller on macOS.
	//
	// Not idempotent: a name that already exists fails with an error wrapping
	// os.ErrExist, which is what EEXIST is on Linux.
	CreateInterface(name string, privateKey []byte, listenPort int, address string) error

	// RemoveInterface removes the WireGuard interface with the given name.
	// Idempotent: removing a non-existent interface returns nil.
	RemoveInterface(name string) error

	// RemoveInterfaces removes every WireGuard interface whose name starts
	// with prefix, which is how a start clears the interfaces a killed
	// process left behind. Idempotent: with no such interface it returns nil.
	RemoveInterfaces(prefix string) error

	// ConfigurePeer adds or updates a peer on the given WireGuard interface.
	// Idempotent: re-applying the same peer config returns nil.
	ConfigurePeer(iface string, publicKey string, allowedIPs []string, psk string) error

	// RemovePeer removes a peer from the given WireGuard interface by public key.
	// Idempotent: removing a non-existent peer returns nil.
	RemovePeer(iface string, publicKey string) error

	// PeerHandshakes returns the time of the latest handshake of every peer
	// on the given interface, keyed by the peer's public key in standard
	// base64. A peer that never completed a handshake maps to the zero time.
	PeerHandshakes(iface string) (map[string]time.Time, error)
}
