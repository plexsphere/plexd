package bridge

// AccessController abstracts WireGuard interface operations for user access testability.
// Every method except CreateInterface must be idempotent: repeating an
// operation that is already applied returns nil.
type AccessController interface {
	// CreateInterface creates a WireGuard interface with the given name and listen port.
	// Not idempotent: a name that already exists fails with an error wrapping
	// os.ErrExist, which is what EEXIST is on Linux.
	CreateInterface(name string, listenPort int) error

	// RemoveInterface removes the WireGuard interface with the given name.
	// Idempotent: removing a non-existent interface returns nil.
	RemoveInterface(name string) error

	// ConfigurePeer adds or updates a peer on the given WireGuard interface.
	// Idempotent: re-applying the same peer config returns nil.
	ConfigurePeer(iface string, publicKey string, allowedIPs []string, psk string) error

	// RemovePeer removes a peer from the given WireGuard interface by public key.
	// Idempotent: removing a non-existent peer returns nil.
	RemovePeer(iface string, publicKey string) error
}
