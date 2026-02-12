package bridge

// AccessController abstracts WireGuard interface operations for user access testability.
// All methods must be idempotent: repeating an operation that is already applied returns nil.
type AccessController interface {
	// CreateInterface creates a WireGuard interface with the given name and listen port.
	// Idempotent: creating an already-existing interface with the same config returns nil.
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
