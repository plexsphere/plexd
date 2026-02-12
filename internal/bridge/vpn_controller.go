package bridge

// VPNController abstracts OS-level WireGuard tunnel operations for site-to-site testability.
// All methods must be idempotent: repeating an operation that is already applied returns nil.
type VPNController interface {
	// CreateTunnelInterface creates a WireGuard interface for a site-to-site tunnel.
	// name is the interface name, listenPort is the UDP port.
	// Idempotent: creating an already-existing interface with the same config returns nil.
	CreateTunnelInterface(name string, listenPort int) error

	// RemoveTunnelInterface removes the WireGuard interface with the given name.
	// Idempotent: removing a non-existent interface returns nil.
	RemoveTunnelInterface(name string) error

	// ConfigureTunnelPeer configures the remote peer on the given tunnel interface.
	// publicKey is base64-encoded, allowedIPs are the remote subnets, endpoint is host:port.
	// psk may be empty if not used.
	// Idempotent: re-applying the same config returns nil.
	ConfigureTunnelPeer(iface string, publicKey string, allowedIPs []string, endpoint string, psk string) error

	// RemoveTunnelPeer removes the remote peer from the given tunnel interface.
	// Idempotent: removing a non-existent peer returns nil.
	RemoveTunnelPeer(iface string, publicKey string) error
}
