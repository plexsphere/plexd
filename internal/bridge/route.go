package bridge

// RouteController abstracts OS-level routing and forwarding operations for testability.
// All methods must be idempotent: repeating an operation that is already applied returns nil.
type RouteController interface {
	// EnableForwarding enables IP forwarding between the mesh and access interfaces.
	EnableForwarding(meshIface, accessIface string) error

	// DisableForwarding reverses the forwarding setup.
	DisableForwarding(meshIface, accessIface string) error

	// AddRoute adds a route for the given CIDR subnet via the given interface.
	// Idempotent: adding an existing route returns nil.
	AddRoute(subnet, iface string) error

	// RemoveRoute removes the route for the given CIDR subnet via the given interface.
	// Idempotent: removing a non-existent route returns nil.
	RemoveRoute(subnet, iface string) error

	// AddNATMasquerade configures NAT masquerading on the given interface.
	AddNATMasquerade(iface string) error

	// RemoveNATMasquerade removes NAT masquerading from the given interface.
	// Idempotent: removing non-existent masquerade returns nil.
	RemoveNATMasquerade(iface string) error
}
