package bridge

import "errors"

// ErrNATUnavailable is returned by AddNATMasquerade on a platform whose route
// controller was built without a NAT backend. Bridge mode still runs without
// NAT when bridge.enable_nat is false.
var ErrNATUnavailable = errors.New("NAT masquerade is not available on this platform")

// NATController programs NAT masquerade for bridge egress.
// NetlinkRouteController implements it itself through nftables. The macOS and
// Windows route controllers delegate to one handed to their constructor,
// because on those platforms the firewall backend owns the NAT rules:
// PFController on macOS and WFPController on Windows. A controller built
// without one — which is what the tests do — fails AddNATMasquerade with
// ErrNATUnavailable.
// All methods must be idempotent: repeating an operation that is already
// applied returns nil.
type NATController interface {
	// AddNATMasquerade configures NAT masquerading for bridge egress.
	// Linux and macOS scope the translation to iface. Windows scopes it by
	// mesh source prefix through WinNAT, which cannot bind to an interface,
	// and ignores iface: mesh-sourced traffic is translated on its way out of
	// whichever adapter carries the route.
	AddNATMasquerade(iface string) error

	// RemoveNATMasquerade removes NAT masquerading from the given interface.
	// Idempotent: removing non-existent masquerade returns nil.
	RemoveNATMasquerade(iface string) error
}

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

	NATController
}
