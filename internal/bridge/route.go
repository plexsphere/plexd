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

// UserAccessInterfacePrefix begins the name of every kernel interface plexd
// creates for a wireguard user access provider, so that the interfaces a
// killed process left behind can be found by their name.
const UserAccessInterfacePrefix = "wg-ua-"

// MeshSourceRewriter rewrites the source address of packets forwarded from a
// user access interface into the mesh to the address of the mesh interface,
// the bridge's mesh address. A mesh node accepts from the bridge only that
// address, so a packet that kept a device's address would be dropped by the
// first peer it meets.
// It is a dependency of its own rather than a method of NATController, so a
// NAT backend need not implement it. NetlinkRouteController implements it
// through nftables, and policy.PFController through pf on macOS, beside the
// NAT rule it holds. The WinNAT backend on Windows does not implement it.
// All methods must be idempotent.
type MeshSourceRewriter interface {
	// AddMeshSourceRewrite rewrites the source of packets that arrive on
	// fromIface and leave through meshIface. A rewrite that exists for
	// fromIface is left alone.
	AddMeshSourceRewrite(fromIface, meshIface string) error

	// RemoveMeshSourceRewrite removes the rewrite for fromIface.
	// Idempotent: removing a rewrite that does not exist returns nil.
	RemoveMeshSourceRewrite(fromIface, meshIface string) error

	// ResetMeshSourceRewrite removes every rewrite, also those a process
	// that was killed left behind.
	// Idempotent: resetting when no rewrite exists returns nil.
	ResetMeshSourceRewrite() error
}

// NATExempter keeps the host's NAT from translating what is forwarded between
// the mesh interface and a tunnel's link. Windows needs it while a NetNat
// object covers the mesh prefix. All methods must be idempotent.
type NATExempter interface {
	ExemptFromNAT(iface string) error
	UnexemptFromNAT(iface string) error
	ResetNATExemptions() error
}

// CleanupUserAccess removes what a process that was killed left behind: every
// interface whose name starts with UserAccessInterfacePrefix, through
// access.RemoveInterfaces, and with a rewriter every mesh source rewrite,
// through rewriter.ResetMeshSourceRewrite. A nil access or rewriter is
// skipped. Both run; their errors are joined.
//
// Without it a provider's next CreateInterface fails on the name the killed
// process left, and an interface of a bridge that opted out since keeps its
// port open.
func CleanupUserAccess(access AccessController, rewriter MeshSourceRewriter) error {
	var errs []error
	if access != nil {
		if err := access.RemoveInterfaces(UserAccessInterfacePrefix); err != nil {
			errs = append(errs, err)
		}
	}
	if rewriter != nil {
		if err := rewriter.ResetMeshSourceRewrite(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
