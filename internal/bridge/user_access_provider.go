package bridge

import (
	"context"
	"time"
)

// vendorJoinTimeout bounds the commands a vendor client runs to join its
// network and read its state back (tailscale up and tailscale status, netbird
// up and netbird status), so a coordination server that never answers cannot
// hold the caller. It does not bound tailscaled: the daemon runs under the
// caller's context, which ends it.
const vendorJoinTimeout = 60 * time.Second

// ProviderStatus represents the current status of a user access VPN provider.
type ProviderStatus struct {
	// Running indicates whether the provider process is active.
	Running bool `json:"running"`

	// InterfaceName is the network interface created by the provider.
	InterfaceName string `json:"interface_name,omitempty"`

	// IP is the IP address assigned by the provider.
	IP string `json:"ip,omitempty"`

	// Error holds the last error message, if any.
	Error string `json:"error,omitempty"`
}

// UserAccessClient abstracts lifecycle management of the vendor clients
// (Tailscale, Netbird) that serve user access into the mesh via a bridge node.
// A client is the local program behind a user access provider of the control
// plane, and is named apart from it.
//
// Implementations invoke the vendor's CLI or daemon to join an overlay network,
// then report status so the bridge can route traffic between the client's
// interface and the mesh.
//
// All methods must be safe for concurrent use.
type UserAccessClient interface {
	// Name returns the client identifier (e.g. "tailscale", "netbird").
	Name() string

	// Start joins the vendor network with key, the vendor's auth key or setup
	// key. An empty key is refused before any command runs. The key travels
	// on the vendor CLI's command line and is never logged. meshCIDR is the
	// mesh prefix a client advertises as a route, where its vendor lets a
	// client advertise one; a client whose vendor defines routes elsewhere
	// ignores it. A daemon the client starts runs under ctx and ends with
	// it; the join commands run under a timeout of vendorJoinTimeout derived
	// from ctx. An error from the executor stays wrapped, so
	// errors.Is(err, exec.ErrNotFound) reports a missing binary.
	Start(ctx context.Context, key string, meshCIDR string) error

	// Stop gracefully shuts down the provider and removes its network interface.
	// Idempotent: calling Stop when not running returns nil.
	Stop() error

	// Status returns the current provider status.
	Status() ProviderStatus
}
