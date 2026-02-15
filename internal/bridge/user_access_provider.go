package bridge

import "context"

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

// UserAccessProvider abstracts lifecycle management of external VPN providers
// (Tailscale, Netbird, etc.) used for user access into the mesh via a bridge node.
//
// Implementations invoke the provider's CLI or daemon to join an overlay network,
// then report status so the bridge can route traffic between the provider's
// interface and the mesh.
//
// All methods must be safe for concurrent use.
type UserAccessProvider interface {
	// Name returns the provider identifier (e.g. "tailscale", "netbird").
	Name() string

	// Start launches the provider daemon/process. The auth credential
	// (auth key, setup key) is read from the environment by the implementation.
	// The context controls the provider lifetime — cancelling it should trigger
	// a graceful stop.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the provider and removes its network interface.
	// Idempotent: calling Stop when not running returns nil.
	Stop() error

	// Status returns the current provider status.
	Status() ProviderStatus
}
