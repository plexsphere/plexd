package bridge

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// TunnelConfig holds the configuration for creating a tunnel via a TunnelProvider.
type TunnelConfig struct {
	// TunnelID is the unique identifier for this tunnel.
	TunnelID string `json:"tunnel_id"`

	// LocalSubnets are the local CIDR subnets to expose through the tunnel.
	LocalSubnets []string `json:"local_subnets"`

	// RemoteSubnets are the remote CIDR subnets reachable through the tunnel.
	RemoteSubnets []string `json:"remote_subnets"`

	// RemoteEndpoint is the remote tunnel peer address (host:port or IP).
	RemoteEndpoint string `json:"remote_endpoint"`

	// PSK is the pre-shared key for tunnel authentication.
	PSK string `json:"psk"`

	// Extra holds provider-specific configuration parameters.
	Extra map[string]string `json:"extra,omitempty"`
}

// TunnelStatus represents the current status of a tunnel managed by a TunnelProvider.
type TunnelStatus struct {
	// TunnelID is the unique identifier for this tunnel.
	TunnelID string `json:"tunnel_id"`

	// Running indicates whether the tunnel is active.
	Running bool `json:"running"`

	// InterfaceName is the network interface used by the tunnel.
	InterfaceName string `json:"interface_name,omitempty"`

	// Error holds the last error message, if any.
	Error string `json:"error,omitempty"`
}

// tunnelIDPattern restricts tunnel IDs to safe alphanumeric strings with dashes.
// This prevents path traversal when tunnel IDs are used in file paths.
var tunnelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}$`)

// ValidateTunnelID checks that a tunnel ID is safe for use in file paths
// and shell arguments. Returns an error if the ID is invalid.
func ValidateTunnelID(id string) error {
	if !tunnelIDPattern.MatchString(id) {
		return fmt.Errorf("bridge: invalid tunnel ID %q: must match %s", id, tunnelIDPattern.String())
	}
	return nil
}

// ValidateTunnelConfig validates all fields of a TunnelConfig before they are
// interpolated into config files. This prevents newline injection and config
// injection in strongSwan/OpenVPN configurations.
func ValidateTunnelConfig(cfg TunnelConfig) error {
	if err := ValidateTunnelID(cfg.TunnelID); err != nil {
		return err
	}
	if strings.ContainsAny(cfg.RemoteEndpoint, "\n\r") {
		return fmt.Errorf("bridge: invalid remote endpoint %q: contains newline", cfg.RemoteEndpoint)
	}
	if strings.ContainsAny(cfg.PSK, "\n\r") {
		return fmt.Errorf("bridge: invalid PSK: contains newline")
	}
	if err := validateSubnets("local subnet", cfg.LocalSubnets); err != nil {
		return err
	}
	if err := validateSubnets("remote subnet", cfg.RemoteSubnets); err != nil {
		return err
	}
	return nil
}

// validateSubnets checks that no subnet string contains newline characters.
func validateSubnets(label string, subnets []string) error {
	for _, s := range subnets {
		if strings.ContainsAny(s, "\n\r") {
			return fmt.Errorf("bridge: invalid %s %q: contains newline", label, s)
		}
	}
	return nil
}

// DefaultTunnelConfigDir is the default directory used for tunnel config files.
// It is isolated from /tmp to prevent other users from reading PSK material.
const DefaultTunnelConfigDir = "/run/plexd/tunnels"

// ensureTunnelConfigDir creates the given directory with restrictive
// permissions (0700) if it does not already exist.
func ensureTunnelConfigDir(dir string) error {
	return os.MkdirAll(dir, 0700)
}

// TunnelProvider abstracts lifecycle management of non-WireGuard tunnel
// technologies (IPsec, OpenVPN, etc.) used for site-to-site connectivity
// via a bridge node.
//
// Implementations invoke the tunnel daemon/CLI to establish encrypted tunnels
// to external networks. The bridge manager uses TunnelProvider alongside the
// existing VPNController (WireGuard) to support heterogeneous site-to-site
// connectivity.
//
// All methods must be safe for concurrent use.
type TunnelProvider interface {
	// Name returns the provider identifier (e.g. "ipsec", "openvpn").
	Name() string

	// CreateTunnel establishes a tunnel with the given configuration.
	// The context controls the tunnel lifetime.
	// Returns an error if the tunnel cannot be created or already exists.
	CreateTunnel(ctx context.Context, cfg TunnelConfig) error

	// RemoveTunnel tears down the tunnel with the given ID.
	// Idempotent: removing a non-existent tunnel returns nil.
	RemoveTunnel(tunnelID string) error

	// TunnelStatus returns the status of the tunnel with the given ID.
	// Returns a zero-value TunnelStatus with Running=false if the tunnel
	// does not exist.
	TunnelStatus(tunnelID string) TunnelStatus

	// ActiveTunnels returns the IDs of all active tunnels.
	ActiveTunnels() []string

	// Stop gracefully shuts down all tunnels managed by this provider.
	// Idempotent: calling Stop when no tunnels are active returns nil.
	Stop() error
}
