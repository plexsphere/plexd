package bridge

import (
	"fmt"
	"net"
	"time"
)

const (
	DefaultRelayListenPort  = 51821
	DefaultMaxRelaySessions = 100
	DefaultSessionTTL       = 5 * time.Minute

	DefaultUserAccessInterfaceName = "wg-access"
	DefaultUserAccessListenPort    = 51822
	DefaultMaxAccessPeers          = 50

	DefaultMaxIngressRules    = 20
	DefaultIngressDialTimeout = 10 * time.Second
)

// Config holds the configuration for bridge mode.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// Enabled controls whether bridge mode is active.
	// Default: false
	Enabled bool

	// AccessInterface is the name of the access-side network interface.
	AccessInterface string

	// AccessSubnets are the CIDR subnets reachable via the access-side interface.
	AccessSubnets []string

	// EnableNAT controls whether NAT masquerading is applied on the access-side interface.
	// nil means use default (true); explicit false disables NAT.
	EnableNAT *bool

	// RelayEnabled controls whether the bridge node serves as a relay.
	// Default: false. Requires Enabled=true.
	RelayEnabled bool

	// RelayListenPort is the UDP port for relay traffic.
	// Default: 51821
	RelayListenPort int

	// MaxRelaySessions is the maximum number of concurrent relay sessions.
	// Default: 100
	MaxRelaySessions int

	// SessionTTL is the time-to-live for relay sessions.
	// Default: 5m. Minimum: 30s.
	SessionTTL time.Duration

	// UserAccessEnabled controls whether user access integration is active.
	// Default: false. Requires Enabled=true.
	UserAccessEnabled bool

	// UserAccessInterfaceName is the name of the WireGuard interface for user access.
	// Default: "wg-access"
	UserAccessInterfaceName string

	// UserAccessListenPort is the UDP port for the user access WireGuard interface.
	// Default: 51822
	UserAccessListenPort int

	// MaxAccessPeers is the maximum number of concurrent user access peers.
	// Default: 50
	MaxAccessPeers int

	// IngressEnabled controls whether public ingress is active.
	// Default: false. Requires Enabled=true.
	IngressEnabled bool

	// MaxIngressRules is the maximum number of concurrent ingress rules.
	// Default: 20
	MaxIngressRules int

	// IngressDialTimeout is the timeout for dialing target mesh peers.
	// Default: 10s. Minimum: 1s.
	IngressDialTimeout time.Duration
}

// BoolPtr returns a pointer to the given bool value.
func BoolPtr(v bool) *bool { return &v }

// natEnabled returns the effective NAT setting: true unless explicitly set to false.
func (c *Config) natEnabled() bool {
	if c.EnableNAT == nil {
		return true
	}
	return *c.EnableNAT
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	// EnableNAT is handled via natEnabled(); nil means default true.
	if c.RelayListenPort == 0 {
		c.RelayListenPort = DefaultRelayListenPort
	}
	if c.MaxRelaySessions == 0 {
		c.MaxRelaySessions = DefaultMaxRelaySessions
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = DefaultSessionTTL
	}
	if c.UserAccessInterfaceName == "" {
		c.UserAccessInterfaceName = DefaultUserAccessInterfaceName
	}
	if c.UserAccessListenPort == 0 {
		c.UserAccessListenPort = DefaultUserAccessListenPort
	}
	if c.MaxAccessPeers == 0 {
		c.MaxAccessPeers = DefaultMaxAccessPeers
	}
	if c.MaxIngressRules == 0 {
		c.MaxIngressRules = DefaultMaxIngressRules
	}
	if c.IngressDialTimeout == 0 {
		c.IngressDialTimeout = DefaultIngressDialTimeout
	}
}

// Validate checks that configuration values are acceptable.
// When bridge mode is disabled, validation is skipped.
func (c *Config) Validate() error {
	if c.RelayEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: relay requires bridge mode to be enabled")
	}
	if c.UserAccessEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: user access requires bridge mode to be enabled")
	}
	if c.IngressEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: ingress requires bridge mode to be enabled")
	}
	if !c.Enabled {
		return nil
	}
	if c.AccessInterface == "" {
		return fmt.Errorf("bridge: config: AccessInterface is required when enabled")
	}
	if len(c.AccessSubnets) == 0 {
		return fmt.Errorf("bridge: config: at least one AccessSubnet is required when enabled")
	}
	for _, subnet := range c.AccessSubnets {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			return fmt.Errorf("bridge: config: invalid CIDR %q: %w", subnet, err)
		}
	}
	if c.RelayEnabled {
		if c.RelayListenPort < 1 || c.RelayListenPort > 65535 {
			return fmt.Errorf("bridge: config: RelayListenPort must be between 1 and 65535")
		}
		if c.MaxRelaySessions <= 0 {
			return fmt.Errorf("bridge: config: MaxRelaySessions must be positive when relay is enabled")
		}
		if c.SessionTTL < 30*time.Second {
			return fmt.Errorf("bridge: config: SessionTTL must be at least 30s")
		}
	}
	if c.UserAccessEnabled {
		if c.UserAccessListenPort < 1 || c.UserAccessListenPort > 65535 {
			return fmt.Errorf("bridge: config: UserAccessListenPort must be between 1 and 65535")
		}
		if c.UserAccessInterfaceName == "" {
			return fmt.Errorf("bridge: config: UserAccessInterfaceName is required when user access is enabled")
		}
		if c.MaxAccessPeers <= 0 {
			return fmt.Errorf("bridge: config: MaxAccessPeers must be positive when user access is enabled")
		}
	}
	if c.IngressEnabled {
		if c.MaxIngressRules <= 0 {
			return fmt.Errorf("bridge: config: MaxIngressRules must be positive when ingress is enabled")
		}
		if c.IngressDialTimeout < 1*time.Second {
			return fmt.Errorf("bridge: config: IngressDialTimeout must be at least 1s")
		}
	}
	return nil
}
