package wireguard

import "errors"

// Config holds the configuration for WireGuard tunnel management.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// InterfaceName is the WireGuard network interface name.
	// Default: "plexd0"
	InterfaceName string `yaml:"interface_name"`

	// ListenPort is the UDP port WireGuard listens on.
	// Default: 51820
	ListenPort int `yaml:"listen_port"`

	// MTU is the interface MTU. 0 means system default.
	MTU int `yaml:"mtu"`

	// EdgePSK controls whether plexd fetches each edge's PSK from the control
	// plane and programs it on the peer. A pointer, so an unset key stays
	// distinguishable from an explicit false: WireGuard needs the same PSK on
	// both ends of a tunnel, so during a rolling upgrade an operator sets
	// `edge_psk: false` on upgraded nodes until every node of the Domain runs a
	// plexd that installs edge PSKs, and that false must survive ApplyDefaults.
	// Default: true (nil reads as enabled).
	EdgePSK *bool `yaml:"edge_psk"`
}

// EdgePSKEnabled returns the effective EdgePSK setting: true unless explicitly
// set to false.
func (c *Config) EdgePSKEnabled() bool {
	return c.EdgePSK == nil || *c.EdgePSK
}

// DefaultInterfaceName is the default WireGuard interface name.
const DefaultInterfaceName = "plexd0"

// DefaultListenPort is the default WireGuard UDP listen port.
const DefaultListenPort = 51820

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	if c.InterfaceName == "" {
		c.InterfaceName = DefaultInterfaceName
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultListenPort
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *Config) Validate() error {
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		return errors.New("wireguard: config: ListenPort must be between 1 and 65535")
	}
	if c.MTU < 0 {
		return errors.New("wireguard: config: MTU must not be negative")
	}
	return nil
}
