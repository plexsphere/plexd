package wireguard

import "errors"

// Config holds the configuration for WireGuard tunnel management.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// InterfaceName is the WireGuard network interface name.
	// Default: "wg0"
	InterfaceName string

	// ListenPort is the UDP port WireGuard listens on.
	// Default: 51820
	ListenPort int

	// MTU is the interface MTU. 0 means system default.
	MTU int
}

// DefaultInterfaceName is the default WireGuard interface name.
const DefaultInterfaceName = "wg0"

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
