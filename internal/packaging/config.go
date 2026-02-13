// Package packaging implements systemd service packaging for bare-metal Linux servers.
package packaging

import (
	"errors"
)

// InstallConfig holds the configuration for packaging and installing plexd as a systemd service.
// InstallConfig is passed as a constructor argument — no file I/O in this package.
type InstallConfig struct {
	// BinaryPath is the path to install the plexd binary.
	// Default: /usr/local/bin/plexd
	BinaryPath string

	// ConfigDir is the configuration directory.
	// Default: /etc/plexd
	ConfigDir string

	// DataDir is the data directory.
	// Default: /var/lib/plexd
	DataDir string

	// RunDir is the runtime directory.
	// Default: /var/run/plexd
	RunDir string

	// UnitFilePath is the path for the systemd unit file.
	// Default: /etc/systemd/system/plexd.service
	UnitFilePath string

	// ServiceName is the systemd service name.
	// Default: plexd
	ServiceName string

	// APIBaseURL is the control plane API URL (optional).
	APIBaseURL string

	// TokenValue is the bootstrap token value (optional).
	TokenValue string

	// TokenFile is the path to the token file to copy from (optional).
	TokenFile string
}

// DefaultBinaryPath is the default path to install the plexd binary.
const DefaultBinaryPath = "/usr/local/bin/plexd"

// DefaultConfigDir is the default configuration directory.
const DefaultConfigDir = "/etc/plexd"

// DefaultDataDir is the default data directory.
const DefaultDataDir = "/var/lib/plexd"

// DefaultRunDir is the default runtime directory.
const DefaultRunDir = "/var/run/plexd"

// DefaultServiceName is the default systemd service name.
const DefaultServiceName = "plexd"

// DefaultUnitFilePath is the default path for the systemd unit file.
const DefaultUnitFilePath = "/etc/systemd/system/plexd.service"

// ApplyDefaults sets default values for zero-valued fields.
func (c *InstallConfig) ApplyDefaults() {
	if c.BinaryPath == "" {
		c.BinaryPath = DefaultBinaryPath
	}
	if c.ConfigDir == "" {
		c.ConfigDir = DefaultConfigDir
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if c.RunDir == "" {
		c.RunDir = DefaultRunDir
	}
	if c.ServiceName == "" {
		c.ServiceName = DefaultServiceName
	}
	if c.UnitFilePath == "" {
		c.UnitFilePath = DefaultUnitFilePath
	}
}

// Validate checks that required fields are set.
func (c *InstallConfig) Validate() error {
	if c.BinaryPath == "" {
		return errors.New("packaging: config: BinaryPath is required")
	}
	if c.ConfigDir == "" {
		return errors.New("packaging: config: ConfigDir is required")
	}
	if c.DataDir == "" {
		return errors.New("packaging: config: DataDir is required")
	}
	if c.RunDir == "" {
		return errors.New("packaging: config: RunDir is required")
	}
	if c.ServiceName == "" {
		return errors.New("packaging: config: ServiceName is required")
	}
	if c.UnitFilePath == "" {
		return errors.New("packaging: config: UnitFilePath is required")
	}
	return nil
}
