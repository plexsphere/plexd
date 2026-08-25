// Package packaging installs plexd as a host service: a systemd unit on Linux,
// a launchd daemon on macOS, a Windows service on Windows.
package packaging

import (
	"errors"

	"github.com/plexsphere/plexd/internal/paths"
)

// InstallConfig holds the configuration for packaging and installing plexd as a host service.
// InstallConfig is passed as a constructor argument — no file I/O in this package.
type InstallConfig struct {
	// BinaryPath is the path to install the plexd binary.
	// Default: DefaultBinaryPath
	BinaryPath string

	// ConfigDir is the configuration directory.
	// Default: paths.ConfigDir()
	ConfigDir string

	// DataDir is the data directory.
	// Default: paths.DataDir()
	DataDir string

	// RunDir is the runtime directory.
	// Default: paths.RunDir()
	RunDir string

	// LogDir is the directory the service manager writes plexd's output to.
	// Empty where the manager keeps the logs itself (journald on Linux, the
	// Event Log on Windows).
	// Default: DefaultLogDir
	LogDir string

	// UnitFilePath is the path of the service definition file. Empty where the
	// manager keeps no file (the Service Control Manager on Windows).
	// Default: DefaultUnitFilePath
	UnitFilePath string

	// ServiceName is the name the host's service manager knows plexd by.
	// Default: plexd
	ServiceName string

	// APIBaseURL is the control plane API URL (optional).
	APIBaseURL string

	// TokenValue is the bootstrap token value (optional).
	TokenValue string

	// TokenFile is the path to the token file to copy from (optional).
	TokenFile string
}

// The install paths are resolved per platform, which is why they are vars
// rather than consts. Only the service name is the same everywhere.

// DefaultBinaryPath is the default path to install the plexd binary,
// resolved per platform by defaultBinaryPath.
var DefaultBinaryPath = defaultBinaryPath()

// DefaultConfigDir is the default configuration directory.
var DefaultConfigDir = paths.ConfigDir()

// DefaultDataDir is the default data directory.
var DefaultDataDir = paths.DataDir()

// DefaultRunDir is the default runtime directory.
var DefaultRunDir = paths.RunDir()

// DefaultLogDir is the default directory the service manager writes plexd's
// output to, resolved per platform by defaultLogDir. It is empty where the
// manager keeps the logs itself.
var DefaultLogDir = defaultLogDir()

// DefaultServiceName is the default service name.
const DefaultServiceName = "plexd"

// DefaultUnitFilePath is the default path of the service definition file,
// resolved per platform by defaultUnitFilePath. It is empty where the manager
// keeps no file.
var DefaultUnitFilePath = defaultUnitFilePath()

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
	if c.LogDir == "" {
		c.LogDir = DefaultLogDir
	}
	if c.ServiceName == "" {
		c.ServiceName = DefaultServiceName
	}
	if c.UnitFilePath == "" {
		c.UnitFilePath = DefaultUnitFilePath
	}
}

// Validate checks that required fields are set.
//
// UnitFilePath and LogDir are not required: the Service Control Manager keeps
// neither a definition file nor a log directory, and the two managers that do
// need one check it themselves.
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
	return nil
}
