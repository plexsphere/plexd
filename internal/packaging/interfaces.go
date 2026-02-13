package packaging

// SystemdController abstracts systemd service management for testability.
// All methods that modify state must be idempotent: repeating an operation
// that is already applied returns nil.
type SystemdController interface {
	// IsAvailable returns true if systemd (systemctl) is available on the system.
	IsAvailable() bool

	// DaemonReload executes systemctl daemon-reload to reload unit file changes.
	DaemonReload() error

	// Enable enables the named service to start on boot.
	Enable(service string) error

	// Disable disables the named service from starting on boot.
	Disable(service string) error

	// Stop stops the named service. Returns nil if the service is not running.
	Stop(service string) error

	// IsActive returns true if the named service is currently running.
	IsActive(service string) bool
}

// RootChecker abstracts privilege checking for testability.
type RootChecker interface {
	// IsRoot returns true if the current process has root privileges.
	IsRoot() bool
}
