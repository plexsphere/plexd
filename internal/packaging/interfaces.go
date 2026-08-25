package packaging

import (
	"context"
	"errors"
)

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

	// Start starts the named service.
	Start(service string) error

	// Stop stops the named service. Returns nil if the service is not running.
	Stop(service string) error

	// Restart restarts the named service. The caller may be the process being
	// restarted, so the command is run under ctx and returns once systemd has
	// accepted the request.
	Restart(ctx context.Context, service string) error

	// IsActive returns true if the named service is currently running.
	IsActive(service string) bool
}

// RootChecker abstracts privilege checking for testability.
type RootChecker interface {
	// IsRoot returns true if the current process has root privileges.
	IsRoot() bool
}

// ServiceStatus is what Status reports about a registered service.
type ServiceStatus string

const (
	// StatusRunning means the service is running.
	StatusRunning ServiceStatus = "running"

	// StatusStopped means the service is registered but not running.
	StatusStopped ServiceStatus = "stopped"
)

// ErrNotRegistered is returned by Status when the service definition is missing.
var ErrNotRegistered = errors.New("packaging: service is not registered")

// ServiceManager registers plexd with the host's service manager and drives
// the registered service. NewServiceManager returns the host's own: systemd
// on Linux and other Unix, launchd on macOS, the Service Control Manager on
// Windows. Every method takes the InstallConfig it acts on, so the service
// name and the definition path have one source.
type ServiceManager interface {
	// Name identifies the manager in messages: "systemd", "launchd" or
	// "service control manager".
	Name() string

	// Available reports whether the manager can be driven from this process.
	Available() bool

	// Registered reports whether the service definition exists.
	Registered(cfg InstallConfig) (bool, error)

	// Register writes the service definition so the service exists and is
	// known to the manager. It never starts the service. Repeating it
	// rewrites the same definition and returns nil.
	Register(cfg InstallConfig) error

	// Unregister stops the service if it runs and removes its definition.
	// A definition that is already gone is not an error.
	Unregister(cfg InstallConfig) error

	// Start starts the service now.
	Start(cfg InstallConfig) error

	// Stop stops the service and returns once it has stopped. A service
	// that is not running is not an error.
	Stop(cfg InstallConfig) error

	// Restart asks the manager to restart the service and returns once the
	// request is accepted. The caller may be the process being restarted,
	// so the restart itself completes after Restart returns.
	Restart(ctx context.Context, cfg InstallConfig) error

	// Status reports whether the service runs. It returns ErrNotRegistered
	// when the definition is missing.
	Status(cfg InstallConfig) (ServiceStatus, error)
}
