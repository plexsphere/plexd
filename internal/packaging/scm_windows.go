//go:build windows

package packaging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// stopTimeout bounds how long stop waits for the SCM to report
	// SERVICE_STOPPED: the daemon drains for up to 30 seconds (drainTimeout in
	// cmd/plexd/cmd/up.go), plus five for the process to exit.
	stopTimeout = 35 * time.Second

	// stopPollInterval is how often stop asks the SCM for the service state.
	stopPollInterval = 200 * time.Millisecond

	// recoveryResetPeriod is the window, in seconds, after which the SCM
	// forgets a service's failure count.
	recoveryResetPeriod = 60
)

// scmManager is the ServiceManager for Windows. The Service Control Manager
// keeps the service definition in its own database, so there is no file to
// write and cfg.UnitFilePath is unused here.
type scmManager struct{ logger *slog.Logger }

// NewSCMManager returns the Service Control Manager ServiceManager.
func NewSCMManager(logger *slog.Logger) ServiceManager {
	return &scmManager{logger: logger}
}

func (m *scmManager) Name() string { return "service control manager" }

// Available reports whether this process can open the SCM with the access an
// install needs. An elevated process and the LocalSystem service both can.
func (m *scmManager) Available() bool {
	c, err := mgr.Connect()
	if err != nil {
		return false
	}
	_ = c.Disconnect()
	return true
}

// commandLine is the BinaryPathName the SCM stores: the executable followed by
// the arguments the service is started with. It matches what CreateService
// builds from the same values, so a re-install through UpdateConfig writes the
// identical string.
func commandLine(cfg InstallConfig) string {
	configPath := filepath.Join(cfg.ConfigDir, "config.yaml")
	return syscall.EscapeArg(cfg.BinaryPath) + " " + syscall.EscapeArg("up") +
		" " + syscall.EscapeArg("--config") + " " + syscall.EscapeArg(configPath)
}

// serviceConfig is the SCM configuration plexd registers itself with. An empty
// ServiceStartName means LocalSystem.
func serviceConfig(cfg InstallConfig) mgr.Config {
	return mgr.Config{
		DisplayName:    "plexd node agent",
		Description:    "Plexsphere node agent. Registers the node, builds WireGuard mesh tunnels and enforces network policy.",
		StartType:      mgr.StartAutomatic,
		ErrorControl:   mgr.ErrorNormal,
		BinaryPathName: commandLine(cfg),
	}
}

// recoveryActions is the SCM's counterpart to the unit file's Restart=always
// and RestartSec=5s. The SCM applies the last action to every later failure,
// so three restarts plus SetRecoveryActionsOnNonCrashFailures restart the
// service indefinitely.
func recoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}
}

func (m *scmManager) Registered(cfg InstallConfig) (bool, error) {
	c, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("packaging: connect to service control manager: %w", err)
	}
	defer func() { _ = c.Disconnect() }()

	s, err := c.OpenService(cfg.ServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, fmt.Errorf("packaging: open service %s: %w", cfg.ServiceName, err)
	}
	_ = s.Close()
	return true, nil
}

func (m *scmManager) Register(cfg InstallConfig) error {
	c, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("packaging: connect to service control manager: %w", err)
	}
	defer func() { _ = c.Disconnect() }()

	configPath := filepath.Join(cfg.ConfigDir, "config.yaml")

	s, err := c.OpenService(cfg.ServiceName)
	switch {
	case err == nil:
		// A re-install: refresh the command line rather than fail.
		defer func() { _ = s.Close() }()
		if err := s.UpdateConfig(serviceConfig(cfg)); err != nil {
			return fmt.Errorf("packaging: update service: %w", err)
		}
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		s, err = c.CreateService(cfg.ServiceName, cfg.BinaryPath, serviceConfig(cfg), "up", "--config", configPath)
		if err != nil {
			return fmt.Errorf("packaging: create service: %w", err)
		}
		defer func() { _ = s.Close() }()
	default:
		return fmt.Errorf("packaging: open service %s: %w", cfg.ServiceName, err)
	}

	if err := s.SetRecoveryActions(recoveryActions(), recoveryResetPeriod); err != nil {
		return fmt.Errorf("packaging: set recovery actions: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("packaging: set recovery on non-crash failures: %w", err)
	}

	// Removing first makes the registration idempotent; the source may not
	// exist, which is why the error is dropped. InstallAsEventCreate points the
	// source at %SystemRoot%\System32\EventCreate.exe, whose message table
	// renders event ids 1 to 1000 as the message text, so plexd ships no
	// message DLL of its own.
	_ = eventlog.Remove(cfg.ServiceName)
	if err := eventlog.InstallAsEventCreate(cfg.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return fmt.Errorf("packaging: register event log source: %w", err)
	}

	m.logger.Info("service registered", "name", cfg.ServiceName, "binary", cfg.BinaryPath)
	return nil
}

func (m *scmManager) Unregister(cfg InstallConfig) error {
	c, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("packaging: connect to service control manager: %w", err)
	}
	defer func() { _ = c.Disconnect() }()

	s, err := c.OpenService(cfg.ServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("packaging: open service %s: %w", cfg.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	// Best effort: the service may not be running.
	if err := m.stop(s); err != nil {
		m.logger.Info("stop service", "error", err)
	}

	// The SCM completes the deletion once the last handle closes, which the
	// deferred Close does.
	if err := s.Delete(); err != nil {
		return fmt.Errorf("packaging: delete service: %w", err)
	}
	if err := eventlog.Remove(cfg.ServiceName); err != nil {
		m.logger.Info("remove event log source", "error", err)
	}
	return nil
}

// stop asks the SCM to stop the service and waits for it to report stopped.
func (m *scmManager) stop(s *mgr.Service) error {
	if _, err := s.Control(svc.Stop); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return fmt.Errorf("packaging: stop service: %w", err)
	}

	deadline := time.Now().Add(stopTimeout)
	for {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("packaging: query service: %w", err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("packaging: stop service: not stopped after %s", stopTimeout)
		}
		time.Sleep(stopPollInterval)
	}
}

func (m *scmManager) Start(cfg InstallConfig) error {
	c, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("packaging: connect to service control manager: %w", err)
	}
	defer func() { _ = c.Disconnect() }()

	s, err := c.OpenService(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("packaging: open service %s: %w", cfg.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Start(); err != nil {
		return fmt.Errorf("packaging: start service: %w", err)
	}
	return nil
}

func (m *scmManager) Stop(cfg InstallConfig) error {
	c, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("packaging: connect to service control manager: %w", err)
	}
	defer func() { _ = c.Disconnect() }()

	s, err := c.OpenService(cfg.ServiceName)
	if err != nil {
		return fmt.Errorf("packaging: open service %s: %w", cfg.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	return m.stop(s)
}

// Restart hands the request to a process that outlives the caller. The SCM has
// no restart control, and the caller is the service being restarted, so
// stopping it from inside would kill whatever was meant to start it again.
// Windows PowerShell 5.1 ships with every supported Windows, and
// Restart-Service waits for the stop before it starts.
//
// ctx is unused for that reason: the child must survive the caller's context.
func (m *scmManager) Restart(_ context.Context, cfg InstallConfig) error {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return fmt.Errorf("packaging: restart service: %w", err)
	}

	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Restart-Service -Name '%s'", cfg.ServiceName))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("packaging: restart service: %w", err)
	}
	return cmd.Process.Release()
}

func (m *scmManager) Status(cfg InstallConfig) (ServiceStatus, error) {
	c, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("packaging: connect to service control manager: %w", err)
	}
	defer func() { _ = c.Disconnect() }()

	s, err := c.OpenService(cfg.ServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "", ErrNotRegistered
		}
		return "", fmt.Errorf("packaging: open service %s: %w", cfg.ServiceName, err)
	}
	defer func() { _ = s.Close() }()

	status, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("packaging: query service: %w", err)
	}
	if status.State == svc.Running {
		return StatusRunning, nil
	}
	return StatusStopped, nil
}
