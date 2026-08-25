package packaging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// realSystemdController implements SystemdController using os/exec to call systemctl.
type realSystemdController struct{}

// NewSystemdController returns a SystemdController that calls the real systemctl binary.
func NewSystemdController() SystemdController {
	return &realSystemdController{}
}

func (c *realSystemdController) IsAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func (c *realSystemdController) DaemonReload() error {
	return c.run("daemon-reload")
}

func (c *realSystemdController) Enable(service string) error {
	return c.run("enable", service)
}

func (c *realSystemdController) Disable(service string) error {
	return c.run("disable", service)
}

func (c *realSystemdController) Start(service string) error {
	return c.run("start", service)
}

func (c *realSystemdController) Stop(service string) error {
	return c.run("stop", service)
}

// Restart runs systemctl restart under ctx. The caller is usually the daemon
// being restarted, so systemd may kill this process — and the systemctl child
// inside its cgroup — before the command returns. That is the same best effort
// the action had when it shelled out to systemctl itself.
func (c *realSystemdController) Restart(ctx context.Context, service string) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("packaging: systemctl restart: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func (c *realSystemdController) IsActive(service string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", service).Run()
	return err == nil
}

func (c *realSystemdController) run(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("packaging: systemctl %s: %s: %w", args[0], strings.TrimSpace(string(output)), err)
	}
	return nil
}

// systemdManager is the ServiceManager for hosts with systemd. The unit file
// is the definition; systemctl is driven through a SystemdController so the
// file flow is testable without systemd.
type systemdManager struct {
	ctl    SystemdController
	logger *slog.Logger
}

// NewSystemdManager returns the systemd ServiceManager over ctl.
func NewSystemdManager(ctl SystemdController, logger *slog.Logger) ServiceManager {
	return &systemdManager{ctl: ctl, logger: logger}
}

func (m *systemdManager) Name() string { return "systemd" }

func (m *systemdManager) Available() bool { return m.ctl.IsAvailable() }

func (m *systemdManager) Registered(cfg InstallConfig) (bool, error) {
	if cfg.UnitFilePath == "" {
		return false, errors.New("packaging: config: UnitFilePath is required")
	}
	if _, err := os.Stat(cfg.UnitFilePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("packaging: stat unit file: %w", err)
	}
	return true, nil
}

func (m *systemdManager) Register(cfg InstallConfig) error {
	if cfg.UnitFilePath == "" {
		return errors.New("packaging: config: UnitFilePath is required")
	}

	unitContent := GenerateUnitFile(cfg)
	if err := os.MkdirAll(filepath.Dir(cfg.UnitFilePath), 0o755); err != nil {
		return fmt.Errorf("packaging: create unit file directory: %w", err)
	}
	if err := os.WriteFile(cfg.UnitFilePath, []byte(unitContent), 0o644); err != nil {
		return fmt.Errorf("packaging: write unit file: %w", err)
	}
	m.logger.Info("unit file written", "path", cfg.UnitFilePath)

	if err := m.ctl.DaemonReload(); err != nil {
		return fmt.Errorf("packaging: daemon-reload: %w", err)
	}
	m.logger.Info("systemd daemon reloaded")
	return nil
}

func (m *systemdManager) Unregister(cfg InstallConfig) error {
	// Stop and disable are best effort: the service may not be running, and
	// may never have been enabled.
	if err := m.ctl.Stop(cfg.ServiceName); err != nil {
		m.logger.Info("stop service", "error", err)
	}
	if err := m.ctl.Disable(cfg.ServiceName); err != nil {
		m.logger.Info("disable service", "error", err)
	}

	if err := os.Remove(cfg.UnitFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("packaging: remove unit file: %w", err)
	}
	m.logger.Info("unit file removed", "path", cfg.UnitFilePath)

	if err := m.ctl.DaemonReload(); err != nil {
		return fmt.Errorf("packaging: daemon-reload: %w", err)
	}
	return nil
}

func (m *systemdManager) Start(cfg InstallConfig) error { return m.ctl.Start(cfg.ServiceName) }

func (m *systemdManager) Stop(cfg InstallConfig) error { return m.ctl.Stop(cfg.ServiceName) }

func (m *systemdManager) Restart(ctx context.Context, cfg InstallConfig) error {
	return m.ctl.Restart(ctx, cfg.ServiceName)
}

func (m *systemdManager) Status(cfg InstallConfig) (ServiceStatus, error) {
	registered, err := m.Registered(cfg)
	if err != nil {
		return "", err
	}
	if !registered {
		return "", ErrNotRegistered
	}
	if m.ctl.IsActive(cfg.ServiceName) {
		return StatusRunning, nil
	}
	return StatusStopped, nil
}
