package packaging

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const maxTokenLength = 512

// Installer handles installing and uninstalling plexd as a systemd service.
type Installer struct {
	cfg     InstallConfig
	systemd SystemdController
	root    RootChecker
	logger  *slog.Logger
}

// NewInstaller creates a new Installer with defaults applied.
func NewInstaller(cfg InstallConfig, systemd SystemdController, root RootChecker, logger *slog.Logger) *Installer {
	cfg.ApplyDefaults()
	return &Installer{
		cfg:     cfg,
		systemd: systemd,
		root:    root,
		logger:  logger.With("component", "packaging"),
	}
}

// Install installs plexd as a systemd service.
func (ins *Installer) Install() error {
	// 1. Check root
	if !ins.root.IsRoot() {
		return errors.New("packaging: install requires root privileges")
	}

	// 2. Check systemd
	if !ins.systemd.IsAvailable() {
		return errors.New("packaging: systemd is not available")
	}

	// 3. Create directories
	dirs := []struct {
		path string
		perm os.FileMode
	}{
		{ins.cfg.ConfigDir, 0o755},
		{ins.cfg.DataDir, 0o700},
		{ins.cfg.RunDir, 0o755},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("packaging: create directory %s: %w", d.path, err)
		}
		ins.logger.Info("directory created", "path", d.path, "perm", fmt.Sprintf("%04o", d.perm))
	}

	// 4. Copy binary
	if err := ins.copyBinary(); err != nil {
		return err
	}

	// 5. Write default config if absent
	configPath := filepath.Join(ins.cfg.ConfigDir, "config.yaml")
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		content := GenerateDefaultConfig(ins.cfg.APIBaseURL)
		if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("packaging: write config: %w", err)
		}
		ins.logger.Info("default config written", "path", configPath)
	} else if err == nil {
		ins.logger.Info("existing config preserved", "path", configPath)
	} else {
		return fmt.Errorf("packaging: stat config: %w", err)
	}

	// 6. Write bootstrap token if provided
	if err := ins.writeToken(); err != nil {
		return err
	}

	// 7. Write unit file
	unitContent := GenerateUnitFile(ins.cfg)
	// Create parent directory for unit file if needed
	unitDir := filepath.Dir(ins.cfg.UnitFilePath)
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("packaging: create unit file directory: %w", err)
	}
	if err := os.WriteFile(ins.cfg.UnitFilePath, []byte(unitContent), 0o644); err != nil {
		return fmt.Errorf("packaging: write unit file: %w", err)
	}
	ins.logger.Info("unit file written", "path", ins.cfg.UnitFilePath)

	// 8. Daemon reload
	if err := ins.systemd.DaemonReload(); err != nil {
		return fmt.Errorf("packaging: daemon-reload: %w", err)
	}
	ins.logger.Info("systemd daemon reloaded")

	return nil
}

// Uninstall removes the plexd systemd service. If purge is true, data and config dirs are also removed.
func (ins *Installer) Uninstall(purge bool) error {
	// 1. Check root
	if !ins.root.IsRoot() {
		return errors.New("packaging: uninstall requires root privileges")
	}

	// 2. Check if installed (unit file exists)
	if _, err := os.Stat(ins.cfg.UnitFilePath); errors.Is(err, os.ErrNotExist) {
		ins.logger.Info("plexd is not installed, nothing to do")
		return nil
	}

	// 3. Stop service (ignore errors — service may not be running)
	if err := ins.systemd.Stop(ins.cfg.ServiceName); err != nil {
		ins.logger.Info("stop service", "error", err)
	}

	// 4. Disable service
	if err := ins.systemd.Disable(ins.cfg.ServiceName); err != nil {
		ins.logger.Info("disable service", "error", err)
	}

	// 5. Remove unit file
	if err := os.Remove(ins.cfg.UnitFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("packaging: remove unit file: %w", err)
	}
	ins.logger.Info("unit file removed", "path", ins.cfg.UnitFilePath)

	// 6. Daemon reload
	if err := ins.systemd.DaemonReload(); err != nil {
		return fmt.Errorf("packaging: daemon-reload: %w", err)
	}

	// 7. Remove binary
	if err := os.Remove(ins.cfg.BinaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("packaging: remove binary: %w", err)
	}
	ins.logger.Info("binary removed", "path", ins.cfg.BinaryPath)

	// 8. Purge directories if requested
	if purge {
		for _, dir := range []string{ins.cfg.DataDir, ins.cfg.ConfigDir} {
			if err := os.RemoveAll(dir); err != nil {
				return fmt.Errorf("packaging: remove directory %s: %w", dir, err)
			}
			ins.logger.Info("directory removed", "path", dir)
		}
	}

	return nil
}

func (ins *Installer) copyBinary() error {
	srcPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("packaging: resolve executable path: %w", err)
	}

	// Resolve symlinks
	srcPath, err = filepath.EvalSymlinks(srcPath)
	if err != nil {
		return fmt.Errorf("packaging: resolve symlinks: %w", err)
	}

	dstPath := ins.cfg.BinaryPath

	// Skip if source and destination are the same
	if srcPath == dstPath {
		ins.logger.Info("binary already at install path, skipping copy", "path", dstPath)
		return nil
	}

	// Create parent directory if needed
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("packaging: create binary directory: %w", err)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("packaging: open source binary: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("packaging: create destination binary: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("packaging: copy binary: %w", err)
	}

	ins.logger.Info("binary installed", "src", srcPath, "dst", dstPath)
	return nil
}

func (ins *Installer) writeToken() error {
	var tokenValue string

	if ins.cfg.TokenValue != "" {
		tokenValue = strings.TrimSpace(ins.cfg.TokenValue)
	} else if ins.cfg.TokenFile != "" {
		data, err := os.ReadFile(ins.cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("packaging: read token file %q: %w", ins.cfg.TokenFile, err)
		}
		tokenValue = strings.TrimSpace(string(data))
	}

	if tokenValue == "" {
		return nil // No token provided
	}

	// Validate token
	if err := validateInstallToken(tokenValue); err != nil {
		return err
	}

	tokenPath := filepath.Join(ins.cfg.ConfigDir, "bootstrap-token")
	if err := os.WriteFile(tokenPath, []byte(tokenValue), 0o600); err != nil {
		return fmt.Errorf("packaging: write bootstrap token: %w", err)
	}
	ins.logger.Info("bootstrap token written", "path", tokenPath)
	return nil
}

func validateInstallToken(token string) error {
	if len(token) > maxTokenLength {
		return fmt.Errorf("packaging: token exceeds maximum length of %d bytes", maxTokenLength)
	}
	for i := 0; i < len(token); i++ {
		if token[i] < 0x20 || token[i] > 0x7E {
			return errors.New("packaging: token contains non-printable characters")
		}
	}
	return nil
}
