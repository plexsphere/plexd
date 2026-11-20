package packaging

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const maxTokenLength = 512

// dirSpec is a directory Install creates, with the mode it creates it under.
type dirSpec struct {
	path string
	perm os.FileMode
}

// Installer handles installing and uninstalling plexd as a host service. It
// owns the files that are the same everywhere — the binary, the config, the
// token — and leaves the service definition to the host's ServiceManager.
type Installer struct {
	cfg    InstallConfig
	mgr    ServiceManager
	root   RootChecker
	logger *slog.Logger
}

// NewInstaller creates a new Installer with defaults applied.
func NewInstaller(cfg InstallConfig, mgr ServiceManager, root RootChecker, logger *slog.Logger) *Installer {
	cfg.ApplyDefaults()
	return &Installer{
		cfg:    cfg,
		mgr:    mgr,
		root:   root,
		logger: logger.With("component", "packaging"),
	}
}

// Install installs plexd as a host service.
func (ins *Installer) Install() error {
	// 1. Check privileges
	if !ins.root.IsRoot() {
		return fmt.Errorf("packaging: install requires %s privileges", privilegeName)
	}

	// 2. Check the host's service manager
	if !ins.mgr.Available() {
		return fmt.Errorf("packaging: %s is not available", ins.mgr.Name())
	}

	// 3. Read the CA bundle before anything is written, so an unusable
	// --ca-file leaves the host as it was.
	caPEM, err := ins.readCAFile()
	if err != nil {
		return err
	}

	// 4. Create directories. LogDir is empty wherever the service manager
	// keeps the logs itself, and then there is nothing to create. The hooks
	// directory is created here because plexd cannot create it under its
	// systemd unit, which keeps /etc read-only; the hook watcher only needs
	// it to exist.
	dirs := []dirSpec{
		{ins.cfg.ConfigDir, 0o755},
		{filepath.Join(ins.cfg.ConfigDir, "hooks"), 0o755},
		{ins.cfg.DataDir, 0o700},
		{ins.cfg.RunDir, 0o755},
	}
	if ins.cfg.LogDir != "" {
		dirs = append(dirs, dirSpec{ins.cfg.LogDir, 0o755})
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("packaging: create directory %s: %w", d.path, err)
		}
		ins.logger.Info("directory created", "path", d.path, "perm", fmt.Sprintf("%04o", d.perm))
	}

	// 5. Copy binary
	if err := ins.copyBinary(); err != nil {
		return err
	}

	// 6. Write default config if absent. An existing one is the operator's
	// and is never edited, so a CA bundle given now is installed but not
	// named in it.
	configPath := filepath.Join(ins.cfg.ConfigDir, "config.yaml")
	var caDst string
	if caPEM != nil {
		caDst = filepath.Join(ins.cfg.ConfigDir, InstalledCAFileName)
	}
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		content := GenerateDefaultConfig(ins.cfg.APIBaseURL, caDst)
		if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
			return fmt.Errorf("packaging: write config: %w", err)
		}
		ins.logger.Info("default config written", "path", configPath)
	} else if err == nil {
		ins.logger.Info("existing config preserved", "path", configPath)
		if caDst != "" {
			ins.logger.Warn("existing config preserved, api.tls_ca_file not written", "path", configPath, "tls_ca_file", caDst)
		}
	} else {
		return fmt.Errorf("packaging: stat config: %w", err)
	}

	// 7. Install the CA bundle if provided
	if err := ins.writeCAFile(caPEM); err != nil {
		return err
	}

	// 8. Write bootstrap token if provided
	if err := ins.writeToken(); err != nil {
		return err
	}

	// 9. Register the service. The manager never starts it: --api-url is
	// optional, so an install can legitimately precede a usable configuration.
	// Every manager already prefixes its errors with "packaging:".
	return ins.mgr.Register(ins.cfg)
}

// Uninstall removes the plexd host service. If purge is true, data and config dirs are also removed.
func (ins *Installer) Uninstall(purge bool) error {
	// 1. Check privileges
	if !ins.root.IsRoot() {
		return fmt.Errorf("packaging: uninstall requires %s privileges", privilegeName)
	}

	// 2. Check if installed
	registered, err := ins.mgr.Registered(ins.cfg)
	if err != nil {
		return fmt.Errorf("packaging: query service: %w", err)
	}
	if !registered {
		ins.logger.Info("plexd is not installed, nothing to do")
		return nil
	}

	// 3. Stop the service and remove its definition.
	if err := ins.mgr.Unregister(ins.cfg); err != nil {
		return err
	}

	// 4. Remove binary
	if err := ins.removeBinary(); err != nil {
		return err
	}

	// 5. Purge directories if requested
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

// readCAFile reads the bundle named by CAFile and returns only its
// certificates, each re-encoded as PEM. The copy is world-readable, so a
// combined PEM that also holds a private key must not carry the key into it.
// A certificate is re-encoded without the PEM headers its block may carry:
// plexd reads the copy with x509.CertPool.AppendCertsFromPEM, which skips a
// block that has headers, so an accepted certificate would otherwise be one
// plexd never trusts. An empty CAFile returns nil and no error.
func (ins *Installer) readCAFile() ([]byte, error) {
	path := ins.cfg.CAFile
	if path == "" {
		return nil, nil
	}
	rest, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("packaging: read CA file %q: %w", path, err)
	}

	var certs []byte
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			continue
		}
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("packaging: no certificate found in CA file %q", path)
	}
	return certs, nil
}

// writeCAFile writes the bundle readCAFile returned into the config directory.
// It needs no check for a CAFile that already names the destination: the
// bytes were read before anything was written. A nil pem writes nothing.
func (ins *Installer) writeCAFile(pem []byte) error {
	if pem == nil {
		return nil
	}
	dst := filepath.Join(ins.cfg.ConfigDir, InstalledCAFileName)
	if err := os.WriteFile(dst, pem, 0o644); err != nil {
		return fmt.Errorf("packaging: write CA file: %w", err)
	}
	ins.logger.Info("CA bundle installed", "src", ins.cfg.CAFile, "dst", dst)
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
