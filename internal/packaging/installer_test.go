package packaging

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Mock SystemdController ---

type mockSystemdController struct {
	available       bool
	active          bool
	daemonReloadErr error
	enableErr       error
	disableErr      error
	stopErr         error

	daemonReloadCalls int
	enableCalls       []string
	disableCalls      []string
	stopCalls         []string
}

func (m *mockSystemdController) IsAvailable() bool { return m.available }
func (m *mockSystemdController) IsActive(_ string) bool { return m.active }

func (m *mockSystemdController) DaemonReload() error {
	m.daemonReloadCalls++
	return m.daemonReloadErr
}

func (m *mockSystemdController) Enable(service string) error {
	m.enableCalls = append(m.enableCalls, service)
	return m.enableErr
}

func (m *mockSystemdController) Disable(service string) error {
	m.disableCalls = append(m.disableCalls, service)
	return m.disableErr
}

func (m *mockSystemdController) Stop(service string) error {
	m.stopCalls = append(m.stopCalls, service)
	return m.stopErr
}

// --- Mock RootChecker ---

type mockRootChecker struct {
	isRoot bool
}

func (m *mockRootChecker) IsRoot() bool { return m.isRoot }

// --- Test helpers ---

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestInstaller creates an Installer with mock dependencies and paths under t.TempDir().
// It creates a fake source binary at a temp location and sets BinaryPath under tmpDir.
func newTestInstaller(t *testing.T, cfg InstallConfig, systemd *mockSystemdController, root *mockRootChecker) (*Installer, string) {
	t.Helper()
	tmpDir := t.TempDir()

	// Remap paths to temp directory
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = filepath.Join(tmpDir, "usr", "local", "bin", "plexd")
	}
	if cfg.ConfigDir == "" {
		cfg.ConfigDir = filepath.Join(tmpDir, "etc", "plexd")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(tmpDir, "var", "lib", "plexd")
	}
	if cfg.RunDir == "" {
		cfg.RunDir = filepath.Join(tmpDir, "var", "run", "plexd")
	}
	if cfg.UnitFilePath == "" {
		cfg.UnitFilePath = filepath.Join(tmpDir, "etc", "systemd", "system", "plexd.service")
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "plexd"
	}

	return NewInstaller(cfg, systemd, root, testLogger()), tmpDir
}

// --- Install tests ---

func TestInstall_RejectsNonRoot(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: false}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	err := ins.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error for non-root")
	}
	if !strings.Contains(err.Error(), "root privileges") {
		t.Errorf("Install() error = %q, want message about root privileges", err)
	}

	// Verify no files were created
	entries, readErr := os.ReadDir(tmpDir)
	if readErr != nil {
		t.Fatalf("ReadDir(%q) failed: %v", tmpDir, readErr)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files created, found %d entries in %s", len(entries), tmpDir)
	}
}

func TestInstall_RejectsNoSystemd(t *testing.T) {
	systemd := &mockSystemdController{available: false}
	root := &mockRootChecker{isRoot: true}
	ins, _ := newTestInstaller(t, InstallConfig{}, systemd, root)

	err := ins.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error for unavailable systemd")
	}
	if !strings.Contains(err.Error(), "systemd") {
		t.Errorf("Install() error = %q, want message about systemd", err)
	}
}

func TestInstall_CreatesDirectories(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	tests := []struct {
		name string
		path string
		perm os.FileMode
	}{
		{"ConfigDir", filepath.Join(tmpDir, "etc", "plexd"), 0o755},
		{"DataDir", filepath.Join(tmpDir, "var", "lib", "plexd"), 0o700},
		{"RunDir", filepath.Join(tmpDir, "var", "run", "plexd"), 0o755},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("Stat(%q) = %v", tt.path, err)
			}
			if !info.IsDir() {
				t.Errorf("%q is not a directory", tt.path)
			}
			got := info.Mode().Perm()
			if got != tt.perm {
				t.Errorf("%q perm = %04o, want %04o", tt.path, got, tt.perm)
			}
		})
	}
}

func TestInstall_CopiesBinary(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "usr", "local", "bin", "plexd")
	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatalf("Stat(%q) = %v", binaryPath, err)
	}
	if info.Size() == 0 {
		t.Error("binary file is empty")
	}

	perm := info.Mode().Perm()
	if perm != 0o755 {
		t.Errorf("binary perm = %04o, want 0755", perm)
	}
}

func TestInstall_WritesUnitFile(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	unitPath := filepath.Join(tmpDir, "etc", "systemd", "system", "plexd.service")
	data, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", unitPath, err)
	}

	content := string(data)
	if !strings.Contains(content, "[Unit]") {
		t.Error("unit file missing [Unit] section")
	}
	if !strings.Contains(content, "[Service]") {
		t.Error("unit file missing [Service] section")
	}
	if !strings.Contains(content, "[Install]") {
		t.Error("unit file missing [Install] section")
	}
	if !strings.Contains(content, "ExecStart=") {
		t.Error("unit file missing ExecStart directive")
	}
}

func TestInstall_CallsDaemonReload(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, _ := newTestInstaller(t, InstallConfig{}, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	if systemd.daemonReloadCalls < 1 {
		t.Errorf("DaemonReload() called %d times, want >= 1", systemd.daemonReloadCalls)
	}
}

func TestInstall_WritesDefaultConfig(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	configPath := filepath.Join(tmpDir, "etc", "plexd", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", configPath, err)
	}

	content := string(data)
	if !strings.Contains(content, "plexd configuration") {
		t.Errorf("default config missing expected content, got:\n%s", content)
	}
}

func TestInstall_PreservesExistingConfig(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	// Pre-create a config file
	configDir := filepath.Join(tmpDir, "etc", "plexd")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) = %v", configDir, err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	existingContent := "# my custom config\napi_url: https://custom.example.com\n"
	if err := os.WriteFile(configPath, []byte(existingContent), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) = %v", configPath, err)
	}

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", configPath, err)
	}
	if string(data) != existingContent {
		t.Errorf("config was overwritten, got:\n%s\nwant:\n%s", string(data), existingContent)
	}
}

func TestInstall_WritesTokenFromValue(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	cfg := InstallConfig{
		TokenValue: "test-token-123",
	}
	ins, tmpDir := newTestInstaller(t, cfg, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	tokenPath := filepath.Join(tmpDir, "etc", "plexd", "bootstrap-token")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", tokenPath, err)
	}
	if string(data) != "test-token-123" {
		t.Errorf("token = %q, want %q", string(data), "test-token-123")
	}

	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("Stat(%q) = %v", tokenPath, err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("token perm = %04o, want 0600", perm)
	}
}

func TestInstall_WritesTokenFromFile(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}

	// Create a temp token file
	tokenSrcDir := t.TempDir()
	tokenSrcPath := filepath.Join(tokenSrcDir, "token.txt")
	if err := os.WriteFile(tokenSrcPath, []byte("file-token-456\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) = %v", tokenSrcPath, err)
	}

	cfg := InstallConfig{
		TokenFile: tokenSrcPath,
	}
	ins, tmpDir := newTestInstaller(t, cfg, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	tokenPath := filepath.Join(tmpDir, "etc", "plexd", "bootstrap-token")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", tokenPath, err)
	}
	if string(data) != "file-token-456" {
		t.Errorf("token = %q, want %q", string(data), "file-token-456")
	}
}

func TestInstall_SkipsTokenWhenNoneProvided(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	tokenPath := filepath.Join(tmpDir, "etc", "plexd", "bootstrap-token")
	if _, err := os.Stat(tokenPath); err == nil {
		t.Errorf("bootstrap-token should not exist when no token is provided")
	}
}

func TestInstall_RejectsInvalidToken(t *testing.T) {
	t.Run("token at max length", func(t *testing.T) {
		systemd := &mockSystemdController{available: true}
		root := &mockRootChecker{isRoot: true}
		cfg := InstallConfig{
			TokenValue: strings.Repeat("a", 512),
		}
		ins, _ := newTestInstaller(t, cfg, systemd, root)

		err := ins.Install()
		if err != nil {
			t.Fatalf("Install() = %v, want nil for 512-byte token (max allowed)", err)
		}
	})

	t.Run("token too long", func(t *testing.T) {
		systemd := &mockSystemdController{available: true}
		root := &mockRootChecker{isRoot: true}
		cfg := InstallConfig{
			TokenValue: strings.Repeat("a", 513),
		}
		ins, _ := newTestInstaller(t, cfg, systemd, root)

		err := ins.Install()
		if err == nil {
			t.Fatal("Install() = nil, want error for token exceeding max length")
		}
		if !strings.Contains(err.Error(), "maximum length") {
			t.Errorf("Install() error = %q, want message about maximum length", err)
		}
	})

	t.Run("token with non-printable characters", func(t *testing.T) {
		systemd := &mockSystemdController{available: true}
		root := &mockRootChecker{isRoot: true}
		cfg := InstallConfig{
			TokenValue: "token-with-\x01-control-char",
		}
		ins, _ := newTestInstaller(t, cfg, systemd, root)

		err := ins.Install()
		if err == nil {
			t.Fatal("Install() = nil, want error for token with non-printable characters")
		}
		if !strings.Contains(err.Error(), "non-printable") {
			t.Errorf("Install() error = %q, want message about non-printable characters", err)
		}
	})
}

// --- Uninstall tests ---

func TestUninstall_StopsAndDisablesService(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	// Pre-create unit file so uninstall proceeds
	unitDir := filepath.Join(tmpDir, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) = %v", unitDir, err)
	}
	unitPath := filepath.Join(unitDir, "plexd.service")
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) = %v", unitPath, err)
	}

	// Pre-create binary
	binDir := filepath.Join(tmpDir, "usr", "local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) = %v", binDir, err)
	}
	binPath := filepath.Join(binDir, "plexd")
	if err := os.WriteFile(binPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q) = %v", binPath, err)
	}

	if err := ins.Uninstall(false); err != nil {
		t.Fatalf("Uninstall(false) = %v", err)
	}

	if len(systemd.stopCalls) != 1 || systemd.stopCalls[0] != "plexd" {
		t.Errorf("Stop calls = %v, want [plexd]", systemd.stopCalls)
	}
	if len(systemd.disableCalls) != 1 || systemd.disableCalls[0] != "plexd" {
		t.Errorf("Disable calls = %v, want [plexd]", systemd.disableCalls)
	}
}

func TestUninstall_PurgeRemovesAllDirs(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	// Pre-create directories and unit file
	configDir := filepath.Join(tmpDir, "etc", "plexd")
	dataDir := filepath.Join(tmpDir, "var", "lib", "plexd")
	unitDir := filepath.Join(tmpDir, "etc", "systemd", "system")
	binDir := filepath.Join(tmpDir, "usr", "local", "bin")

	for _, d := range []string{configDir, dataDir, unitDir, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) = %v", d, err)
		}
	}

	unitPath := filepath.Join(unitDir, "plexd.service")
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) = %v", unitPath, err)
	}
	binPath := filepath.Join(binDir, "plexd")
	if err := os.WriteFile(binPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q) = %v", binPath, err)
	}

	if err := ins.Uninstall(true); err != nil {
		t.Fatalf("Uninstall(true) = %v", err)
	}

	// DataDir and ConfigDir should be removed
	if _, err := os.Stat(dataDir); err == nil {
		t.Errorf("DataDir %q still exists after purge", dataDir)
	}
	if _, err := os.Stat(configDir); err == nil {
		t.Errorf("ConfigDir %q still exists after purge", configDir)
	}
}

func TestUninstall_NoPurgePreservesDirs(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	// Pre-create directories and unit file
	configDir := filepath.Join(tmpDir, "etc", "plexd")
	dataDir := filepath.Join(tmpDir, "var", "lib", "plexd")
	unitDir := filepath.Join(tmpDir, "etc", "systemd", "system")
	binDir := filepath.Join(tmpDir, "usr", "local", "bin")

	for _, d := range []string{configDir, dataDir, unitDir, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) = %v", d, err)
		}
	}

	unitPath := filepath.Join(unitDir, "plexd.service")
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) = %v", unitPath, err)
	}
	binPath := filepath.Join(binDir, "plexd")
	if err := os.WriteFile(binPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q) = %v", binPath, err)
	}

	if err := ins.Uninstall(false); err != nil {
		t.Fatalf("Uninstall(false) = %v", err)
	}

	// DataDir and ConfigDir should still exist
	if _, err := os.Stat(dataDir); err != nil {
		t.Errorf("DataDir %q should still exist after non-purge uninstall", dataDir)
	}
	if _, err := os.Stat(configDir); err != nil {
		t.Errorf("ConfigDir %q should still exist after non-purge uninstall", configDir)
	}
}

func TestUninstall_IdempotentWhenNotInstalled(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	ins, _ := newTestInstaller(t, InstallConfig{}, systemd, root)

	// No unit file exists, uninstall should return nil
	err := ins.Uninstall(false)
	if err != nil {
		t.Fatalf("Uninstall(false) = %v, want nil when not installed", err)
	}
}

func TestUninstall_RejectsNonRoot(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: false}
	ins, _ := newTestInstaller(t, InstallConfig{}, systemd, root)

	err := ins.Uninstall(false)
	if err == nil {
		t.Fatal("Uninstall() = nil, want error for non-root")
	}
	if !strings.Contains(err.Error(), "root privileges") {
		t.Errorf("Uninstall() error = %q, want message about root privileges", err)
	}
}

func TestInstall_DaemonReloadFailure(t *testing.T) {
	systemd := &mockSystemdController{
		available:       true,
		daemonReloadErr: errors.New("daemon-reload failed"),
	}
	root := &mockRootChecker{isRoot: true}
	ins, _ := newTestInstaller(t, InstallConfig{}, systemd, root)

	err := ins.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error for daemon-reload failure")
	}
	if !strings.Contains(err.Error(), "daemon-reload") {
		t.Errorf("Install() error = %q, want message about daemon-reload", err)
	}
}

func TestUninstall_DaemonReloadFailure(t *testing.T) {
	systemd := &mockSystemdController{
		available:       true,
		daemonReloadErr: errors.New("daemon-reload failed"),
	}
	root := &mockRootChecker{isRoot: true}
	ins, tmpDir := newTestInstaller(t, InstallConfig{}, systemd, root)

	// Pre-create unit file so uninstall proceeds past the "not installed" check
	unitDir := filepath.Join(tmpDir, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) = %v", unitDir, err)
	}
	unitPath := filepath.Join(unitDir, "plexd.service")
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) = %v", unitPath, err)
	}

	err := ins.Uninstall(false)
	if err == nil {
		t.Fatal("Uninstall() = nil, want error for daemon-reload failure")
	}
	if !strings.Contains(err.Error(), "daemon-reload") {
		t.Errorf("Uninstall() error = %q, want message about daemon-reload", err)
	}
}

func TestInstall_TokenFileReadFailure(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	cfg := InstallConfig{
		TokenFile: "/nonexistent/path/token.txt",
	}
	ins, _ := newTestInstaller(t, cfg, systemd, root)

	err := ins.Install()
	if err == nil {
		t.Fatal("Install() = nil, want error for unreadable token file")
	}
	if !strings.Contains(err.Error(), "read token file") {
		t.Errorf("Install() error = %q, want message about read token file", err)
	}
}

func TestInstall_WithAPIBaseURL(t *testing.T) {
	systemd := &mockSystemdController{available: true}
	root := &mockRootChecker{isRoot: true}
	cfg := InstallConfig{
		APIBaseURL: "https://api.example.com",
	}
	ins, tmpDir := newTestInstaller(t, cfg, systemd, root)

	if err := ins.Install(); err != nil {
		t.Fatalf("Install() = %v", err)
	}

	configPath := filepath.Join(tmpDir, "etc", "plexd", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", configPath, err)
	}

	content := string(data)
	if !strings.Contains(content, "https://api.example.com") {
		t.Errorf("default config missing API URL, got:\n%s", content)
	}
}
