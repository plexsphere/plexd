package packaging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewSystemdController_ImplementsInterface(t *testing.T) {
	var _ SystemdController = NewSystemdController()
}

func TestNewRootChecker_ImplementsInterface(t *testing.T) {
	var _ RootChecker = NewRootChecker()
}

func TestRealSystemdController_IsAvailable(t *testing.T) {
	ctrl := NewSystemdController()
	// Just verify it returns a bool without panicking.
	// The actual value depends on the test environment.
	_ = ctrl.IsAvailable()
}

// --- systemdManager ---

// newTestSystemdManager returns a systemd manager over ctl and a config whose
// unit file lives under t.TempDir(), so the file flow runs on every platform.
func newTestSystemdManager(t *testing.T, ctl *mockSystemdController) (ServiceManager, InstallConfig) {
	t.Helper()
	cfg := InstallConfig{
		BinaryPath:   filepath.Join(t.TempDir(), "plexd"),
		ConfigDir:    filepath.Join(t.TempDir(), "etc"),
		DataDir:      filepath.Join(t.TempDir(), "data"),
		RunDir:       filepath.Join(t.TempDir(), "run"),
		UnitFilePath: filepath.Join(t.TempDir(), "systemd", "plexd.service"),
		ServiceName:  "plexd",
	}
	return NewSystemdManager(ctl, testLogger()), cfg
}

func TestSystemdManager_RegisterWritesUnitAndReloads(t *testing.T) {
	ctl := &mockSystemdController{available: true}
	mgr, cfg := newTestSystemdManager(t, ctl)

	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	data, err := os.ReadFile(cfg.UnitFilePath)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", cfg.UnitFilePath, err)
	}
	if !strings.Contains(string(data), "ExecStart=") {
		t.Errorf("unit file missing ExecStart directive, got:\n%s", data)
	}
	if ctl.daemonReloadCalls != 1 {
		t.Errorf("DaemonReload() called %d times, want 1", ctl.daemonReloadCalls)
	}
}

func TestSystemdManager_RegisterRequiresUnitFilePath(t *testing.T) {
	ctl := &mockSystemdController{available: true}
	mgr, cfg := newTestSystemdManager(t, ctl)
	cfg.UnitFilePath = ""

	err := mgr.Register(cfg)
	if err == nil {
		t.Fatal("Register() = nil, want error for empty UnitFilePath")
	}
	if want := "packaging: config: UnitFilePath is required"; err.Error() != want {
		t.Errorf("Register() error = %q, want %q", err.Error(), want)
	}
}

func TestSystemdManager_RegisteredMissingFile(t *testing.T) {
	ctl := &mockSystemdController{available: true}
	mgr, cfg := newTestSystemdManager(t, ctl)

	registered, err := mgr.Registered(cfg)
	if err != nil {
		t.Fatalf("Registered() = %v, want nil for a missing unit file", err)
	}
	if registered {
		t.Error("Registered() = true, want false for a missing unit file")
	}
}

func TestSystemdManager_UnregisterStopsDisablesRemovesReloads(t *testing.T) {
	ctl := &mockSystemdController{available: true}
	mgr, cfg := newTestSystemdManager(t, ctl)

	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}
	ctl.daemonReloadCalls = 0

	if err := mgr.Unregister(cfg); err != nil {
		t.Fatalf("Unregister() = %v", err)
	}

	if len(ctl.stopCalls) != 1 || ctl.stopCalls[0] != "plexd" {
		t.Errorf("Stop calls = %v, want [plexd]", ctl.stopCalls)
	}
	if len(ctl.disableCalls) != 1 || ctl.disableCalls[0] != "plexd" {
		t.Errorf("Disable calls = %v, want [plexd]", ctl.disableCalls)
	}
	if _, err := os.Stat(cfg.UnitFilePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(unit file) = %v, want os.ErrNotExist", err)
	}
	if ctl.daemonReloadCalls != 1 {
		t.Errorf("DaemonReload() called %d times, want 1", ctl.daemonReloadCalls)
	}
}

// A service that is not running answers systemctl stop with an error, and an
// uninstall that gave up there would leave the unit file behind for good.
func TestSystemdManager_UnregisterToleratesStopError(t *testing.T) {
	ctl := &mockSystemdController{available: true, stopErr: errors.New("unit not loaded")}
	mgr, cfg := newTestSystemdManager(t, ctl)

	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	if err := mgr.Unregister(cfg); err != nil {
		t.Fatalf("Unregister() = %v, want nil despite the Stop failure", err)
	}
	if _, err := os.Stat(cfg.UnitFilePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(unit file) = %v, want os.ErrNotExist", err)
	}
}

func TestSystemdManager_RestartCallsController(t *testing.T) {
	ctl := &mockSystemdController{available: true}
	mgr, cfg := newTestSystemdManager(t, ctl)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := mgr.Restart(ctx, cfg); err != nil {
		t.Fatalf("Restart() = %v", err)
	}
	if len(ctl.restartCalls) != 1 || ctl.restartCalls[0] != "plexd" {
		t.Errorf("Restart calls = %v, want [plexd]", ctl.restartCalls)
	}
	if ctl.restartCtx == nil || ctl.restartCtx.Err() == nil {
		t.Error("Restart() did not pass the caller's context through to the controller")
	}
}

func TestSystemdManager_StatusNotRegistered(t *testing.T) {
	ctl := &mockSystemdController{available: true}
	mgr, cfg := newTestSystemdManager(t, ctl)

	_, err := mgr.Status(cfg)
	if !errors.Is(err, ErrNotRegistered) {
		t.Errorf("Status() error = %v, want ErrNotRegistered", err)
	}
}

func TestSystemdManager_StatusRunning(t *testing.T) {
	ctl := &mockSystemdController{available: true, active: true}
	mgr, cfg := newTestSystemdManager(t, ctl)

	if err := mgr.Register(cfg); err != nil {
		t.Fatalf("Register() = %v", err)
	}

	status, err := mgr.Status(cfg)
	if err != nil {
		t.Fatalf("Status() = %v", err)
	}
	if status != StatusRunning {
		t.Errorf("Status() = %q, want %q", status, StatusRunning)
	}

	ctl.active = false
	status, err = mgr.Status(cfg)
	if err != nil {
		t.Fatalf("Status() = %v", err)
	}
	if status != StatusStopped {
		t.Errorf("Status() = %q, want %q", status, StatusStopped)
	}
}
