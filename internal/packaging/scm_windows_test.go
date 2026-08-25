//go:build windows

package packaging

import (
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// TestServiceConfig pins the service definition the SCM stores. The SCM calls
// themselves need a real Service Control Manager and are exercised on a Windows
// host rather than in CI, so what is under test here is the configuration those
// calls carry.
func TestServiceConfig(t *testing.T) {
	cfg := InstallConfig{
		BinaryPath:  `C:\Program Files\plexd\plexd.exe`,
		ConfigDir:   `C:\ProgramData\plexd`,
		ServiceName: "plexd",
	}

	got := serviceConfig(cfg)

	if want := "plexd node agent"; got.DisplayName != want {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, want)
	}
	if got.StartType != mgr.StartAutomatic {
		t.Errorf("StartType = %d, want mgr.StartAutomatic (%d)", got.StartType, mgr.StartAutomatic)
	}
	if got.ErrorControl != mgr.ErrorNormal {
		t.Errorf("ErrorControl = %d, want mgr.ErrorNormal (%d)", got.ErrorControl, mgr.ErrorNormal)
	}
	// The install path holds a space, so the executable must be quoted or the
	// SCM would read "C:\Program" as the binary and "Files\plexd\plexd.exe" as
	// its first argument. The config path has none and stays bare.
	want := `"C:\Program Files\plexd\plexd.exe" up --config C:\ProgramData\plexd\config.yaml`
	if got.BinaryPathName != want {
		t.Errorf("BinaryPathName = %q, want %q", got.BinaryPathName, want)
	}
	// An empty ServiceStartName is LocalSystem.
	if got.ServiceStartName != "" {
		t.Errorf("ServiceStartName = %q, want empty (LocalSystem)", got.ServiceStartName)
	}
}

// TestRecoveryActions is the SCM's side of the unit file's Restart=always and
// RestartSec=5s: the SCM applies the last action to every later failure, so
// three restarts keep the service coming back indefinitely.
func TestRecoveryActions(t *testing.T) {
	got := recoveryActions()

	if len(got) != 3 {
		t.Fatalf("recoveryActions() returned %d actions, want 3", len(got))
	}
	for i, action := range got {
		if action.Type != mgr.ServiceRestart {
			t.Errorf("action %d type = %d, want mgr.ServiceRestart (%d)", i, action.Type, mgr.ServiceRestart)
		}
		if action.Delay != 5*time.Second {
			t.Errorf("action %d delay = %s, want 5s", i, action.Delay)
		}
	}
}
