//go:build windows

package packaging

import (
	"log/slog"
	"os"
	"path/filepath"
)

// programFiles returns %ProgramFiles%, the per-machine program root. Windows
// sets the variable for every process, services included; the fallback covers
// one started with a stripped environment. It is read per call rather than once
// at init so a test can redirect it with t.Setenv.
//
// This follows programData in internal/paths/paths_windows.go, which reads
// ProgramData the same way.
func programFiles() string {
	if v := os.Getenv("ProgramFiles"); v != "" {
		return v
	}
	return `C:\Program Files`
}

func defaultBinaryPath() string { return filepath.Join(programFiles(), "plexd", "plexd.exe") }

// defaultUnitFilePath is empty because the Service Control Manager keeps the
// service definition in its own database, not in a file.
func defaultUnitFilePath() string { return "" }

// defaultLogDir is empty because the service writes to the Application Event
// Log under source plexd.
func defaultLogDir() string { return "" }

// NewServiceManager returns the host's own service manager.
func NewServiceManager(logger *slog.Logger) ServiceManager {
	return NewSCMManager(logger)
}
