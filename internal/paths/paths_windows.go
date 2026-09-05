//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

// programData returns %ProgramData%, the per-machine application data root.
// Windows sets the variable for every process, services included; the fallback
// covers one started with a stripped environment. It is read per call rather
// than once at init so a test can redirect it with t.Setenv.
//
// This follows diskRootPath in internal/actions/builtins_windows.go, which
// reads SystemDrive the same way.
func programData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

func configDir() string { return filepath.Join(programData(), "plexd") }

// dataDir is a directory below configDir rather than configDir itself, because
// plexd deregister --purge removes it whole and would otherwise delete
// config.yaml along with the identity.
func dataDir() string { return filepath.Join(programData(), "plexd", "data") }

func runDir() string { return filepath.Join(programData(), "plexd", "run") }

// socketPath is a named pipe: the local node API is served over the pipe
// namespace on Windows. That namespace is not a directory, so nothing here is
// derived from runDir. The run directory stays as it is, created by
// plexd install (internal/packaging/installer.go).
func socketPath() string { return `\\.\pipe\plexd` }
