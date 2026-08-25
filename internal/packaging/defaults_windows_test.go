//go:build windows

package packaging

import "testing"

// TestDefaults_Windows pins the binary under %ProgramFiles%. The variable is
// set here rather than read from the runner, so the assertion is the same on
// every host: what is under test is how plexd composes the path, not what the
// CI image happens to set ProgramFiles to. DefaultBinaryPath is resolved at
// init, so the resolver is called directly.
func TestDefaults_Windows(t *testing.T) {
	t.Setenv("ProgramFiles", `D:\PF`)

	if got, want := defaultBinaryPath(), `D:\PF\plexd\plexd.exe`; got != want {
		t.Errorf("defaultBinaryPath() = %q, want %q", got, want)
	}
	if got := defaultUnitFilePath(); got != "" {
		t.Errorf("defaultUnitFilePath() = %q, want empty: the SCM keeps no definition file", got)
	}
	if got := defaultLogDir(); got != "" {
		t.Errorf("defaultLogDir() = %q, want empty: the service writes to the Event Log", got)
	}
}

// TestDefaults_Windows_ProgramFilesUnset covers the resolver's only shadow
// path. os.Getenv has no error return and reports an unset variable as the
// empty string, so an empty ProgramFiles is the single case programFiles has
// to answer for; without the fallback the path would be drive-relative.
func TestDefaults_Windows_ProgramFilesUnset(t *testing.T) {
	t.Setenv("ProgramFiles", "")

	if got, want := defaultBinaryPath(), `C:\Program Files\plexd\plexd.exe`; got != want {
		t.Errorf("defaultBinaryPath() = %q, want %q", got, want)
	}
}
