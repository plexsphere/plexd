//go:build windows

package paths

import "testing"

// TestPaths_Windows pins the layout under %ProgramData%. The variable is set
// here rather than read from the runner, so the assertion is the same on every
// host: what is under test is how plexd composes the path, not what the CI
// image happens to set ProgramData to. The socket address is the named pipe,
// which ProgramData does not reach: it is the same string on every host.
func TestPaths_Windows(t *testing.T) {
	t.Setenv("ProgramData", `D:\PD`)

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigDir", ConfigDir(), `D:\PD\plexd`},
		{"DataDir", DataDir(), `D:\PD\plexd\data`},
		{"RunDir", RunDir(), `D:\PD\plexd\run`},
		{"ConfigFile", ConfigFile(), `D:\PD\plexd\config.yaml`},
		{"HooksDir", HooksDir(), `D:\PD\plexd\hooks`},
		{"TokenFile", TokenFile(), `D:\PD\plexd\bootstrap-token`},
		{"SocketPath", SocketPath(), `\\.\pipe\plexd`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestPaths_Windows_ProgramDataUnset covers the resolver's only shadow path.
// os.Getenv has no error return and reports an unset variable as the empty
// string, so an empty ProgramData is the single case programData has to answer
// for. Without the fallback the paths would be drive-relative — exactly the bug
// this package removes.
func TestPaths_Windows_ProgramDataUnset(t *testing.T) {
	t.Setenv("ProgramData", "")

	if got, want := ConfigDir(), `C:\ProgramData\plexd`; got != want {
		t.Errorf("ConfigDir() = %q, want %q", got, want)
	}
}
