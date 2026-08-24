package paths

import (
	"path/filepath"
	"testing"
)

// TestPaths_Derived pins the four derived paths to their base directory, on
// whatever platform the test runs. The exact strings per platform are asserted
// by the tagged tests beside this file.
func TestPaths_Derived(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigFile", ConfigFile(), filepath.Join(ConfigDir(), "config.yaml")},
		{"HooksDir", HooksDir(), filepath.Join(ConfigDir(), "hooks")},
		{"TokenFile", TokenFile(), filepath.Join(ConfigDir(), "bootstrap-token")},
		{"SocketPath", SocketPath(), filepath.Join(RunDir(), "api.sock")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestPaths_Absolute keeps the defaults independent of the working directory.
// A relative default would resolve against wherever the daemon happened to be
// started, which on Windows is how "/var/run/plexd" used to land on whichever
// drive was current.
func TestPaths_Absolute(t *testing.T) {
	tests := []struct {
		name string
		got  string
	}{
		{"ConfigDir", ConfigDir()},
		{"DataDir", DataDir()},
		{"RunDir", RunDir()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !filepath.IsAbs(tt.got) {
				t.Errorf("%s() = %q, want an absolute path", tt.name, tt.got)
			}
		})
	}
}

// TestPaths_DataDirDistinct guards the invariant plexd deregister --purge
// relies on: it calls os.RemoveAll on the data directory, so a data directory
// equal to the configuration directory would delete config.yaml with the
// identity and still report success.
func TestPaths_DataDirDistinct(t *testing.T) {
	if DataDir() == ConfigDir() {
		t.Errorf("DataDir() and ConfigDir() are both %q, want distinct directories", DataDir())
	}
}
