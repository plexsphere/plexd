//go:build darwin

package paths

import "testing"

// TestPaths_Darwin pins the macOS layout: application support data under
// /Library, runtime state under /var/run where a launchd daemon puts its
// socket. The space in "Application Support" is part of every path here, which
// is the detail a consumer that builds a shell command has to quote.
func TestPaths_Darwin(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigDir", ConfigDir(), "/Library/Application Support/plexd"},
		{"DataDir", DataDir(), "/Library/Application Support/plexd/data"},
		{"RunDir", RunDir(), "/var/run/plexd"},
		{"ConfigFile", ConfigFile(), "/Library/Application Support/plexd/config.yaml"},
		{"HooksDir", HooksDir(), "/Library/Application Support/plexd/hooks"},
		{"TokenFile", TokenFile(), "/Library/Application Support/plexd/bootstrap-token"},
		{"SocketPath", SocketPath(), "/var/run/plexd/api.sock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}
