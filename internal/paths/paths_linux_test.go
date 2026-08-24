//go:build linux

package paths

import "testing"

// TestPaths_Linux is the byte-for-byte guarantee that moving the defaults
// behind this package left Linux exactly as it was. Every string below is the
// literal the agent shipped before internal/paths existed.
func TestPaths_Linux(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigDir", ConfigDir(), "/etc/plexd"},
		{"DataDir", DataDir(), "/var/lib/plexd"},
		{"RunDir", RunDir(), "/var/run/plexd"},
		{"ConfigFile", ConfigFile(), "/etc/plexd/config.yaml"},
		{"HooksDir", HooksDir(), "/etc/plexd/hooks"},
		{"TokenFile", TokenFile(), "/etc/plexd/bootstrap-token"},
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
