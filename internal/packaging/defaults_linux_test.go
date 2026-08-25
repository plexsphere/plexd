//go:build linux

package packaging

import "testing"

// TestDefaults_Linux is the byte-for-byte guarantee that moving the install
// paths behind per-platform resolvers left Linux exactly as it was. Every
// string below is the literal the installer shipped before this package
// answered for macOS and Windows too.
func TestDefaults_Linux(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"DefaultBinaryPath", DefaultBinaryPath, "/usr/local/bin/plexd"},
		{"DefaultUnitFilePath", DefaultUnitFilePath, "/etc/systemd/system/plexd.service"},
		{"DefaultLogDir", DefaultLogDir, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}
