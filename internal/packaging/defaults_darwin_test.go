//go:build darwin

package packaging

import "testing"

// TestDefaults_Darwin pins the macOS layout: a LaunchDaemon plist keyed by the
// reverse-DNS label launchd knows the daemon by, and a log directory, because
// launchd writes the daemon's output to a file rather than to a journal.
func TestDefaults_Darwin(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"DefaultBinaryPath", DefaultBinaryPath, "/usr/local/bin/plexd"},
		{"DefaultUnitFilePath", DefaultUnitFilePath, "/Library/LaunchDaemons/com.plexsphere.plexd.plist"},
		{"DefaultLogDir", DefaultLogDir, "/Library/Logs/plexd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}
