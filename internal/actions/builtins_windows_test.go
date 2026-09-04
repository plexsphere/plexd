//go:build windows

package actions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

// TestPlatformCommandsOnWindows pins the Windows branch of the platform
// commands: every binary is addressed by its System32 path, and the flags are
// the Windows spellings rather than the iputils ones. The service runs as
// LocalSystem, so a bare "ipconfig" would execute whatever a writable PATH
// entry ahead of System32 provides, with SYSTEM rights. traceroute is the
// sharpest case: Windows ships tracert.exe and no traceroute.exe, so every
// PATH hit for the Unix name — including a traceroute.bat, which PATHEXT makes
// executable — could only be a planted file.
func TestPlatformCommandsOnWindows(t *testing.T) {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory() = %v", err)
	}

	tracerouteBin, tracerouteArgs, err := tracerouteCommand("20", "10.99.0.2")
	if err != nil {
		t.Fatalf("tracerouteCommand() = %v", err)
	}
	pingBin, pingArgs := pingCommand("3", "10.99.0.2")
	networkBin, networkArgs := networkListCommand()
	processBin, processArgs := processListCommand()

	tests := []struct {
		name     string
		gotBin   string
		wantBin  string
		gotArgs  []string
		wantArgs []string
	}{
		{"networkListCommand", networkBin, filepath.Join(systemDir, "ipconfig.exe"), networkArgs, []string{"/all"}},
		{"processListCommand", processBin, filepath.Join(systemDir, "tasklist.exe"), processArgs, nil},
		{"pingCommand", pingBin, filepath.Join(systemDir, "ping.exe"), pingArgs, []string{"-n", "3", "-w", "3000", "10.99.0.2"}},
		{"tracerouteCommand", tracerouteBin, filepath.Join(systemDir, "tracert.exe"), tracerouteArgs, []string{"-d", "-h", "20", "-w", "3000", "10.99.0.2"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !filepath.IsAbs(tc.gotBin) {
				t.Errorf("%s() = %q, want an absolute path", tc.name, tc.gotBin)
			}
			if tc.gotBin != tc.wantBin {
				t.Errorf("%s() = %q, want %q", tc.name, tc.gotBin, tc.wantBin)
			}
			if !slices.Equal(tc.gotArgs, tc.wantArgs) {
				t.Errorf("%s() args = %v, want %v", tc.name, tc.gotArgs, tc.wantArgs)
			}
		})
	}
}

// TestPingSucceeded pins the reading of ping.exe output. The binary exits 0
// for any ICMP response, so diagnostics.ping_peer would report an unreachable
// peer as reachable if it went by the exit status alone: only a line carrying
// the TTL= token of an echo reply counts as a success.
func TestPingSucceeded(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "echo reply",
			out: "Pinging 10.99.0.2 with 32 bytes of data:\r\n" +
				"Reply from 10.99.0.2: bytes=32 time<1ms TTL=128\r\n",
			want: true,
		},
		{
			name: "localized echo reply",
			out:  "Antwort von 10.99.0.2: Bytes=32 Zeit<1ms TTL=128\r\n",
			want: true,
		},
		{
			name: "destination host unreachable",
			out: "Pinging 10.99.0.2 with 32 bytes of data:\r\n" +
				"Reply from 10.99.0.1: Destination host unreachable.\r\n",
			want: false,
		},
		{
			name: "ttl expired in transit",
			out:  "Reply from 10.99.0.1: TTL expired in transit.\r\n",
			want: false,
		},
		{
			name: "request timed out",
			out:  "Request timed out.\r\n",
			want: false,
		},
		{
			name: "no output",
			out:  "",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pingSucceeded([]byte(tc.out)); got != tc.want {
				t.Errorf("pingSucceeded(%q) = %t, want %t", tc.out, got, tc.want)
			}
		})
	}
}

func TestBuiltinServiceReloadConfig_Unsupported(t *testing.T) {
	fn := ServiceReloadConfig()
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if !errors.Is(err, errReloadSignalUnsupported) {
		t.Fatalf("expected errReloadSignalUnsupported, got %v", err)
	}
	if want := "actions: reload config: reload signal not supported on windows; restart the service instead"; err.Error() != want {
		t.Errorf("error text = %q, want %q", err.Error(), want)
	}
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if stdout != "" {
		t.Errorf("expected empty stdout, got %q", stdout)
	}
	if stderr != "" {
		t.Errorf("expected empty stderr, got %q", stderr)
	}
}

// TestReplaceExecutable pins the Windows swap. Windows refuses to rename over a
// running image, so the running executable is moved aside first and the copy
// stays until the next upgrade removes it.
func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plexd.exe")
	old := target + ".old"

	writeTmp := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatalf("WriteFile(%q) = %v", p, err)
		}
		return p
	}

	if err := os.WriteFile(target, []byte("v1 binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(target) = %v", err)
	}

	if err := replaceExecutable(writeTmp(".plexd-upgrade-1", "v2 binary"), target); err != nil {
		t.Fatalf("replaceExecutable() = %v", err)
	}
	if got := readFile(t, target); got != "v2 binary" {
		t.Errorf("target = %q, want %q", got, "v2 binary")
	}
	if got := readFile(t, old); got != "v1 binary" {
		t.Errorf("%q = %q, want the previous binary %q", old, got, "v1 binary")
	}

	// A second upgrade replaces the stale .old rather than failing on it.
	if err := replaceExecutable(writeTmp(".plexd-upgrade-2", "v3 binary"), target); err != nil {
		t.Fatalf("second replaceExecutable() = %v", err)
	}
	if got := readFile(t, target); got != "v3 binary" {
		t.Errorf("target = %q, want %q", got, "v3 binary")
	}
	if got := readFile(t, old); got != "v2 binary" {
		t.Errorf("%q = %q, want the previous binary %q", old, got, "v2 binary")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) = %v", path, err)
	}
	return string(data)
}
