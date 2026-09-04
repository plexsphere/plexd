//go:build unix

package actions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
)

// TestPlatformCommandsOnDarwin pins the macOS branch of the platform commands:
// every binary is addressed by absolute path, because launchd starts the
// daemon with a minimal PATH and a lookup would run whatever the first
// writable entry provides, and ping is passed the BSD wait, which is in
// milliseconds rather than the seconds iputils reads. Linux resolves its own
// system paths and keeps the iputils flags, so the check is macOS-only.
func TestPlatformCommandsOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the absolute paths and the BSD wait are the macOS branch of the platform commands")
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
		{"networkListCommand", networkBin, "/sbin/ifconfig", networkArgs, []string{"-a"}},
		{"processListCommand", processBin, "/bin/ps", processArgs, []string{"aux"}},
		{"pingCommand", pingBin, "/sbin/ping", pingArgs, []string{"-c", "3", "-W", "3000", "10.99.0.2"}},
		{"tracerouteCommand", tracerouteBin, "/usr/sbin/traceroute", tracerouteArgs, []string{"-n", "-m", "20", "-w", "3", "10.99.0.2"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gotBin != tc.wantBin {
				t.Errorf("%s() = %q, want %q", tc.name, tc.gotBin, tc.wantBin)
			}
			if _, err := os.Stat(tc.wantBin); err != nil {
				t.Errorf("Stat(%q) = %v, want the macOS system binary", tc.wantBin, err)
			}
			if !slices.Equal(tc.gotArgs, tc.wantArgs) {
				t.Errorf("%s() args = %v, want %v", tc.name, tc.gotArgs, tc.wantArgs)
			}
		})
	}
}

// TestSystemBin pins the resolution order behind the Linux platform commands:
// an existing system path wins over a PATH entry of the same name, the lookup
// only answers where no system path holds the binary, and a binary that is
// nowhere comes back as the bare name plus the lookup error.
func TestSystemBin(t *testing.T) {
	system, planted := t.TempDir(), t.TempDir()
	write := func(dir string) string {
		t.Helper()
		p := filepath.Join(dir, "plexd-systembin")
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("WriteFile(%q) = %v", p, err)
		}
		return p
	}
	installed, plantedPath := write(system), write(planted)
	absent := filepath.Join(system, "absent")
	t.Setenv("PATH", planted)

	if got, err := systemBin("plexd-systembin", installed); err != nil || got != installed {
		t.Errorf("systemBin(installed) = %q, %v, want %q, <nil>", got, err, installed)
	}
	if got, err := systemBin("plexd-systembin", absent); err != nil || got != plantedPath {
		t.Errorf("systemBin(absent) = %q, %v, want the PATH hit %q, <nil>", got, err, plantedPath)
	}
	if got, err := systemBin("plexd-absent", absent); err == nil || got != "plexd-absent" {
		t.Errorf("systemBin(nowhere) = %q, %v, want %q and a lookup error", got, err, "plexd-absent")
	}
}

// TestPlatformCommandsOnLinux pins the Linux branch of the platform commands.
// plexd runs as root under systemd, so a PATH entry ahead of the system
// directories — a unit drop-in extending PATH, an operator shell carrying
// ~/bin — must not decide which binary runs. Every command is resolved here
// with a writable directory planted at the front of PATH; where the host ships
// the system binary, that one has to win.
func TestPlatformCommandsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the system paths and the PATH lookup are the Linux branch of the platform commands")
	}

	planted := t.TempDir()
	for _, name := range []string{"ip", "ps", "ping", "traceroute"} {
		if err := os.WriteFile(filepath.Join(planted, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("WriteFile(%q) = %v", name, err)
		}
	}
	t.Setenv("PATH", planted)

	tracerouteBin, _, err := tracerouteCommand("20", "10.99.0.2")
	if err != nil {
		t.Fatalf("tracerouteCommand() = %v", err)
	}
	pingBin, _ := pingCommand("3", "10.99.0.2")
	networkBin, _ := networkListCommand()
	processBin, _ := processListCommand()

	tests := []struct {
		name       string
		gotBin     string
		systemBins []string
	}{
		{"networkListCommand", networkBin, []string{"/usr/sbin/ip", "/sbin/ip"}},
		{"processListCommand", processBin, []string{"/usr/bin/ps", "/bin/ps"}},
		{"pingCommand", pingBin, []string{"/usr/bin/ping", "/bin/ping"}},
		{"tracerouteCommand", tracerouteBin, []string{"/usr/sbin/traceroute", "/usr/bin/traceroute", "/bin/traceroute"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := ""
			for _, p := range tc.systemBins {
				if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
					want = p
					break
				}
			}
			if want == "" {
				t.Skipf("none of %v is installed on this host", tc.systemBins)
			}
			if tc.gotBin != want {
				t.Errorf("%s() = %q, want %q: the planted PATH entry must not win", tc.name, tc.gotBin, want)
			}
		})
	}
}

// TestPingSucceeded pins the Unix reading of ping output: iputils and BSD ping
// both report an unreachable peer through the exit status, which the caller
// already reads, so the output is not consulted a second time.
func TestPingSucceeded(t *testing.T) {
	if !pingSucceeded([]byte("Request timed out")) {
		t.Error("pingSucceeded() = false, want true: the exit status is the Unix answer")
	}
}

func TestBuiltinServiceReloadConfig(t *testing.T) {
	// Ignore SIGHUP so the test process isn't killed.
	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)

	fn := ServiceReloadConfig()
	stdout, stderr, exitCode, err := fn(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s", err, stdout)
	}

	if _, ok := result["status"]; !ok {
		t.Error("missing key 'status' in JSON output")
	}
	if result["status"] != "reload_signal_sent" {
		t.Errorf("expected status='reload_signal_sent', got %q", result["status"])
	}
	if _, ok := result["pid"]; !ok {
		t.Error("missing key 'pid' in JSON output")
	}
}

func TestDiskTotalBytes_EmptyPath(t *testing.T) {
	// unix.Statfs("") fails with ENOENT, which diskTotalBytes reports as 0.
	if got := diskTotalBytes(""); got != 0 {
		t.Errorf("diskTotalBytes(%q) = %d, want 0", "", got)
	}
}

// TestReplaceExecutable pins the Unix swap: a single rename over the running
// executable, which Unix allows, leaving no copy behind.
func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "plexd")
	tmp := filepath.Join(dir, ".plexd-upgrade-1")

	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(target) = %v", err)
	}
	if err := os.WriteFile(tmp, []byte("new binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(tmp) = %v", err)
	}

	if err := replaceExecutable(tmp, target); err != nil {
		t.Fatalf("replaceExecutable() = %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) = %v", err)
	}
	if string(got) != "new binary" {
		t.Errorf("target = %q, want %q", got, "new binary")
	}
	if _, err := os.Stat(target + ".old"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(%q.old) = %v, want os.ErrNotExist: Unix keeps no copy", target, err)
	}
}
