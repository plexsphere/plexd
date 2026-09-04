//go:build unix

package actions

import (
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

// systemBin returns the first of paths that exists, and only falls back to a
// PATH lookup for distributions that place the binary elsewhere. plexd runs as
// root under systemd, so it must not take the first PATH match: an entry ahead
// of the system directories that an unprivileged account can write to would
// run with root rights. When neither finds the binary, the bare name is
// returned along with the lookup error, so a caller that cannot report the
// error still fails with the usual "executable file not found".
func systemBin(name string, paths ...string) (string, error) {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return name, err
	}
	return path, nil
}

// networkListCommand returns the command that lists the host's network
// interfaces. On macOS ifconfig is addressed by absolute path, because launchd
// starts the daemon with a minimal PATH.
func networkListCommand() (string, []string) {
	if runtime.GOOS == "darwin" {
		return "/sbin/ifconfig", []string{"-a"}
	}
	path, _ := systemBin("ip", "/usr/sbin/ip", "/sbin/ip")
	return path, []string{"addr", "show"}
}

// processListCommand returns the command that lists the host's processes. On
// macOS ps is addressed by absolute path, because launchd starts the daemon
// with a minimal PATH.
func processListCommand() (string, []string) {
	if runtime.GOOS == "darwin" {
		return "/bin/ps", []string{"aux"}
	}
	path, _ := systemBin("ps", "/usr/bin/ps", "/bin/ps")
	return path, []string{"aux", "--no-headers"}
}

// pingCommand returns the command that sends count echo requests to target. On
// macOS ping is addressed by absolute path, because launchd starts the daemon
// with a minimal PATH, and BSD ping reads -W in milliseconds where iputils
// reads it in seconds, so the same three-second wait is spelled differently.
func pingCommand(count, target string) (string, []string) {
	if runtime.GOOS == "darwin" {
		return "/sbin/ping", []string{"-c", count, "-W", "3000", target}
	}
	path, _ := systemBin("ping", "/usr/bin/ping", "/bin/ping")
	return path, []string{"-c", count, "-W", "3", target}
}

// pingSucceeded reports whether out holds a real echo reply. iputils and BSD
// ping both signal an unreachable peer through the exit status, which the
// caller already reads, so the output itself carries no further answer.
func pingSucceeded([]byte) bool { return true }

// tracerouteCommand returns the command that traces the route to target. On
// macOS traceroute is addressed by absolute path for the same reason as ping.
// Linux distributions do not all ship it, and place it in different
// directories, so there a missing binary is reported to the caller.
func tracerouteCommand(maxHops, target string) (string, []string, error) {
	args := []string{"-n", "-m", maxHops, "-w", "3", target}
	if runtime.GOOS == "darwin" {
		return "/usr/sbin/traceroute", args, nil
	}
	path, err := systemBin("traceroute", "/usr/sbin/traceroute", "/usr/bin/traceroute", "/bin/traceroute")
	if err != nil {
		return "", nil, err
	}
	return path, args, nil
}

// diskRootPath returns the filesystem path whose capacity diagnostics.collect
// reports as disk_total.
func diskRootPath() string {
	return "/"
}

// diskTotalBytes returns the total capacity of the filesystem holding path, or
// 0 when it cannot be determined.
func diskTotalBytes(path string) uint64 {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0
	}
	// Bsize is int64 on linux/amd64, int32 on linux/mipsle and uint32 on darwin.
	return st.Blocks * uint64(st.Bsize)
}

// kernelRelease returns the running kernel release, or "" when uname fails.
func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// sendReloadSignal asks the process to reload its configuration.
func sendReloadSignal(pid int) error {
	return unix.Kill(pid, unix.SIGHUP)
}

// replaceExecutable installs the verified binary at binaryPath. Unix allows
// renaming over a running executable, so this is a single atomic rename.
func replaceExecutable(tmpPath, binaryPath string) error {
	return os.Rename(tmpPath, binaryPath)
}
