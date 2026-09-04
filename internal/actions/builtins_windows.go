//go:build windows

package actions

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// systemDirBin returns the absolute path of the helper binary name in the
// Windows system directory. The service runs as LocalSystem, so a bare name
// would be resolved through %PATH%, and exec.LookPath returns the first match
// in PATH order rather than the System32 one: a machine-PATH entry ahead of
// System32 that an unprivileged user can write to would then run with SYSTEM
// rights. GetSystemDirectory is the authoritative answer; %SystemRoot% is set
// by the kernel for every session and only serves as a fallback.
func systemDirBin(name string) string {
	dir, err := windows.GetSystemDirectory()
	if err != nil || dir == "" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		dir = filepath.Join(root, "System32")
	}
	return filepath.Join(dir, name)
}

// networkListCommand returns the command that lists the host's network
// interfaces.
func networkListCommand() (string, []string) {
	return systemDirBin("ipconfig.exe"), []string{"/all"}
}

// processListCommand returns the command that lists the host's processes.
func processListCommand() (string, []string) {
	return systemDirBin("tasklist.exe"), nil
}

// pingCommand returns the command that sends count echo requests to target.
// Windows ping takes the count as -n and the per-reply wait as -w in
// milliseconds, not the iputils -c and -W.
func pingCommand(count, target string) (string, []string) {
	return systemDirBin("ping.exe"), []string{"-n", count, "-w", "3000", target}
}

// pingSucceeded reports whether out holds a real echo reply. ping.exe exits 0
// for any ICMP response, a router's "Destination host unreachable" and a "TTL
// expired in transit" included, so the exit status alone would report a peer
// behind a broken tunnel as reachable. The TTL= token is the one part of a
// reply line Windows does not localize.
func pingSucceeded(out []byte) bool {
	return bytes.Contains(out, []byte("TTL="))
}

// tracerouteCommand returns the command that traces the route to target.
// Windows ships tracert.exe and has no traceroute.exe, so a PATH lookup for
// the Unix name could only ever resolve a planted file — and PATHEXT would let
// a traceroute.bat count as one. -d suppresses name resolution like -n does on
// Unix, and -w is the per-hop wait in milliseconds. The error return exists for
// the Unix build, where the binary is optional; here it is always nil.
func tracerouteCommand(maxHops, target string) (string, []string, error) {
	return systemDirBin("tracert.exe"), []string{"-d", "-h", maxHops, "-w", "3000", target}, nil
}

// errReloadSignalUnsupported is returned by sendReloadSignal because Windows
// has no signal that maps to a configuration reload.
var errReloadSignalUnsupported = errors.New("reload signal not supported on windows; restart the service instead")

// diskRootPath returns the filesystem path whose capacity diagnostics.collect
// reports as disk_total.
func diskRootPath() string {
	if drive := os.Getenv("SystemDrive"); drive != "" {
		return drive + `\`
	}
	return `C:\`
}

// diskTotalBytes returns the total capacity of the volume holding path, or 0
// when it cannot be determined.
func diskTotalBytes(path string) uint64 {
	dir, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var freeToCaller, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(dir, &freeToCaller, &total, &totalFree); err != nil {
		return 0
	}
	return total
}

// kernelRelease returns the running Windows version as major.minor.build.
func kernelRelease() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// sendReloadSignal asks the process to reload its configuration.
func sendReloadSignal(_ int) error {
	return errReloadSignalUnsupported
}

// replaceExecutable installs the verified binary at binaryPath. Windows
// refuses to rename over a running image, which binaryPath is: the agent is
// upgrading itself. The running executable is moved aside first, which Windows
// does allow, and the leftover is removed by the next upgrade or by
// plexd uninstall.
func replaceExecutable(tmpPath, binaryPath string) error {
	old := binaryPath + ".old"
	// A leftover from the previous upgrade; a missing one is the normal case.
	_ = os.Remove(old)

	if err := os.Rename(binaryPath, old); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, binaryPath); err != nil {
		// Put the running image back, so a failed upgrade leaves the node with
		// the binary it started with rather than none at all.
		_ = os.Rename(old, binaryPath)
		return err
	}
	return nil
}
