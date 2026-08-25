//go:build windows

package actions

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

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
