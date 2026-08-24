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
