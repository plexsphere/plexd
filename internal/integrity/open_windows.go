//go:build windows

package integrity

import (
	"os"

	"golang.org/x/sys/windows"
)

// openForHash opens path for reading as os.Open does, but shares delete access
// along with read and write access. os.Open leaves FILE_SHARE_DELETE out, and
// while any handle without it is open Windows refuses to rename the file.
// service.upgrade moves the running binary aside with exactly such a rename
// (internal/actions/builtins_windows.go), and every pass hashes that binary,
// so a pass must never hold the only handle that blocks it. The hash goes on
// reading the bytes of the file it opened.
func openForHash(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
