//go:build darwin

package tunnel

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// DECISION: the pty is allocated the way libSystem's posix_openpt, grantpt and
// unlockpt do it, through golang.org/x/sys/unix, rather than through a pty
// module or cgo. x/sys has no wrapper that reads the slave's name, and its
// direct-syscall path is deprecated on macOS, so the name comes from
// libSystem's ptsname_r through purego, which needs no cgo and is already the
// way plexd reaches libSystem (internal/metrics).

// libSystemPath is the C library every macOS process links.
const libSystemPath = "/usr/lib/libSystem.B.dylib"

// ptsnameR resolves libSystem's ptsname_r once.
var ptsnameR = sync.OnceValues(func() (uintptr, error) {
	lib, err := purego.Dlopen(libSystemPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return 0, fmt.Errorf("dlopen %s: %w", libSystemPath, err)
	}
	fn, err := purego.Dlsym(lib, "ptsname_r")
	if err != nil {
		return 0, fmt.Errorf("dlsym ptsname_r: %w", err)
	}
	return fn, nil
})

// openPTY allocates a pseudo-terminal and returns its master and slave. The
// ioctls run through the file's raw connection rather than through Fd, which
// would switch the master to blocking mode and keep a pending Read from
// returning when the master is closed.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel: pty: open /dev/ptmx: %w", err)
	}
	var name string
	if err := controlFile(master, func(fd int) error {
		if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
			return fmt.Errorf("grant: %w", err)
		}
		if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
			return fmt.Errorf("unlock: %w", err)
		}
		var err error
		if name, err = ptsname(fd); err != nil {
			return fmt.Errorf("read the pty name: %w", err)
		}
		return nil
	}); err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("tunnel: pty: %w", err)
	}
	slave, err = os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("tunnel: pty: open slave: %w", err)
	}
	return master, slave, nil
}

// ptsname returns the name of the slave of the pty whose master is fd.
// ptsname_r answers -1 and sets errno on failure.
func ptsname(fd int) (string, error) {
	fn, err := ptsnameR()
	if err != nil {
		return "", err
	}
	var buf [128]byte
	r1, _, errno := purego.SyscallN(fn, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if int32(r1) != 0 {
		return "", syscall.Errno(errno)
	}
	raw, _, _ := bytes.Cut(buf[:], []byte{0})
	return string(raw), nil
}
