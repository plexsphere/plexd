//go:build linux

package tunnel

import (
	"fmt"
	"math"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// DECISION: the pty is opened through golang.org/x/sys/unix, already a direct
// dependency, rather than through a pty module. Opening /dev/ptmx, unlocking it
// and naming its slave are three ioctls; a module would add a dependency for
// them.

// ptyOpener opens the pty of an ssh session. It is a variable so tests can make
// the allocation fail.
var ptyOpener = openPTY

// openPTY allocates a pseudo-terminal and returns its master and slave. The
// ioctls run through the file's raw connection rather than through Fd, which
// would switch the master to blocking mode and keep a pending Read from
// returning when the master is closed.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel: pty: open /dev/ptmx: %w", err)
	}
	var n int
	if err := controlFile(master, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return fmt.Errorf("unlock: %w", err)
		}
		var err error
		n, err = unix.IoctlGetInt(fd, unix.TIOCGPTN)
		if err != nil {
			return fmt.Errorf("read the pty number: %w", err)
		}
		return nil
	}); err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("tunnel: pty: %w", err)
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("tunnel: pty: open slave: %w", err)
	}
	return master, slave, nil
}

// setWinsize sets the window size of the pty f belongs to. The ssh wire
// carries 32-bit dimensions and the kernel 16-bit ones, so larger values are
// clamped. It is safe to call while another goroutine closes f: the raw
// connection holds the descriptor for the length of the ioctl.
func setWinsize(f *os.File, rows, cols uint32) error {
	ws := &unix.Winsize{Row: uint16(min(rows, math.MaxUint16)), Col: uint16(min(cols, math.MaxUint16))}
	return controlFile(f, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws)
	})
}

// controlFile runs fn on f's descriptor without taking it out of the runtime
// poller, and reports fn's error or the error of reaching the descriptor.
func controlFile(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var fnErr error
	if err := rc.Control(func(fd uintptr) { fnErr = fn(int(fd)) }); err != nil {
		return err
	}
	return fnErr
}
