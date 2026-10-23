//go:build linux || darwin

package tunnel

import (
	"math"
	"os"

	"golang.org/x/sys/unix"
)

// ptyOpener opens the pty of an ssh session. It is a variable so tests can make
// the allocation fail.
var ptyOpener = openPTY

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
