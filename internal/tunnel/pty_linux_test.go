//go:build linux

package tunnel

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openTestPTY opens a pty the test closes on cleanup, or skips when the host
// has none.
func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, s, err := openPTY()
	if err != nil {
		t.Skipf("no pty on this host: %v", err)
	}
	t.Cleanup(func() {
		m.Close()
		s.Close()
	})
	return m, s
}

func TestOpenPTY_RoundTrip(t *testing.T) {
	master, slave := openTestPTY(t)

	if _, err := slave.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write the slave: %v", err)
	}
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := master.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case s := <-got:
		if !strings.HasPrefix(s, "hello") {
			t.Errorf("master read %q, want the bytes written to the slave", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing written to the slave reached the master")
	}
}

// Closing the master releases a Read pending on it, which holds only while the
// master stays in non-blocking mode.
func TestOpenPTY_CloseUnblocksRead(t *testing.T) {
	master, _ := openTestPTY(t)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		buf := make([]byte, 64)
		_, _ = master.Read(buf)
	}()
	// Give the read time to block on the empty pty.
	time.Sleep(50 * time.Millisecond)
	master.Close()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("a Read pending on the master outlived its Close")
	}
}

func TestSetWinsize_ReadsBackAndClamps(t *testing.T) {
	m, s := openTestPTY(t)

	for _, tc := range []struct {
		name               string
		rows, cols         uint32
		wantRows, wantCols uint16
	}{
		{"40x100", 40, 100, 40, 100},
		{"clamped to 16 bits", 70000, 1 << 20, 65535, 65535},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := setWinsize(m, tc.rows, tc.cols); err != nil {
				t.Fatalf("setWinsize() error: %v", err)
			}
			// The window size is the pty's, so the slave reads what the master set.
			ws, err := unix.IoctlGetWinsize(int(s.Fd()), unix.TIOCGWINSZ)
			if err != nil {
				t.Fatalf("IoctlGetWinsize() error: %v", err)
			}
			if ws.Row != tc.wantRows || ws.Col != tc.wantCols {
				t.Errorf("winsize = %dx%d, want %dx%d", ws.Row, ws.Col, tc.wantRows, tc.wantCols)
			}
		})
	}

	// A closed file refuses the ioctl rather than reaching a reused descriptor.
	m.Close()
	if err := setWinsize(m, 10, 10); err == nil {
		t.Error("setWinsize() on a closed master: want an error")
	}
}
