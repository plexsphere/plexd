//go:build linux

package ifbind

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// boundDevice reads SO_BINDTODEVICE back from the socket of ln and returns
// the name of the interface it is bound to, and true. An unbound socket
// returns the empty name.
func boundDevice(t *testing.T, ln net.Listener) (string, bool) {
	t.Helper()
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatalf("raw connection of the listener on %s: %v", ln.Addr(), err)
	}
	var dev string
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		dev, optErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("control the listener on %s: %v", ln.Addr(), err)
	}
	if optErr != nil {
		t.Fatalf("read SO_BINDTODEVICE of the listener on %s: %v", ln.Addr(), optErr)
	}
	return dev, true
}

// checkNoDevice wants err, from a listen with Control(name) for an
// interface that does not exist, to wrap the kernel's ENODEV. A kernel
// before 5.1 checks for CAP_NET_RAW before it looks up the name, so there an
// unprivileged process gets EPERM in its place.
func checkNoDevice(t *testing.T, name string, err error) {
	t.Helper()
	if errors.Is(err, syscall.ENODEV) {
		return
	}
	if errors.Is(err, syscall.EPERM) && kernelBefore(t, 5, 1) {
		return
	}
	t.Errorf("listen with Control(%q) = %v, want it to wrap ENODEV", name, err)
}

// kernelBefore reports whether the release of the running kernel is older
// than major.minor.
func kernelBefore(t *testing.T, major, minor int) bool {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatalf("uname: %v", err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var gotMajor, gotMinor int
	if _, err := fmt.Sscanf(release, "%d.%d", &gotMajor, &gotMinor); err != nil {
		t.Fatalf("parse the kernel release %q: %v", release, err)
	}
	return gotMajor < major || gotMajor == major && gotMinor < minor
}
