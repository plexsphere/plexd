//go:build linux || darwin

package ifbind

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// loopbackName returns the name of the loopback interface: lo on Linux and
// lo0 on macOS.
func loopbackName() string {
	if runtime.GOOS == "darwin" {
		return "lo0"
	}
	return "lo"
}

// accepted is what one Accept returned.
type accepted struct {
	conn net.Conn
	err  error
}

func TestControl_BindsLoopback(t *testing.T) {
	lo := loopbackName()
	for _, tc := range []struct {
		name string
		addr string
	}{
		{name: "127.0.0.1", addr: "127.0.0.1:0"},
		{name: "::1", addr: "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "::1" {
				plain, err := net.Listen("tcp", tc.addr)
				if err != nil {
					t.Skipf("listen on %s without a control: %v; the host cannot bind ::1", tc.addr, err)
				}
				_ = plain.Close()
			}

			lc := net.ListenConfig{Control: Control(lo)}
			ln, err := lc.Listen(context.Background(), "tcp", tc.addr)
			if errors.Is(err, syscall.EPERM) {
				t.Skipf("listen on %s with Control(%q): %v; a Linux kernel before 5.7 asks for CAP_NET_RAW", tc.addr, lo, err)
			}
			if err != nil {
				t.Fatalf("listen on %s with Control(%q): %v, want a listener", tc.addr, lo, err)
			}
			defer func() { _ = ln.Close() }()
			if got, ok := boundDevice(t, ln); ok && got != lo {
				t.Errorf("listener bound to %q, want %q", got, lo)
			}

			// The deadline ends the Accept below even when the dial fails, so
			// the goroutine is gone before the test returns.
			if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set the accept deadline: %v", err)
			}
			acc := make(chan accepted, 1)
			go func() {
				c, err := ln.Accept()
				acc <- accepted{conn: c, err: err}
			}()
			client, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
			if dialErr == nil {
				defer func() { _ = client.Close() }()
			}
			server := <-acc
			if server.conn != nil {
				defer func() { _ = server.conn.Close() }()
			}

			if dialErr != nil {
				t.Fatalf("dial %s, bound to %s: %v, want a connection", ln.Addr(), lo, dialErr)
			}
			if server.err != nil {
				t.Fatalf("accept on %s, bound to %s: %v, want the dialed connection", ln.Addr(), lo, server.err)
			}
			if got, want := server.conn.RemoteAddr().String(), client.LocalAddr().String(); got != want {
				t.Errorf("accepted a connection from %s, want the client's %s", got, want)
			}
			if got, want := client.RemoteAddr().String(), ln.Addr().String(); got != want {
				t.Errorf("client connected to %s, want the listener's %s", got, want)
			}
		})
	}
}

func TestControl_UnknownInterface(t *testing.T) {
	const name = "plexd-none0"
	lc := net.ListenConfig{Control: Control(name)}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if ln != nil {
		_ = ln.Close()
		t.Errorf("listen with Control(%q) listened on %s, want no listener", name, ln.Addr())
	}
	const want = "bind to interface plexd-none0"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("listen with Control(%q) = %v, want an error that contains %q", name, err, want)
	}
	checkNoDevice(t, name, err)
}
