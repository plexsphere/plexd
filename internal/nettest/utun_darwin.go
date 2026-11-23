//go:build darwin

package nettest

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	// utunMTU is the MTU of the utuns NewUTUN creates.
	utunMTU = 1420
	// utunOffset is the room in front of each packet that wireguard-go's
	// utun needs for the 4-byte address family it reads and writes there.
	utunOffset = 4
)

// UTUN is a utun a test owns, addressed and routed the way plexd's macOS
// controllers do it. A packet the test injects arrives at the host on the
// utun, and a packet the host sends out of the utun the test can await.
type UTUN struct {
	dev     tun.Device
	name    string
	packets chan Packet
}

// NewUTUN creates a utun that carries cidr and routes route over it, with
// the commands wireguard.DarwinController and bridge.DarwinRouteController
// run: ifconfig <utun> inet <cidr> <address> alias, route -n add -inet
// <route> -interface <utun>, ifconfig <utun> up. It then waits until a
// socket can bind the address of cidr, and stops the test when any step
// fails.
//
// The device is closed when the test ends, which takes its address and
// route with it. A test that needs forwarding calls EnableForwarding before
// NewUTUN, so the utun is gone before forwarding is restored.
func NewUTUN(t testing.TB, cidr, route string) *UTUN {
	t.Helper()

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	// "utun" asks for the next free unit.
	dev, err := tun.CreateTUN("utun", utunMTU)
	if err != nil {
		t.Fatalf("create a utun: %v", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		t.Fatalf("name of the utun: %v", err)
	}

	u := &UTUN{dev: dev, name: name, packets: make(chan Packet, 256)}
	stop := make(chan struct{}) // closed before the cleanup closes the device
	readDone := make(chan struct{})
	eventsDone := make(chan struct{})
	go u.read(t, stop, readDone)
	// A device reports link events on a channel nothing else reads, and one
	// that fills up stalls the device's own listener. The channel closes
	// once the device is closed.
	go func() {
		defer close(eventsDone)
		for range dev.Events() {
		}
	}()
	t.Cleanup(func() {
		close(stop)
		if err := dev.Close(); err != nil {
			t.Errorf("close %s: %v", name, err)
		}
		<-readDone
		<-eventsDone
	})

	runTool(t, "/sbin/ifconfig", name, "inet", prefix.String(), prefix.Addr().String(), "alias")
	runTool(t, "/sbin/route", "-n", "add", "-inet", route, "-interface", name)
	runTool(t, "/sbin/ifconfig", name, "up")
	waitForAddr(t, prefix.Addr())
	return u
}

// Name returns the utun's interface name, such as utun7.
func (u *UTUN) Name() string {
	return u.name
}

// Inject writes pkt, an IPv4 packet, into the utun, so the host receives it
// on the utun from the network behind it. It stops the test when the write
// fails.
func (u *UTUN) Inject(t testing.TB, pkt []byte) {
	t.Helper()
	buf := make([]byte, utunOffset+len(pkt))
	copy(buf[utunOffset:], pkt)
	if _, err := u.dev.Write([][]byte{buf}, utunOffset); err != nil {
		t.Fatalf("write into %s: %v", u.name, err)
	}
}

// Await waits up to wait for a packet the host sent out of the utun that
// match accepts, and skips every other one. It reports false when none came.
func (u *UTUN) Await(wait time.Duration, match func(Packet) bool) (Packet, bool) {
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	for {
		select {
		case p := <-u.packets:
			if match(p) {
				return p, true
			}
		case <-timeout.C:
			return Packet{}, false
		}
	}
}

// read hands every IPv4 TCP segment and UDP datagram the host writes into
// the device to u.packets, and ignores every other packet. It returns when
// stop is closed or a read fails, and closes done.
func (u *UTUN) read(t testing.TB, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	bufs := make([][]byte, u.dev.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, utunOffset+65535)
	}
	sizes := make([]int, len(bufs))
	for {
		n, err := u.dev.Read(bufs, sizes, utunOffset)
		for i := range n {
			// The device reuses its buffers, and a parsed payload shares
			// the memory it was parsed from.
			p, ok := ParseIPv4(bytes.Clone(bufs[i][utunOffset : utunOffset+sizes[i]]))
			if !ok {
				continue
			}
			select {
			case u.packets <- p:
			case <-stop:
				return
			}
		}
		if err != nil {
			select {
			case <-stop:
			default:
				t.Errorf("read from %s: %v", u.name, err)
			}
			return
		}
	}
}

// EnableForwarding switches IPv4 forwarding on for the whole host, as a
// macOS bridge does, and restores the value it found when the test ends. It
// stops the test when it cannot read or set the value, and reports a failed
// restore as an error.
//
// Call it before NewUTUN. Cleanups run in the reverse order of their
// registration, so the utuns the test creates afterwards are closed before
// forwarding is restored.
func EnableForwarding(t testing.TB) {
	t.Helper()

	// macOS has one IPv4 forwarding knob for the whole host.
	before := strings.TrimSpace(runTool(t, "/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding="+before).CombinedOutput(); err != nil {
			t.Errorf("restore net.inet.ip.forwarding to %s: %v\n%s", before, err, out)
		}
	})
	runTool(t, "/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1")
}

// runTool runs one host command with a timeout of 10 s and returns its
// combined output. It stops the test with that output when the command
// fails.
func runTool(t testing.TB, name string, args ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// waitForAddr waits up to 10 s until a UDP socket can bind addr, and stops
// the test when none could. A host holds a fresh address back for a moment
// after it is assigned.
func waitForAddr(t testing.TB, addr netip.Addr) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.ListenPacket("udp4", netip.AddrPortFrom(addr, 0).String())
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no socket could bind %s within 10 s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
