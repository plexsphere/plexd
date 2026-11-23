//go:build darwin

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	// The package declares its own ipv4, the header view of the mesh source
	// rewrite.
	xipv4 "golang.org/x/net/ipv4"
)

// TestRTTMeshOnly_DropsOtherInterfaces shows on loopback sockets that the
// macOS rttMeshOnly hands over what arrived on the interface it names and
// drops the rest. A datagram from one local socket to another arrives on
// lo0, so a wrapper for lo0 hands it over and a wrapper for any other
// interface drops it. That the kernel names lo0 for a loopback datagram is
// not measured; TestRTTProbe_RealUTUN proves the filter on two utuns.
func TestRTTMeshOnly_DropsOtherInterfaces(t *testing.T) {
	const msg = "wireguard: rtt probe dropped a datagram from another interface"
	logs := &syncBuffer{}
	logger := slogTextLogger(logs)
	recv, send := listenLoopback(t), listenLoopback(t)
	lo0, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatalf("InterfaceByName(lo0): %v", err)
	}

	// readOne reads one datagram through conn and gives up after 1 s.
	readOne := func(t *testing.T, conn net.PacketConn) ([]byte, net.Addr, error) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		buf := make([]byte, 64)
		n, from, err := conn.ReadFrom(buf)
		return buf[:n], from, err
	}
	sendTo := func(t *testing.T, payload string) {
		t.Helper()
		if _, err := send.WriteTo([]byte(payload), recv.LocalAddr()); err != nil {
			t.Fatalf("send to %s: %v", recv.LocalAddr(), err)
		}
	}

	t.Run("hands over a datagram that arrived on the named interface", func(t *testing.T) {
		conn, err := rttMeshOnly(recv, "lo0", logger)
		if err != nil {
			t.Fatalf("rttMeshOnly(lo0) = %v, want a socket", err)
		}
		sendTo(t, "on lo0")
		got, from, err := readOne(t, conn)
		if err != nil || string(got) != "on lo0" || from == nil || from.String() != send.LocalAddr().String() {
			t.Errorf("ReadFrom through the wrapper for lo0 = %q from %v, %v; want %q from %s",
				got, from, err, "on lo0", send.LocalAddr())
		}
	})

	t.Run("drops a datagram that arrived on another interface", func(t *testing.T) {
		ifaces, err := net.Interfaces()
		if err != nil {
			t.Fatalf("net.Interfaces: %v", err)
		}
		var other *net.Interface
		for i := range ifaces {
			if ifaces[i].Name != "lo0" {
				other = &ifaces[i]
				break
			}
		}
		if other == nil {
			t.Skip("the host lists no interface but lo0")
		}

		conn, err := rttMeshOnly(recv, other.Name, logger)
		if err != nil {
			t.Fatalf("rttMeshOnly(%s) = %v, want a socket", other.Name, err)
		}
		sendTo(t, "not on "+other.Name)
		got, from, err := readOne(t, conn)
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("ReadFrom through the wrapper for %s = %q from %v, %v; want a timeout: the datagram arrived on lo0",
				other.Name, got, from, err)
		}
		parts := []string{"component=wireguard", "source=" + send.LocalAddr().String(), fmt.Sprintf("interface_index=%d", lo0.Index)}
		if n := logCount(logs.String(), msg, "DEBUG", parts...); n < 1 {
			t.Errorf("%d Debug lines %q with %v, want at least 1:\n%s", n, msg, parts, logs.String())
		}
	})

	t.Run("an unknown interface closes the socket", func(t *testing.T) {
		conn := listenLoopback(t)
		got, err := rttMeshOnly(conn, "plexd-none0", logger)
		const want = "wireguard: rtt probe: receive interface of plexd-none0: "
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("rttMeshOnly(plexd-none0) = %v, %v; want no socket and an error that starts with %q", got, err, want)
		}
		if _, err := conn.WriteTo([]byte("after"), send.LocalAddr()); !errors.Is(err, net.ErrClosed) {
			t.Errorf("WriteTo after the failed rttMeshOnly = %v, want net.ErrClosed: the socket is still open", err)
		}
	})

	t.Run("a datagram without a control message counts as from another interface", func(t *testing.T) {
		for _, tc := range []struct {
			cm   *xipv4.ControlMessage
			want bool
		}{
			{nil, false},
			{&xipv4.ControlMessage{IfIndex: 2}, false},
			{&xipv4.ControlMessage{IfIndex: 1}, true},
		} {
			if got := rttArrivedOn(tc.cm, 1); got != tc.want {
				t.Errorf("rttArrivedOn(%v, 1) = %v, want %v", tc.cm, got, tc.want)
			}
		}
	})
}
