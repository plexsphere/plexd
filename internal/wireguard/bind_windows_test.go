//go:build windows

package wireguard

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
)

func TestSkipResets_CallsAgainPastResets(t *testing.T) {
	results := []error{windows.WSAECONNRESET, windows.WSAENETRESET, nil}
	calls := 0
	fn := skipResets(func([][]byte, []int, []conn.Endpoint) (int, error) {
		err := results[calls]
		calls++
		return 1, err
	})

	n, err := fn(nil, nil, nil)
	if n != 1 || err != nil {
		t.Fatalf("receive = (%d, %v), want (1, nil)", n, err)
	}
	if calls != len(results) {
		t.Errorf("calls = %d, want %d", calls, len(results))
	}
}

func TestSkipResets_ReturnsOtherErrors(t *testing.T) {
	for _, want := range []error{net.ErrClosed, windows.WSAEMSGSIZE} {
		calls := 0
		fn := skipResets(func([][]byte, []int, []conn.Endpoint) (int, error) {
			calls++
			return 0, want
		})
		if _, err := fn(nil, nil, nil); !errors.Is(err, want) {
			t.Errorf("receive error = %v, want %v", err, want)
		}
		if calls != 1 {
			t.Errorf("%v: calls = %d, want 1", want, calls)
		}
	}
}

// TestDefaultBind_SurvivesPortUnreachable sends from the default bind to a
// loopback port nothing listens on, which on Windows answers with an ICMP port
// unreachable, and checks that the bind still receives a datagram afterwards.
func TestDefaultBind_SurvivesPortUnreachable(t *testing.T) {
	bind := newDefaultBind()
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer bind.Close()

	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := closed.LocalAddr().String()
	closed.Close()
	ep, err := bind.ParseEndpoint(dead)
	if err != nil {
		t.Fatalf("ParseEndpoint(%s): %v", dead, err)
	}
	for range 3 {
		if err := bind.Send([][]byte{{0}}, ep); err != nil {
			t.Fatalf("Send to %s: %v", dead, err)
		}
	}

	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatalf("dial bind: %v", err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("hello")); err != nil {
		t.Fatalf("write to bind: %v", err)
	}

	// fns[0] is the IPv4 receive function.
	bufs := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	received := make(chan error, 1)
	go func() {
		_, err := fns[0](bufs, sizes, eps)
		received <- err
	}()
	select {
	case err := <-received:
		if err != nil {
			t.Fatalf("receive after port unreachable: %v, want the datagram", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no datagram received within 10s")
	}
	if got := string(bufs[0][:sizes[0]]); got != "hello" {
		t.Errorf("received %q, want %q", got, "hello")
	}
}
