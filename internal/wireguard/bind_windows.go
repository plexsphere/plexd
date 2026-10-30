//go:build windows

package wireguard

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
)

// newDefaultBind returns wireguard-go's Windows bind with its receive
// functions wrapped to survive the reset reports of an unconnected UDP
// socket.
//
// WinRingBind, the default bind on Windows, leaves SIO_UDP_CONNRESET and
// SIO_UDP_NETRESET on, which the Go net package turns off for every UDP
// socket it opens (go.dev/issue/5834). An ICMP port or network unreachable
// answering a datagram the device sent, as it does once a relay stops while
// its host still runs, then completes a pending receive with WSAECONNRESET or
// WSAENETRESET. wireguard-go reads that error as permanent and ends the
// device's receive routine for the address family, so the device still sends
// but never receives again, on any peer, until the bind is reopened.
func newDefaultBind() conn.Bind {
	return resetTolerantBind{conn.NewDefaultBind()}
}

// resetTolerantBind is a conn.Bind whose receive functions skip the reset
// reports (see newDefaultBind).
type resetTolerantBind struct {
	conn.Bind
}

func (b resetTolerantBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = skipResets(fn)
	}
	return fns, actual, nil
}

// skipResets returns a receive function that calls fn again while it reports
// a reset. WinRingBind posts the next receive request before it reports the
// status of the one it completed, so calling it again waits for the next
// datagram.
func skipResets(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, err := fn(bufs, sizes, eps)
			if !errors.Is(err, windows.WSAECONNRESET) && !errors.Is(err, windows.WSAENETRESET) {
				return n, err
			}
		}
	}
}
