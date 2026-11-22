// Package winpipe opens the Windows named-pipe listeners plexd serves on: the
// local node API and the WireGuard UAPI. It wraps the listener of
// golang.zx2c4.com/wireguard/ipc/namedpipe so that Close returns in every
// order of events.
//
// That listener's Close hands one signal to the listener's goroutine and then
// waits for the goroutine to finish. While an Accept is in flight the
// goroutine can take the signal and live on: it treats the aborted connect as
// a close only when ConnectNamedPipe reported nil or a cancelled completion.
// Measured on Windows Server 2025 for plexsphere/plexd#236, two other results
// reach it. ConnectNamedPipe returns ERROR_OPERATION_ABORTED itself when the
// cancel lands before the kernel has queued the connect, and the goroutine
// then hands that error to Accept and waits for a signal that was already
// spent. ConnectNamedPipe returns ERROR_NO_DATA when a client connected and
// left before it ran, and the goroutine then waits for the next client. In
// both, Close blocks for good, and so does an http.Server.Shutdown above it,
// which closes its listeners before it looks at its context.
//
// The wrapper file carries no build tag, so its tests run on every platform
// against a stand-in for that listener.
package winpipe

import (
	"net"
	"sync"
	"time"
)

// resignalInterval is how long Close waits for the listener to finish before
// it sends the close signal again. A close that loses neither race finishes in
// well under a millisecond, so the timer fires only after a spent signal.
const resignalInterval = 10 * time.Millisecond

// listener is a net.Listener whose Close sends the inner listener's close
// signal until the inner listener is done.
type listener struct {
	net.Listener

	closeOnce sync.Once
	closing   chan struct{} // closed when Close begins
	closeErr  error         // what the inner Close that finished first returned
}

// NewListener wraps the named-pipe listener inner. Close on the result
// returns once inner has shut down, in every order of Accept, Close and
// client connects, and Accept reports net.ErrClosed for any error inner
// returns after Close began.
func NewListener(inner net.Listener) net.Listener {
	return &listener{Listener: inner, closing: make(chan struct{})}
}

// Accept returns the next connection. Once Close has begun, an error of the
// inner listener is reported as net.ErrClosed: the raw result of an aborted
// connect says nothing a caller could act on, and net.ErrClosed is what an
// accept loop tests for.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		select {
		case <-l.closing:
			return nil, net.ErrClosed
		default:
		}
	}
	return c, err
}

// Close shuts the inner listener down and returns when it is done. Every call
// of the inner Close delivers one more close signal and returns once the
// listener's goroutine has finished, whoever's signal ended it. So Close
// calls it again whenever the listener is still up after resignalInterval: a
// signal spent on an aborted connect is followed by one the goroutine takes
// wherever it waits by then. All calls return together when the goroutine
// ends, and Close waits for them, so it leaves no goroutine behind.
func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closing)

		var (
			wg       sync.WaitGroup
			doneOnce sync.Once
			done     = make(chan struct{})
		)
		signal := func() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := l.Listener.Close()
				doneOnce.Do(func() {
					l.closeErr = err
					close(done)
				})
			}()
		}

		signal()
		ticker := time.NewTicker(resignalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				wg.Wait()
				return
			case <-ticker.C:
				signal()
			}
		}
	})
	return l.closeErr
}
