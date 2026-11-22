package winpipe

import (
	"errors"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// errAborted stands in for the ERROR_OPERATION_ABORTED the pipe listener
// hands to Accept after a connect that was cancelled before it was queued.
var errAborted = errors.New("the I/O operation has been aborted")

// spent says what a stand-in listener does with a close signal that reaches
// it while an Accept is in flight.
type spent int

const (
	// abortsAccept: the signal is spent, Accept gets errAborted, and the
	// goroutine waits for the next signal or Accept. This is the pipe
	// listener after ConnectNamedPipe returned ERROR_OPERATION_ABORTED.
	abortsAccept spent = iota
	// retriesConnect: the signal is spent and the Accept stays in flight.
	// This is the pipe listener after ConnectNamedPipe returned
	// ERROR_NO_DATA.
	retriesConnect
)

// pipeModel is a stand-in for the listener of wireguard's ipc/namedpipe with
// its channel protocol kept: Close sends one signal on closeCh and waits for
// doneCh, and one goroutine serves accepts and signals. losses lists what the
// goroutine does with each signal it takes during an Accept; once the list is
// used up, a signal closes the listener, as it always does outside an Accept.
type pipeModel struct {
	acceptCh chan chan error
	closeCh  chan int
	doneCh   chan int
	inFlight chan struct{} // receives once per Accept that reached the goroutine
	losses   []spent
}

func newPipeModel(losses ...spent) *pipeModel {
	m := &pipeModel{
		acceptCh: make(chan chan error),
		closeCh:  make(chan int),
		doneCh:   make(chan int),
		inFlight: make(chan struct{}, 16),
		losses:   losses,
	}
	go m.routine()
	return m
}

func (m *pipeModel) routine() {
	defer close(m.doneCh)
	for {
		select {
		case <-m.closeCh:
			return
		case response := <-m.acceptCh:
			m.inFlight <- struct{}{}
			closed := false
			for answered := false; !answered; {
				<-m.closeCh
				switch {
				case len(m.losses) == 0:
					response <- net.ErrClosed
					closed, answered = true, true
				case m.losses[0] == abortsAccept:
					m.losses = m.losses[1:]
					response <- errAborted
					answered = true
				default: // retriesConnect
					m.losses = m.losses[1:]
				}
			}
			if closed {
				return
			}
		}
	}
}

func (m *pipeModel) Accept() (net.Conn, error) {
	ch := make(chan error)
	select {
	case m.acceptCh <- ch:
		return nil, <-ch
	case <-m.doneCh:
		return nil, net.ErrClosed
	}
}

func (m *pipeModel) Close() error {
	select {
	case m.closeCh <- 1:
		<-m.doneCh
	case <-m.doneCh:
	}
	return nil
}

func (m *pipeModel) Addr() net.Addr { return nil }

func TestListener_CloseReturnsAfterSpentSignals(t *testing.T) {
	tests := []struct {
		name   string
		accept bool // an Accept is in flight when Close is called
		losses []spent
	}{
		{name: "no accept in flight"},
		{name: "accept in flight, signal closes", accept: true},
		{name: "connect aborted", accept: true, losses: []spent{abortsAccept}},
		{name: "connect retried", accept: true, losses: []spent{retriesConnect}},
		{name: "retried then aborted", accept: true, losses: []spent{retriesConnect, abortsAccept}},
		{name: "retried twice then aborted", accept: true, losses: []spent{retriesConnect, retriesConnect, abortsAccept}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			model := newPipeModel(tc.losses...)
			ln := NewListener(model)

			acceptErr := make(chan error, 1)
			if tc.accept {
				go func() {
					_, err := ln.Accept()
					acceptErr <- err
				}()
				<-model.inFlight
			}

			closed := make(chan error, 1)
			go func() { closed <- ln.Close() }()

			select {
			case err := <-closed:
				if err != nil {
					t.Errorf("Close() = %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not return within 5s")
			}

			if tc.accept {
				select {
				case err := <-acceptErr:
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("Accept did not return within 5s of Close")
				}
			}

			// A second Close finds the listener down and returns at once.
			if err := ln.Close(); err != nil {
				t.Errorf("second Close() = %v, want nil", err)
			}
			if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("Accept on a closed listener = %v, want net.ErrClosed", err)
			}
		})
	}
}

// An error the inner listener returns while nobody is closing reaches the
// caller as it is.
func TestListener_AcceptErrorBeforeClosePassesThrough(t *testing.T) {
	defer goleak.VerifyNone(t)

	want := errors.New("accept failed")
	ln := NewListener(failingListener{err: want})
	if _, err := ln.Accept(); !errors.Is(err, want) {
		t.Errorf("Accept() = %v, want %v", err, want)
	}
	if err := ln.Close(); !errors.Is(err, want) {
		t.Errorf("Close() = %v, want the inner listener's %v", err, want)
	}
}

type failingListener struct{ err error }

func (f failingListener) Accept() (net.Conn, error) { return nil, f.err }
func (f failingListener) Close() error              { return f.err }
func (f failingListener) Addr() net.Addr            { return nil }
