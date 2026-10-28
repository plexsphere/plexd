//go:build linux || darwin

package tunnel

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// The names and the bound of the kept shell, as the kept-shell contract of
// plexsphere/plexsphere#948 fixes them. A client asks sshShellStateRequest
// once its shell request succeeded, and the agent sends
// sshShellTakenOverRequest to the connection whose shell a newer attach takes.
const (
	sshShellStateRequest     = "shell-state@plexsphere.com"
	sshShellTakenOverRequest = "shell-taken-over@plexsphere.com"
	sshShellReplayBytes      = 64 << 10
	shellStateStarted        = "started"
	shellStateReattached     = "reattached"
)

// DECISION: an interactive shell, a shell request on a channel whose pty-req
// was granted, belongs to the session rather than to its channel. A session
// keeps at most one, and a later interactive shell request on any of its
// connections reattaches to it, so a closed terminal or a dropped network no
// longer ends the operator's work. A shell without a pty and every exec stay
// bound to their channel: they are scripted and have no screen to restore.
//
// DECISION: a reattach replays the shell's last sshShellReplayBytes of output
// before it answers the shell request, in the contract's order, and records
// the attachment first, so a shell-state request a client sends right after
// the answer always finds it.
//
// DECISION: the newest attach takes the shell over. plexd sends the older
// connection sshShellTakenOverRequest and then closes it; the WebSocket under
// it closes with 1000. golang.org/x/crypto/ssh has no way to send
// SSH_MSG_DISCONNECT, so no disconnect message comes in between. The request is
// sent on its own goroutine and waited for at most drainTimeout, so an older
// connection whose transport no longer drains cannot hold up the new client.
// It is best effort during a key re-exchange: x/crypto/ssh holds a packet sent
// then until the exchange completes, and the close ends the exchange. Making
// sure would take a second request the contract does not name, for a case that
// needs a rekey, about one per GiB, to meet a takeover.
// When the attached channel belongs to the requesting connection, plexd closes
// only that channel: disconnecting the requester would end its own new channel.
//
// DECISION: shellMu serializes the interactive shell requests, so no
// connection may hold it unbounded. A request whose connection a takeover
// closed, or whose channel closed, while it waited is refused, or it would take
// the shell from the connection that holds it now. While a request waits, its
// channel's other requests keep being read (serveKeptShellDraining), and only
// the attached channel resizes the shell. Once any takeover is done, plexd
// writes only to the requesting connection, and closes it when the replay and
// the answer are not written within drainTimeout. A shell whose process is gone
// counts as exited at once, while its last output still drains, so a request
// then starts a new shell instead of taking the dying one from the channel owed
// its exit status.
//
// DECISION: a connection attached to the kept shell frees its slot of
// sshMaxConnsPerSession as soon as it ends, while a channel-bound process keeps
// its connection's slot until it is gone. At most one kept shell runs per
// session and a reconnect reattaches to it, so hanging up starts no second
// process either way.

// shellReplay keeps the last sshShellReplayBytes written to it. Its buffer is
// allocated on the first non-empty add.
type shellReplay struct {
	buf   []byte
	start int // index of the oldest byte held
	n     int // bytes held
}

// add appends p, dropping the oldest bytes beyond sshShellReplayBytes.
func (r *shellReplay) add(p []byte) {
	if len(p) == 0 {
		return
	}
	if r.buf == nil {
		r.buf = make([]byte, sshShellReplayBytes)
	}
	size := len(r.buf)
	if len(p) >= size {
		copy(r.buf, p[len(p)-size:])
		r.start, r.n = 0, size
		return
	}
	end := (r.start + r.n) % size
	copied := copy(r.buf[end:], p)
	copy(r.buf, p[copied:])
	r.n += len(p)
	if over := r.n - size; over > 0 {
		r.start = (r.start + over) % size
		r.n = size
	}
}

// bytes returns a copy of the bytes held, oldest first.
func (r *shellReplay) bytes() []byte {
	out := make([]byte, r.n)
	if r.n == 0 {
		return out
	}
	copied := copy(out, r.buf[r.start:min(r.start+r.n, len(r.buf))])
	copy(out[copied:], r.buf[:r.n-copied])
	return out
}

// keptShell is a session's interactive shell, which outlives the channel that
// started it. Its output goes into the replay and to the channel attached at
// the moment, if any. The lock order is sshSession.shellMu, writeMu, mu, and no
// method holds mu across a channel write.
type keptShell struct {
	// master is the pty master. The shell owns it and closes it once the
	// process exited.
	master *os.File
	// writeMu is held across every write to the attached channel, so the
	// replay of an attach and the live output after it stay in order.
	writeMu sync.Mutex

	mu       sync.Mutex
	replay   shellReplay
	attached *shellAttachment
	exited   bool
}

// shellAttachment is the channel a kept shell's output goes to.
type shellAttachment struct {
	conn         *ssh.ServerConn
	ch           ssh.Channel
	connectionID string
	// state is what shell-state answers on conn: shellStateStarted or
	// shellStateReattached.
	state string
}

// Write keeps p for the replay and carries it to the attached channel. It
// never fails, so a client that went away never stops the copy from the
// master and the shell never blocks on a full pty.
func (k *keptShell) Write(p []byte) (int, error) {
	k.writeMu.Lock()
	defer k.writeMu.Unlock()
	k.mu.Lock()
	k.replay.add(p)
	a := k.attached
	k.mu.Unlock()
	if a != nil {
		_, _ = a.ch.Write(p)
	}
	return len(p), nil
}

// attach writes the replay to a's channel, makes it the attached one, and
// calls answer with the number of bytes it replayed. Every chunk of output is
// either in the replay or written after it, never both, and answer runs before
// finish can end the channel. It returns false, without calling answer, for a
// shell that exited.
func (k *keptShell) attach(a *shellAttachment, answer func(replayed int)) bool {
	k.writeMu.Lock()
	defer k.writeMu.Unlock()
	k.mu.Lock()
	if k.exited {
		k.mu.Unlock()
		return false
	}
	replay := k.replay.bytes()
	k.attached = a
	k.mu.Unlock()
	if len(replay) > 0 {
		_, _ = a.ch.Write(replay)
	}
	answer(len(replay))
	return true
}

// release detaches the attached channel and returns it, or nil. live is false
// for a shell that exited; its attached channel stays, to get the exit status.
func (k *keptShell) release() (a *shellAttachment, live bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.exited {
		return nil, false
	}
	a = k.attached
	k.attached = nil
	return a, true
}

// end marks the shell exited as soon as its process is gone, while its last
// output may still be on the way to the attached channel, so no request
// attaches to it any more.
func (k *keptShell) end() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.exited = true
}

// detach detaches ch when it is the attached channel, and reports whether it
// was.
func (k *keptShell) detach(ch ssh.Channel) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.attached == nil || k.attached.ch != ch {
		return false
	}
	k.attached = nil
	return true
}

// resize sets the pty's size for ch while ch is the attached channel, and
// reports whether it did. A channel a takeover or a detach left behind cannot
// set the size under the channel that holds the shell now.
func (k *keptShell) resize(ch ssh.Channel, rows, cols uint32) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.attached == nil || k.attached.ch != ch {
		return false
	}
	return setWinsize(k.master, rows, cols) == nil
}

// stateFor returns the shell-state answer for conn: the state of the
// attachment when conn holds it, else "".
func (k *keptShell) stateFor(conn *ssh.ServerConn) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.attached == nil || k.attached.conn != conn {
		return ""
	}
	return k.attached.state
}

// finish marks the shell exited, if end has not, and returns the channel
// attached at that moment, or nil.
func (k *keptShell) finish() *shellAttachment {
	k.writeMu.Lock()
	defer k.writeMu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.exited = true
	a := k.attached
	k.attached = nil
	return a
}

// sshMaxQueuedChannelRequests bounds the requests a channel may send while its
// shell request waits. Each window-change that wants no reply replaces the one
// before it, so a terminal resized meanwhile stays far below it.
const sshMaxQueuedChannelRequests = 64

// serveKeptShellDraining runs serveKeptShell while it keeps reading the
// channel's other requests, and returns them, in the order they came, for
// serveChannel to answer after the shell request. x/crypto/ssh hands a channel
// its requests from the connection's one read loop, through a queue of 16. A
// request loop that stopped reading while serveKeptShell waits would stall that
// read loop at the 17th request, and with it the window adjusts and channel
// closes the wait itself depends on, which closing the connection does not
// undo. The requests are answered only afterwards, because SSH replies carry no
// id and a client matches them to its requests in order. A channel that sends
// more than sshMaxQueuedChannelRequests meanwhile has its connection closed.
func (s *sshSession) serveKeptShellDraining(conn *ssh.ServerConn, ch ssh.Channel, req *ssh.Request, st *channelState, reqs <-chan *ssh.Request) []*ssh.Request {
	var queued []*ssh.Request
	stop, drained, gone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(drained)
		overflowed := false
		for {
			select {
			case <-stop:
				return
			case r, ok := <-reqs:
				if !ok {
					close(gone)
					return
				}
				if overflowed {
					continue
				}
				if r.Type == "window-change" && !r.WantReply {
					queued = slices.DeleteFunc(queued, func(q *ssh.Request) bool { return q.Type == "window-change" && !q.WantReply })
				}
				if len(queued) == sshMaxQueuedChannelRequests {
					overflowed = true
					s.logger.Warn("ssh channel sent too many requests while its shell request waited; closing the connection", "connection_id", conn.RemoteAddr().String())
					_ = conn.Close()
					continue
				}
				queued = append(queued, r)
			}
		}
	}()

	s.serveKeptShell(conn, ch, req, st, gone)
	close(stop)
	<-drained
	return queued
}

// serveKeptShell answers an interactive shell request: it reattaches the
// channel to the session's kept shell, taking it over from the channel
// attached to it, or starts the kept shell when none runs. The channel's pty
// becomes the kept shell's when it starts one, and is closed when it
// reattaches. gone closes when the channel ends.
func (s *sshSession) serveKeptShell(conn *ssh.ServerConn, ch ssh.Channel, req *ssh.Request, st *channelState, gone <-chan struct{}) {
	s.shellMu.Lock()
	defer s.shellMu.Unlock()

	connectionID := conn.RemoteAddr().String()
	s.mu.Lock()
	k, closed := s.shell, s.closed
	_, served := s.served[conn]
	s.mu.Unlock()
	// A request that waited here while a takeover closed its connection, or
	// while its channel closed, must not take the shell from the connection
	// that holds it now.
	reason := ""
	switch {
	case closed || !served:
		reason = "the connection is closing"
	case isClosed(gone):
		reason = "the channel closed"
	}
	if reason != "" {
		s.logger.Info("ssh request refused", "request", req.Type, "reason", reason)
		_ = req.Reply(false, nil)
		return
	}

	var old *shellAttachment
	live := false
	if k != nil {
		old, live = k.release()
	}
	if old != nil && old.conn != conn {
		s.takeOver(old, connectionID)
	}

	// From here on plexd writes only to this connection. One that stops
	// draining is closed after drainTimeout, so it cannot hold shellMu.
	stuck := time.AfterFunc(drainTimeout, func() {
		s.logger.Warn("ssh kept shell request not answered within the drain bound; closing the connection", "connection_id", connectionID)
		_ = conn.Close()
	})
	defer stuck.Stop()

	if live {
		if old != nil && old.conn == conn {
			_ = old.ch.Close()
			s.logger.Info("ssh kept shell taken over",
				"connection_id", connectionID,
				"previous_connection_id", old.connectionID,
			)
		}
		// A failed resize leaves the old size; the next window-change retries.
		_ = setWinsize(k.master, st.rows, st.cols)
		a := &shellAttachment{conn: conn, ch: ch, connectionID: connectionID, state: shellStateReattached}
		if k.attach(a, func(replayed int) {
			s.logger.Info("ssh kept shell reattached", "connection_id", connectionID, "replay_bytes", replayed)
			_ = req.Reply(true, nil)
		}) {
			st.master.Close()
			st.slave.Close()
			st.master, st.slave = nil, nil
			st.started, st.kept = true, k
			s.copyInput(k, ch)
			return
		}
	}
	// No shell runs, or it exited; start a new one.

	k = &keptShell{master: st.master}
	s.mu.Lock()
	s.shell = k
	s.mu.Unlock()
	k.attach(&shellAttachment{conn: conn, ch: ch, connectionID: connectionID, state: shellStateStarted}, func(int) {
		s.logger.Info("ssh kept shell started", "connection_id", connectionID)
		_ = req.Reply(true, nil)
	})
	// The master now belongs to k, and started keeps serveChannel from closing
	// it.
	st.started, st.kept = true, k
	s.copyInput(k, ch)

	state := *st
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runKeptShell(conn, k, state)
	}()
}

// isClosed reports whether c is closed.
func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// takeOver tells old's connection that a newer attach took its shell, and
// closes that connection.
func (s *sshSession) takeOver(old *shellAttachment, connectionID string) {
	// A request the connection already sent is refused from now on.
	s.mu.Lock()
	delete(s.served, old.conn)
	s.mu.Unlock()

	sent := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(sent)
		_, _, _ = old.conn.SendRequest(sshShellTakenOverRequest, false, nil)
	}()
	select {
	case <-sent:
	case <-time.After(drainTimeout):
	}
	_ = old.conn.Close()
	s.logger.Info("ssh kept shell taken over",
		"connection_id", connectionID,
		"previous_connection_id", old.connectionID,
	)
}

// copyInput carries ch's input to the kept shell's pty until ch ends. It never
// closes the master.
func (s *sshSession) copyInput(k *keptShell, ch ssh.Channel) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_, _ = io.Copy(k.master, ch)
	}()
}

// runKeptShell runs the kept shell on the session's context, so only the
// session's close stops it, and reports its exit to the channel attached when
// it ends.
func (s *sshSession) runKeptShell(conn *ssh.ServerConn, k *keptShell, st channelState) {
	status, err := s.launch(s.ctx, conn, nil, k, LaunchModeShell, "", st)

	s.mu.Lock()
	if s.shell == k {
		s.shell = nil
	}
	s.mu.Unlock()
	a := k.finish()

	if err != nil {
		status = 1
		s.logger.Warn("ssh session launch failed", "mode", LaunchModeShell, "error", err)
	}
	if a != nil {
		if err != nil {
			fmt.Fprintf(a.ch.Stderr(), "plexd: %v\r\n", err)
		}
		_ = a.ch.CloseWrite()
		sendExitStatus(a.ch, status)
		_ = a.ch.Close()
	}
	k.master.Close()

	// The status is logged as a number, never as a signal name: the systemd e2e
	// suite treats SIGKILL in plexd's journal as a crash.
	s.logger.Info("ssh process exited", "mode", LaunchModeShell, "exit_status", status)
}

// shellStateFor returns the shell-state answer for conn, or "" when conn holds
// no kept shell. It releases s.mu before it asks the shell, so a takeover in
// progress never delays the answer.
func (s *sshSession) shellStateFor(conn *ssh.ServerConn) string {
	s.mu.Lock()
	k := s.shell
	s.mu.Unlock()
	if k == nil {
		return ""
	}
	return k.stateFor(conn)
}

// serveGlobalRequests answers shell-state with the connection's state and
// refuses every other global request, tcpip-forward among them. The request's
// payload is ignored.
func (s *sshSession) serveGlobalRequests(conn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type == sshShellStateRequest {
			if state := s.shellStateFor(conn); state != "" {
				_ = req.Reply(true, ssh.Marshal(struct{ State string }{state}))
				continue
			}
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}
