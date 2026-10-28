//go:build linux || darwin

package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/plexsphere/plexd/internal/api"
)

// keptShellWait bounds every step a kept-shell test waits for, so a test whose
// behavior is wrong fails instead of hanging.
const keptShellWait = 5 * time.Second

// The contract's names and bound, spelled out rather than taken from the
// constants under test.
const (
	wantShellStateRequest     = "shell-state@plexsphere.com"
	wantShellTakenOverRequest = "shell-taken-over@plexsphere.com"
	wantReplayBytes           = 65536
)

// bounded runs fn on its own goroutine and fails the test unless it returns
// within d.
func bounded[T any](t *testing.T, d time.Duration, what string, fn func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- fn() }()
	select {
	case v := <-done:
		return v
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
	var zero T
	return zero
}

// fakeShellFloodBytes is how much the fake shell's flood writes.
const fakeShellFloodBytes = 102400

// fakeShellFlood returns what the fake shell's flood writes: a to z
// repeating, with no newline.
func fakeShellFlood() []byte {
	b := make([]byte, fakeShellFloodBytes)
	for i := range b {
		b[i] = 'a' + byte(i%26)
	}
	return b
}

// fakeShellLauncher is a fakeLauncher whose process acts as a small shell. It
// reads one command per line from files[0], the pty slave for a shell with a
// pty and standard input otherwise, and answers on the slave, or on standard
// output without a pty:
//
//	say X      writes out-X-out
//	size       writes rows R cols C, read from the pty through TIOCGWINSZ
//	flood      writes fakeShellFlood
//	tick       writes tick every 100 ms from then on
//	delayed X  writes out-X-out 200 ms later
//	exit N     returns N
//	later N    returns N 300 ms later
//
// Each line it writes ends in \n, which the tty maps to \r\n; the tty also
// echoes what the client types. It returns 129, a death by SIGHUP, once its
// context ends. An input that ends early does not end it: it waits for its
// context then, as a process that ignores the hang-up would.
type fakeShellLauncher struct {
	*fakeLauncher

	mu   sync.Mutex
	runs []*fakeShellRun
	fail error
}

// fakeShellRun is one process of a fakeShellLauncher.
type fakeShellRun struct {
	req LaunchRequest
	// cancelled closes when the run's context ends while it runs, returned
	// as the run returns.
	cancelled, returned chan struct{}
	// ticks counts the tick lines written.
	ticks atomic.Int32
}

// over reports whether the run returned or saw its context end.
func (r *fakeShellRun) over() bool {
	select {
	case <-r.returned:
		return true
	case <-r.cancelled:
		return true
	default:
		return false
	}
}

func newFakeShellLauncher() *fakeShellLauncher {
	l := &fakeShellLauncher{}
	l.fakeLauncher = &fakeLauncher{run: l.serve}
	return l
}

// failNext makes the next launch return err at once.
func (l *fakeShellLauncher) failNext(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail = err
}

// awaitRun waits for the run with index i to start and returns it.
func (l *fakeShellLauncher) awaitRun(t *testing.T, i int) *fakeShellRun {
	t.Helper()
	var r *fakeShellRun
	waitForCondition(t, keptShellWait, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		if len(l.runs) > i {
			r = l.runs[i]
			return true
		}
		return false
	})
	return r
}

func (l *fakeShellLauncher) serve(ctx context.Context, req LaunchRequest, files []*os.File) (int, error) {
	r := &fakeShellRun{req: req, cancelled: make(chan struct{}), returned: make(chan struct{})}
	l.mu.Lock()
	l.runs = append(l.runs, r)
	fail := l.fail
	l.fail = nil
	l.mu.Unlock()
	defer close(r.returned)
	stopWatch := context.AfterFunc(ctx, func() { close(r.cancelled) })
	defer stopWatch()
	if fail != nil {
		return 0, fail
	}

	in, out := files[0], files[0]
	if len(files) == 3 {
		out = files[1]
	}
	var outMu sync.Mutex
	write := func(s string) {
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = io.WriteString(out, s)
	}

	stop := make(chan struct{})
	var helpers sync.WaitGroup
	lines := make(chan string)
	go func() {
		defer close(lines)
		rd := bufio.NewReader(in)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			select {
			case lines <- strings.TrimRight(line, "\r\n"):
			case <-stop:
				return
			}
		}
	}()
	defer func() {
		close(stop)
		helpers.Wait()
		// Closing the input wakes the reader, which reads through the poller.
		in.Close()
		for range lines {
		}
	}()

	input := lines
	for {
		select {
		case <-ctx.Done():
			return 129, nil
		case line, ok := <-input:
			if !ok {
				input = nil
				continue
			}
			cmd, arg, _ := strings.Cut(line, " ")
			switch cmd {
			case "say":
				write("out-" + arg + "-out\n")
			case "size":
				var ws *unix.Winsize
				err := controlFile(in, func(fd int) error {
					var err error
					ws, err = unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
					return err
				})
				if err != nil {
					write("size: " + err.Error() + "\n")
					continue
				}
				write(fmt.Sprintf("rows %d cols %d\n", ws.Row, ws.Col))
			case "flood":
				write(string(fakeShellFlood()))
			case "tick":
				helpers.Add(1)
				go func() {
					defer helpers.Done()
					ticker := time.NewTicker(100 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-stop:
							return
						case <-ticker.C:
							write("tick\n")
							r.ticks.Add(1)
						}
					}
				}()
			case "delayed":
				helpers.Add(1)
				go func() {
					defer helpers.Done()
					select {
					case <-stop:
					case <-time.After(200 * time.Millisecond):
						write("out-" + arg + "-out\n")
					}
				}()
			case "exit":
				n, _ := strconv.Atoi(arg)
				return n, nil
			case "later":
				n, _ := strconv.Atoi(arg)
				select {
				case <-ctx.Done():
					return 129, nil
				case <-time.After(300 * time.Millisecond):
					return n, nil
				}
			}
		}
	}
}

// connectRaw asks the session for a connection as h.dial does, wraps the
// server's end with wrap when it is set, and returns the client's end.
func (h *sshHarness) connectRaw(t *testing.T, wrap func(net.Conn) net.Conn) net.Conn {
	t.Helper()
	var client net.Conn
	connectionID := fmt.Sprintf("conn-%d", h.conns.Add(1))
	err := h.mgr.ConnectSSHSession(h.entry.SessionID, connectionID, func(context.Context) (net.Conn, error) {
		server, c, err := connPair()
		if err != nil {
			return nil, err
		}
		client = c
		if wrap != nil {
			server = wrap(server)
		}
		return server, nil
	})
	if err != nil {
		if client != nil {
			client.Close()
		}
		t.Fatalf("ConnectSSHSession() error: %v", err)
	}
	return client
}

// loginWith logs in as the session's user with token and closes the client on
// cleanup.
func (h *sshHarness) loginWith(t *testing.T, token string) *ssh.Client {
	t.Helper()
	client, err := h.dial(sshTestUser, token)
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// dialWrapped logs in over a connection whose server end wrap wraps.
func (h *sshHarness) dialWrapped(t *testing.T, wrap func(net.Conn) net.Conn) *ssh.Client {
	t.Helper()
	client, err := sshClientOver(h.connectRaw(t, wrap), sshTestUser, h.token(t, nil))
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// dialWatching logs in and hands every global request the server sends the
// connection to the test on the returned channel, which closes when the
// connection ends. A request that wants a reply is refused, as ssh.NewClient
// does.
func (h *sshHarness) dialWatching(t *testing.T) (*ssh.Client, <-chan *ssh.Request) {
	t.Helper()
	conn := h.connectRaw(t, nil)
	_ = conn.SetDeadline(time.Now().Add(keptShellWait))
	c, chans, reqs, err := ssh.NewClientConn(conn, "plexd", &ssh.ClientConfig{
		User:            sshTestUser,
		Auth:            []ssh.AuthMethod{ssh.Password(h.token(t, nil))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		conn.Close()
		t.Fatalf("ssh login: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})

	watched := make(chan *ssh.Request, 64)
	none := make(chan *ssh.Request)
	go func() {
		defer close(none)
		defer close(watched)
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			select {
			case watched <- req:
			default:
				// More requests than any test expects; the test sees the
				// first 64 and fails on their count.
			}
		}
	}()
	client := ssh.NewClient(c, chans, none)
	t.Cleanup(func() { client.Close() })
	return client, watched
}

// drainRequests collects what a dialWatching channel delivers until it closes.
func drainRequests(t *testing.T, reqs <-chan *ssh.Request) []*ssh.Request {
	t.Helper()
	var got []*ssh.Request
	timeout := time.After(keptShellWait)
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return got
			}
			got = append(got, req)
		case <-timeout:
			t.Fatalf("the connection's request channel did not close within %v; got %d requests", keptShellWait, len(got))
		}
	}
}

// stallingConn is a server end whose writes, once armed, block until it is
// closed, as a transport that no longer drains does.
type stallingConn struct {
	net.Conn
	armed               atomic.Bool
	stalled, closed     chan struct{}
	stallOnce, closeOne sync.Once
}

func newStallingConn(c net.Conn) *stallingConn {
	return &stallingConn{Conn: c, stalled: make(chan struct{}), closed: make(chan struct{})}
}

func (c *stallingConn) arm() { c.armed.Store(true) }

func (c *stallingConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		c.stallOnce.Do(func() { close(c.stalled) })
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *stallingConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// shellOutput collects what one stream of a session channel receives.
type shellOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *shellOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *shellOutput) bytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Clone(o.buf.Bytes())
}

// waitFor waits until cond accepts what the stream received and returns it.
func (o *shellOutput) waitFor(t *testing.T, what string, cond func([]byte) bool) []byte {
	t.Helper()
	deadline := time.After(keptShellWait)
	for {
		got := o.bytes()
		if cond(got) {
			return got
		}
		select {
		case <-deadline:
			t.Fatalf("%s did not arrive within %v; received %d bytes, ending %q", what, keptShellWait, len(got), got[max(0, len(got)-200):])
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// await waits until the stream received want and returns all it received.
func (o *shellOutput) await(t *testing.T, want string) string {
	t.Helper()
	return string(o.waitFor(t, strconv.Quote(want), func(b []byte) bool { return bytes.Contains(b, []byte(want)) }))
}

// shellChannel is a session channel whose streams the test drives.
type shellChannel struct {
	*ssh.Session
	in          io.WriteCloser
	out, errOut *shellOutput
}

// newShellChannel opens a session channel on client with its streams wired
// for the test, and requests a pty of rows by cols for term unless term is
// empty.
func newShellChannel(t *testing.T, client *ssh.Client, term string, rows, cols int) *shellChannel {
	t.Helper()
	session := newSSHChannel(t, client)
	in, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error: %v", err)
	}
	sc := &shellChannel{Session: session, in: in, out: &shellOutput{}, errOut: &shellOutput{}}
	session.Stdout, session.Stderr = sc.out, sc.errOut
	if term != "" {
		err := bounded(t, keptShellWait, "pty-req", func() error {
			return session.RequestPty(term, rows, cols, ssh.TerminalModes{})
		})
		if err != nil {
			t.Fatalf("RequestPty() error: %v", err)
		}
	}
	return sc
}

// shell sends the channel's shell request and returns its outcome within d.
func (sc *shellChannel) shell(t *testing.T, d time.Duration) error {
	t.Helper()
	return bounded(t, d, "the shell request", sc.Shell)
}

// openKeptShell opens a channel with a pty on client and starts its
// interactive shell.
func openKeptShell(t *testing.T, client *ssh.Client, term string, rows, cols int) *shellChannel {
	t.Helper()
	sc := newShellChannel(t, client, term, rows, cols)
	if err := sc.shell(t, keptShellWait); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	return sc
}

// send types line into the channel.
func (sc *shellChannel) send(t *testing.T, line string) {
	t.Helper()
	err := bounded(t, keptShellWait, "typing "+strconv.Quote(line), func() error {
		_, err := io.WriteString(sc.in, line+"\n")
		return err
	})
	if err != nil {
		t.Fatalf("typing %q: %v", line, err)
	}
}

// wait waits for the channel to end and returns Wait's error.
func (sc *shellChannel) wait(t *testing.T) error {
	t.Helper()
	return bounded(t, keptShellWait, "the channel's Wait", sc.Wait)
}

// windowChange resizes the channel's pty and reports whether plexd granted it.
func (sc *shellChannel) windowChange(t *testing.T, rows, cols uint32) bool {
	t.Helper()
	payload := ssh.Marshal(struct{ Cols, Rows, Width, Height uint32 }{cols, rows, 0, 0})
	r := bounded(t, keptShellWait, "window-change", func() replyResult {
		ok, err := sc.SendRequest("window-change", true, payload)
		return replyResult{ok: ok, err: err}
	})
	if r.err != nil {
		t.Fatalf("window-change: %v", r.err)
	}
	return r.ok
}

type replyResult struct {
	ok      bool
	payload []byte
	err     error
}

// globalRequest sends a global request that wants a reply on client.
func globalRequest(t *testing.T, client *ssh.Client, name string, payload []byte) (bool, []byte) {
	t.Helper()
	r := bounded(t, keptShellWait, name, func() replyResult {
		ok, reply, err := client.SendRequest(name, true, payload)
		return replyResult{ok, reply, err}
	})
	if r.err != nil {
		t.Fatalf("%s: %v", name, r.err)
	}
	return r.ok, r.payload
}

// shellState asks client's connection for its shell state, and returns
// whether it was granted and the state it carried. A granted answer must be
// exactly one SSH string.
func shellState(t *testing.T, client *ssh.Client) (bool, string) {
	t.Helper()
	ok, payload := globalRequest(t, client, wantShellStateRequest, nil)
	if !ok {
		return false, ""
	}
	var st struct{ State string }
	if err := ssh.Unmarshal(payload, &st); err != nil {
		t.Fatalf("shell-state payload %x: %v", payload, err)
	}
	if want := ssh.Marshal(struct{ State string }{st.State}); !bytes.Equal(payload, want) {
		t.Errorf("shell-state payload = %x, want exactly one string %x", payload, want)
	}
	return true, st.State
}

// wantShellState fails the test unless client's connection answers
// shell-state with state.
func wantShellState(t *testing.T, client *ssh.Client, state string) {
	t.Helper()
	if ok, got := shellState(t, client); !ok || got != state {
		t.Errorf("shell-state = %v %q, want success with %q", ok, got, state)
	}
}

// logLines returns the lines of the harness's log whose message is msg.
func (h *sshHarness) logLines(msg string) []string {
	var lines []string
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			lines = append(lines, line)
		}
	}
	return lines
}

// awaitLog waits until msg was logged and returns its lines.
func (h *sshHarness) awaitLog(t *testing.T, msg string) []string {
	t.Helper()
	waitForCondition(t, keptShellWait, func() bool { return len(h.logLines(msg)) > 0 })
	return h.logLines(msg)
}

// awaitLaunches waits until the launcher was called n times.
func awaitLaunches(t *testing.T, l *fakeShellLauncher, n int) []launchCall {
	t.Helper()
	waitForCondition(t, keptShellWait, func() bool { return len(l.launches()) >= n })
	launches := l.launches()
	if len(launches) != n {
		t.Fatalf("launcher called %d times, want %d", len(launches), n)
	}
	return launches
}

// Criterion: shellReplay.bytes() is empty before any add, and after an add of
// an empty slice.
func TestShellReplay_EmptyUntilBytesAreAdded(t *testing.T) {
	if sshShellReplayBytes != wantReplayBytes {
		t.Fatalf("sshShellReplayBytes = %d, want %d", sshShellReplayBytes, wantReplayBytes)
	}
	var r shellReplay
	if got := r.bytes(); len(got) != 0 {
		t.Errorf("bytes() before any add = %d bytes, want none", len(got))
	}
	r.add(nil)
	r.add([]byte{})
	if got := r.bytes(); len(got) != 0 {
		t.Errorf("bytes() after empty adds = %d bytes, want none", len(got))
	}
}

// replayTestBytes returns n bytes no period repeats, so a ring that drops or
// reorders bytes shows it.
func replayTestBytes(n int, seed uint64) []byte {
	rng := rand.New(rand.NewPCG(seed, 139))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// Criterion: 10 bytes, exactly 65,536 bytes and 65,537 bytes, each added in
// one call to a fresh ring, leave the last 10, the 65,536 and the last 65,536.
func TestShellReplay_KeepsTheLastBytesOfOneAdd(t *testing.T) {
	for _, n := range []int{10, wantReplayBytes, wantReplayBytes + 1} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			data := replayTestBytes(n, uint64(n))
			var r shellReplay
			r.add(data)
			want := data[max(0, n-wantReplayBytes):]
			got := r.bytes()
			if !bytes.Equal(got, want) {
				t.Fatalf("bytes() = %d bytes, want the last %d added (first difference at %d)", len(got), len(want), firstDifference(got, want))
			}
			// The copy is the caller's, also when the ring starts at its
			// buffer's first byte.
			for i := range got {
				got[i] ^= 0xff
			}
			if again := r.bytes(); !bytes.Equal(again, want) {
				t.Errorf("changing the returned slice changed the ring (first difference at %d)", firstDifference(again, want))
			}
		})
	}
}

// Criterion: 200 KiB added in 7-byte calls leave the last 65,536 bytes in
// order, and changing the returned slice leaves the next bytes() unchanged.
func TestShellReplay_KeepsTheLastBytesOfSmallAddsInOrder(t *testing.T) {
	data := replayTestBytes(200<<10, 7)
	var r shellReplay
	for p := data; len(p) > 0; {
		n := min(7, len(p))
		r.add(p[:n])
		p = p[n:]
	}
	want := data[len(data)-wantReplayBytes:]
	got := r.bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("bytes() = %d bytes, want the last %d added (first difference at %d)", len(got), len(want), firstDifference(got, want))
	}
	for i := range got {
		got[i] ^= 0xff
	}
	if again := r.bytes(); !bytes.Equal(again, want) {
		t.Errorf("changing the returned slice changed the ring (first difference at %d)", firstDifference(again, want))
	}
}

// firstDifference returns the first index at which a and b differ, or the
// shorter length when one is a prefix of the other.
func firstDifference(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// Criterion: pty-req (24x80, xterm-256color) and shell, then shell-state,
// answer success with exactly the string "started"; one launch with PTY true,
// mode shell and term xterm-256color; ssh kept shell started logged with
// connection_id=conn-1.
func TestSSHSession_KeptShellStartAnswersStarted(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	client := h.login(t, nil)
	openKeptShell(t, client, "xterm-256color", 24, 80)

	ok, payload := globalRequest(t, client, wantShellStateRequest, nil)
	if !ok {
		t.Fatal("shell-state was refused, want started")
	}
	var st struct{ State string }
	if err := ssh.Unmarshal(payload, &st); err != nil {
		t.Fatalf("shell-state payload %x does not unmarshal into one string: %v", payload, err)
	}
	if st.State != "started" {
		t.Errorf("shell-state = %q, want started", st.State)
	}
	if want := ssh.Marshal(struct{ State string }{"started"}); !bytes.Equal(payload, want) {
		t.Errorf("shell-state payload = %x, want %x with no trailing bytes", payload, want)
	}

	launches := awaitLaunches(t, l, 1)
	if got := launches[0].req; !got.PTY || got.Mode != "shell" || got.Term != "xterm-256color" {
		t.Errorf("launch = %+v, want a pty shell for xterm-256color", got)
	}
	lines := h.logLines("ssh kept shell started")
	if len(lines) != 1 || !strings.Contains(lines[0], "connection_id=conn-1") {
		t.Errorf("ssh kept shell started lines = %q, want one naming connection_id=conn-1", lines)
	}
}

// Criterion: after say one and a closed connection 1, the shell is detached and
// still runs 500 ms later; connection 2 with pty-req 50x120 vt100 receives
// out-one-out before it sends anything, answers reattached, sizes 50x120 and
// after a window-change 60x130, with still one launch for xterm-256color; the
// log carries neither the token nor out-one-out.
func TestSSHSession_KeptShellReattachReplaysAndResizes(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	token := h.token(t, nil)

	c1 := h.loginWith(t, token)
	sh1 := openKeptShell(t, c1, "xterm-256color", 24, 80)
	run := l.awaitRun(t, 0)
	sh1.send(t, "say one")
	sh1.out.await(t, "out-one-out")
	c1.Close()
	if lines := h.awaitLog(t, "ssh kept shell detached"); !strings.Contains(lines[0], "connection_id=conn-1") {
		t.Errorf("ssh kept shell detached line = %q, want connection_id=conn-1", lines[0])
	}
	time.Sleep(500 * time.Millisecond)
	if run.over() {
		t.Fatal("the shell stopped once the connection that started it closed")
	}

	c2 := h.loginWith(t, token)
	sh2 := openKeptShell(t, c2, "vt100", 50, 120)
	// Connection 2 has sent nothing yet.
	sh2.out.await(t, "out-one-out")
	wantShellState(t, c2, "reattached")
	sh2.send(t, "size")
	sh2.out.await(t, "rows 50 cols 120")
	if !sh2.windowChange(t, 60, 130) {
		t.Fatal("window-change to 60x130 was refused")
	}
	sh2.send(t, "size")
	sh2.out.await(t, "rows 60 cols 130")

	launches := l.launches()
	if len(launches) != 1 || launches[0].req.Term != "xterm-256color" {
		t.Errorf("launches = %+v, want the one of the first connection, for xterm-256color", launches)
	}
	logs := h.logs.String()
	if strings.Contains(logs, token) {
		t.Error("the logs carry the session token")
	}
	if strings.Contains(logs, "out-one-out") {
		t.Error("the logs carry the shell's output")
	}
}

// Criterion: delayed two, connection 1 closed at once and a reattach 500 ms
// later: out-two-out, written while no client was attached, reaches
// connection 2 before it sends anything.
func TestSSHSession_KeptShellReplaysOutputWrittenWhileDetached(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1 := h.login(t, nil)
	sh1 := openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)
	sh1.send(t, "delayed two")
	c1.Close()
	time.Sleep(500 * time.Millisecond)

	c2 := h.login(t, nil)
	sh2 := openKeptShell(t, c2, "xterm", 24, 80)
	// Connection 2 has sent nothing yet.
	sh2.out.await(t, "out-two-out")
	wantShellState(t, c2, "reattached")
	if n := len(l.launches()); n != 1 {
		t.Errorf("launcher called %d times, want 1", n)
	}
}

// Criterion: after connection 1 received all 102,400 flood bytes and closed,
// the first 65,536 bytes connection 2 receives are the last 65,536 of the
// flood, and ssh kept shell reattached is logged with replay_bytes=65536.
func TestSSHSession_KeptShellReplaysTheLastFloodBytes(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	flood := fakeShellFlood()

	c1 := h.login(t, nil)
	sh1 := openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)
	sh1.send(t, "flood")
	sh1.out.waitFor(t, "all 102,400 flood bytes on connection 1", func(b []byte) bool { return bytes.HasSuffix(b, flood) })
	c1.Close()
	h.awaitLog(t, "ssh kept shell detached")

	c2 := h.login(t, nil)
	sh2 := openKeptShell(t, c2, "xterm", 24, 80)
	got := sh2.out.waitFor(t, "65,536 replayed bytes on connection 2", func(b []byte) bool { return len(b) >= wantReplayBytes })
	if want := flood[len(flood)-wantReplayBytes:]; !bytes.Equal(got[:wantReplayBytes], want) {
		t.Errorf("the first %d bytes on connection 2 differ from the flood's last ones at %d", wantReplayBytes, firstDifference(got[:wantReplayBytes], want))
	}
	lines := h.logLines("ssh kept shell reattached")
	if len(lines) != 1 || !strings.Contains(lines[0], "replay_bytes=65536") {
		t.Errorf("ssh kept shell reattached lines = %q, want one with replay_bytes=65536", lines)
	}
}

// Criterion: a reattach to a shell that wrote nothing logs replay_bytes=0, and
// the first bytes connection 2 receives come from its own say two.
func TestSSHSession_KeptShellReattachToASilentShell(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1 := h.login(t, nil)
	openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)
	c1.Close()
	h.awaitLog(t, "ssh kept shell detached")

	c2 := h.login(t, nil)
	sh2 := openKeptShell(t, c2, "xterm", 24, 80)
	lines := h.logLines("ssh kept shell reattached")
	if len(lines) != 1 || !strings.Contains(lines[0], "replay_bytes=0") {
		t.Errorf("ssh kept shell reattached lines = %q, want one with replay_bytes=0", lines)
	}
	sh2.send(t, "say two")
	out := sh2.out.await(t, "out-two-out")
	// The tty's echo of the typed line comes first, then the answer.
	if !strings.HasPrefix(out, "say two") {
		t.Errorf("connection 2 received %q, want its own say two first", out)
	}
}

// Criterion: shell-state fails before any shell, after a shell without a pty,
// after an exec on a pty, after the attached channel closed while its
// connection stayed open, and on a session whose token lists allowed commands.
func TestSSHSession_KeptShellStateRefusedWithoutAnAttachedShell(t *testing.T) {
	refused := func(t *testing.T, client *ssh.Client) {
		t.Helper()
		if ok, state := shellState(t, client); ok {
			t.Errorf("shell-state answered %q, want failure", state)
		}
	}

	t.Run("before any shell", func(t *testing.T) {
		h := startSSHHarness(t, newFakeShellLauncher().fakeLauncher, nil)
		refused(t, h.login(t, nil))
	})

	t.Run("shell without a pty", func(t *testing.T) {
		l := newFakeShellLauncher()
		h := startSSHHarness(t, l.fakeLauncher, nil)
		client := h.login(t, nil)
		if err := newShellChannel(t, client, "", 0, 0).shell(t, keptShellWait); err != nil {
			t.Fatalf("Shell() error: %v", err)
		}
		if run := l.awaitRun(t, 0); run.req.PTY || run.req.Mode != "shell" {
			t.Fatalf("launch = %+v, want a shell without a pty", run.req)
		}
		refused(t, client)
	})

	t.Run("exec on a pty", func(t *testing.T) {
		l := newFakeShellLauncher()
		h := startSSHHarness(t, l.fakeLauncher, nil)
		client := h.login(t, nil)
		sc := newShellChannel(t, client, "xterm", 24, 80)
		if err := bounded(t, keptShellWait, "exec", func() error { return sc.Start("uptime") }); err != nil {
			t.Fatalf("Start() error: %v", err)
		}
		if run := l.awaitRun(t, 0); !run.req.PTY || run.req.Mode != "exec" {
			t.Fatalf("launch = %+v, want an exec on a pty", run.req)
		}
		refused(t, client)
	})

	t.Run("attached channel closed", func(t *testing.T) {
		l := newFakeShellLauncher()
		h := startSSHHarness(t, l.fakeLauncher, nil)
		client := h.login(t, nil)
		sc := openKeptShell(t, client, "xterm", 24, 80)
		run := l.awaitRun(t, 0)
		wantShellState(t, client, "started")
		sc.Close()
		h.awaitLog(t, "ssh kept shell detached")
		refused(t, client)
		if run.over() {
			t.Error("the kept shell stopped with its channel")
		}
	})

	t.Run("another connection attached", func(t *testing.T) {
		l := newFakeShellLauncher()
		h := startSSHHarness(t, l.fakeLauncher, nil)
		holder := h.login(t, nil)
		openKeptShell(t, holder, "xterm", 24, 80)
		other := h.login(t, nil)
		refused(t, other)
		wantShellState(t, holder, "started")
	})

	t.Run("allowed-command session", func(t *testing.T) {
		l := newFakeShellLauncher()
		h := startSSHHarness(t, l.fakeLauncher, nil)
		client := h.login(t, []string{"uptime"})
		if err := newShellChannel(t, client, "xterm", 24, 80).shell(t, keptShellWait); err == nil {
			t.Fatal("shell was granted under an allowed-command list, want refused")
		}
		refused(t, client)
		if n := len(l.launches()); n != 0 {
			t.Errorf("launcher called %d times, want 0", n)
		}
	})
}

// Criterion: keepalive@openssh.com and tcpip-forward with want_reply true are
// both refused.
func TestSSHSession_KeptShellRefusesOtherGlobalRequests(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	client := h.login(t, nil)
	// With a kept shell attached, only shell-state is answered.
	openKeptShell(t, client, "xterm", 24, 80)
	wantShellState(t, client, "started")

	for _, req := range []struct {
		name    string
		payload []byte
	}{
		{"keepalive@openssh.com", nil},
		{"tcpip-forward", ssh.Marshal(struct {
			Addr string
			Port uint32
		}{"127.0.0.1", 0})},
	} {
		if ok, _ := globalRequest(t, client, req.name, req.payload); ok {
			t.Errorf("%s was granted, want refused", req.name)
		}
	}
}

// Criterion: pty-req and shell on two connections at once, 20 times on a fresh
// harness each, start one launch and log ssh kept shell started once per
// round, and the connection left open answers reattached.
func TestSSHSession_KeptShellConcurrentShellsStartOne(t *testing.T) {
	for round := range 20 {
		t.Run(fmt.Sprintf("round %d", round+1), func(t *testing.T) {
			l := newFakeShellLauncher()
			h := startSSHHarness(t, l.fakeLauncher, nil)
			clients := []*ssh.Client{h.login(t, nil), h.login(t, nil)}
			sessions := []*ssh.Session{newSSHChannel(t, clients[0]), newSSHChannel(t, clients[1])}

			start := make(chan struct{})
			errs := make(chan error, len(sessions))
			for _, s := range sessions {
				go func() {
					<-start
					if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
						errs <- fmt.Errorf("pty-req: %w", err)
						return
					}
					errs <- s.Shell()
				}()
			}
			close(start)
			for range sessions {
				select {
				case err := <-errs:
					if err != nil {
						t.Errorf("shell: %v", err)
					}
				case <-time.After(drainTimeout + keptShellWait):
					t.Fatal("a shell request did not return")
				}
			}

			// The second request served takes the shell over and closes the
			// first one's connection.
			gone := make(chan int, len(clients))
			for i, c := range clients {
				go func() {
					_ = c.Wait()
					gone <- i
				}()
			}
			var closed int
			select {
			case closed = <-gone:
			case <-time.After(keptShellWait):
				t.Fatal("neither connection was taken over")
			}
			wantShellState(t, clients[1-closed], "reattached")

			if n := len(h.logLines("ssh kept shell started")); n != 1 {
				t.Errorf("ssh kept shell started logged %d times, want 1", n)
			}
			awaitLaunches(t, l, 1)
		})
	}
}

// Criterion: an interactive shell on connection 2 sends connection 1 exactly
// one request, shell-taken-over with want_reply false and an empty payload,
// then closes it within drainTimeout; when connection 2's Shell() returns, ssh
// kept shell taken over names conn-2 and conn-1, and connection 2 answers
// reattached.
func TestSSHSession_KeptShellTakeoverNotifiesAndClosesTheOlderConnection(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1, reqs1 := h.dialWatching(t)
	openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)

	c2 := h.login(t, nil)
	sh2 := newShellChannel(t, c2, "xterm", 24, 80)
	c1Closed := make(chan time.Time, 1)
	go func() {
		_ = c1.Wait()
		c1Closed <- time.Now()
	}()
	start := time.Now()
	if err := sh2.shell(t, drainTimeout+keptShellWait); err != nil {
		t.Fatalf("Shell() on connection 2: %v", err)
	}
	lines := h.logLines("ssh kept shell taken over")
	if len(lines) != 1 || !strings.Contains(lines[0], "connection_id=conn-2 previous_connection_id=conn-1") {
		t.Errorf("ssh kept shell taken over lines when Shell() returned = %q, want one with connection_id=conn-2 previous_connection_id=conn-1", lines)
	}

	got := drainRequests(t, reqs1)
	if len(got) != 1 {
		t.Fatalf("connection 1 received %d global requests, want exactly 1", len(got))
	}
	if req := got[0]; req.Type != wantShellTakenOverRequest || req.WantReply || len(req.Payload) != 0 {
		t.Errorf("connection 1 received %q want_reply=%v payload=%x, want %s with want_reply false and an empty payload", req.Type, req.WantReply, req.Payload, wantShellTakenOverRequest)
	}
	select {
	case at := <-c1Closed:
		if took := at.Sub(start); took > drainTimeout {
			t.Errorf("connection 1's Wait returned %v after the takeover began, want at most %v", took, drainTimeout)
		}
	case <-time.After(keptShellWait):
		t.Fatal("connection 1's Wait never returned")
	}
	wantShellState(t, c2, "reattached")
}

// Criterion: with all four connections held and connection 1 attached, a
// takeover from connection 4 lets a fifth dial succeed within 3 s.
func TestSSHSession_KeptShellTakeoverFreesTheSlot(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1 := h.login(t, nil)
	openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)
	h.login(t, nil)
	h.login(t, nil)
	c4 := h.login(t, nil)
	if err := h.mgr.ConnectSSHSession(h.entry.SessionID, "fifth", func(context.Context) (net.Conn, error) {
		return nil, errors.New("dialed")
	}); !errors.Is(err, ErrSSHConnectionLimit) {
		t.Fatalf("a fifth connection before the takeover: error = %v, want ErrSSHConnectionLimit", err)
	}

	openKeptShell(t, c4, "xterm", 24, 80)
	var fifth *ssh.Client
	waitForCondition(t, 3*time.Second, func() bool {
		client, err := h.dial(sshTestUser, h.token(t, nil))
		if err != nil {
			return false
		}
		fifth = client
		return true
	})
	fifth.Close()
}

// Criterion: a takeover from connection 2 while connection 1's transport no
// longer drains returns connection 2's Shell() within drainTimeout plus 1 s and
// closes connection 1's server end.
func TestSSHSession_KeptShellTakeoverBoundsAStalledSend(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	var stall *stallingConn
	c1 := h.dialWrapped(t, func(c net.Conn) net.Conn {
		stall = newStallingConn(c)
		return stall
	})
	openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)
	stall.arm()

	c2 := h.login(t, nil)
	sh2 := newShellChannel(t, c2, "xterm", 24, 80)
	start := time.Now()
	if err := sh2.shell(t, drainTimeout+time.Second); err != nil {
		t.Fatalf("Shell() on connection 2: %v", err)
	}
	if took := time.Since(start); took > drainTimeout+time.Second {
		t.Errorf("Shell() on connection 2 took %v, want at most %v", took, drainTimeout+time.Second)
	}
	select {
	case <-stall.stalled:
	default:
		t.Error("no write to connection 1 stalled, so nothing held the takeover")
	}
	select {
	case <-stall.closed:
	default:
		t.Error("connection 1's server end is still open")
	}
	wantShellState(t, c2, "reattached")
}

// Criterion: a second interactive channel on the attached connection ends the
// first with an *ssh.ExitMissingError, sends no global request, and the second
// channel answers say x with out-x-out and shell-state with reattached.
func TestSSHSession_KeptShellSecondChannelOnTheSameConnection(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1, reqs1 := h.dialWatching(t)
	sh1 := openKeptShell(t, c1, "xterm", 24, 80)
	l.awaitRun(t, 0)
	sh2 := openKeptShell(t, c1, "xterm", 24, 80)

	var missing *ssh.ExitMissingError
	if err := sh1.wait(t); !errors.As(err, &missing) {
		t.Errorf("the first channel's Wait() = %v, want an *ssh.ExitMissingError", err)
	}
	sh2.send(t, "say x")
	sh2.out.await(t, "out-x-out")
	wantShellState(t, c1, "reattached")
	lines := h.logLines("ssh kept shell taken over")
	if len(lines) != 1 || !strings.Contains(lines[0], "connection_id=conn-1 previous_connection_id=conn-1") {
		t.Errorf("ssh kept shell taken over lines = %q, want one naming conn-1 twice", lines)
	}

	c1.Close()
	if got := drainRequests(t, reqs1); len(got) != 0 {
		t.Errorf("the connection received %d global requests, the first %q; want none", len(got), got[0].Type)
	}
	if n := len(l.launches()); n != 1 {
		t.Errorf("launcher called %d times, want 1", n)
	}
}

// Criterion: with all four connections held and connection 1 attached, closing
// connection 1 lets a new dial succeed within 3 s while the launcher still
// runs.
func TestSSHSession_KeptShellDetachFreesTheSlot(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1 := h.login(t, nil)
	openKeptShell(t, c1, "xterm", 24, 80)
	run := l.awaitRun(t, 0)
	for range sshMaxConnsPerSession - 1 {
		h.login(t, nil)
	}
	if err := h.mgr.ConnectSSHSession(h.entry.SessionID, "fifth", func(context.Context) (net.Conn, error) {
		return nil, errors.New("dialed")
	}); !errors.Is(err, ErrSSHConnectionLimit) {
		t.Fatalf("a fifth connection while four are open: error = %v, want ErrSSHConnectionLimit", err)
	}

	c1.Close()
	var next *ssh.Client
	waitForCondition(t, 3*time.Second, func() bool {
		client, err := h.dial(sshTestUser, h.token(t, nil))
		if err != nil {
			return false
		}
		next = client
		return true
	})
	next.Close()
	if run.over() {
		t.Error("the kept shell stopped when its connection closed")
	}
}

// Criterion: exit 7 while attached ends the channel with exit status 7 and logs
// ssh process exited with mode=shell exit_status=7; an interactive shell on a
// new channel then answers started, launches again, and receives no out- bytes
// of the first shell.
func TestSSHSession_KeptShellExitReportsStatusAndTheNextShellStartsFresh(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	client := h.login(t, nil)

	sh1 := openKeptShell(t, client, "xterm", 24, 80)
	sh1.send(t, "say one")
	sh1.out.await(t, "out-one-out")
	sh1.send(t, "exit 7")
	if got := exitStatus(t, sh1.wait(t)); got != 7 {
		t.Errorf("exit status = %d, want 7", got)
	}
	if lines := h.awaitLog(t, "ssh process exited"); len(lines) != 1 || !strings.Contains(lines[0], "mode=shell exit_status=7") {
		t.Errorf("ssh process exited lines = %q, want one with mode=shell exit_status=7", lines)
	}

	sh2 := openKeptShell(t, client, "xterm", 24, 80)
	wantShellState(t, client, "started")
	awaitLaunches(t, l, 2)
	sh2.send(t, "say two")
	out := sh2.out.await(t, "out-two-out")
	if i := strings.Index(out, "out-"); i != strings.Index(out, "out-two-out") {
		t.Errorf("the new shell's channel received %q, want no output of the first shell", out)
	}
}

// Criterion: say one, later 0 and a connection closed at once; 600 ms later an
// interactive shell on a new connection answers started, logs ssh kept shell
// started a second time, launches again, and receives no out-one-out.
func TestSSHSession_KeptShellExitWhileDetachedStartsAFreshShell(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1 := h.login(t, nil)
	sh1 := openKeptShell(t, c1, "xterm", 24, 80)
	run := l.awaitRun(t, 0)
	sh1.send(t, "say one")
	sh1.send(t, "later 0")
	c1.Close()
	time.Sleep(600 * time.Millisecond)

	c2 := h.login(t, nil)
	sh2 := openKeptShell(t, c2, "xterm", 24, 80)
	wantShellState(t, c2, "started")
	if n := len(h.logLines("ssh kept shell started")); n != 2 {
		t.Errorf("ssh kept shell started logged %d times, want 2", n)
	}
	awaitLaunches(t, l, 2)
	sh2.send(t, "say two")
	if out := sh2.out.await(t, "out-two-out"); strings.Contains(out, "out-one-out") {
		t.Errorf("the new connection received %q, want no output of the exited shell", out)
	}
	select {
	case <-run.cancelled:
		t.Error("the first shell was stopped, want it to have exited on its own")
	default:
	}
}

// Criterion: a launcher error for the kept shell reaches the attached channel's
// stderr as plexd: helper refused with exit status 1, logs ssh session launch
// failed with mode=shell, and the next interactive shell launches again.
func TestSSHSession_KeptShellLaunchErrorReachesTheAttachedChannel(t *testing.T) {
	l := newFakeShellLauncher()
	l.failNext(errors.New("helper refused"))
	h := startSSHHarness(t, l.fakeLauncher, nil)
	client := h.login(t, nil)

	sh1 := openKeptShell(t, client, "xterm", 24, 80)
	if got := exitStatus(t, sh1.wait(t)); got != 1 {
		t.Errorf("exit status = %d, want 1", got)
	}
	if got := string(sh1.errOut.bytes()); got != "plexd: helper refused\r\n" {
		t.Errorf("stderr = %q, want %q", got, "plexd: helper refused\r\n")
	}
	lines := h.awaitLog(t, "ssh session launch failed")
	if len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") || !strings.Contains(lines[0], "mode=shell") {
		t.Errorf("ssh session launch failed lines = %q, want one warning with mode=shell", lines)
	}

	openKeptShell(t, client, "xterm", 24, 80)
	wantShellState(t, client, "started")
	awaitLaunches(t, l, 2)
}

// Criterion: CloseSession with reasonDrained on a detached kept shell cancels
// the launcher's context and Launch returns within drainTimeout.
func TestSSHSession_KeptShellCloseSessionStopsADetachedShell(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)

	c1 := h.login(t, nil)
	openKeptShell(t, c1, "xterm", 24, 80)
	run := l.awaitRun(t, 0)
	c1.Close()
	h.awaitLog(t, "ssh kept shell detached")

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		h.mgr.CloseSession(h.entry.SessionID, reasonDrained)
	}()
	deadline, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	for _, w := range []struct {
		ch   <-chan struct{}
		what string
	}{
		{run.cancelled, "the launcher's context ending"},
		{run.returned, "Launch returning"},
	} {
		select {
		case <-w.ch:
		case <-deadline.Done():
			t.Fatalf("%s did not happen within %v of CloseSession", w.what, drainTimeout)
		}
	}
	awaitClosed(t, closed, keptShellWait, "CloseSession returning")
	if strings.Contains(h.logs.String(), "timed out waiting for ssh handlers to drain") {
		t.Error("the session's handlers did not drain within drainTimeout")
	}
}

// Criterion: with IdleTimeoutSeconds 1, a shell left ticking after its
// connection closed does not hold the session open: it closes with
// terminated_by idle_timeout within 3 s while the shell still writes, and the
// launcher returns.
func TestSSHSession_KeptShellDetachedOutputIsNotActivity(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, func(e *api.NodeStateSession) { e.IdleTimeoutSeconds = 1 })
	mu, records := recordCloses(h.mgr)

	c1 := h.login(t, nil)
	sh1 := openKeptShell(t, c1, "xterm", 24, 80)
	run := l.awaitRun(t, 0)
	sh1.send(t, "tick")
	waitForCondition(t, keptShellWait, func() bool { return run.ticks.Load() > 0 })
	c1.Close()
	closedAt := time.Now()
	h.awaitLog(t, "ssh kept shell detached")
	ticksAtDetach := run.ticks.Load()

	waitForCondition(t, 3*time.Second-time.Since(closedAt), func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(*records) == 1
	})
	mu.Lock()
	reason := (*records)[0].reason
	mu.Unlock()
	if got := TerminatedByFromReason(reason); got != api.TerminatedByIdleTimeout {
		t.Errorf("terminated_by = %q, want %q", got, api.TerminatedByIdleTimeout)
	}
	if run.ticks.Load() <= ticksAtDetach {
		t.Error("the shell wrote nothing while detached, so the idle close proves nothing")
	}
	awaitClosed(t, run.returned, drainTimeout, "the launcher returning")
}

// Criterion: a shell without pty-req stays bound to its channel: closing the
// channel cancels the launcher's context within drainTimeout.
func TestSSHSession_KeptShellNotKeptWithoutAPTY(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	client := h.login(t, nil)

	sc := newShellChannel(t, client, "", 0, 0)
	if err := sc.shell(t, keptShellWait); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	run := l.awaitRun(t, 0)
	if run.req.PTY || run.req.Mode != "shell" {
		t.Fatalf("launch = %+v, want a shell without a pty", run.req)
	}
	sc.Close()
	awaitClosed(t, run.cancelled, drainTimeout, "stopping the shell of a closed channel")
}

// A shell request that arrives while the kept shell has exited but its output
// is still draining starts a fresh shell. It does not take the dying shell over
// from the channel attached to it, which gets the exit status.
func TestSSHSession_KeptShellReattachWhileItExitsStartsAFreshShell(t *testing.T) {
	exit, returned := make(chan struct{}), make(chan struct{})
	var runs atomic.Int32
	launcher := &fakeLauncher{run: func(ctx context.Context, _ LaunchRequest, files []*os.File) (int, error) {
		if runs.Add(1) > 1 {
			<-ctx.Done()
			return 129, nil
		}
		// A write end that outlives the process holds the drain open for
		// drainTimeout after the process exited.
		fd, err := unix.Dup(int(files[0].Fd()))
		if err != nil {
			return 1, err
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		<-exit
		close(returned)
		return 7, nil
	}}
	h := startSSHHarness(t, launcher, nil)
	first := h.login(t, nil)
	sc := openKeptShell(t, first, "xterm", 24, 80)
	wantShellState(t, first, "started")

	close(exit)
	awaitClosed(t, returned, keptShellWait, "the first shell exiting")
	second := h.login(t, nil)
	openKeptShell(t, second, "xterm", 24, 80)
	wantShellState(t, second, "started")
	if n := len(launcher.launches()); n != 2 {
		t.Errorf("launcher called %d times, want 2", n)
	}
	if got := exitStatus(t, sc.wait(t)); got != 7 {
		t.Errorf("the attached channel's exit status = %d, want 7", got)
	}
}

// A reattach whose replay or answer cannot be written closes the requesting
// connection after drainTimeout, so the next connection can take the shell.
func TestSSHSession_KeptShellStuckReattachIsBounded(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	first := h.login(t, nil)
	sc := openKeptShell(t, first, "xterm", 24, 80)
	sc.send(t, "say one")
	sc.out.await(t, "out-one-out")

	var stall *stallingConn
	stuck := h.dialWrapped(t, func(c net.Conn) net.Conn {
		stall = newStallingConn(c)
		return stall
	})
	stuckChannel := newShellChannel(t, stuck, "xterm", 24, 80)
	stall.arm()
	go func() { _ = stuckChannel.Shell() }()
	awaitClosed(t, stall.stalled, keptShellWait, "the stuck reattach's first write")

	third := h.login(t, nil)
	thirdChannel := newShellChannel(t, third, "xterm", 24, 80)
	if err := thirdChannel.shell(t, drainTimeout+time.Second); err != nil {
		t.Fatalf("Shell() behind a stuck reattach: %v", err)
	}
	thirdChannel.out.await(t, "out-one-out")
	wantShellState(t, third, "reattached")
	awaitClosed(t, stall.closed, keptShellWait, "closing the stuck connection")
}

// A shell request that waited for the session's shell lock on a connection a
// takeover closed meanwhile is refused. It does not take the shell over from
// the connection that just took it.
func TestSSHSession_KeptShellRequestFromATakenOverConnectionIsRefused(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	var stall *stallingConn
	first := h.dialWrapped(t, func(c net.Conn) net.Conn {
		stall = newStallingConn(c)
		return stall
	})
	openKeptShell(t, first, "xterm", 24, 80)
	queued := newShellChannel(t, first, "xterm", 24, 80)
	stall.arm()

	second, secondRequests := h.dialWatching(t)
	secondChannel := newShellChannel(t, second, "xterm", 24, 80)
	secondShell := make(chan error, 1)
	go func() { secondShell <- secondChannel.Shell() }()
	// The takeover's request to the first connection stalls, holding the
	// session's shell lock, while the first connection asks for a shell again.
	awaitClosed(t, stall.stalled, keptShellWait, "the takeover request to the first connection")
	go func() { _, _ = queued.SendRequest("shell", true, nil) }()

	select {
	case err := <-secondShell:
		if err != nil {
			t.Fatalf("the second connection's Shell(): %v", err)
		}
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("the second connection's shell request was not answered")
	}
	waitForCondition(t, keptShellWait, func() bool {
		for _, line := range h.logLines("ssh request refused") {
			if strings.Contains(line, "request=shell") {
				return true
			}
		}
		return false
	})
	wantShellState(t, second, "reattached")
	select {
	case req, ok := <-secondRequests:
		if ok {
			t.Errorf("the second connection got the global request %q, want none", req.Type)
		}
	default:
	}
}

// A reattach applies the size the channel last asked for: a window-change
// after pty-req and before shell counts.
func TestSSHSession_KeptShellReattachUsesTheLatestWindowChange(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	openKeptShell(t, h.login(t, nil), "xterm", 24, 80)

	sc := newShellChannel(t, h.login(t, nil), "xterm", 24, 80)
	if !sc.windowChange(t, 50, 200) {
		t.Fatal("window-change before the shell request was refused")
	}
	if err := sc.shell(t, keptShellWait); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	sc.send(t, "size")
	sc.out.await(t, "rows 50 cols 200")
}

// keptShellOf returns the harness session's kept shell (white-box).
func keptShellOf(t *testing.T, h *sshHarness) *keptShell {
	t.Helper()
	h.mgr.mu.Lock()
	s := h.mgr.sessions[h.entry.SessionID].(*sshSession)
	h.mgr.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shell == nil {
		t.Fatal("the session runs no kept shell")
	}
	return s.shell
}

// corkConn is a client end whose writes, while corked, are held back and then
// sent in one write, so the peer reads them as one burst.
type corkConn struct {
	net.Conn
	mu     sync.Mutex
	corked bool
	held   []byte
}

func (c *corkConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.corked {
		c.held = append(c.held, p...)
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *corkConn) cork() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corked = true
}

func (c *corkConn) uncork() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corked = false
	_, err := c.Conn.Write(c.held)
	c.held = nil
	return err
}

// A shell request waiting on the kept shell must not stall its connection's
// read loop, which carries the window adjusts and channel closes the wait
// depends on. The attached channel's client stops reading, so the shell's
// output blocks with the shell's write lock held. A second channel on the same
// connection then asks for the shell and sends more requests than
// x/crypto/ssh queues per channel, in one burst, so the client's answer to
// plexd closing the first channel can only come after all of them.
func TestSSHSession_KeptShellRequestBurstDoesNotStallTheConnection(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	conn := &corkConn{Conn: h.connectRaw(t, nil)}
	client, err := sshClientOver(conn, sshTestUser, h.token(t, nil))
	if err != nil {
		t.Fatalf("ssh login: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	attached := newSSHChannel(t, client)
	if err := attached.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	in, err := attached.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe() error: %v", err)
	}
	// Taken and never read: the client's window fills and stays full.
	if _, err := attached.StdoutPipe(); err != nil {
		t.Fatalf("StdoutPipe() error: %v", err)
	}
	if err := bounded(t, keptShellWait, "the shell request", attached.Shell); err != nil {
		t.Fatalf("Shell() error: %v", err)
	}
	for range 30 {
		if _, err := io.WriteString(in, "flood\n"); err != nil {
			t.Fatalf("typing flood: %v", err)
		}
	}
	k := keptShellOf(t, h)
	waitForCondition(t, keptShellWait, func() bool {
		for range 10 {
			if k.writeMu.TryLock() {
				k.writeMu.Unlock()
				return false
			}
			time.Sleep(20 * time.Millisecond)
		}
		return true
	})

	second := newSSHChannel(t, client)
	if err := second.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty() error: %v", err)
	}
	conn.cork()
	if _, err := second.SendRequest("shell", false, nil); err != nil {
		t.Fatalf("shell: %v", err)
	}
	for i := range 40 {
		if err := second.WindowChange(30+i, 100); err != nil {
			t.Fatalf("window-change %d: %v", i, err)
		}
	}
	if err := conn.uncork(); err != nil {
		t.Fatalf("sending the burst: %v", err)
	}

	other := h.login(t, nil)
	otherChannel := newShellChannel(t, other, "xterm", 24, 80)
	if err := otherChannel.shell(t, 2*drainTimeout+time.Second); err != nil {
		t.Fatalf("Shell() on another connection: %v", err)
	}
	wantShellState(t, other, "reattached")
}

// takeoverStalledOn attaches a channel on a connection whose writes stall,
// and starts a takeover from another connection that stalls on it for up to
// drainTimeout while it holds the session's shell lock. It returns the
// stalled connection and the client that takes over, whose global requests
// the test watches.
func takeoverStalledOn(t *testing.T, h *sshHarness) (*stallingConn, *ssh.Client, <-chan *ssh.Request) {
	t.Helper()
	var stall *stallingConn
	held := h.dialWrapped(t, func(c net.Conn) net.Conn {
		stall = newStallingConn(c)
		return stall
	})
	openKeptShell(t, held, "xterm", 24, 80)
	taker, takerRequests := h.dialWatching(t)
	takerChannel := newShellChannel(t, taker, "xterm", 24, 80)
	stall.arm()
	go func() { _ = takerChannel.Shell() }()
	awaitClosed(t, stall.stalled, keptShellWait, "the takeover request to the stalled connection")
	return stall, taker, takerRequests
}

// A shell request whose channel closed while it waited for the session's
// shell lock is refused: it does not take the shell from the connection that
// took it meanwhile.
func TestSSHSession_KeptShellRequestFromAClosedChannelIsRefused(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	stall, taker, takerRequests := takeoverStalledOn(t, h)

	waiting := newShellChannel(t, h.login(t, nil), "xterm", 24, 80)
	if _, err := waiting.SendRequest("shell", false, nil); err != nil {
		t.Fatalf("shell: %v", err)
	}
	waiting.Close()

	awaitClosed(t, stall.closed, drainTimeout+time.Second, "the takeover closing the stalled connection")
	waitForCondition(t, keptShellWait, func() bool {
		for _, line := range h.logLines("ssh request refused") {
			if strings.Contains(line, "request=shell") && strings.Contains(line, "channel closed") {
				return true
			}
		}
		return false
	})
	wantShellState(t, taker, "reattached")
	select {
	case req, ok := <-takerRequests:
		if ok {
			t.Errorf("the connection that took the shell got the global request %q, want none", req.Type)
		}
	default:
	}
}

// Requests a channel sends while its shell request waits are answered after
// the shell request, in the order they came, since SSH replies carry no id.
func TestSSHSession_KeptShellRequestsQueuedBehindTheShellAnswerInOrder(t *testing.T) {
	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	takeoverStalledOn(t, h)

	waiting := newShellChannel(t, h.login(t, nil), "xterm", 24, 80)
	if _, err := waiting.SendRequest("shell", false, nil); err != nil {
		t.Fatalf("shell: %v", err)
	}
	payload := ssh.Marshal(struct{ Cols, Rows, Width, Height uint32 }{120, 40, 0, 0})
	r := bounded(t, drainTimeout+keptShellWait, "the queued window-change", func() replyResult {
		ok, err := waiting.SendRequest("window-change", true, payload)
		return replyResult{ok: ok, err: err}
	})
	if r.err != nil || !r.ok {
		t.Fatalf("window-change = %v, %v; want granted", r.ok, r.err)
	}
	if lines := h.logLines("ssh kept shell reattached"); len(lines) != 2 || !strings.Contains(lines[1], "connection_id=conn-3") {
		t.Fatalf("reattach lines when the window-change was answered = %q, want conn-3's after the taker's", lines)
	}
	if rows, cols := ptySize(t, keptShellOf(t, h).master); rows != 40 || cols != 120 {
		t.Errorf("pty size after the queued window-change = %dx%d, want 40x120", rows, cols)
	}
}

// ptySize reads the window size of the pty f belongs to.
func ptySize(t *testing.T, f *os.File) (rows, cols uint16) {
	t.Helper()
	if err := controlFile(f, func(fd int) error {
		ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		if err == nil {
			rows, cols = ws.Row, ws.Col
		}
		return err
	}); err != nil {
		t.Fatalf("TIOCGWINSZ: %v", err)
	}
	return rows, cols
}

// nopChannel is an ssh.Channel that discards writes, standing in for an
// attached channel in white-box tests of keptShell.
type nopChannel struct{ ssh.Channel }

func (nopChannel) Write(p []byte) (int, error) { return len(p), nil }

// Only the attached channel resizes a kept shell: a channel a takeover or a
// detach left behind cannot set the size under the channel that holds it.
func TestKeptShell_ResizeOnlyFromTheAttachedChannel(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("no pty on this host: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	k := &keptShell{master: master}
	held, left := &nopChannel{}, &nopChannel{}
	if !k.attach(&shellAttachment{ch: left}, func(int) {}) {
		t.Fatal("attach to a live shell failed")
	}
	if !k.resize(left, 30, 100) {
		t.Fatal("the attached channel's resize was refused")
	}
	k.release()
	k.attach(&shellAttachment{ch: held}, func(int) {})
	if !k.resize(held, 50, 200) {
		t.Fatal("the attached channel's resize was refused")
	}
	if k.resize(left, 24, 80) {
		t.Error("a channel no longer attached resized the shell")
	}
	if rows, cols := ptySize(t, slave); rows != 50 || cols != 200 {
		t.Errorf("pty size = %dx%d, want 50x200", rows, cols)
	}
}
