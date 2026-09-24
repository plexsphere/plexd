//go:build linux

package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The test binary doubles as the child session helper: with
// PLEXD_TEST_SESSION_HELPER_CHILD=1 it serves fd 3 the way
// `plexd session-helper --child` does, trusting the key in
// PLEXD_TEST_SESSION_HELPER_KEY and resolving users from the passwd file in
// PLEXD_TEST_SESSION_HELPER_PASSWD.
func init() {
	if os.Getenv("PLEXD_TEST_SESSION_HELPER_CHILD") != "1" {
		return
	}
	os.Exit(runTestSessionHelperChild())
}

func runTestSessionHelperChild() int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	key, err := ParseSessionSigningPublicKey(os.Getenv("PLEXD_TEST_SESSION_HELPER_KEY"))
	if err != nil {
		logger.Error("child helper key", "error", err)
		return 1
	}
	if p := os.Getenv("PLEXD_TEST_SESSION_HELPER_PASSWD"); p != "" {
		passwdPath = p
	}
	fc, err := net.FileConn(os.NewFile(3, "plexd-session-helper"))
	if err != nil {
		logger.Error("child helper fd 3", "error", err)
		return 1
	}
	if err := RunSessionHelper(fc.(*net.UnixConn), []ed25519.PublicKey{key}, logger); err != nil {
		logger.Error("child helper", "error", err)
		return 1
	}
	return 0
}

// helperUser is the login name the passwd fixture maps to the current uid, so
// the helper starts processes as the user running the tests without having to
// switch.
const helperUser = "plexd-helper-test"

// usePasswdFixture points passwdPath at a file holding one entry for
// helperUser with the current uid and gid, a fresh home and shell. It returns
// the fixture's path.
func usePasswdFixture(t *testing.T, shell string) string {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "passwd")
	entry := fmt.Sprintf("root:x:0:0:root:/root:/bin/sh\n%s:x:%d:%d:test:%s:%s\n", helperUser, os.Getuid(), os.Getgid(), home, shell)
	if err := os.WriteFile(path, []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := passwdPath
	passwdPath = path
	t.Cleanup(func() { passwdPath = prev })
	return path
}

// shortTempDir returns a directory whose socket paths stay under the 108-byte
// limit of sun_path, which t.TempDir can exceed.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "plexd-sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// serveHelperSocket listens on a fresh socket and serves every connection with
// RunSessionHelper, or with serve when it is set. It returns the socket path.
func serveHelperSocket(t *testing.T, keys []ed25519.PublicKey, serve func(*net.UnixConn)) string {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "helper.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if serve == nil {
		serve = func(c *net.UnixConn) { _ = RunSessionHelper(c, keys, discardLogger()) }
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	return path
}

// testHelperChild starts the test binary as the child helper, handing it the
// first trusted key and passwd.
func testHelperChild(passwd string) func([]ed25519.PublicKey) *exec.Cmd {
	return func(keys []ed25519.PublicKey) *exec.Cmd {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			"PLEXD_TEST_SESSION_HELPER_CHILD=1",
			"PLEXD_TEST_SESSION_HELPER_KEY="+base64.StdEncoding.EncodeToString(keys[0]),
			"PLEXD_TEST_SESSION_HELPER_PASSWD="+passwd,
		)
		return cmd
	}
}

// helperFixture is a signing key, a passwd fixture and a client for them.
type helperFixture struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	passwd string
	client *SessionHelperClient
}

// newSocketHelper serves RunSessionHelper on a socket and returns a client
// dialing it.
func newSocketHelper(t *testing.T, shell string) *helperFixture {
	t.Helper()
	pub, priv := newSigningKey(t)
	passwd := usePasswdFixture(t, shell)
	path := serveHelperSocket(t, []ed25519.PublicKey{pub}, nil)
	return &helperFixture{
		pub: pub, priv: priv, passwd: passwd,
		client: NewSessionHelperClient(path, nil, staticKeys{pub}, discardLogger()),
	}
}

func (f *helperFixture) request(t *testing.T, mode, command string, allowed []string) LaunchRequest {
	t.Helper()
	return LaunchRequest{
		Version:   1,
		SessionID: "sess-helper",
		User:      helperUser,
		Token:     sessionToken(t, f.priv, "sess-helper", helperUser, allowed),
		Mode:      mode,
		Command:   command,
	}
}

// execResult is what one process without a pty produced.
type execResult struct {
	status         int
	err            error
	stdout, stderr string
}

// launchPiped runs req through client with three pipes and an empty stdin,
// and collects the output.
func launchPiped(ctx context.Context, t *testing.T, client *SessionHelperClient, req LaunchRequest, onStdout func(line string)) execResult {
	t.Helper()
	stdinR, stdinW, _ := os.Pipe()
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()
	stdinW.Close()
	defer stdoutR.Close()
	defer stderrR.Close()

	var wg sync.WaitGroup
	var stdout, stderr strings.Builder
	wg.Add(2)
	go func() {
		defer wg.Done()
		r := bufio.NewReader(stdoutR)
		for {
			line, err := r.ReadString('\n')
			stdout.WriteString(line)
			if line != "" && onStdout != nil {
				onStdout(line)
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stderr, stderrR)
	}()

	status, err := client.Launch(ctx, req, []*os.File{stdinR, stdoutW, stderrW})
	wg.Wait()
	return execResult{status: status, err: err, stdout: stdout.String(), stderr: stderr.String()}
}

// waitGone polls until pid no longer names a live process: it is reaped, or a
// zombie nobody reaps (a container without an init).
func waitGone(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	waitForCondition(t, within, func() bool {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return true
		}
		fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
		return len(fields) > 0 && fields[0] == "Z"
	})
}

func TestSessionHelper_ExecExitStatuses(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")

	for _, tc := range []struct {
		command    string
		wantStatus int
		wantOut    string
	}{
		{"echo hi", 0, "hi\n"},
		{"exit 3", 3, ""},
		{"kill -9 $$", 137, ""},
	} {
		t.Run(tc.command, func(t *testing.T) {
			res := launchPiped(context.Background(), t, f.client, f.request(t, LaunchModeExec, tc.command, nil), nil)
			if res.err != nil {
				t.Fatalf("Launch() error: %v (stderr %q)", res.err, res.stderr)
			}
			if res.status != tc.wantStatus {
				t.Errorf("status = %d, want %d", res.status, tc.wantStatus)
			}
			if res.stdout != tc.wantOut {
				t.Errorf("stdout = %q, want %q", res.stdout, tc.wantOut)
			}
		})
	}
}

func TestSessionHelper_PTYShell(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("no pty on this host: %v", err)
	}
	defer master.Close()

	output := make(chan string, 1)
	go func() {
		var out strings.Builder
		_, _ = io.Copy(&out, master)
		output <- out.String()
	}()
	if _, err := master.Write([]byte("tty; echo $((6*7)); exit 5\n")); err != nil {
		t.Fatalf("write the master: %v", err)
	}

	req := f.request(t, LaunchModeShell, "", nil)
	req.PTY, req.Term = true, "xterm-256color"
	status, err := f.client.Launch(context.Background(), req, []*os.File{slave})
	if err != nil {
		t.Fatalf("Launch() error: %v", err)
	}
	if status != 5 {
		t.Errorf("status = %d, want 5", status)
	}
	select {
	case out := <-output:
		if !strings.Contains(out, "/dev/pts/") || !strings.Contains(out, "42") {
			t.Errorf("pty output = %q, want the tty name and 42", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pty never reached EOF")
	}
}

// newSocketHelperAs is newSocketHelper with helperUser mapped to uid, so the
// helper has to switch users, which needs root.
func newSocketHelperAs(t *testing.T, uid int) *helperFixture {
	t.Helper()
	passwd := filepath.Join(t.TempDir(), "passwd")
	entry := fmt.Sprintf("%s:x:%d:%d:test:/:/bin/sh\n", helperUser, uid, uid)
	if err := os.WriteFile(passwd, []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := passwdPath
	passwdPath = passwd
	t.Cleanup(func() { passwdPath = prev })

	pub, priv := newSigningKey(t)
	return &helperFixture{
		pub: pub, priv: priv, passwd: passwd,
		client: NewSessionHelperClient(serveHelperSocket(t, []ed25519.PublicKey{pub}, nil), nil, staticKeys{pub}, discardLogger()),
	}
}

// The helper hands the pty to the login user, as sshd does, so programs that
// open the terminal by name can. Switching to another user needs root.
func TestSessionHelper_PTYBelongsToLoginUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("switching to another user needs root")
	}
	const uid = 65534
	f := newSocketHelperAs(t, uid)
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("no pty on this host: %v", err)
	}
	defer master.Close()

	output := make(chan string, 1)
	go func() {
		var out strings.Builder
		_, _ = io.Copy(&out, master)
		output <- out.String()
	}()
	if _, err := master.Write([]byte("stat -c %u \"$(tty)\"; exit\n")); err != nil {
		t.Fatalf("write the master: %v", err)
	}

	req := f.request(t, LaunchModeShell, "", nil)
	req.PTY, req.Term = true, "xterm"
	if status, err := f.client.Launch(context.Background(), req, []*os.File{slave}); err != nil || status != 0 {
		t.Fatalf("Launch() = %d, %v; want 0", status, err)
	}
	select {
	case out := <-output:
		if !strings.Contains(out, strconv.Itoa(uid)) {
			t.Errorf("pty output = %q, want the pty owned by uid %d", out, uid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pty never reached EOF")
	}
}

// A pty request carries a pty slave. The helper hands the pty to the login
// user, so it refuses any other descriptor before it starts anything.
func TestSessionHelper_RefusesPTYRequestWithoutAPTY(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")

	for _, tc := range []struct{ name, path string }{
		{"regular file", filepath.Join(t.TempDir(), "run.sh")},
		{"character device outside devpts", os.DevNull},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.OpenFile(tc.path, os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			req := f.request(t, LaunchModeShell, "", nil)
			req.PTY, req.Term = true, "xterm"
			_, err = f.client.Launch(context.Background(), req, []*os.File{file})
			if !errors.Is(err, ErrSessionHelperRefused) || !strings.HasSuffix(err.Error(), "the pty descriptor is not a pseudo-terminal slave") {
				t.Errorf("Launch() error = %v, want the descriptor refused", err)
			}
		})
	}
}

// A refused pty request leaves the owner of its descriptor alone: a file that
// is no pty, and a pty another session holds, such as a root login's terminal
// that plexd opened. Switching to another user needs root.
func TestSessionHelper_RefusedPTYKeepsItsOwner(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("switching to another user needs root")
	}
	f := newSocketHelperAs(t, 65534)
	launch := func(t *testing.T, file *os.File) {
		t.Helper()
		owner := func() uint32 {
			info, err := os.Stat(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			return info.Sys().(*syscall.Stat_t).Uid
		}
		before := owner()
		req := f.request(t, LaunchModeShell, "", nil)
		req.PTY, req.Term = true, "xterm"
		if _, err := f.client.Launch(context.Background(), req, []*os.File{file}); !errors.Is(err, ErrSessionHelperRefused) {
			t.Errorf("Launch() error = %v, want a refusal", err)
		}
		if after := owner(); after != before {
			t.Errorf("%s changed owner from uid %d to %d", file.Name(), before, after)
		}
	}

	t.Run("a file that is no pty", func(t *testing.T) {
		file, err := os.Create(filepath.Join(t.TempDir(), "run.sh"))
		if err != nil {
			t.Fatal(err)
		}
		launch(t, file)
	})

	t.Run("a pty another session holds", func(t *testing.T) {
		master, slave, err := openPTY()
		if err != nil {
			t.Skipf("no pty on this host: %v", err)
		}
		defer master.Close()
		holder := exec.Command("sleep", "30")
		holder.Stdin = slave
		holder.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
		if err := holder.Start(); err != nil {
			t.Fatalf("start the session that holds the pty: %v", err)
		}
		t.Cleanup(func() {
			_ = holder.Process.Kill()
			_ = holder.Wait()
		})
		launch(t, slave)
	})
}

func TestSessionHelper_ScrubbedEnvironment(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")

	// The shell's own environment is exactly what the helper passed.
	res := launchPiped(context.Background(), t, f.client, f.request(t, LaunchModeExec, `tr '\0' '\n' < /proc/$$/environ`, nil), nil)
	if res.err != nil || res.status != 0 {
		t.Fatalf("Launch() = %d, %v (stderr %q)", res.status, res.err, res.stderr)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(res.stdout), "\n") {
		names = append(names, strings.SplitN(line, "=", 2)[0])
	}
	if got := strings.Join(names, ","); got != "HOME,USER,LOGNAME,SHELL,PATH" {
		t.Errorf("environment = %s, want exactly HOME,USER,LOGNAME,SHELL,PATH", got)
	}

	// env shows the five with their values; anything else is a variable the
	// shell maintains itself.
	res = launchPiped(context.Background(), t, f.client, f.request(t, LaunchModeExec, "env", nil), nil)
	if res.err != nil || res.status != 0 {
		t.Fatalf("Launch() = %d, %v (stderr %q)", res.status, res.err, res.stderr)
	}
	want := map[string]string{
		"USER":    helperUser,
		"LOGNAME": helperUser,
		"SHELL":   "/bin/sh",
		"PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(res.stdout), "\n") {
		name, value, _ := strings.Cut(line, "=")
		switch name {
		case "PWD", "OLDPWD", "SHLVL", "_":
			continue
		case "HOME":
			if !strings.HasSuffix(value, "/home") {
				t.Errorf("HOME = %q, want the fixture's home", value)
			}
		default:
			if w, ok := want[name]; !ok || w != value {
				t.Errorf("env carries %s=%q, want only HOME, USER, LOGNAME, SHELL and PATH", name, value)
			}
		}
		seen[name] = true
	}
	for _, name := range []string{"HOME", "USER", "LOGNAME", "SHELL", "PATH"} {
		if !seen[name] {
			t.Errorf("env lacks %s", name)
		}
	}
}

func TestSessionHelper_RefusesUnauthorized(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")
	marker := filepath.Join(t.TempDir(), "marker")
	_, otherPriv := newSigningKey(t)

	foreign := f.request(t, LaunchModeExec, "touch "+marker, nil)
	foreign.Token = sessionToken(t, otherPriv, "sess-helper", helperUser, nil)

	for _, tc := range []struct {
		name   string
		req    LaunchRequest
		reason string
	}{
		{"token signed by another key", foreign, "token refused: " + ErrSessionTokenSignature.Error()},
		{"shell under an allowed-command list", f.request(t, LaunchModeShell, "", []string{"uptime"}), "interactive shell is not allowed for this session"},
		{"exec outside the allowed-command list", f.request(t, LaunchModeExec, "touch "+marker, []string{"uptime"}), "command is not in this session's allowed-command list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := launchPiped(context.Background(), t, f.client, tc.req, nil)
			if !errors.Is(res.err, ErrSessionHelperRefused) {
				t.Fatalf("Launch() error = %v, want ErrSessionHelperRefused", res.err)
			}
			if !strings.HasSuffix(res.err.Error(), ": "+tc.reason) {
				t.Errorf("Launch() error = %q, want the reason %q", res.err, tc.reason)
			}
		})
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused exec left %s behind (stat error %v)", marker, err)
	}
}

func TestSessionHelper_RefusesBadModes(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")

	for _, tc := range []struct {
		name   string
		req    LaunchRequest
		reason string
	}{
		{"exec without a command", f.request(t, LaunchModeExec, "", nil), "exec request carries no command"},
		{"exec with 1025 bytes", f.request(t, LaunchModeExec, strings.Repeat("x", 1025), nil), "command exceeds 1024 bytes"},
		{"shell with a command", f.request(t, LaunchModeShell, "id", nil), "shell request carries a command"},
		{"unknown mode", f.request(t, "subsystem", "sftp", nil), `unknown mode "subsystem"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := launchPiped(context.Background(), t, f.client, tc.req, nil)
			if !errors.Is(res.err, ErrSessionHelperRefused) || !strings.HasSuffix(res.err.Error(), ": "+tc.reason) {
				t.Errorf("Launch() error = %v, want the refusal %q", res.err, tc.reason)
			}
		})
	}
}

func TestSessionHelper_RefusesUnknownUserAndBadShell(t *testing.T) {
	t.Run("unknown user", func(t *testing.T) {
		f := newSocketHelper(t, "/bin/sh")
		req := f.request(t, LaunchModeExec, "id", nil)
		req.User = "ghost"
		req.Token = sessionToken(t, f.priv, "sess-helper", "ghost", nil)
		res := launchPiped(context.Background(), t, f.client, req, nil)
		if !errors.Is(res.err, ErrSessionHelperRefused) || !strings.HasSuffix(res.err.Error(), `: user "ghost" does not exist on this node`) {
			t.Errorf("Launch() error = %v, want the unknown user refused", res.err)
		}
	})

	t.Run("shell that does not exist", func(t *testing.T) {
		f := newSocketHelper(t, "/nonexistent/sh")
		res := launchPiped(context.Background(), t, f.client, f.request(t, LaunchModeExec, "id", nil), nil)
		want := ": start /nonexistent/sh as " + helperUser + ": "
		if !errors.Is(res.err, ErrSessionHelperRefused) || !strings.Contains(res.err.Error(), want) {
			t.Errorf("Launch() error = %v, want %q", res.err, want)
		}
	})
}

// sendRawRequest hands RunSessionHelper a request with n descriptors over a
// socketpair, bypassing the client's own count check, and returns the answer.
func sendRawRequest(t *testing.T, req LaunchRequest, n int) helperResponse {
	t.Helper()
	line, _ := json.Marshal(req)
	return sendRawLine(t, append(line, '\n'), n)
}

// sendRawLine is sendRawRequest for a request line given as bytes.
func sendRawLine(t *testing.T, line []byte, n int) helperResponse {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	unixConn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "pair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	client, server := unixConn(pair[0]), unixConn(pair[1])
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() { done <- RunSessionHelper(server, nil, discardLogger()) }()

	var files []*os.File
	defer func() { closeFiles(files) }()
	var fds []int
	for i := 0; i < n; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		fds = append(fds, int(f.Fd()))
	}
	if _, _, err := client.WriteMsgUnix(line, syscall.UnixRights(fds...), nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	answer, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("RunSessionHelper() error: %v", err)
	}
	var resp helperResponse
	if err := json.Unmarshal(answer, &resp); err != nil {
		t.Fatalf("decode %q: %v", answer, err)
	}
	return resp
}

func TestSessionHelper_RefusesWrongFDCounts(t *testing.T) {
	base := LaunchRequest{Version: 1, SessionID: "sess-helper", User: helperUser, Mode: LaunchModeExec, Command: "id"}
	// sendRawRequest sends descriptors on /dev/null, so those are the ones a
	// refusal must not leave open.
	isDevNull := func(target string) bool { return target == os.DevNull }
	before := countFDs(t, isDevNull)

	for _, tc := range []struct {
		name string
		pty  bool
		n    int
		want string
	}{
		{"zero descriptors", false, 0, "expected 3 file descriptors, got 0"},
		{"two descriptors without a pty", false, 2, "expected 3 file descriptors, got 2"},
		{"three descriptors with a pty", true, 3, "expected 1 file descriptors, got 3"},
		{"more descriptors than the helper takes", false, sessionHelperMaxFDs + 1, "request carries too many file descriptors"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.PTY = tc.pty
			if resp := sendRawRequest(t, req, tc.n); resp.Error != tc.want {
				t.Errorf("answer = %+v, want the refusal %q", resp, tc.want)
			}
		})
	}
	if after := countFDs(t, isDevNull); after != before {
		t.Errorf("descriptors on %s went from %d to %d; a received descriptor was not closed", os.DevNull, before, after)
	}

	t.Run("malformed requests", func(t *testing.T) {
		old := base
		old.Version = 2
		if resp := sendRawRequest(t, old, 3); resp.Error != "unsupported request version 2" {
			t.Errorf("answer = %+v, want the version refused", resp)
		}
		for _, tc := range []struct {
			name string
			line []byte
			want string
		}{
			{"a line without a newline past the cap", bytes.Repeat([]byte("x"), maxLaunchRequestBytes+1), "request exceeds 16384 bytes"},
			{"a line that is not JSON", []byte("{not json}\n"), "request is not valid JSON"},
		} {
			if resp := sendRawLine(t, tc.line, 3); resp.Error != tc.want {
				t.Errorf("%s: answer = %+v, want the refusal %q", tc.name, resp, tc.want)
			}
		}
	})
}

// FuzzParseLaunchRequestLine holds the decoder of the first bytes a request
// brings into the root helper to its contract: it never panics, and a request
// it accepts carries the one version there is.
func FuzzParseLaunchRequestLine(f *testing.F) {
	valid, _ := json.Marshal(LaunchRequest{Version: 1, SessionID: "s", User: "u", Token: "t", Mode: LaunchModeExec, Command: "id"})
	f.Add(append(valid, '\n'))
	f.Add(valid)
	f.Add([]byte("{not json}\n"))
	f.Add([]byte(`{"v":2}` + "\n"))
	f.Add([]byte("null\n"))
	f.Add([]byte("\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, line []byte) {
		req, reason := parseLaunchRequestLine(line)
		if reason == "" && req.Version != launchRequestVersion {
			t.Fatalf("accepted a request of version %d", req.Version)
		}
	})
}

func TestSessionHelper_CancelKillsProcessGroup(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pids := make(chan int, 1)
	res := launchPiped(ctx, t, f.client, f.request(t, LaunchModeExec, "echo $$; sleep 30", nil), func(line string) {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			pids <- pid
			cancel()
		}
	})
	if res.err != nil || res.status != 129 {
		t.Fatalf("Launch() = %d, %v; want 129, the death by SIGHUP", res.status, res.err)
	}
	waitGone(t, <-pids, 3*time.Second)
}

// A cancelled launch returns the status the helper answered with, so a process
// that handles SIGHUP and exits cleanly is recorded with its own exit code. The
// trap waits on a background sleep: a trapped signal interrupts wait, but not a
// foreground command.
func TestSessionHelperClient_CancelKeepsTheProcessStatus(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res := launchPiped(ctx, t, f.client, f.request(t, LaunchModeExec, "trap 'exit 0' HUP; echo ready; sleep 30 & wait", nil), func(string) { cancel() })
	if res.err != nil || res.status != 0 {
		t.Fatalf("Launch() = %d, %v; want 0 from the trap", res.status, res.err)
	}
}

// A process that ignores SIGHUP is killed with SIGKILL once the grace passed.
func TestSessionHelper_CancelEscalatesToSIGKILL(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pids := make(chan int, 1)
	start := time.Now()
	res := launchPiped(ctx, t, f.client, f.request(t, LaunchModeExec, "trap '' HUP; echo $$; sleep 30", nil), func(line string) {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			pids <- pid
			cancel()
		}
	})
	if res.err != nil || res.status != 137 {
		t.Fatalf("Launch() = %d, %v; want 137, the death by SIGKILL", res.status, res.err)
	}
	// The output reaches EOF only once the group is gone.
	if took, bound := time.Since(start), sessionHelperKillGrace+drainTimeout+time.Second; took > bound {
		t.Errorf("the launch took %v to end, want at most %v", took, bound)
	}
	waitGone(t, <-pids, sessionHelperKillGrace+3*time.Second)
}

// A cancelled launch returns only once the helper stopped the process, so the
// channel slot it held is never free while its helper still runs. The process
// ignores SIGHUP and lets go of its output, so only the helper's answer can
// hold the launch.
func TestSessionHelperClient_CancelWaitsForTheHelper(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var pid int
	res := launchPiped(ctx, t, f.client, f.request(t, LaunchModeExec, "trap '' HUP; echo $$; exec >/dev/null 2>&1; sleep 30", nil), func(line string) {
		if p, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			pid = p
			cancel()
		}
	})
	if res.err != nil || res.status != 137 {
		t.Fatalf("Launch() = %d, %v; want 137, the death by SIGKILL", res.status, res.err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("the process was still there when the launch returned (kill -0: %v)", err)
	}
}

func TestSessionHelper_KillsLeftoverProcesses(t *testing.T) {
	f := newSocketHelper(t, "/bin/sh")

	res := launchPiped(context.Background(), t, f.client, f.request(t, LaunchModeExec, "sleep 30 & echo $!", nil), nil)
	if res.err != nil || res.status != 0 {
		t.Fatalf("Launch() = %d, %v", res.status, res.err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(res.stdout))
	if err != nil {
		t.Fatalf("stdout %q carries no pid", res.stdout)
	}
	waitGone(t, pid, 3*time.Second)
}

func TestSessionHelperClient_SocketAndChildModes(t *testing.T) {
	pub, priv := newSigningKey(t)
	passwd := usePasswdFixture(t, "/bin/sh")
	req := LaunchRequest{
		Version: 1, SessionID: "sess-helper", User: helperUser, Mode: LaunchModeExec, Command: "echo hi",
		Token: sessionToken(t, priv, "sess-helper", helperUser, nil),
	}

	t.Run("socket", func(t *testing.T) {
		path := serveHelperSocket(t, []ed25519.PublicKey{pub}, nil)
		childStarted := false
		client := NewSessionHelperClient(path, func([]ed25519.PublicKey) *exec.Cmd {
			childStarted = true
			return exec.Command("/bin/false")
		}, staticKeys{pub}, discardLogger())
		res := launchPiped(context.Background(), t, client, req, nil)
		if res.err != nil || res.status != 0 || res.stdout != "hi\n" {
			t.Errorf("Launch() = %d, %v, stdout %q; want 0 and hi", res.status, res.err, res.stdout)
		}
		if childStarted {
			t.Error("a child helper was started although the socket listens")
		}
	})

	t.Run("child", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.sock")
		client := NewSessionHelperClient(missing, testHelperChild(passwd), staticKeys{pub}, discardLogger())
		res := launchPiped(context.Background(), t, client, req, nil)
		if res.err != nil || res.status != 0 || res.stdout != "hi\n" {
			t.Errorf("Launch() = %d, %v, stdout %q; want 0 and hi", res.status, res.err, res.stdout)
		}
	})

	t.Run("child is killed with the process group on cancel", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.sock")
		client := NewSessionHelperClient(missing, testHelperChild(passwd), staticKeys{pub}, discardLogger())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sleeper := req
		sleeper.Command = "echo $$; sleep 30"
		pids := make(chan int, 1)
		res := launchPiped(ctx, t, client, sleeper, func(line string) {
			if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
				pids <- pid
				cancel()
			}
		})
		if res.err != nil || res.status != 129 {
			t.Fatalf("Launch() = %d, %v; want 129, the death by SIGHUP", res.status, res.err)
		}
		waitGone(t, <-pids, 3*time.Second)
	})
}

func TestSessionHelperClient_DialFailureDoesNotFallBack(t *testing.T) {
	pub, priv := newSigningKey(t)
	path := filepath.Join(shortTempDir(t), "dead.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()

	childStarted := false
	client := NewSessionHelperClient(path, func([]ed25519.PublicKey) *exec.Cmd {
		childStarted = true
		return exec.Command("/bin/false")
	}, staticKeys{pub}, discardLogger())
	req := LaunchRequest{Version: 1, SessionID: "s", User: helperUser, Mode: LaunchModeExec, Command: "id", Token: sessionToken(t, priv, "s", helperUser, nil)}

	res := launchPiped(context.Background(), t, client, req, nil)
	if res.err == nil || !strings.HasPrefix(res.err.Error(), "tunnel: session helper: dial "+path+": ") {
		t.Errorf("Launch() error = %v, want the dial failure", res.err)
	}
	if childStarted {
		t.Error("the client fell back to a child helper although the socket exists")
	}
}

// Only a missing socket path starts the child helper. A path whose state
// cannot be read is an error, for the same reason a refused dial is; a path
// holding something other than a socket is no helper socket.
func TestSessionHelperClient_SocketPathStates(t *testing.T) {
	pub, priv := newSigningKey(t)
	req := LaunchRequest{Version: 1, SessionID: "s", User: helperUser, Mode: LaunchModeExec, Command: "id", Token: sessionToken(t, priv, "s", helperUser, nil)}
	launch := func(t *testing.T, path string) (execResult, bool) {
		t.Helper()
		childStarted := false
		client := NewSessionHelperClient(path, func([]ed25519.PublicKey) *exec.Cmd {
			childStarted = true
			return exec.Command("/bin/false")
		}, staticKeys{pub}, discardLogger())
		res := launchPiped(context.Background(), t, client, req, nil)
		return res, childStarted
	}

	t.Run("stat failure does not fall back", func(t *testing.T) {
		// ENOTDIR, which root gets as well.
		const path = "/dev/null/helper.sock"
		res, childStarted := launch(t, path)
		if res.err == nil || !strings.HasPrefix(res.err.Error(), "tunnel: session helper: stat "+path+": ") {
			t.Errorf("Launch() error = %v, want the stat failure", res.err)
		}
		if childStarted {
			t.Error("the client fell back to a child helper although the socket path could not be read")
		}
	})

	t.Run("regular file falls back to the child", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "helper.sock")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, childStarted := launch(t, path); !childStarted {
			t.Error("no child helper was started for a path that holds no socket")
		}
	})
}

func TestSessionHelperClient_ResponseErrors(t *testing.T) {
	pub, _ := newSigningKey(t)
	req := LaunchRequest{Version: 1, SessionID: "s", User: helperUser, Mode: LaunchModeExec, Command: "id"}

	// answering reads the request, as a helper does, then answers with reply.
	answering := func(reply string) func(*net.UnixConn) {
		return func(c *net.UnixConn) {
			_, files, _ := readLaunchRequest(c)
			closeFiles(files)
			if reply != "" {
				_, _ = c.Write([]byte(reply))
			}
		}
	}

	for _, tc := range []struct {
		name       string
		serve      func(*net.UnixConn)
		wantPrefix string
	}{
		{"closed without an answer", answering(""), "tunnel: session helper: no response: EOF"},
		{"not json", answering("not json\n"), "tunnel: session helper: malformed response: "},
		{"neither member", answering("{}\n"), "tunnel: session helper: malformed response: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := serveHelperSocket(t, nil, tc.serve)
			client := NewSessionHelperClient(path, nil, staticKeys{pub}, discardLogger())
			res := launchPiped(context.Background(), t, client, req, nil)
			if res.err == nil || !strings.HasPrefix(res.err.Error(), tc.wantPrefix) {
				t.Errorf("Launch() error = %v, want prefix %q", res.err, tc.wantPrefix)
			}
		})
	}

	t.Run("child that does not exist", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.sock")
		client := NewSessionHelperClient(missing, func([]ed25519.PublicKey) *exec.Cmd {
			return exec.Command("/nonexistent/plexd", "session-helper", "--child")
		}, staticKeys{pub}, discardLogger())
		res := launchPiped(context.Background(), t, client, req, nil)
		if res.err == nil || !strings.HasPrefix(res.err.Error(), "tunnel: session helper: start child: ") {
			t.Errorf("Launch() error = %v, want the start failure", res.err)
		}
	})
}

func TestSessionHelperClient_ClosesFilesOnSendFailure(t *testing.T) {
	pub, _ := newSigningKey(t)
	path := serveHelperSocket(t, nil, func(c *net.UnixConn) { _, _ = io.Copy(io.Discard, c) })
	client := NewSessionHelperClient(path, nil, staticKeys{pub}, discardLogger())

	var files []*os.File
	for i := 0; i < 3; i++ {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	// A descriptor that is already gone makes the sendmsg fail.
	files[1].Close()

	_, err := client.Launch(context.Background(), LaunchRequest{Version: 1, Mode: LaunchModeExec, Command: "id"}, files)
	if err == nil || !strings.HasPrefix(err.Error(), "tunnel: session helper: send request: ") {
		t.Fatalf("Launch() error = %v, want the send failure", err)
	}
	for _, i := range []int{0, 2} {
		if err := files[i].Close(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("file %d was left open after the failed send (Close error %v)", i, err)
		}
	}
}
