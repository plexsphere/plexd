//go:build linux

package tunnel

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// passwdPath is where the session helper resolves login users. It is a
// variable so tests can point it at a fixture.
var passwdPath = "/etc/passwd"

const (
	// sessionHelperIOTimeout bounds reading the request and writing the
	// response.
	sessionHelperIOTimeout = 10 * time.Second
	// sessionHelperKillGrace is how long a process gets between SIGHUP and
	// SIGKILL once plexd hung up.
	sessionHelperKillGrace = 2 * time.Second
	// sessionHelperMaxFDs is the most descriptors a request may carry before
	// the helper treats it as malformed.
	sessionHelperMaxFDs = 16
)

// sessionHelperPath is the PATH every process the helper starts gets.
const sessionHelperPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// RunSessionHelper serves one request of the session helper protocol on conn
// (see SessionHelperClient) and verifies it against keys: the session token,
// the mode against the token's allowed commands, and the login user against
// /etc/passwd. It then starts the shell or command as that user, in its own
// session and process group, with the received descriptors as its standard
// streams, and answers with its exit status.
//
// It returns nil once it wrote a response, a refusal included, and an error
// when it could not read a request or write the response. Every received
// descriptor is closed before it returns.
//
// DECISION: the helper kills what is left of the process group once the main
// process exited, so a command cannot leave a process behind that outlives the
// session. Under socket activation systemd also kills the instance's cgroup
// (KillMode=control-group).
func RunSessionHelper(conn *net.UnixConn, keys []ed25519.PublicKey, logger *slog.Logger) error {
	req, files, err := readLaunchRequest(conn)
	if err != nil {
		closeFiles(files)
		return fmt.Errorf("session helper: read request: %w", err)
	}

	refuse := func(reason string) error {
		closeFiles(files)
		logger.Warn("session helper refused a request", "session_id", req.SessionID, "reason", reason)
		return writeHelperResponse(conn, helperResponse{Error: reason})
	}

	if req.malformed != "" {
		return refuse(req.malformed)
	}
	if want := req.fileCount(); len(files) != want {
		return refuse(fmt.Sprintf("expected %d file descriptors, got %d", want, len(files)))
	}

	claims, err := VerifySessionToken(req.Token, keys, req.SessionID, req.User, time.Now())
	if err != nil {
		return refuse("token refused: " + err.Error())
	}

	// The token's list is enforced here whatever plexd checked before.
	switch req.Mode {
	case LaunchModeShell:
		if req.Command != "" {
			return refuse("shell request carries a command")
		}
		if len(claims.AllowedCommands) > 0 {
			return refuse("interactive shell is not allowed for this session")
		}
	case LaunchModeExec:
		if req.Command == "" {
			return refuse("exec request carries no command")
		}
		if len(req.Command) > maxSSHCommandBytes {
			return refuse(fmt.Sprintf("command exceeds %d bytes", maxSSHCommandBytes))
		}
		if len(claims.AllowedCommands) > 0 && !slices.Contains(claims.AllowedCommands, req.Command) {
			return refuse("command is not in this session's allowed-command list")
		}
	default:
		return refuse(fmt.Sprintf("unknown mode %q", req.Mode))
	}

	account, err := lookupLoginUser(req.User)
	if err != nil {
		return refuse(err.Error())
	}
	// The pty changes owner below, so nothing but a pty slave may stand in for
	// it.
	if req.PTY {
		if err := checkPTYSlave(files[0]); err != nil {
			return refuse(err.Error())
		}
	}

	cmd := buildSessionCommand(req.LaunchRequest, account, files)
	if err := cmd.Start(); err != nil {
		return refuse(fmt.Sprintf("start %s as %s: %v", account.shell, account.name, err))
	}
	// plexd opened the pty, so it belongs to plexd's user. Like sshd, the
	// helper hands it to the login user, or programs that open the terminal
	// by name (screen, pinentry-curses) cannot. It does so only now: Start
	// made the pty the new session's controlling terminal as the login user,
	// which the kernel refuses for a terminal another session holds, so a
	// descriptor plexd opened on someone else's terminal never changes hands.
	if req.PTY && int(account.uid) != os.Getuid() {
		if err := files[0].Chown(int(account.uid), -1); err != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
			return refuse(fmt.Sprintf("hand the pty to %s: %v", account.name, err))
		}
	}
	// The child holds its own copies.
	closeFiles(files)
	pid := cmd.Process.Pid
	logger.Info("session helper started process",
		"session_id", req.SessionID,
		"user", account.name,
		"mode", req.Mode,
		"command", req.Command,
		"pid", pid,
	)

	// plexd hanging up is the stop signal: SIGHUP to the process group, then
	// SIGKILL once the grace has passed.
	exited := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		var b [64]byte
		for {
			if _, err := conn.Read(b[:]); err != nil {
				break
			}
		}
		select {
		case <-exited:
			return
		default:
		}
		_ = syscall.Kill(-pid, syscall.SIGHUP)
		select {
		case <-exited:
		case <-time.After(sessionHelperKillGrace):
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}()

	_ = cmd.Wait()
	status := exitStatusOf(cmd.ProcessState)
	// Anything the process left behind in its group goes with it.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	close(exited)
	_ = conn.SetReadDeadline(time.Now())
	<-watched

	logger.Info("session helper process exited", "session_id", req.SessionID, "exit_status", status)
	return writeHelperResponse(conn, helperResponse{ExitStatus: &status})
}

// decodedLaunchRequest is a decoded request, or the reason it is refused.
type decodedLaunchRequest struct {
	LaunchRequest
	malformed string
}

// readLaunchRequest reads one request line and the descriptors sent with it.
// The descriptors are returned on every path, so the caller can close them.
func readLaunchRequest(conn *net.UnixConn) (decodedLaunchRequest, []*os.File, error) {
	if err := conn.SetReadDeadline(time.Now().Add(sessionHelperIOTimeout)); err != nil {
		return decodedLaunchRequest{}, nil, err
	}
	buf := make([]byte, maxLaunchRequestBytes+1)
	oob := make([]byte, syscall.CmsgSpace(sessionHelperMaxFDs*4))
	n, oobn, flags, _, err := conn.ReadMsgUnix(buf, oob)
	files := receivedFiles(oob[:oobn])
	if err != nil {
		return decodedLaunchRequest{}, files, err
	}
	var req decodedLaunchRequest
	if flags&syscall.MSG_CTRUNC != 0 {
		req.malformed = "request carries too many file descriptors"
	}

	line := buf[:n]
	for !bytes.Contains(line, []byte("\n")) && len(line) <= maxLaunchRequestBytes {
		m, err := conn.Read(buf[len(line):])
		line = buf[:len(line)+m]
		if err != nil {
			return decodedLaunchRequest{}, files, err
		}
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return decodedLaunchRequest{}, files, err
	}
	if req.malformed != "" {
		return req, files, nil
	}
	req.LaunchRequest, req.malformed = parseLaunchRequestLine(line)
	return req, files, nil
}

// parseLaunchRequestLine decodes the request line that starts buf, and returns
// the reason it is refused when it is malformed. A refused request keeps what
// was decoded, so the refusal can name its session.
func parseLaunchRequestLine(buf []byte) (LaunchRequest, string) {
	var req LaunchRequest
	end := bytes.IndexByte(buf, '\n')
	switch {
	case end < 0:
		return req, fmt.Sprintf("request exceeds %d bytes", maxLaunchRequestBytes)
	case json.Unmarshal(buf[:end], &req) != nil:
		return req, "request is not valid JSON"
	case req.Version != launchRequestVersion:
		return req, fmt.Sprintf("unsupported request version %d", req.Version)
	}
	return req, ""
}

// receivedFiles turns the SCM_RIGHTS in oob into files.
func receivedFiles(oob []byte) []*os.File {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var files []*os.File
	for _, msg := range msgs {
		fds, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "session-helper-fd"))
		}
	}
	return files
}

func writeHelperResponse(conn *net.UnixConn, resp helperResponse) error {
	line, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("session helper: encode response: %w", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(sessionHelperIOTimeout)); err != nil {
		return fmt.Errorf("session helper: write response: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("session helper: write response: %w", err)
	}
	return nil
}

// checkPTYSlave refuses a descriptor that is not a pseudo-terminal slave: a
// character device of the Unix98 pty slave majors, 136 to 143, on devpts.
func checkPTYSlave(f *os.File) error {
	var st unix.Stat_t
	var fs unix.Statfs_t
	err := controlFile(f, func(fd int) error {
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		return unix.Fstatfs(fd, &fs)
	})
	major := unix.Major(uint64(st.Rdev))
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || fs.Type != unix.DEVPTS_SUPER_MAGIC || major < 136 || major > 143 {
		return errors.New("the pty descriptor is not a pseudo-terminal slave")
	}
	return nil
}

// loginUser is the part of a passwd entry the helper starts a process from.
type loginUser struct {
	name        string
	uid, gid    uint32
	home, shell string
	groups      []uint32
}

// lookupLoginUser resolves name from passwdPath. Supplementary groups come from
// os/user, which reads /etc/group; the primary group stands in when that
// fails. NSS sources such as LDAP are not consulted.
func lookupLoginUser(name string) (loginUser, error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return loginUser{}, fmt.Errorf("read %s: %w", passwdPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 || fields[0] != name {
			continue
		}
		uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
		gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
		if uidErr != nil || gidErr != nil {
			return loginUser{}, fmt.Errorf("user %q has a malformed entry in %s", name, passwdPath)
		}
		u := loginUser{name: name, uid: uint32(uid), gid: uint32(gid), home: fields[5], shell: fields[6]}
		if u.shell == "" {
			u.shell = "/bin/sh"
		}
		u.groups = supplementaryGroups(fields[2], u.gid)
		return u, nil
	}
	if err := scanner.Err(); err != nil {
		return loginUser{}, fmt.Errorf("read %s: %w", passwdPath, err)
	}
	return loginUser{}, fmt.Errorf("user %q does not exist on this node", name)
}

func supplementaryGroups(uid string, gid uint32) []uint32 {
	u, err := user.LookupId(uid)
	if err != nil {
		return []uint32{gid}
	}
	ids, err := u.GroupIds()
	if err != nil {
		return []uint32{gid}
	}
	groups := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if g, err := strconv.ParseUint(id, 10, 32); err == nil {
			groups = append(groups, uint32(g))
		}
	}
	return groups
}

// buildSessionCommand builds the process for req: a login shell, or one command
// through the shell, with a scrubbed environment and the received descriptors
// as its standard streams.
func buildSessionCommand(req LaunchRequest, u loginUser, files []*os.File) *exec.Cmd {
	base := filepath.Base(u.shell)
	args := []string{"-" + base}
	if req.Mode == LaunchModeExec {
		args = []string{base, "-c", req.Command}
	}
	env := []string{
		"HOME=" + u.home,
		"USER=" + u.name,
		"LOGNAME=" + u.name,
		"SHELL=" + u.shell,
		sessionHelperPath,
	}
	if req.PTY {
		env = append(env, "TERM="+req.Term)
	}
	dir := "/"
	if info, err := os.Stat(u.home); err == nil && info.IsDir() {
		dir = u.home
	}

	cmd := &exec.Cmd{Path: u.shell, Args: args, Env: env, Dir: dir}
	if req.PTY {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[0], files[0]
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[1], files[2]
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: req.PTY, Ctty: 0}
	// A helper already running as the login user (the child helper, started by
	// an unprivileged plexd) cannot and need not switch.
	if int(u.uid) != os.Getuid() {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: u.uid, Gid: u.gid, Groups: u.groups}
	}
	return cmd
}

// exitStatusOf is the exit code, or 128 plus the signal for a death by signal,
// the way a shell reports it.
func exitStatusOf(state *os.ProcessState) int {
	if state == nil {
		return 1
	}
	var ws syscall.WaitStatus
	if s, ok := state.Sys().(syscall.WaitStatus); ok {
		ws = s
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return state.ExitCode()
}
