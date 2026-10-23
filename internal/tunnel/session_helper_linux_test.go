//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ptySlavePrefix is where Linux names the slave of a pty.
const ptySlavePrefix = "/dev/pts/"

// ttyOwnerCommand prints the owner uid of the file it is given (GNU stat).
const ttyOwnerCommand = "stat -c %u"

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

// The shell's environment is exactly what the helper passed, read from the
// kernel rather than through env, which the shell adds its own variables to.
func TestSessionHelper_ExactEnvironment(t *testing.T) {
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
}

// A refusal closes every descriptor the request carried. sendRawRequest sends
// descriptors on /dev/null, so those are the ones a refusal must not leave
// open; only Linux names each descriptor's file in /proc/self/fd.
func TestSessionHelper_RefusalsCloseReceivedFDs(t *testing.T) {
	isDevNull := func(target string) bool { return target == os.DevNull }
	before := countFDs(t, isDevNull)
	for _, tc := range wrongFDCountCases {
		if resp := sendRawRequest(t, wrongFDCountRequest(tc.pty), tc.n); resp.Error != tc.want {
			t.Errorf("%s: answer = %+v, want the refusal %q", tc.name, resp, tc.want)
		}
	}
	if after := countFDs(t, isDevNull); after != before {
		t.Errorf("descriptors on %s went from %d to %d; a received descriptor was not closed", os.DevNull, before, after)
	}
}
