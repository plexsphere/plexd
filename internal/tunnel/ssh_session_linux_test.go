//go:build linux

package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// countFDs counts this process's descriptors whose target match accepts.
// Counting only the targets a test is about keeps descriptors other tests
// close in the background, a garbage-collected file among them, out of it.
func countFDs(t *testing.T, match func(target string) bool) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && match(target) {
			n++
		}
	}
	return n
}

// A pty exec the control plane did not record never runs, and its pty is closed
// with the refusal.
func TestSSHSession_RefusedPTYExecClosesThePTY(t *testing.T) {
	launcher := &fakeLauncher{}
	h := startSSHHarness(t, launcher, nil)
	h.reporter.mu.Lock()
	h.reporter.commandStartedErr = errors.New("control plane unreachable")
	h.reporter.mu.Unlock()
	client := h.login(t, nil)

	isPTY := func(target string) bool { return target == "/dev/ptmx" || strings.HasPrefix(target, "/dev/pts/") }
	before := countFDs(t, isPTY)
	for i := 0; i < 3; i++ {
		session := newSSHChannel(t, client)
		if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
			t.Fatalf("RequestPty() error: %v", err)
		}
		if got := exitStatus(t, session.Run("uptime")); got != 1 {
			t.Errorf("exit status = %d, want 1", got)
		}
	}
	waitForCondition(t, 2*time.Second, func() bool { return countFDs(t, isPTY) <= before })
	if n := len(launcher.launches()); n != 0 {
		t.Errorf("launcher called %d times, want 0", n)
	}
}

// Criterion: the pty descriptors counted after the kept shell started return
// to that count within 2 s after three reattaches from new connections, each
// of which allocated a pty of its own.
func TestSSHSession_KeptShellReattachClosesTheSparePTYs(t *testing.T) {
	// An *os.File nothing references any more is closed by its finalizer once
	// the garbage collector runs, which the polling below would trigger. With
	// the collector off, only the closes plexd makes itself bring the count
	// back.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	l := newFakeShellLauncher()
	h := startSSHHarness(t, l.fakeLauncher, nil)
	isPTY := func(target string) bool { return target == "/dev/ptmx" || strings.HasPrefix(target, "/dev/pts/") }

	openKeptShell(t, h.login(t, nil), "xterm", 24, 80)
	l.awaitRun(t, 0)
	before := countFDs(t, isPTY)

	var last *shellChannel
	for i := 0; i < 3; i++ {
		client := h.login(t, nil)
		last = openKeptShell(t, client, "xterm", 24, 80)
		wantShellState(t, client, "reattached")
	}
	waitForCondition(t, 2*time.Second, func() bool { return countFDs(t, isPTY) <= before })
	// The kept shell's own pty is still open: the shell still answers.
	last.send(t, "say x")
	last.out.await(t, "out-x-out")
	if n := len(l.launches()); n != 1 {
		t.Errorf("launcher called %d times, want 1", n)
	}
}
