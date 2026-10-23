//go:build linux

package tunnel

import (
	"errors"
	"os"
	"path/filepath"
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
