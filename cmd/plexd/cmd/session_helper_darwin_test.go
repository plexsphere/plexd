//go:build darwin

package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// plexd starts the child helper with exactly sessionHelperChildArgs, so the
// command must accept that line and return every key it carries. Anything but
// a child with keys is refused: macOS has no helper socket.
func TestSessionHelperKeys_Darwin(t *testing.T) {
	prevChild, prevKeys := sessionHelperChild, sessionHelperTrustedKeys
	t.Cleanup(func() { sessionHelperChild, sessionHelperTrustedKeys = prevChild, prevKeys })

	t.Run("not a child", func(t *testing.T) {
		sessionHelperChild, sessionHelperTrustedKeys = false, nil
		const want = "plexd session-helper: plexd starts it as its own child (--child); macOS has no helper socket"
		if _, err := sessionHelperKeys(discardLogger()); err == nil || err.Error() != want {
			t.Errorf("sessionHelperKeys() error = %v, want %q", err, want)
		}
	})

	t.Run("a child without keys", func(t *testing.T) {
		sessionHelperChild, sessionHelperTrustedKeys = true, nil
		const want = "--child needs at least one --trusted-key"
		if _, err := sessionHelperKeys(discardLogger()); err == nil || err.Error() != want {
			t.Errorf("sessionHelperKeys() error = %v, want %q", err, want)
		}
	})

	t.Run("the line plexd starts the child with", func(t *testing.T) {
		sessionHelperChild, sessionHelperTrustedKeys = false, nil
		var keys []ed25519.PublicKey
		for i := 0; i < 2; i++ {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, pub)
		}
		args := sessionHelperChildArgs(keys)
		if args[0] != sessionHelperCmd.Name() {
			t.Fatalf("args[0] = %q, want the %s command", args[0], sessionHelperCmd.Name())
		}
		if err := sessionHelperCmd.ParseFlags(args[1:]); err != nil {
			t.Fatalf("ParseFlags(%q) error: %v", args[1:], err)
		}
		got, err := sessionHelperKeys(discardLogger())
		if err != nil {
			t.Fatalf("sessionHelperKeys() error: %v", err)
		}
		if len(got) != len(keys) {
			t.Fatalf("got %d keys, want %d", len(got), len(keys))
		}
		for i := range keys {
			if !got[i].Equal(keys[i]) {
				t.Errorf("key %d differs from the key it was built from", i)
			}
		}
	})
}

// A child helper writes through the daemon log writer once plexd installed
// one, and to plexd's stderr before that.
func TestSessionHelperStderr(t *testing.T) {
	prev := daemonLog
	t.Cleanup(func() { daemonLog = prev })

	daemonLog = nil
	if got := sessionHelperStderr(); got != os.Stderr {
		t.Errorf("sessionHelperStderr() = %v without a daemon log writer, want os.Stderr", got)
	}

	path := filepath.Join(t.TempDir(), "plexd.log")
	w := newReopeningLogFile(path)
	t.Cleanup(func() { _ = w.Close() })
	daemonLog = w
	line := []byte("level=INFO msg=\"session helper started process\"\n")
	if n, err := sessionHelperStderr().Write(line); n != len(line) || err != nil {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(line))
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(line) {
		t.Errorf("daemon log = %q, %v; want the child's line", got, err)
	}
}

// os/exec copies a child's stderr into a writer that is no file through a
// pipe, and closes the pipe when a write fails. The child helper's next log
// line would then kill it with SIGPIPE before it answers, and the command's
// exit status would be lost. A line the daemon log refuses is dropped instead,
// as plexd's own logger drops it.
func TestSessionHelperStderr_DropsRefusedLines(t *testing.T) {
	prev := daemonLog
	t.Cleanup(func() { daemonLog = prev })

	// The writer cannot open a file in a directory that does not exist.
	daemonLog = newReopeningLogFile(filepath.Join(t.TempDir(), "gone", "plexd.log"))
	line := []byte("level=INFO msg=\"session helper process exited\"\n")
	if n, err := sessionHelperStderr().Write(line); n != len(line) || err != nil {
		t.Errorf("Write() = %d, %v; want %d, nil so the child's pipe stays open", n, err, len(line))
	}
}
