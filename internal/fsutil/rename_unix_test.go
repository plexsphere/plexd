//go:build unix

package fsutil

import (
	"os"
	"syscall"
	"testing"
)

// replaceRefused is false for every error on Unix: rename(2) is never refused
// because another handle holds the target, so every writer error in
// writeSameFileConcurrently stays a failure.
func replaceRefused(error) bool { return false }

func TestReplaceRefused_NeverOnUnix(t *testing.T) {
	for _, err := range []error{
		&os.LinkError{Op: "rename", Old: "a", New: "b", Err: syscall.EACCES},
		nil,
	} {
		if replaceRefused(err) {
			t.Errorf("replaceRefused(%v) = true, want false on unix", err)
		}
	}
}
