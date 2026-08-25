//go:build windows

package packaging

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestRealRootChecker_IsRoot pins the Windows checker to the token elevation
// state rather than to a fixed expectation: the GitHub windows-latest runner is
// elevated and a developer's shell usually is not, so what is under test is that
// plexd reads the same answer the API gives.
func TestRealRootChecker_IsRoot(t *testing.T) {
	checker := NewRootChecker()
	want := windows.GetCurrentProcessToken().IsElevated()
	if got := checker.IsRoot(); got != want {
		t.Errorf("IsRoot() = %v, want %v (token elevation)", got, want)
	}
}
