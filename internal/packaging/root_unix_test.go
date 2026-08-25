//go:build unix

package packaging

import (
	"os"
	"testing"
)

func TestRealRootChecker_IsRoot(t *testing.T) {
	checker := NewRootChecker()
	// In CI, we're not root
	if os.Getuid() != 0 && checker.IsRoot() {
		t.Error("IsRoot() = true, want false for non-root user")
	}
	if os.Getuid() == 0 && !checker.IsRoot() {
		t.Error("IsRoot() = false, want true for root user")
	}
}
