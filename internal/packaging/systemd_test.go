package packaging

import (
	"os"
	"testing"
)

func TestNewSystemdController_ImplementsInterface(t *testing.T) {
	var _ SystemdController = NewSystemdController()
}

func TestNewRootChecker_ImplementsInterface(t *testing.T) {
	var _ RootChecker = NewRootChecker()
}

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

func TestRealSystemdController_IsAvailable(t *testing.T) {
	ctrl := NewSystemdController()
	// Just verify it returns a bool without panicking.
	// The actual value depends on the test environment.
	_ = ctrl.IsAvailable()
}
