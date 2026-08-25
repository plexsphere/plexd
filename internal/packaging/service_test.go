package packaging

import (
	"context"
	"testing"
)

// TestService_RestartAppliesDefaults proves the caller can hand NewService an
// empty InstallConfig and still reach the installed service: the daemon builds
// its controller before it knows anything about the installation, so the
// service name has to come from the defaults.
func TestService_RestartAppliesDefaults(t *testing.T) {
	mgr := &mockServiceManager{available: true}
	svc := NewService(mgr, InstallConfig{})

	if !svc.Available() {
		t.Error("Available() = false, want the manager's answer")
	}
	if err := svc.Restart(context.Background()); err != nil {
		t.Fatalf("Restart() = %v", err)
	}

	if len(mgr.restartCalls) != 1 {
		t.Fatalf("Restart called %d times, want 1", len(mgr.restartCalls))
	}
	if got := mgr.restartCalls[0].ServiceName; got != DefaultServiceName {
		t.Errorf("manager received ServiceName %q, want %q", got, DefaultServiceName)
	}
}
