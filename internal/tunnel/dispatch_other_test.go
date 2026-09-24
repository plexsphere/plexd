//go:build !linux

package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Off Linux an ssh entry is settled like a k8s one: one warning, no listener,
// no activity row, even with ssh sessions wired.
func TestDispatcher_SSHUnsupportedOffLinux(t *testing.T) {
	d, mgr, reporter, logs := newTestDispatcher(t, Config{})
	deps, _ := newSSHTestDeps(t, reporter, &fakeLauncher{})
	mgr.SetSSHSessionDeps(deps)

	snapshot := sessionsSnapshot(sshEntry("sess-ssh", "ops", time.Now().Add(5*time.Minute)))
	d.Handle(context.Background(), snapshot)
	d.Handle(context.Background(), snapshot)

	if mgr.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount()=0, got %d", mgr.ActiveCount())
	}
	if n := logs.count("unsupported session kind; no listener provisioned"); n != 1 {
		t.Errorf("unsupported-kind warned %d times across two pulls, want 1", n)
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if len(reporter.startedCalls) != 0 {
		t.Errorf("expected no started row, got %d", len(reporter.startedCalls))
	}
}

func TestSessionManager_SSHUnsupportedOffLinux(t *testing.T) {
	mgr := newTestManager(t, Config{})
	deps, _ := newSSHTestDeps(t, &mockReporter{}, &fakeLauncher{})
	mgr.SetSSHSessionDeps(deps)

	_, err := mgr.CreateSession(context.Background(), sshEntry("sess-ssh", "ops", time.Now().Add(5*time.Minute)))
	if !errors.Is(err, ErrSSHSessionsUnsupported) {
		t.Errorf("CreateSession() error = %v, want ErrSSHSessionsUnsupported", err)
	}
}
