package bridge

import (
	"context"
	"errors"
	"testing"
)

// Compile-time check that NetbirdProvider implements UserAccessProvider.
var _ UserAccessProvider = (*NetbirdProvider)(nil)

const netbirdStatusJSON = `{"ip":"100.119.0.1/16","fqdn":"bridge-node.netbird.cloud","connected":true,"interface":{"name":"wt0"}}`

func TestNetbirdProvider_Name(t *testing.T) {
	p := NewNetbirdProvider(newMockCommandExecutor(), discardLogger())
	if got := p.Name(); got != "netbird" {
		t.Fatalf("Name() = %q, want %q", got, "netbird")
	}
}

func TestNetbirdProvider_Start_Success(t *testing.T) {
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-setup-test123")

	exec := newMockCommandExecutor()
	exec.runOutputs[commandKey("netbird", "up", "--setup-key", "nbkey-setup-test123")] = []byte("connected\n")
	exec.runOutputs[commandKey("netbird", "status", "--json")] = []byte(netbirdStatusJSON)

	p := NewNetbirdProvider(exec, discardLogger())
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}

	// Verify status.
	st := p.Status()
	if !st.Running {
		t.Error("expected Running = true")
	}
	if st.IP != "100.119.0.1" {
		t.Errorf("IP = %q, want %q", st.IP, "100.119.0.1")
	}
	if st.InterfaceName != "wt0" {
		t.Errorf("InterfaceName = %q, want %q", st.InterfaceName, "wt0")
	}

	// Verify the commands that were executed.
	calls := exec.execCallsFor("Run")
	if len(calls) != 2 {
		t.Fatalf("expected 2 Run calls, got %d", len(calls))
	}
	if calls[0].Name != "netbird" || calls[0].Args[0] != "up" {
		t.Errorf("first call = %v, want netbird up", calls[0])
	}
	if calls[1].Name != "netbird" || calls[1].Args[0] != "status" {
		t.Errorf("second call = %v, want netbird status", calls[1])
	}
}

func TestNetbirdProvider_Start_MissingSetupKey(t *testing.T) {
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "")

	exec := newMockCommandExecutor()
	p := NewNetbirdProvider(exec, discardLogger())

	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error for missing setup key, got nil")
	}
	if got := err.Error(); got != "bridge: netbird: PLEXD_NETBIRD_SETUP_KEY environment variable is not set" {
		t.Errorf("error = %q, want PLEXD_NETBIRD_SETUP_KEY message", got)
	}

	// No commands should have been executed.
	if calls := exec.allCalls(); len(calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(calls))
	}
}

func TestNetbirdProvider_Start_UpError(t *testing.T) {
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-setup-test123")

	upErr := errors.New("connection refused")
	exec := newMockCommandExecutor()
	exec.runErrors[commandKey("netbird", "up", "--setup-key", "nbkey-setup-test123")] = upErr

	p := NewNetbirdProvider(exec, discardLogger())
	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error when netbird up fails, got nil")
	}
	if !errors.Is(err, upErr) {
		t.Errorf("error should wrap upErr, got: %v", err)
	}
	if p.Status().Running {
		t.Error("expected Running = false after failed start")
	}
}

func TestNetbirdProvider_Start_StatusError(t *testing.T) {
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-setup-test123")

	statusErr := errors.New("netbird not ready")
	exec := newMockCommandExecutor()
	exec.runOutputs[commandKey("netbird", "up", "--setup-key", "nbkey-setup-test123")] = []byte("connected\n")
	exec.runErrors[commandKey("netbird", "status", "--json")] = statusErr

	p := NewNetbirdProvider(exec, discardLogger())
	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error when netbird status fails, got nil")
	}
	if !errors.Is(err, statusErr) {
		t.Errorf("error should wrap statusErr, got: %v", err)
	}
}

func TestNetbirdProvider_Stop_Success(t *testing.T) {
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-setup-test123")

	exec := newMockCommandExecutor()
	exec.runOutputs[commandKey("netbird", "up", "--setup-key", "nbkey-setup-test123")] = []byte("connected\n")
	exec.runOutputs[commandKey("netbird", "status", "--json")] = []byte(netbirdStatusJSON)
	exec.runOutputs[commandKey("netbird", "down")] = []byte("disconnected\n")

	p := NewNetbirdProvider(exec, discardLogger())

	// Start first.
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	if !p.Status().Running {
		t.Fatal("expected Running = true after Start")
	}

	// Stop.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() returned unexpected error: %v", err)
	}

	st := p.Status()
	if st.Running {
		t.Error("expected Running = false after Stop")
	}
	if st.IP != "" {
		t.Errorf("IP = %q, want empty after Stop", st.IP)
	}
	if st.InterfaceName != "" {
		t.Errorf("InterfaceName = %q, want empty after Stop", st.InterfaceName)
	}
}

func TestNetbirdProvider_Stop_Idempotent(t *testing.T) {
	exec := newMockCommandExecutor()
	p := NewNetbirdProvider(exec, discardLogger())

	// Stop without Start should return nil.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() on non-running provider returned error: %v", err)
	}

	// No commands should have been issued.
	if calls := exec.allCalls(); len(calls) != 0 {
		t.Errorf("expected 0 calls for idempotent Stop, got %d", len(calls))
	}
}

func TestNetbirdProvider_Status_Running(t *testing.T) {
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-setup-test123")

	exec := newMockCommandExecutor()
	exec.runOutputs[commandKey("netbird", "up", "--setup-key", "nbkey-setup-test123")] = []byte("connected\n")
	exec.runOutputs[commandKey("netbird", "status", "--json")] = []byte(netbirdStatusJSON)

	p := NewNetbirdProvider(exec, discardLogger())
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	st := p.Status()
	if !st.Running {
		t.Error("expected Running = true")
	}
	if st.IP != "100.119.0.1" {
		t.Errorf("IP = %q, want %q", st.IP, "100.119.0.1")
	}
	if st.InterfaceName != "wt0" {
		t.Errorf("InterfaceName = %q, want %q", st.InterfaceName, "wt0")
	}
	if st.Error != "" {
		t.Errorf("Error = %q, want empty", st.Error)
	}
}

func TestNetbirdProvider_Status_NotRunning(t *testing.T) {
	exec := newMockCommandExecutor()
	p := NewNetbirdProvider(exec, discardLogger())

	st := p.Status()
	if st.Running {
		t.Error("expected Running = false for new provider")
	}
	if st.IP != "" {
		t.Errorf("IP = %q, want empty", st.IP)
	}
	if st.InterfaceName != "" {
		t.Errorf("InterfaceName = %q, want empty", st.InterfaceName)
	}
}

func TestNetbirdProvider_ImplementsInterface(t *testing.T) {
	// This is a compile-time check (see var _ above), but we also verify at runtime
	// for clarity.
	var provider interface{} = NewNetbirdProvider(newMockCommandExecutor(), discardLogger())
	if _, ok := provider.(UserAccessProvider); !ok {
		t.Fatal("NetbirdProvider does not implement UserAccessProvider")
	}
}
