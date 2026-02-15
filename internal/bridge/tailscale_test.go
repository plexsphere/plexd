package bridge

import (
	"context"
	"errors"
	"testing"
)

// Compile-time interface check.
var _ UserAccessProvider = (*TailscaleProvider)(nil)

func TestTailscaleProvider_ImplementsInterface(t *testing.T) {
	// Verified by compile-time check above; exercise the constructor.
	p := NewTailscaleProvider(newMockCommandExecutor(), discardLogger())
	if p.Name() != "tailscale" {
		t.Fatal("expected tailscale provider")
	}
}

func TestTailscaleProvider_Name(t *testing.T) {
	p := NewTailscaleProvider(newMockCommandExecutor(), discardLogger())
	if got := p.Name(); got != "tailscale" {
		t.Fatalf("Name() = %q, want %q", got, "tailscale")
	}
}

const tailscaleStatusJSON = `{"Self":{"TailscaleIPs":["100.64.0.1"],"OS":"linux"},"TailscaleIPs":["100.64.0.1"]}`

func TestTailscaleProvider_Start_Success(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}

	// Configure tailscale up to succeed (default nil error).
	// Configure tailscale status --json to return valid JSON.
	exec.runOutputs[commandKey("tailscale", "status", "--json")] = []byte(tailscaleStatusJSON)

	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-auth-test123")

	p := NewTailscaleProvider(exec, discardLogger())
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Verify status.
	status := p.Status()
	if !status.Running {
		t.Fatal("expected Running=true after Start")
	}
	if status.IP != "100.64.0.1" {
		t.Fatalf("Status().IP = %q, want %q", status.IP, "100.64.0.1")
	}
	if status.InterfaceName != "tailscale0" {
		t.Fatalf("Status().InterfaceName = %q, want %q", status.InterfaceName, "tailscale0")
	}

	// Verify calls: Start(tailscaled), Run(tailscale up), Run(tailscale status).
	startCalls := exec.execCallsFor("Start")
	if len(startCalls) != 1 {
		t.Fatalf("expected 1 Start call, got %d", len(startCalls))
	}
	if startCalls[0].Name != "tailscaled" {
		t.Fatalf("Start call name = %q, want %q", startCalls[0].Name, "tailscaled")
	}

	runCalls := exec.execCallsFor("Run")
	if len(runCalls) != 2 {
		t.Fatalf("expected 2 Run calls, got %d", len(runCalls))
	}
	if runCalls[0].Name != "tailscale" {
		t.Fatalf("first Run call name = %q, want %q", runCalls[0].Name, "tailscale")
	}
	if runCalls[1].Name != "tailscale" {
		t.Fatalf("second Run call name = %q, want %q", runCalls[1].Name, "tailscale")
	}
}

func TestTailscaleProvider_Start_MissingAuthKey(t *testing.T) {
	exec := newMockCommandExecutor()
	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "")

	p := NewTailscaleProvider(exec, discardLogger())
	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error for missing auth key")
	}
	if got := err.Error(); got != "bridge: tailscale: PLEXD_TAILSCALE_AUTH_KEY is not set" {
		t.Fatalf("error = %q, want prefix with PLEXD_TAILSCALE_AUTH_KEY", got)
	}

	// No commands should have been executed.
	if calls := exec.allCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 calls, got %d", len(calls))
	}
}

func TestTailscaleProvider_Start_DaemonError(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startErr = errors.New("daemon launch failed")

	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-auth-test123")

	p := NewTailscaleProvider(exec, discardLogger())
	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error when daemon fails")
	}
	if got := err.Error(); got != "bridge: tailscale: start tailscaled: daemon launch failed" {
		t.Fatalf("error = %q, want tailscaled error", got)
	}

	// Should not be running.
	if p.Status().Running {
		t.Fatal("expected Running=false after daemon failure")
	}
}

func TestTailscaleProvider_Start_UpError(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	exec.runErrors[commandKey("tailscale", "up", "--authkey=tskey-auth-test123", "--accept-routes")] = errors.New("auth failed")

	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-auth-test123")

	p := NewTailscaleProvider(exec, discardLogger())
	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error when tailscale up fails")
	}
	if got := err.Error(); got != "bridge: tailscale: tailscale up: auth failed" {
		t.Fatalf("error = %q, want tailscale up error", got)
	}

	// Should not be running.
	if p.Status().Running {
		t.Fatal("expected Running=false after up failure")
	}
}

func TestTailscaleProvider_Start_StatusError(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	exec.runErrors[commandKey("tailscale", "status", "--json")] = errors.New("status unavailable")

	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-auth-test123")

	p := NewTailscaleProvider(exec, discardLogger())
	err := p.Start(context.Background())
	if err == nil {
		t.Fatal("Start() expected error when tailscale status fails")
	}
	if got := err.Error(); got != "bridge: tailscale: tailscale status: status unavailable" {
		t.Fatalf("error = %q, want tailscale status error", got)
	}

	// Should not be running.
	if p.Status().Running {
		t.Fatal("expected Running=false after status failure")
	}
}

func TestTailscaleProvider_Stop_Success(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	exec.runOutputs[commandKey("tailscale", "status", "--json")] = []byte(tailscaleStatusJSON)

	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-auth-test123")

	p := NewTailscaleProvider(exec, discardLogger())

	// Start first.
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if !p.Status().Running {
		t.Fatal("expected Running=true after Start")
	}

	// Stop.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	status := p.Status()
	if status.Running {
		t.Fatal("expected Running=false after Stop")
	}
	if status.IP != "" {
		t.Fatalf("Status().IP = %q, want empty", status.IP)
	}
	if status.InterfaceName != "" {
		t.Fatalf("Status().InterfaceName = %q, want empty", status.InterfaceName)
	}

	// Verify tailscale down was called.
	runCalls := exec.execCallsFor("Run")
	var foundDown bool
	for _, c := range runCalls {
		if c.Name == "tailscale" && len(c.Args) > 0 && c.Args[0] == "down" {
			foundDown = true
			break
		}
	}
	if !foundDown {
		t.Fatal("expected tailscale down to be called")
	}
}

func TestTailscaleProvider_Stop_Idempotent(t *testing.T) {
	exec := newMockCommandExecutor()
	p := NewTailscaleProvider(exec, discardLogger())

	// Stop when not running should return nil.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	// No commands should have been executed.
	if calls := exec.allCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 calls, got %d", len(calls))
	}
}

func TestTailscaleProvider_Status_Running(t *testing.T) {
	exec := newMockCommandExecutor()
	exec.startHandle = &mockCommandHandle{}
	exec.runOutputs[commandKey("tailscale", "status", "--json")] = []byte(tailscaleStatusJSON)

	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-auth-test123")

	p := NewTailscaleProvider(exec, discardLogger())
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	status := p.Status()
	if !status.Running {
		t.Fatal("expected Running=true")
	}
	if status.IP != "100.64.0.1" {
		t.Fatalf("IP = %q, want %q", status.IP, "100.64.0.1")
	}
	if status.InterfaceName != "tailscale0" {
		t.Fatalf("InterfaceName = %q, want %q", status.InterfaceName, "tailscale0")
	}
	if status.Error != "" {
		t.Fatalf("Error = %q, want empty", status.Error)
	}
}

func TestTailscaleProvider_Status_NotRunning(t *testing.T) {
	p := NewTailscaleProvider(newMockCommandExecutor(), discardLogger())

	status := p.Status()
	if status.Running {
		t.Fatal("expected Running=false")
	}
	if status.IP != "" {
		t.Fatalf("IP = %q, want empty", status.IP)
	}
	if status.InterfaceName != "" {
		t.Fatalf("InterfaceName = %q, want empty", status.InterfaceName)
	}
}
