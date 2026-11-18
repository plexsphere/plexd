package bridge

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Compile-time check that NetbirdProvider implements UserAccessClient.
var _ UserAccessClient = (*NetbirdProvider)(nil)

const netbirdStatusJSON = `{"ip":"100.119.0.1/16","fqdn":"bridge-node.netbird.cloud","connected":true,"interface":{"name":"wt0"}}`

// newNetbirdRunner returns an executor on which netbird up succeeds for key
// and netbird status reports netbirdStatusJSON.
func newNetbirdRunner(key string) *mockCommandExecutor {
	runner := newMockCommandExecutor()
	runner.runOutputs[commandKey("netbird", "up", "--setup-key", key)] = []byte("connected\n")
	runner.runOutputs[commandKey("netbird", "status", "--json")] = []byte(netbirdStatusJSON)
	return runner
}

func TestNetbirdProvider_Name(t *testing.T) {
	p := NewNetbirdProvider(newMockCommandExecutor(), discardLogger())
	if got := p.Name(); got != "netbird" {
		t.Fatalf("Name() = %q, want %q", got, "netbird")
	}
}

func TestNetbirdProvider_Start_Success(t *testing.T) {
	// The variable Start read before is set to another key, which must
	// appear in no command.
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-from-env")

	runner := newNetbirdRunner("k")
	p := NewNetbirdProvider(runner, discardLogger())
	if err := p.Start(context.Background(), "k", testMeshCIDR); err != nil {
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

	// Verify the commands that were executed. The mesh CIDR is ignored:
	// NetBird defines routes in its management service.
	calls := runner.allCalls()
	want := [][]string{
		{"Run", "netbird", "up", "--setup-key", "k"},
		{"Run", "netbird", "status", "--json"},
	}
	if got := callLines(calls); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %q, want %q", got, want)
	}
	for _, c := range calls {
		for _, arg := range c.Args {
			if strings.Contains(arg, "nbkey-from-env") {
				t.Errorf("%s %v carries the key from the environment", c.Name, c.Args)
			}
		}
	}
}

// TestNetbirdProvider_Start_Deadlines verifies that netbird up and netbird
// status run under at most 60 s, derived from the caller's context.
func TestNetbirdProvider_Start_Deadlines(t *testing.T) {
	const join = 60 * time.Second

	tests := []struct {
		name string
		// caller is how far away the caller's deadline is; zero for none.
		caller time.Duration
		// The window (lo, hi] the join deadlines must fall into.
		lo, hi time.Duration
	}{
		{name: "caller without deadline", lo: join - 10*time.Second, hi: join},
		{name: "caller deadline beyond the join timeout", caller: time.Hour, lo: join - 10*time.Second, hi: join},
		{name: "caller deadline within the join timeout", caller: 10 * time.Second, lo: 0, hi: 10 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.caller)
				defer cancel()
			}

			runner := newNetbirdRunner("k")
			p := NewNetbirdProvider(runner, discardLogger())
			if err := p.Start(ctx, "k", testMeshCIDR); err != nil {
				t.Fatalf("Start() returned unexpected error: %v", err)
			}

			calls := runner.allCalls()
			if len(calls) != 2 {
				t.Fatalf("recorded %d commands, want 2: %q", len(calls), callLines(calls))
			}
			for _, c := range calls {
				assertCallDeadline(t, c, tc.lo, tc.hi)
			}
		})
	}
}

func TestNetbirdProvider_Start_EmptyKey(t *testing.T) {
	// A key in the environment is no fallback for an empty one.
	t.Setenv("PLEXD_NETBIRD_SETUP_KEY", "nbkey-from-env")

	runner := newNetbirdRunner("nbkey-from-env")
	p := NewNetbirdProvider(runner, discardLogger())

	err := p.Start(context.Background(), "", testMeshCIDR)
	if err == nil {
		t.Fatal("Start() expected error for an empty setup key, got nil")
	}
	if got := err.Error(); got != "bridge: netbird: setup key is empty" {
		t.Errorf("error = %q, want the empty setup key error", got)
	}

	// No commands should have been executed.
	if calls := runner.allCalls(); len(calls) != 0 {
		t.Errorf("expected 0 calls, got %q", callLines(calls))
	}
	if p.Status().Running {
		t.Error("expected Running = false after a refused key")
	}
}

func TestNetbirdProvider_Start_UpError(t *testing.T) {
	upErr := errors.New("connection refused")
	runner := newMockCommandExecutor()
	runner.runErrors[commandKey("netbird", "up", "--setup-key", "nbkey-setup-test123")] = upErr

	p := NewNetbirdProvider(runner, discardLogger())
	err := p.Start(context.Background(), "nbkey-setup-test123", testMeshCIDR)
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
	statusErr := errors.New("netbird not ready")
	runner := newNetbirdRunner("nbkey-setup-test123")
	runner.runErrors[commandKey("netbird", "status", "--json")] = statusErr

	p := NewNetbirdProvider(runner, discardLogger())
	err := p.Start(context.Background(), "nbkey-setup-test123", testMeshCIDR)
	if err == nil {
		t.Fatal("Start() expected error when netbird status fails, got nil")
	}
	if !errors.Is(err, statusErr) {
		t.Errorf("error should wrap statusErr, got: %v", err)
	}
}

// TestNetbirdProvider_Start_KeepsErrNotFound verifies that a missing netbird
// binary stays visible through the error Start returns.
func TestNetbirdProvider_Start_KeepsErrNotFound(t *testing.T) {
	t.Run("mock executor", func(t *testing.T) {
		runner := newMockCommandExecutor()
		runner.runErrors[commandKey("netbird", "up", "--setup-key", "k")] = &exec.Error{Name: "netbird", Err: exec.ErrNotFound}

		err := NewNetbirdProvider(runner, discardLogger()).Start(context.Background(), "k", testMeshCIDR)
		if !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("error = %v, want one wrapping exec.ErrNotFound", err)
		}
	})
	t.Run("standard executor", func(t *testing.T) {
		// A PATH without netbird: the standard executor's error comes from
		// os/exec and must keep exec.ErrNotFound as well.
		t.Setenv("PATH", t.TempDir())

		err := NewNetbirdProvider(NewStdCommandExecutor(), discardLogger()).Start(context.Background(), "k", testMeshCIDR)
		if !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("error = %v, want one wrapping exec.ErrNotFound", err)
		}
	})
}

func TestNetbirdProvider_Start_DoesNotLogKey(t *testing.T) {
	const key = "nbkey-setup-never-logged"

	runner := newNetbirdRunner(key)
	runner.runOutputs[commandKey("netbird", "down")] = []byte("disconnected\n")
	logger, buf := debugLogger()
	p := NewNetbirdProvider(runner, logger)
	if err := p.Start(context.Background(), key, testMeshCIDR); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() returned unexpected error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("expected log output from Start and Stop")
	}
	if strings.Contains(buf.String(), key) {
		t.Fatalf("log output carries the setup key:\n%s", buf.String())
	}
}

func TestNetbirdProvider_Stop_Success(t *testing.T) {
	runner := newNetbirdRunner("nbkey-setup-test123")
	runner.runOutputs[commandKey("netbird", "down")] = []byte("disconnected\n")

	p := NewNetbirdProvider(runner, discardLogger())

	// Start first.
	if err := p.Start(context.Background(), "nbkey-setup-test123", testMeshCIDR); err != nil {
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
	runner := newMockCommandExecutor()
	p := NewNetbirdProvider(runner, discardLogger())

	// Stop without Start should return nil.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() on non-running provider returned error: %v", err)
	}

	// No commands should have been issued.
	if calls := runner.allCalls(); len(calls) != 0 {
		t.Errorf("expected 0 calls for idempotent Stop, got %d", len(calls))
	}
}

func TestNetbirdProvider_Status_Running(t *testing.T) {
	runner := newNetbirdRunner("nbkey-setup-test123")

	p := NewNetbirdProvider(runner, discardLogger())
	if err := p.Start(context.Background(), "nbkey-setup-test123", testMeshCIDR); err != nil {
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
	runner := newMockCommandExecutor()
	p := NewNetbirdProvider(runner, discardLogger())

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
	if _, ok := provider.(UserAccessClient); !ok {
		t.Fatal("NetbirdProvider does not implement UserAccessClient")
	}
}
