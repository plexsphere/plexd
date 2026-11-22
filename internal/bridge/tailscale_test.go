package bridge

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// Compile-time interface check.
var _ UserAccessClient = (*TailscaleProvider)(nil)

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

// testMeshCIDR is the mesh prefix the client tests hand to Start.
const testMeshCIDR = "10.99.0.0/24"

// tailscaleUpKey is the lookup key of the tailscale up command Start runs for
// key and testMeshCIDR.
func tailscaleUpKey(key string) string {
	return commandKey("tailscale", "up", "--authkey="+key, "--accept-routes", "--advertise-routes="+testMeshCIDR)
}

// newTailscaleRunner returns an executor on which tailscaled starts with the
// returned handle and tailscale status reports tailscaleStatusJSON.
func newTailscaleRunner() (*mockCommandExecutor, *mockCommandHandle) {
	runner := newMockCommandExecutor()
	handle := &mockCommandHandle{}
	runner.startHandle = handle
	runner.runOutputs[commandKey("tailscale", "status", "--json")] = []byte(tailscaleStatusJSON)
	return runner, handle
}

// noHostInterface is the ifaceByAddr seam of a test that wants tailscale0: it
// finds no interface, whatever the host carries. The production lookup reads
// the host's interface table, and a test of another package that runs at the
// same time can hold the client's address there: the windows-latest runner
// had a plexd0 with 100.64.0.7, one of the two mesh addresses the daemon
// tests of cmd/plexd/cmd run under.
func noHostInterface(string) string { return "" }

func TestTailscaleProvider_Start_Success(t *testing.T) {
	// The variable Start read before is set to another key, which must
	// appear in no command.
	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-from-env")

	runner, handle := newTailscaleRunner()
	p := NewTailscaleProvider(runner, discardLogger())
	p.ifaceByAddr = noHostInterface
	if err := p.Start(context.Background(), "k", testMeshCIDR); err != nil {
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

	calls := runner.allCalls()
	want := [][]string{
		{"Start", "tailscaled", "--state=mem:"},
		{"Run", "tailscale", "up", "--authkey=k", "--accept-routes", "--advertise-routes=10.99.0.0/24"},
		{"Run", "tailscale", "status", "--json"},
	}
	if got := callLines(calls); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %q, want %q", got, want)
	}
	for _, c := range calls {
		for _, arg := range c.Args {
			if strings.Contains(arg, "tskey-from-env") {
				t.Errorf("%s %v carries the key from the environment", c.Name, c.Args)
			}
		}
	}
	if n := handle.stopCalls(); n != 0 {
		t.Errorf("tailscaled stopped %d times after a successful join, want 0", n)
	}
}

// TestTailscaleProvider_Start_InterfaceByAddress checks that Start reports
// the interface that carries the client's address, which is a utunN on
// macOS, and tailscale0 when no interface carries it or the client lists no
// address.
func TestTailscaleProvider_Start_InterfaceByAddress(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    string // tailscale status --json; empty keeps the runner's
		found     string // what the seam returns for 100.64.0.1
		wantIface string
		wantAsked []string
	}{
		{name: "an interface carries the address", found: "utun9", wantIface: "utun9", wantAsked: []string{"100.64.0.1"}},
		{name: "no interface carries the address", found: "", wantIface: "tailscale0", wantAsked: []string{"100.64.0.1"}},
		{name: "the client lists no address", status: `{"TailscaleIPs":[]}`, found: "utun9", wantIface: "tailscale0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner, _ := newTailscaleRunner()
			if tc.status != "" {
				runner.runOutputs[commandKey("tailscale", "status", "--json")] = []byte(tc.status)
			}
			p := NewTailscaleProvider(runner, discardLogger())
			var asked []string
			p.ifaceByAddr = func(ip string) string {
				asked = append(asked, ip)
				if ip == "100.64.0.1" {
					return tc.found
				}
				return ""
			}

			if err := p.Start(context.Background(), "k", testMeshCIDR); err != nil {
				t.Fatalf("Start() unexpected error: %v", err)
			}
			if got := p.Status().InterfaceName; got != tc.wantIface {
				t.Errorf("Status().InterfaceName = %q, want %q", got, tc.wantIface)
			}
			if !slices.Equal(asked, tc.wantAsked) {
				t.Errorf("the seam was asked for %q, want %q", asked, tc.wantAsked)
			}
		})
	}
}

// TestInterfaceByAddr checks the lookup the production seam runs: no
// interface for something that is no address or an address no interface
// carries, and on Linux and macOS the loopback for 127.0.0.1. The Windows
// loopback's name depends on the host's language, so it is not pinned.
func TestInterfaceByAddr(t *testing.T) {
	for _, ip := range []string{"", "not-an-ip", "192.0.2.123"} {
		if got := interfaceByAddr(ip); got != "" {
			t.Errorf("interfaceByAddr(%q) = %q, want none", ip, got)
		}
	}
	if want := map[string]string{"linux": "lo", "darwin": "lo0"}[runtime.GOOS]; want != "" {
		if got := interfaceByAddr("127.0.0.1"); got != want {
			t.Errorf("interfaceByAddr(\"127.0.0.1\") = %q, want %q", got, want)
		}
	}
}

// TestTailscaleProvider_Start_Deadlines verifies that tailscaled runs under
// the caller's context without a deadline of its own, while tailscale up and
// tailscale status run under at most 60 s, derived from the caller's context.
func TestTailscaleProvider_Start_Deadlines(t *testing.T) {
	const join = 60 * time.Second

	tests := []struct {
		name string
		// caller is how far away the caller's deadline is; zero for none.
		caller time.Duration
		// The windows (lo, hi] the deadlines must fall into; a zero hi
		// wants no deadline.
		daemonLo, daemonHi time.Duration
		joinLo, joinHi     time.Duration
	}{
		{
			name:   "caller without deadline",
			joinLo: join - 10*time.Second, joinHi: join,
		},
		{
			name:     "caller deadline beyond the join timeout",
			caller:   time.Hour,
			daemonLo: time.Hour - 10*time.Second, daemonHi: time.Hour,
			joinLo: join - 10*time.Second, joinHi: join,
		},
		{
			name:     "caller deadline within the join timeout",
			caller:   10 * time.Second,
			daemonLo: 0, daemonHi: 10 * time.Second,
			joinLo: 0, joinHi: 10 * time.Second,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.caller)
				defer cancel()
			}

			runner, _ := newTailscaleRunner()
			p := NewTailscaleProvider(runner, discardLogger())
			if err := p.Start(ctx, "k", testMeshCIDR); err != nil {
				t.Fatalf("Start() unexpected error: %v", err)
			}

			calls := runner.allCalls()
			if len(calls) != 3 {
				t.Fatalf("recorded %d commands, want 3: %q", len(calls), callLines(calls))
			}
			assertCallDeadline(t, calls[0], tc.daemonLo, tc.daemonHi)
			assertCallDeadline(t, calls[1], tc.joinLo, tc.joinHi)
			assertCallDeadline(t, calls[2], tc.joinLo, tc.joinHi)
		})
	}
}

func TestTailscaleProvider_Start_EmptyKey(t *testing.T) {
	// A key in the environment is no fallback for an empty one.
	t.Setenv("PLEXD_TAILSCALE_AUTH_KEY", "tskey-from-env")

	runner, _ := newTailscaleRunner()
	p := NewTailscaleProvider(runner, discardLogger())
	err := p.Start(context.Background(), "", testMeshCIDR)
	if err == nil {
		t.Fatal("Start() expected error for an empty auth key")
	}
	if got := err.Error(); got != "bridge: tailscale: auth key is empty" {
		t.Fatalf("error = %q, want the empty auth key error", got)
	}

	// No commands should have been executed.
	if calls := runner.allCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 calls, got %q", callLines(calls))
	}
	if p.Status().Running {
		t.Fatal("expected Running=false after a refused key")
	}
}

func TestTailscaleProvider_Start_DaemonError(t *testing.T) {
	runner := newMockCommandExecutor()
	runner.startErr = errors.New("daemon launch failed")

	p := NewTailscaleProvider(runner, discardLogger())
	err := p.Start(context.Background(), "tskey-auth-test123", testMeshCIDR)
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
	runner, handle := newTailscaleRunner()
	runner.runErrors[tailscaleUpKey("tskey-auth-test123")] = errors.New("auth failed")

	p := NewTailscaleProvider(runner, discardLogger())
	err := p.Start(context.Background(), "tskey-auth-test123", testMeshCIDR)
	if err == nil {
		t.Fatal("Start() expected error when tailscale up fails")
	}
	if got := err.Error(); got != "bridge: tailscale: tailscale up: auth failed" {
		t.Fatalf("error = %q, want tailscale up error", got)
	}

	// Should not be running, and the daemon is stopped.
	if p.Status().Running {
		t.Fatal("expected Running=false after up failure")
	}
	if n := handle.stopCalls(); n != 1 {
		t.Fatalf("tailscaled stopped %d times, want 1", n)
	}
}

func TestTailscaleProvider_Start_StatusError(t *testing.T) {
	runner, handle := newTailscaleRunner()
	runner.runErrors[commandKey("tailscale", "status", "--json")] = errors.New("status unavailable")

	p := NewTailscaleProvider(runner, discardLogger())
	err := p.Start(context.Background(), "tskey-auth-test123", testMeshCIDR)
	if err == nil {
		t.Fatal("Start() expected error when tailscale status fails")
	}
	if got := err.Error(); got != "bridge: tailscale: tailscale status: status unavailable" {
		t.Fatalf("error = %q, want tailscale status error", got)
	}

	// Should not be running, and the cleanup ran: tailscale down under the
	// join's bound, then the daemon stopped.
	if p.Status().Running {
		t.Fatal("expected Running=false after status failure")
	}
	calls := runner.allCalls()
	last := calls[len(calls)-1]
	if got := callLines([]execCall{last}); !reflect.DeepEqual(got, [][]string{{"Run", "tailscale", "down"}}) {
		t.Fatalf("last command = %q, want tailscale down", got)
	}
	assertCallDeadline(t, last, 0, 60*time.Second)
	if n := handle.stopCalls(); n != 1 {
		t.Fatalf("tailscaled stopped %d times, want 1", n)
	}
}

func TestTailscaleProvider_Start_ParseError(t *testing.T) {
	runner, handle := newTailscaleRunner()
	runner.runOutputs[commandKey("tailscale", "status", "--json")] = []byte("not json")

	p := NewTailscaleProvider(runner, discardLogger())
	err := p.Start(context.Background(), "tskey-auth-test123", testMeshCIDR)
	if err == nil {
		t.Fatal("Start() expected error when tailscale status prints no JSON")
	}
	if got := err.Error(); !strings.HasPrefix(got, "bridge: tailscale: parse status: ") {
		t.Fatalf("error = %q, want parse status error", got)
	}

	if p.Status().Running {
		t.Fatal("expected Running=false after parse failure")
	}
	calls := runner.allCalls()
	if got := callLines(calls[len(calls)-1:]); !reflect.DeepEqual(got, [][]string{{"Run", "tailscale", "down"}}) {
		t.Fatalf("last command = %q, want tailscale down", got)
	}
	if n := handle.stopCalls(); n != 1 {
		t.Fatalf("tailscaled stopped %d times, want 1", n)
	}
}

// TestTailscaleProvider_Start_KeepsErrNotFound verifies that a missing binary
// stays visible through the error Start returns, for the daemon and for the
// CLI.
func TestTailscaleProvider_Start_KeepsErrNotFound(t *testing.T) {
	notFound := func(name string) error { return &exec.Error{Name: name, Err: exec.ErrNotFound} }

	t.Run("tailscaled", func(t *testing.T) {
		runner := newMockCommandExecutor()
		runner.startErr = notFound("tailscaled")

		err := NewTailscaleProvider(runner, discardLogger()).Start(context.Background(), "k", testMeshCIDR)
		if !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("error = %v, want one wrapping exec.ErrNotFound", err)
		}
	})
	t.Run("tailscale", func(t *testing.T) {
		runner, _ := newTailscaleRunner()
		runner.runErrors[tailscaleUpKey("k")] = notFound("tailscale")

		err := NewTailscaleProvider(runner, discardLogger()).Start(context.Background(), "k", testMeshCIDR)
		if !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("error = %v, want one wrapping exec.ErrNotFound", err)
		}
	})
	t.Run("standard executor", func(t *testing.T) {
		// A PATH without tailscaled: the standard executor's error comes
		// from os/exec and must keep exec.ErrNotFound as well.
		t.Setenv("PATH", t.TempDir())

		err := NewTailscaleProvider(NewStdCommandExecutor(), discardLogger()).Start(context.Background(), "k", testMeshCIDR)
		if !errors.Is(err, exec.ErrNotFound) {
			t.Fatalf("error = %v, want one wrapping exec.ErrNotFound", err)
		}
	})
}

func TestTailscaleProvider_Start_DoesNotLogKey(t *testing.T) {
	const key = "tskey-auth-never-logged"

	runner, _ := newTailscaleRunner()
	logger, buf := debugLogger()
	p := NewTailscaleProvider(runner, logger)
	if err := p.Start(context.Background(), key, testMeshCIDR); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("expected log output from Start and Stop")
	}
	if strings.Contains(buf.String(), key) {
		t.Fatalf("log output carries the auth key:\n%s", buf.String())
	}
}

func TestTailscaleProvider_Stop_Success(t *testing.T) {
	runner, handle := newTailscaleRunner()
	p := NewTailscaleProvider(runner, discardLogger())

	// Start first.
	if err := p.Start(context.Background(), "tskey-auth-test123", testMeshCIDR); err != nil {
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
	runCalls := runner.execCallsFor("Run")
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
	if n := handle.stopCalls(); n != 1 {
		t.Fatalf("tailscaled stopped %d times, want 1", n)
	}
}

func TestTailscaleProvider_Stop_Idempotent(t *testing.T) {
	runner := newMockCommandExecutor()
	p := NewTailscaleProvider(runner, discardLogger())

	// Stop when not running should return nil.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	// No commands should have been executed.
	if calls := runner.allCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 calls, got %d", len(calls))
	}
}

func TestTailscaleProvider_Status_Running(t *testing.T) {
	runner, _ := newTailscaleRunner()
	p := NewTailscaleProvider(runner, discardLogger())
	p.ifaceByAddr = noHostInterface
	if err := p.Start(context.Background(), "tskey-auth-test123", testMeshCIDR); err != nil {
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
