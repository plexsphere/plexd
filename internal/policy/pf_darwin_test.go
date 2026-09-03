//go:build darwin

package policy

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// PFController is the macOS FirewallController the enforcer is handed.
var _ FirewallController = (*PFController)(nil)

// natController mirrors bridge.NATController. The contract is checked against
// a local copy because internal/policy must not import internal/bridge: the
// bridge package already depends on this one.
type natController interface {
	AddNATMasquerade(string) error
	RemoveNATMasquerade(string) error
}

var _ natController = (*PFController)(nil)

// newTestPFController returns a controller whose pfctl invocations are
// recorded instead of run.
func newTestPFController(t *testing.T) (*PFController, *recordingRunner) {
	t.Helper()

	runner := newRecordingRunner()
	ctrl := NewPFController(testLogger())
	ctrl.run = runner.Run
	return ctrl, runner
}

// pfKey builds the answer-map key for a pfctl invocation.
func pfKey(args ...string) string {
	return commandKey(pfctlPath, args...)
}

var (
	loadKey   = pfKey("-a", pfAnchor, "-f", "-")
	enableKey = pfKey("-E")
	flushKey  = pfKey("-a", pfAnchor, "-F", "all")
)

const (
	// okRules and okNAT are what pfctl prints for Apple's stock /etc/pf.conf.
	// The scrub-anchor line carries the filter form as a substring, which is
	// why Probe matches per line.
	okRules = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
	okNAT   = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"

	// tokenOut is what pfctl -E prints on a Mac without ALTQ support.
	tokenOut = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 13971906727590307623\n"
)

// sixRules covers every field combination renderRule handles: both actions,
// each protocol and none, a prefix and a bare address on either side, a single
// port and a range, and the wildcard prefix on both sides.
var sixRules = []FirewallRule{
	{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Protocol: "icmp", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.9", DstIP: "10.1.0.0/24", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.9/32", DstIP: "0.0.0.0/0", Action: "deny"},
	{Interface: "utun4", SrcIP: "0.0.0.0/0", DstIP: "0.0.0.0/0", Action: "deny"},
}

// sixRulesText is the anchor sixRules renders to in chain plexd-mesh.
const sixRulesText = pfHeader +
	"# chain plexd-mesh\n" +
	"pass out quick on utun4 inet proto tcp from (utun4) to any keep state\n" +
	"pass out quick on utun4 inet from (utun4) to any no state\n" +
	"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state\n" +
	"pass in quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state\n" +
	"pass in quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state\n" +
	"pass in quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state\n" +
	"block in quick on utun4 inet from 10.0.0.9/32 to any\n" +
	"block in quick on utun4 inet from any to any\n"

// checkCalls asserts that exactly the wanted pfctl invocations ran, in order,
// with the wanted arguments and stdin. Every test pins the whole list: a
// spurious call would reload the anchor or take another pf reference.
func checkCalls(t *testing.T, runner *recordingRunner, want ...runnerCall) {
	t.Helper()

	got := runner.callsFor(pfctlPath)
	if len(got) != len(want) {
		t.Fatalf("pfctl calls = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range got {
		if !slices.Equal(got[i].Args, want[i].Args) {
			t.Errorf("call %d args = %v, want %v", i, got[i].Args, want[i].Args)
		}
		if got[i].Stdin != want[i].Stdin {
			t.Errorf("call %d stdin =\n%q\nwant\n%q", i, got[i].Stdin, want[i].Stdin)
		}
	}
}

// seedProbe answers the two reads Probe runs with what pfctl prints for
// Apple's stock /etc/pf.conf. AddNATMasquerade probes before its first load,
// so every test that configures NAT needs them.
func seedProbe(runner *recordingRunner) {
	runner.outputs[pfKey("-s", "rules")] = []byte(okRules)
	runner.outputs[pfKey("-s", "nat")] = []byte(okNAT)
}

// probeCalls are those two reads, in the order Probe runs them.
var probeCalls = []runnerCall{
	{Args: []string{"-s", "rules"}},
	{Args: []string{"-s", "nat"}},
}

func TestPFController_Probe_OK(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte(okRules)
	runner.outputs[pfKey("-s", "nat")] = []byte(okNAT)

	if err := ctrl.Probe(); err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-s", "rules"}},
		runnerCall{Args: []string{"-s", "nat"}},
	)
}

func TestPFController_Probe_NotRoot(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte("pfctl: /dev/pf: Permission denied")
	runner.errs[pfKey("-s", "rules")] = errors.New("exit status 1")

	err := ctrl.Probe()
	want := `policy: pf: probe: /sbin/pfctl -s rules: exit status 1: pfctl: /dev/pf: Permission denied (policy enforcement on macOS requires root)`
	if err == nil || err.Error() != want {
		t.Fatalf("Probe() error = %v, want %q", err, want)
	}

	checkCalls(t, runner, runnerCall{Args: []string{"-s", "rules"}})
}

func TestPFController_Probe_MissingFilterAnchor(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte("scrub-anchor \"com.apple/*\" all fragment reassemble\n")

	err := ctrl.Probe()
	want := `policy: pf: probe: the main ruleset does not reference anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf`
	if err == nil || err.Error() != want {
		t.Fatalf("Probe() error = %v, want %q", err, want)
	}
}

func TestPFController_Probe_MissingNATAnchor(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte(okRules)
	runner.outputs[pfKey("-s", "nat")] = []byte("rdr-anchor \"com.apple/*\" all\n")

	err := ctrl.Probe()
	want := `policy: pf: probe: the main ruleset does not reference nat-anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf`
	if err == nil || err.Error() != want {
		t.Fatalf("Probe() error = %v, want %q", err, want)
	}
}

func TestPFController_Probe_EmptyOutput(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte("")
	runner.outputs[pfKey("-s", "nat")] = []byte("")

	err := ctrl.Probe()
	want := `policy: pf: probe: the main ruleset does not reference anchor "com.apple/*"; restore /etc/pf.conf and run pfctl -f /etc/pf.conf`
	if err == nil || err.Error() != want {
		t.Fatalf("Probe() error = %v, want %q", err, want)
	}
}

func TestPFController_EnsureChain_LoadsAndEnables(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
	)
	if ctrl.token != "13971906727590307623" {
		t.Errorf("token = %q, want %q", ctrl.token, "13971906727590307623")
	}
}

func TestPFController_EnsureChain_Repeat(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() repeat error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
	)
}

func TestPFController_EnsureChain_EmptyName(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.EnsureChain("")
	want := "policy: pf: ensure chain: chain name is empty"
	if err == nil || err.Error() != want {
		t.Fatalf("EnsureChain() error = %v, want %q", err, want)
	}

	checkCalls(t, runner)
}

func TestPFController_EnsureChain_LoadFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[loadKey] = []byte("pfctl: /dev/pf: Permission denied")
	runner.errs[loadKey] = errors.New("exit status 1")

	err := ctrl.EnsureChain("plexd-mesh")
	want := `policy: pf: ensure chain: /sbin/pfctl -a com.apple/plexd -f -: exit status 1: pfctl: /dev/pf: Permission denied (policy enforcement on macOS requires root)`
	if err == nil || err.Error() != want {
		t.Fatalf("EnsureChain() error = %v, want %q", err, want)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
	)

	// The failed chain was rolled back, so tearing it down is a no-op.
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
	)
}

func TestPFController_EnsureChain_NoToken(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte("pf enabled\n")

	err := ctrl.EnsureChain("plexd-mesh")
	want := `policy: pf: ensure chain: pfctl -E printed no token: "pf enabled"`
	if err == nil || err.Error() != want {
		t.Fatalf("EnsureChain() error = %v, want %q", err, want)
	}
	if _, ok := ctrl.chains["plexd-mesh"]; ok {
		t.Error("chain plexd-mesh is still known after a failed EnsureChain")
	}
}

func TestPFController_ApplyRules_Render(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: sixRulesText},
	)
}

func TestPFController_ApplyRules_ImplicitChain(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: sixRulesText},
		runnerCall{Args: []string{"-E"}},
	)
}

func TestPFController_ApplyRules_TwoInterfaces(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	rules := []FirewallRule{
		{Interface: "utun4", SrcIP: "10.0.0.0/24", Action: "allow"},
		{Interface: "utun5", SrcIP: "10.0.0.0/24", Action: "allow"},
		{Interface: "utun4", SrcIP: "10.0.0.9", Action: "deny"},
	}
	if err := ctrl.ApplyRules("plexd-mesh", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	want := pfHeader +
		"# chain plexd-mesh\n" +
		"pass out quick on utun4 inet proto tcp from (utun4) to any keep state\n" +
		"pass out quick on utun4 inet from (utun4) to any no state\n" +
		"pass out quick on utun5 inet proto tcp from (utun5) to any keep state\n" +
		"pass out quick on utun5 inet from (utun5) to any no state\n" +
		"pass in quick on utun4 inet from 10.0.0.0/24 to any no state\n" +
		"pass in quick on utun5 inet from 10.0.0.0/24 to any no state\n" +
		"block in quick on utun4 inet from 10.0.0.9 to any\n"
	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: want},
		runnerCall{Args: []string{"-E"}},
	)
}

func TestPFController_ApplyRules_Empty(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{}); err != nil {
		t.Fatalf("ApplyRules() empty error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: sixRulesText},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
	)
}

func TestPFController_ApplyRules_Nil(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.ApplyRules("plexd-mesh", nil); err != nil {
		t.Fatalf("ApplyRules() nil error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: sixRulesText},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
	)
}

func TestPFController_ApplyRules_InvalidRule(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", Action: "drop"}})
	want := `policy: pf: apply rules: rule 0: policy: firewall rule: invalid action "drop"`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("ApplyRules() error = %v, want prefix %q", err, want)
	}

	checkCalls(t, runner)
}

func TestPFController_ApplyRules_EmptyInterface(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Action: "allow"}})
	want := "policy: pf: apply rules: rule 0: interface name is empty"
	if err == nil || err.Error() != want {
		t.Fatalf("ApplyRules() error = %v, want %q", err, want)
	}

	checkCalls(t, runner)
}

func TestPFController_ApplyRules_IPv6Address(t *testing.T) {
	ctrl, _ := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", SrcIP: "fd00::/64", Action: "allow"}})
	want := `policy: pf: apply rules: rule 0: non-IPv4 address "fd00::/64"`
	if err == nil || err.Error() != want {
		t.Fatalf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestPFController_ApplyRules_InvalidAddress(t *testing.T) {
	ctrl, _ := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", DstIP: "bogus", Action: "allow"}})
	want := `policy: pf: apply rules: rule 0: invalid IP address "bogus"`
	if err == nil || err.Error() != want {
		t.Fatalf("ApplyRules() error = %v, want %q", err, want)
	}
}

func TestPFController_ApplyRules_EmptyChain(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.ApplyRules("", sixRules)
	want := "policy: pf: apply rules: chain name is empty"
	if err == nil || err.Error() != want {
		t.Fatalf("ApplyRules() error = %v, want %q", err, want)
	}

	checkCalls(t, runner)
}

func TestPFController_ApplyRules_LoadFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	runner.outputs[loadKey] = []byte("stdin:3: syntax error")
	runner.errs[loadKey] = errors.New("exit status 1")

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", SrcIP: "10.2.0.0/24", Action: "allow"}})
	want := `policy: pf: apply rules: /sbin/pfctl -a com.apple/plexd -f -: exit status 1: stdin:3: syntax error`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("ApplyRules() error = %v, want prefix %q", err, want)
	}

	// The rejected rules were rolled back, so the next load carries the ones
	// the kernel accepted before.
	delete(runner.outputs, loadKey)
	delete(runner.errs, loadKey)
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	calls := runner.callsFor(pfctlPath)
	got := calls[len(calls)-1].Stdin
	want = pfHeader + "nat on en1 inet from any to any -> (en1)\n" + sixRulesText[len(pfHeader):]
	if got != want {
		t.Errorf("stdin =\n%q\nwant\n%q", got, want)
	}
}

func TestPFController_RenderParses(t *testing.T) {
	ctrl := NewPFController(testLogger())
	ctrl.natIface = "en1"
	ctrl.chains["plexd-mesh"] = sixRules

	text := ctrl.render()

	// pfctl -n only parses the anchor, which needs no access to /dev/pf, so
	// this runs unprivileged and still proves the rendered syntax is pf's.
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	out, err := execCommand(ctx, text, pfctlPath, "-n", "-q", "-a", pfAnchor, "-f", "-")
	if err != nil {
		t.Fatalf("pfctl rejected the rendered anchor: %v\n%s\n%s", err, text, out)
	}
}

func TestPFController_FlushChain(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.FlushChain("plexd-mesh"); err != nil {
		t.Fatalf("FlushChain() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: sixRulesText},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
	)
}

func TestPFController_FlushChain_Unknown(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	if err := ctrl.FlushChain("plexd-mesh"); err != nil {
		t.Fatalf("FlushChain() error = %v, want nil", err)
	}

	checkCalls(t, runner)
}

// A reload pfctl rejects has to leave the controller's picture at what the
// kernel still enforces. Without the restore the chain would read as empty
// while its rules are loaded, and the next apply would render an anchor
// without them: the operator would see rules vanish with nothing logged.
func TestPFController_FlushChain_LoadFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	runner.outputs[loadKey] = []byte("pfctl: /dev/pf: Permission denied")
	runner.errs[loadKey] = errors.New("exit status 1")

	err := ctrl.FlushChain("plexd-mesh")
	want := `policy: pf: flush chain: /sbin/pfctl -a com.apple/plexd -f -: exit status 1:`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("FlushChain() error = %v, want prefix %q", err, want)
	}

	// The rules the kernel still holds were restored, so the next load carries
	// them again.
	delete(runner.outputs, loadKey)
	delete(runner.errs, loadKey)
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	calls := runner.callsFor(pfctlPath)
	got := calls[len(calls)-1].Stdin
	wantText := pfHeader + "nat on en1 inet from any to any -> (en1)\n" + sixRulesText[len(pfHeader):]
	if got != wantText {
		t.Errorf("stdin =\n%q\nwant\n%q", got, wantText)
	}
}

func TestPFController_DeleteChain_LastReleases(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-F", "all"}},
		runnerCall{Args: []string{"-X", "13971906727590307623"}},
	)
	if ctrl.token != "" {
		t.Errorf("token = %q, want empty", ctrl.token)
	}
}

func TestPFController_DeleteChain_KeepsNAT(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
		probeCalls[0], probeCalls[1],
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "nat on en1 inet from any to any -> (en1)\n# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "nat on en1 inet from any to any -> (en1)\n"},
	)
}

func TestPFController_DeleteChain_Unknown(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}

	checkCalls(t, runner)
}

func TestPFController_DeleteChain_FlushFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	runner.errs[flushKey] = errors.New("exit status 1")

	err := ctrl.DeleteChain("plexd-mesh")
	want := "policy: pf: delete chain: /sbin/pfctl -a com.apple/plexd -F all: exit status 1"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("DeleteChain() error = %v, want prefix %q", err, want)
	}

	// The chain is still known, so a retry flushes again.
	if err := ctrl.DeleteChain("plexd-mesh"); err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("DeleteChain() retry error = %v, want prefix %q", err, want)
	}
	calls := runner.callsFor(pfctlPath)
	if got := len(calls); got != 4 {
		t.Fatalf("pfctl calls = %d, want 4: %+v", got, calls)
	}
}

func TestPFController_DeleteChain_ReleaseFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	runner.errs[pfKey("-X", "13971906727590307623")] = errors.New("exit status 1")

	err := ctrl.DeleteChain("plexd-mesh")
	want := "policy: pf: delete chain: /sbin/pfctl -X 13971906727590307623: exit status 1"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("DeleteChain() error = %v, want prefix %q", err, want)
	}
	// A leaked reference cannot be given back with the same token, so the
	// controller drops it and the retry runs nothing.
	if ctrl.token != "" {
		t.Errorf("token = %q, want empty", ctrl.token)
	}

	before := len(runner.callsFor(pfctlPath))
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() retry error = %v, want nil", err)
	}
	if got := len(runner.callsFor(pfctlPath)); got != before {
		t.Errorf("pfctl calls = %d, want %d", got, before)
	}
}

func TestPFController_AddNATMasquerade(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: sixRulesText},
		probeCalls[0], probeCalls[1],
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "nat on en1 inet from any to any -> (en1)\n" + sixRulesText[len(pfHeader):]},
	)
}

func TestPFController_AddNATMasquerade_Alone(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		probeCalls[0], probeCalls[1],
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "nat on en1 inet from any to any -> (en1)\n"},
		runnerCall{Args: []string{"-E"}},
	)
}

func TestPFController_AddNATMasquerade_Repeat(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() repeat error = %v, want nil", err)
	}

	// Only the first call probes: the anchor reference cannot go away while
	// plexd holds a rule in it, and the reconciler repeats this call.
	natText := pfHeader + "nat on en1 inet from any to any -> (en1)\n"
	checkCalls(t, runner,
		probeCalls[0], probeCalls[1],
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: natText},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: natText},
	)
}

func TestPFController_AddNATMasquerade_EmptyInterface(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.AddNATMasquerade("")
	want := `bridge: add NAT masquerade on "": interface name is empty`
	if err == nil || err.Error() != want {
		t.Fatalf("AddNATMasquerade() error = %v, want %q", err, want)
	}

	checkCalls(t, runner)
}

func TestPFController_AddNATMasquerade_LoadFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	seedProbe(runner)
	runner.outputs[loadKey] = []byte("pfctl: /dev/pf: Permission denied")
	runner.errs[loadKey] = errors.New("exit status 1")

	err := ctrl.AddNATMasquerade("en1")
	want := `bridge: add NAT masquerade on "en1": policy: pf: add NAT masquerade: /sbin/pfctl -a com.apple/plexd -f -: exit status 1:`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("AddNATMasquerade() error = %v, want prefix %q", err, want)
	}
	if !strings.Contains(err.Error(), "(policy enforcement on macOS requires root)") {
		t.Errorf("AddNATMasquerade() error = %v, want the root hint", err)
	}
	if ctrl.natIface != "" {
		t.Errorf("natIface = %q, want empty", ctrl.natIface)
	}
}

// The bridge path is the only caller left once policy enforcement is off, and
// an anchor the main ruleset no longer references translates nothing while
// every pfctl call still succeeds. The first AddNATMasquerade therefore probes,
// and nothing may reach the kernel when that probe fails.
func TestPFController_AddNATMasquerade_ProbeFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte(okRules)
	runner.outputs[pfKey("-s", "nat")] = []byte("rdr-anchor \"com.apple/*\" all\n")

	err := ctrl.AddNATMasquerade("en1")
	want := `bridge: add NAT masquerade on "en1": policy: pf: probe: the main ruleset does not reference nat-anchor "com.apple/*"`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("AddNATMasquerade() error = %v, want prefix %q", err, want)
	}
	if ctrl.natIface != "" {
		t.Errorf("natIface = %q, want empty", ctrl.natIface)
	}

	checkCalls(t, runner, probeCalls[0], probeCalls[1])
}

func TestPFController_RemoveNATMasquerade(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	if err := ctrl.RemoveNATMasquerade("en1"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-E"}},
		probeCalls[0], probeCalls[1],
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "nat on en1 inet from any to any -> (en1)\n# chain plexd-mesh\n"},
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "# chain plexd-mesh\n"},
	)
}

func TestPFController_RemoveNATMasquerade_Alone(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	if err := ctrl.RemoveNATMasquerade("en1"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}

	checkCalls(t, runner,
		probeCalls[0], probeCalls[1],
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: pfHeader + "nat on en1 inet from any to any -> (en1)\n"},
		runnerCall{Args: []string{"-E"}},
		runnerCall{Args: []string{"-a", pfAnchor, "-F", "all"}},
		runnerCall{Args: []string{"-X", "13971906727590307623"}},
	)
}

func TestPFController_RemoveNATMasquerade_NotConfigured(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	if err := ctrl.RemoveNATMasquerade("en1"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}

	checkCalls(t, runner)
}

func TestPFController_RemoveNATMasquerade_LoadFails(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	seedProbe(runner)

	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("en1"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	runner.errs[loadKey] = errors.New("exit status 1")

	err := ctrl.RemoveNATMasquerade("en1")
	want := `bridge: remove NAT masquerade on "en1": policy: pf: remove NAT masquerade:`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("RemoveNATMasquerade() error = %v, want prefix %q", err, want)
	}
	if ctrl.natIface != "en1" {
		t.Errorf("natIface = %q, want %q", ctrl.natIface, "en1")
	}
}

func TestPFController_CommandsCarryDeadline(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[pfKey("-s", "rules")] = []byte(okRules)
	runner.outputs[pfKey("-s", "nat")] = []byte(okNAT)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.Probe(); err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}
	if err := ctrl.EnsureChain("plexd-mesh"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}

	if len(runner.deadlines) == 0 {
		t.Fatal("no command ran")
	}
	for i, hasDeadline := range runner.deadlines {
		if !hasDeadline {
			t.Errorf("call %d ran without a deadline", i)
		}
	}
}

// TestPFController_Real drives the host's pf. It loads rules on plexd99, a
// name pf accepts and no interface carries, so nothing on the machine running
// the test is filtered or translated.
func TestPFController_Real(t *testing.T) {
	// The gate is a variable rather than the effective uid alone: sudo go test
	// ./... on a developer's Mac would otherwise enable pf on their host and
	// load a real anchor, and a panic between the load and the cleanup leaks
	// the pf reference. The Windows real tests gate the same way.
	if os.Getenv("PLEXD_TEST_REAL_PF") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PF=1 to load a real pf anchor")
	}
	if os.Geteuid() != 0 {
		t.Skip("loading a pf anchor needs root; run with sudo")
	}

	pfctlOut := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
		defer cancel()
		out, err := execCommand(ctx, nil, pfctlPath, args...)
		if err != nil {
			t.Fatalf("pfctl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}

	// pf is left as it was found: plexd only releases its own reference, and
	// on a host that had pf enabled another one keeps it on.
	wasEnabled := strings.Contains(pfctlOut("-s", "info"), "Status: Enabled")

	ctrl := NewPFController(testLogger())
	if err := ctrl.Probe(); err != nil {
		t.Fatalf("Probe() error = %v, want nil", err)
	}

	t.Cleanup(func() {
		if err := ctrl.RemoveNATMasquerade("plexd99"); err != nil {
			t.Errorf("cleanup RemoveNATMasquerade() error = %v", err)
		}
		if err := ctrl.DeleteChain("plexd-test"); err != nil {
			t.Errorf("cleanup DeleteChain() error = %v", err)
		}
	})

	if err := ctrl.EnsureChain("plexd-test"); err != nil {
		t.Fatalf("EnsureChain() error = %v, want nil", err)
	}
	rules := []FirewallRule{
		{Interface: "plexd99", SrcIP: "10.255.252.0/30", DstIP: "10.255.252.4/30", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: "plexd99", SrcIP: "10.255.252.8/30", DstIP: "0.0.0.0/0", Action: "deny"},
	}
	if err := ctrl.ApplyRules("plexd-test", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("plexd99"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	// pfctl prints its own normalised form: block becomes "block drop", a
	// single port "port = 443", a pass rule with state carries "flags S/SA",
	// and a dynamic pool a trailing "round-robin".
	loaded := pfctlOut("-a", pfAnchor, "-s", "rules")
	for _, want := range []string{
		"pass out quick on plexd99 inet proto tcp from (plexd99) to any flags S/SA keep state",
		"pass out quick on plexd99 inet from (plexd99) to any no state",
		"pass in quick on plexd99 inet proto tcp from 10.255.252.0/30 to 10.255.252.4/30",
		"block drop in quick on plexd99 inet from 10.255.252.8/30 to any",
	} {
		if !strings.Contains(loaded, want) {
			t.Errorf("loaded rules miss %q:\n%s", want, loaded)
		}
	}
	if nat := pfctlOut("-a", pfAnchor, "-s", "nat"); !strings.Contains(nat, "nat on plexd99 inet all -> (plexd99)") {
		t.Errorf("loaded nat misses the masquerade rule:\n%s", nat)
	}
	if info := pfctlOut("-s", "info"); !strings.Contains(info, "Status: Enabled") {
		t.Errorf("pf is not enabled:\n%s", info)
	}

	if err := ctrl.RemoveNATMasquerade("plexd99"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}
	if err := ctrl.DeleteChain("plexd-test"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}

	if loaded := pfctlOut("-a", pfAnchor, "-s", "rules"); strings.Contains(loaded, "plexd99") {
		t.Errorf("anchor still holds filter rules:\n%s", loaded)
	}
	if nat := pfctlOut("-a", pfAnchor, "-s", "nat"); strings.Contains(nat, "plexd99") {
		t.Errorf("anchor still holds nat rules:\n%s", nat)
	}
	if ctrl.token != "" {
		t.Errorf("token = %q, want empty", ctrl.token)
	}
	if !wasEnabled {
		if info := pfctlOut("-s", "info"); !strings.Contains(info, "Status: Disabled") {
			t.Errorf("pf was left enabled on a host that had it off:\n%s", info)
		}
	}
}
