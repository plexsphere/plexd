//go:build darwin

package policy

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

// PFController is the macOS FirewallController the enforcer is handed, and it
// reports what its logged rules admit.
var (
	_ FirewallController = (*PFController)(nil)
	_ ConnReporter       = (*PFController)(nil)
)

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

// sixRules covers every field combination renderRule handles for IPv4: both
// actions, each protocol and none, a prefix and a bare address on either side,
// a single port and a range, and the wildcard prefix on both sides.
var sixRules = []FirewallRule{
	{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Protocol: "icmp", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.9", DstIP: "10.1.0.0/24", Action: "allow"},
	{Interface: "utun4", SrcIP: "10.0.0.9/32", DstIP: "0.0.0.0/0", Action: "deny"},
	{Interface: "utun4", SrcIP: "0.0.0.0/0", DstIP: "0.0.0.0/0", Action: "deny"},
}

// sixRulesText is the anchor sixRules renders to in chain plexd-mesh: the
// relay probe line for utun4, then every line of each rule in order.
const sixRulesText = pfHeader +
	"# chain plexd-mesh\n" +
	"pass out quick on utun4 proto udp from (utun4) to any port 9 no state\n" +
	// tcp 443
	"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state\n" +
	"pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state\n" +
	"pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state\n" +
	"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
	// udp 53-60
	"pass in quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state\n" +
	"pass out quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state\n" +
	"pass out quick on utun4 inet proto udp from 10.1.0.0/24 port 53:60 to 10.0.0.0/24 no state\n" +
	"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
	// icmp
	"pass in quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state\n" +
	"pass out quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state\n" +
	"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
	// any protocol
	"pass in quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state\n" +
	"pass out quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 keep state\n" +
	"pass out quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state\n" +
	"pass out quick on utun4 inet proto tcp from 10.1.0.0/24 to 10.0.0.9 flags A/A no state\n" +
	"pass out quick on utun4 inet proto udp from 10.1.0.0/24 to 10.0.0.9 no state\n" +
	"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.9 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
	// the deny from 10.0.0.9/32
	"block in quick on utun4 inet from 10.0.0.9/32 to any\n" +
	"block out quick on utun4 inet from 10.0.0.9/32 to any\n" +
	// the IPv4 wildcard deny, whose source is not empty
	"block in quick on utun4 inet from any to any\n" +
	"block out quick on utun4 inet from any to any\n"

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
		"pass out quick on utun4 proto udp from (utun4) to any port 9 no state\n" +
		"pass out quick on utun5 proto udp from (utun5) to any port 9 no state\n" +
		"pass in quick on utun4 inet from 10.0.0.0/24 to any no state\n" +
		"pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to any keep state\n" +
		"pass out quick on utun4 inet from 10.0.0.0/24 to any no state\n" +
		"pass out quick on utun4 inet proto tcp from any to 10.0.0.0/24 flags A/A no state\n" +
		"pass out quick on utun4 inet proto udp from any to 10.0.0.0/24 no state\n" +
		"pass out quick on utun4 inet proto icmp from any to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
		"pass in quick on utun5 inet from 10.0.0.0/24 to any no state\n" +
		"pass out quick on utun5 inet proto tcp from 10.0.0.0/24 to any keep state\n" +
		"pass out quick on utun5 inet from 10.0.0.0/24 to any no state\n" +
		"pass out quick on utun5 inet proto tcp from any to 10.0.0.0/24 flags A/A no state\n" +
		"pass out quick on utun5 inet proto udp from any to 10.0.0.0/24 no state\n" +
		"pass out quick on utun5 inet proto icmp from any to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
		"block in quick on utun4 inet from 10.0.0.9 to any\n" +
		"block out quick on utun4 inet from 10.0.0.9 to any\n"
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

// An IPv6 rule is loaded under inet6, which keeps it to IPv6 packets as inet
// keeps an IPv4 rule to IPv4 ones.
func TestPFController_ApplyRules_IPv6Address(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)

	if err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", SrcIP: "fd00::/64", Action: "allow"}}); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}

	want := pfHeader +
		"# chain plexd-mesh\n" +
		"pass out quick on utun4 proto udp from (utun4) to any port 9 no state\n" +
		"pass in quick on utun4 inet6 from fd00::/64 to any no state\n" +
		"pass out quick on utun4 inet6 proto tcp from fd00::/64 to any keep state\n" +
		"pass out quick on utun4 inet6 from fd00::/64 to any no state\n" +
		"pass out quick on utun4 inet6 proto tcp from any to fd00::/64 flags A/A no state\n" +
		"pass out quick on utun4 inet6 proto udp from any to fd00::/64 no state\n" +
		"pass out quick on utun4 inet6 proto icmp6 from any to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state\n"
	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: want},
		runnerCall{Args: []string{"-E"}},
	)
}

// A rule naming two families matches no packet. It is refused before anything
// reaches pfctl, with the text every backend uses.
func TestPFController_ApplyRules_MixedFamily(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", SrcIP: "fd00::/64", DstIP: "10.1.0.5", Action: "allow"}})
	want := `policy: pf: apply rules: rule 0: policy: firewall rule: source "fd00::/64" and destination "10.1.0.5" differ in address family`
	if err == nil || err.Error() != want {
		t.Fatalf("ApplyRules() error = %v, want %q", err, want)
	}

	checkCalls(t, runner)
}

// checkRenderRule asserts that renderRule returns exactly the wanted lines,
// in order.
func checkRenderRule(t *testing.T, rule FirewallRule, want []string) {
	t.Helper()

	got, err := renderRule(rule)
	if err != nil {
		t.Fatalf("renderRule() error = %v, want nil", err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("renderRule() =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// renderRule writes the family keyword the rule's addresses select on every
// line it returns. The pass in lines of the IPv4 rules are the ones
// sixRulesText pinned before IPv6 was rendered, so an IPv4 rule still lets
// in what it did.
func TestPFController_RenderRuleFamilies(t *testing.T) {
	tests := []struct {
		name string
		rule FirewallRule
		want []string
	}{
		{
			name: "ipv4 rule",
			rule: FirewallRule{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state",
				"pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state",
				"pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
		{
			name: "ipv4 icmp",
			rule: FirewallRule{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Protocol: "icmp", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state",
				"pass out quick on utun4 inet proto icmp from 10.0.0.0/24 to 10.1.0.0/24 no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
		{
			name: "ipv4 wildcard keeps inet",
			rule: FirewallRule{Interface: "utun4", SrcIP: "0.0.0.0/0", DstIP: "0.0.0.0/0", Action: "deny"},
			want: []string{
				"block in quick on utun4 inet from any to any",
				"block out quick on utun4 inet from any to any",
			},
		},
		{
			name: "ipv6 rule",
			rule: FirewallRule{Interface: "utun4", SrcIP: "fd00::/64", DstIP: "fd00::1", Port: 443, Protocol: "tcp", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet6 proto tcp from fd00::/64 to fd00::1 port 443 no state",
				"pass out quick on utun4 inet6 proto tcp from fd00::/64 to fd00::1 port 443 keep state",
				"pass out quick on utun4 inet6 proto tcp from fd00::1 port 443 to fd00::/64 flags A/A no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::1 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			name: "ipv6 icmp is icmp6",
			rule: FirewallRule{Interface: "utun4", SrcIP: "fd00::/64", DstIP: "fd00::1", Protocol: "icmp", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::1 no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::1 no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::1 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			name: "ipv6 host prefix and port range",
			rule: FirewallRule{Interface: "utun4", SrcIP: "fd00::5/128", DstIP: "fd00::/64", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet6 proto udp from fd00::5/128 to fd00::/64 port 53:60 no state",
				"pass out quick on utun4 inet6 proto udp from fd00::5/128 to fd00::/64 port 53:60 no state",
				"pass out quick on utun4 inet6 proto udp from fd00::/64 port 53:60 to fd00::5/128 no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::5/128 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			name: "ipv6 prefix is masked",
			rule: FirewallRule{Interface: "utun4", SrcIP: "fd00::7/64", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet6 from fd00::/64 to any no state",
				"pass out quick on utun4 inet6 proto tcp from fd00::/64 to any keep state",
				"pass out quick on utun4 inet6 from fd00::/64 to any no state",
				"pass out quick on utun4 inet6 proto tcp from any to fd00::/64 flags A/A no state",
				"pass out quick on utun4 inet6 proto udp from any to fd00::/64 no state",
				"pass out quick on utun4 inet6 proto icmp6 from any to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			name: "ipv6 wildcard keeps inet6",
			rule: FirewallRule{Interface: "utun4", SrcIP: "::/0", DstIP: "fd00::1", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet6 from any to fd00::1 no state",
				"pass out quick on utun4 inet6 proto tcp from any to fd00::1 keep state",
				"pass out quick on utun4 inet6 from any to fd00::1 no state",
				"pass out quick on utun4 inet6 proto tcp from fd00::1 to any flags A/A no state",
				"pass out quick on utun4 inet6 proto udp from fd00::1 to any no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::1 to any icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			// The block out line names the interface's own addresses, so a
			// packet the Mac forwards out of the interface is left alone.
			name: "default deny covers both families",
			rule: FirewallRule{Interface: "utun4", Action: "deny"},
			want: []string{
				"block in quick on utun4 from any to any",
				"block out quick on utun4 from (utun4) to any",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRenderRule(t, tt.rule, tt.want)
		})
	}
}

// An allow renders its pass in line, the node's own traffic and the reply
// mirrors; a deny renders a block line for each direction. The tcp 443,
// ICMPv6 and default deny examples of #178 are cases of
// TestPFController_RenderRuleFamilies; these are the others.
func TestPFController_RenderRuleLines(t *testing.T) {
	tests := []struct {
		name string
		rule FirewallRule
		want []string
	}{
		{
			// UDP keeps no state in either direction, and no tcp line appears.
			name: "udp port range",
			rule: FirewallRule{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state",
				"pass out quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state",
				"pass out quick on utun4 inet proto udp from 10.1.0.0/24 port 53:60 to 10.0.0.0/24 no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
		{
			// A rule without a protocol keeps state for the node's own TCP
			// only, and mirrors TCP, UDP and ICMPv6.
			name: "ipv6 any protocol",
			rule: FirewallRule{Interface: "utun4", SrcIP: "fd00::/64", DstIP: "fd00::1", Action: "allow"},
			want: []string{
				"pass in quick on utun4 inet6 from fd00::/64 to fd00::1 no state",
				"pass out quick on utun4 inet6 proto tcp from fd00::/64 to fd00::1 keep state",
				"pass out quick on utun4 inet6 from fd00::/64 to fd00::1 no state",
				"pass out quick on utun4 inet6 proto tcp from fd00::1 to fd00::/64 flags A/A no state",
				"pass out quick on utun4 inet6 proto udp from fd00::1 to fd00::/64 no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::1 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			// A rule without addresses names no family, so it gets the ICMP
			// mirror of each.
			name: "allow without addresses",
			rule: FirewallRule{Interface: "utun4", Action: "allow"},
			want: []string{
				"pass in quick on utun4 from any to any no state",
				"pass out quick on utun4 proto tcp from any to any keep state",
				"pass out quick on utun4 from any to any no state",
				"pass out quick on utun4 proto tcp from any to any flags A/A no state",
				"pass out quick on utun4 proto udp from any to any no state",
				"pass out quick on utun4 inet proto icmp from any to any icmp-type { echorep, unreach, timex, paramprob } no state",
				"pass out quick on utun4 inet6 proto icmp6 from any to any icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			// A deny keeps its protocol in both lines, and only an empty
			// source becomes the interface's own addresses.
			name: "deny without source",
			rule: FirewallRule{Interface: "utun4", DstIP: "fd00::1", Protocol: "icmp", Action: "deny"},
			want: []string{
				"block in quick on utun4 inet6 proto icmp6 from any to fd00::1",
				"block out quick on utun4 inet6 proto icmp6 from (utun4) to fd00::1",
			},
		},
		{
			// A source that names an address stays the source of the block
			// out line, and the port range stays on both lines.
			name: "deny with port range",
			rule: FirewallRule{Interface: "utun4", SrcIP: "10.0.0.9", DstIP: "10.1.0.0/24", Port: 8000, PortTo: 8080, Protocol: "tcp", Action: "deny"},
			want: []string{
				"block in quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 port 8000:8080",
				"block out quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 port 8000:8080",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRenderRule(t, tt.rule, tt.want)
		})
	}
}

// The relay probe line opens a chain once per interface, in the order the
// rules first name each one, and it is the only pass out line whose source
// is an interface's own addresses: the node's own traffic is matched by the
// rules, not by an interface-wide pass.
func TestPFController_RenderProbeLines(t *testing.T) {
	ctrl := NewPFController(testLogger())
	ctrl.chains["plexd-mesh"] = []FirewallRule{
		{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: "utun5", Action: "allow"},
		{Interface: "utun4", SrcIP: "fd00::/64", Action: "allow"},
		{Interface: "utun5", Action: "deny"},
		{Interface: "utun4", Action: "deny"},
	}

	text, _ := ctrl.render()
	var got []string
	for _, line := range strings.Split(string(text), "\n") {
		if strings.HasPrefix(line, "pass out ") && strings.Contains(line, " from (") {
			got = append(got, line)
		}
	}
	want := []string{
		"pass out quick on utun4 proto udp from (utun4) to any port 9 no state",
		"pass out quick on utun5 proto udp from (utun5) to any port 9 no state",
	}
	if !slices.Equal(got, want) {
		t.Errorf("pass out lines from an interface =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A chain without rules renders as its comment line alone, whether it was
// ensured, applied empty or nil, or flushed, so pf holds no filter line for
// it: no probe line and no block line.
func TestPFController_RenderEmptyChain(t *testing.T) {
	const want = pfHeader + "# chain plexd-mesh\n"

	for _, tt := range []struct {
		name  string
		rules []FirewallRule
	}{
		{name: "nil", rules: nil},
		{name: "empty", rules: []FirewallRule{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := NewPFController(testLogger())
			ctrl.chains["plexd-mesh"] = tt.rules
			if text, _ := ctrl.render(); string(text) != want {
				t.Errorf("render() =\n%q\nwant\n%q", text, want)
			}
		})
	}

	t.Run("flushed", func(t *testing.T) {
		ctrl, runner := newTestPFController(t)
		runner.outputs[enableKey] = []byte(tokenOut)

		if err := ctrl.ApplyRules("plexd-mesh", sixRules); err != nil {
			t.Fatalf("ApplyRules() error = %v, want nil", err)
		}
		if err := ctrl.FlushChain("plexd-mesh"); err != nil {
			t.Fatalf("FlushChain() error = %v, want nil", err)
		}
		if text, _ := ctrl.render(); string(text) != want {
			t.Errorf("render() =\n%q\nwant\n%q", text, want)
		}
	})
}

// A logged rule puts log on the lines that see a connection's first packet: a
// SYN line ahead of the tcp pass in line, the node's own pass out lines, and
// for udp, icmp or no protocol the pass in line too. Mirrors never log.
func TestPFController_RenderRuleLogged(t *testing.T) {
	tcp443 := FirewallRule{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"}
	logged443 := tcp443
	logged443.LogTag = "3/0"
	loggedAny := FirewallRule{Interface: "utun4", SrcIP: "10.0.0.9", DstIP: "10.1.0.0/24", Action: "allow", LogTag: "3/3"}

	tests := []struct {
		name string
		rule FirewallRule
		want []string
	}{
		{
			name: "tcp",
			rule: logged443,
			want: []string{
				"pass in log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 flags S/SA no state",
				"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state",
				"pass out log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state",
				"pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
		{
			// The same rule without a tag renders exactly as it did before
			// logging existed.
			name: "tcp untagged",
			rule: tcp443,
			want: []string{
				"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state",
				"pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state",
				"pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
		{
			// Neither udp line keeps state, so both log every packet they
			// pass. The mirrors do not log.
			name: "udp",
			rule: FirewallRule{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.0/24", Port: 53, Protocol: "udp", Action: "allow", LogTag: "3/1"},
			want: []string{
				"pass in log quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53 no state",
				"pass out log quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53 no state",
				"pass out quick on utun4 inet proto udp from 10.1.0.0/24 port 53 to 10.0.0.0/24 no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
		{
			name: "ipv6 icmp",
			rule: FirewallRule{Interface: "utun4", SrcIP: "fd00::/64", DstIP: "fd00::1", Protocol: "icmp", Action: "allow", LogTag: "3/2"},
			want: []string{
				"pass in log quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::1 no state",
				"pass out log quick on utun4 inet6 proto icmp6 from fd00::/64 to fd00::1 no state",
				"pass out quick on utun4 inet6 proto icmp6 from fd00::1 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
			},
		},
		{
			// The unlogged tcp lines keep the rest of a TCP connection, and
			// the Mac's replies to an inbound one, from reaching the logged
			// protocol-less lines.
			name: "no protocol",
			rule: loggedAny,
			want: []string{
				"pass in log quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 flags S/SA no state",
				"pass in quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 no state",
				"pass in log quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state",
				"pass out log quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 keep state",
				"pass out quick on utun4 inet proto tcp from 10.0.0.9 to 10.1.0.0/24 no state",
				"pass out log quick on utun4 inet from 10.0.0.9 to 10.1.0.0/24 no state",
				"pass out quick on utun4 inet proto tcp from 10.1.0.0/24 to 10.0.0.9 flags A/A no state",
				"pass out quick on utun4 inet proto udp from 10.1.0.0/24 to 10.0.0.9 no state",
				"pass out quick on utun4 inet proto icmp from 10.1.0.0/24 to 10.0.0.9 icmp-type { echorep, unreach, timex, paramprob } no state",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRenderRule(t, tt.rule, tt.want)
		})
	}

	// The default deny behind logged rules renders its block lines without
	// log.
	t.Run("block lines", func(t *testing.T) {
		ctrl := NewPFController(testLogger())
		ctrl.chains["plexd-mesh"] = []FirewallRule{logged443, loggedAny, {Interface: "utun4", Action: "deny"}}
		text, _ := ctrl.render()

		var got []string
		for _, line := range strings.Split(string(text), "\n") {
			if strings.HasPrefix(line, "block ") {
				got = append(got, line)
			}
		}
		want := []string{
			"block in quick on utun4 from any to any",
			"block out quick on utun4 from (utun4) to any",
		}
		if !slices.Equal(got, want) {
			t.Errorf("block lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
}

// render maps each logged line to its rule's tag under the number pf gives
// it, which counts the rules pfctl loads from the first filter line on. In
// the chain below the relay probe line is filter line 0 and the untagged
// rule's lines are 1 to 4, so the logged rule's pass in log line is filter
// line 5 and its pass out log line 7. pfctl loads the untagged rule's ICMP
// mirror as four rules, one per icmp-type, so pf numbers those two lines 8
// and 10.
func TestPFController_RenderLogTags(t *testing.T) {
	filterLines := func(text []byte) []string {
		var lines []string
		for _, line := range strings.Split(string(text), "\n") {
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "nat ") {
				continue
			}
			lines = append(lines, line)
		}
		return lines
	}

	t.Run("after an untagged rule", func(t *testing.T) {
		ctrl := NewPFController(testLogger())
		ctrl.chains["plexd-mesh"] = []FirewallRule{
			{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow"},
			{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.6", Port: 8443, Protocol: "tcp", Action: "allow", LogTag: "1/1"},
			{Interface: "utun4", Action: "deny"},
		}
		text, tags := ctrl.render()

		lines := filterLines(text)
		if len(lines) != 12 {
			t.Fatalf("filter lines = %d, want 12:\n%s", len(lines), text)
		}
		if want := "pass out quick on utun4 proto udp from (utun4) to any port 9 no state"; lines[0] != want {
			t.Errorf("filter line 0 = %q, want %q", lines[0], want)
		}
		if want := "pass in log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.6 port 8443 flags S/SA no state"; lines[5] != want {
			t.Errorf("filter line 5 = %q, want %q", lines[5], want)
		}
		if want := "pass out log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.6 port 8443 keep state"; lines[7] != want {
			t.Errorf("filter line 7 = %q, want %q", lines[7], want)
		}
		if want := map[uint32]string{8: "1/1", 10: "1/1"}; !maps.Equal(tags, want) {
			t.Errorf("render() tags = %v, want %v", tags, want)
		}
	})

	// A rule without addresses has an ICMP mirror for each family, four and
	// five rules, so the logged rule behind it starts at 18.
	t.Run("after both icmp mirrors", func(t *testing.T) {
		ctrl := NewPFController(testLogger())
		ctrl.chains["plexd-mesh"] = []FirewallRule{
			{Interface: "utun4", Action: "allow", LogTag: "2/0"},
			{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow", LogTag: "2/1"},
			{Interface: "utun4", Action: "deny"},
		}
		_, tags := ctrl.render()

		want := map[uint32]string{1: "2/0", 3: "2/0", 4: "2/0", 6: "2/0", 18: "2/1", 20: "2/1"}
		if !maps.Equal(tags, want) {
			t.Errorf("render() tags = %v, want %v", tags, want)
		}
	})

	t.Run("untagged", func(t *testing.T) {
		ctrl := NewPFController(testLogger())
		ctrl.chains["plexd-mesh"] = sixRules
		if _, tags := ctrl.render(); tags == nil || len(tags) != 0 {
			t.Errorf("render() tags = %v, want an empty map", tags)
		}
	})
}

// tcp443Rules is a logged tcp rule and the default deny, the ruleset the
// connection logging tests apply.
func tcp443Rules(tag string) []FirewallRule {
	return []FirewallRule{
		{Interface: "utun4", SrcIP: "10.0.0.0/24", DstIP: "10.1.0.5", Port: 443, Protocol: "tcp", Action: "allow", LogTag: tag},
		{Interface: "utun4", Action: "deny"},
	}
}

// The anchor tcp443Rules renders to with its tag and without it.
const (
	tcp443LoggedText = pfHeader +
		"# chain plexd-mesh\n" +
		"pass out quick on utun4 proto udp from (utun4) to any port 9 no state\n" +
		"pass in log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 flags S/SA no state\n" +
		"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state\n" +
		"pass out log quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state\n" +
		"pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state\n" +
		"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
		"block in quick on utun4 from any to any\n" +
		"block out quick on utun4 from (utun4) to any\n"

	tcp443UnloggedText = pfHeader +
		"# chain plexd-mesh\n" +
		"pass out quick on utun4 proto udp from (utun4) to any port 9 no state\n" +
		"pass in quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 no state\n" +
		"pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state\n" +
		"pass out quick on utun4 inet proto tcp from 10.1.0.5 port 443 to 10.0.0.0/24 flags A/A no state\n" +
		"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state\n" +
		"block in quick on utun4 from any to any\n" +
		"block out quick on utun4 from (utun4) to any\n"
)

// A logged apply opens a reader once and loads the log lines. The tags change
// only when pf took the anchor, the ones they replace stay one more load, and
// deleting the last chain closes the reader.
func TestPFController_ApplyRules_ConnLog(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	ctrl.SetConnSink(&pflogTestSink{})
	reader, released := idlePflogReader()
	opens := 0
	ctrl.openLog = func() (*pflogReader, error) {
		opens++
		return reader, nil
	}

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("1/0")); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: tcp443LoggedText},
		runnerCall{Args: []string{"-E"}},
	)
	if want := map[uint32]string{1: "1/0", 3: "1/0"}; !maps.Equal(ctrl.logTags, want) {
		t.Errorf("logTags = %v, want %v", ctrl.logTags, want)
	}

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("2/0")); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	if opens != 1 {
		t.Errorf("openLog calls = %d, want 1", opens)
	}
	if tag, ok := ctrl.pflogTag(3); !ok || tag != "2/0" {
		t.Errorf("pflogTag(3) = %q, %v, want %q, true", tag, ok, "2/0")
	}
	if want := map[uint32]string{1: "1/0", 3: "1/0"}; !maps.Equal(ctrl.prevLogTags, want) {
		t.Errorf("prevLogTags = %v, want %v", ctrl.prevLogTags, want)
	}

	// A load pf refuses changes no tag.
	runner.outputs[loadKey] = []byte("stdin:3: syntax error")
	runner.errs[loadKey] = errors.New("exit status 1")
	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("3/0")); err == nil {
		t.Fatal("ApplyRules() error = nil, want the load error")
	}
	if want := map[uint32]string{1: "2/0", 3: "2/0"}; !maps.Equal(ctrl.logTags, want) {
		t.Errorf("logTags after a refused load = %v, want %v", ctrl.logTags, want)
	}
	delete(runner.outputs, loadKey)
	delete(runner.errs, loadKey)

	// Deleting the last chain flushes the anchor and closes the reader. A
	// record pf wrote before the flush still finds its line.
	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if reader.running() || !released.Load() {
		t.Error("the reader still runs after the last chain was deleted")
	}
	if ctrl.reader != nil {
		t.Error("the controller still holds the closed reader")
	}
	if len(ctrl.logTags) != 0 {
		t.Errorf("logTags after the flush = %v, want none", ctrl.logTags)
	}
	if tag, ok := ctrl.pflogTag(1); !ok || tag != "2/0" {
		t.Errorf("pflogTag(1) after the flush = %q, %v, want %q, true", tag, ok, "2/0")
	}
}

// When the reader cannot open, the logged rules are stored and loaded without
// their tags, so pf enforces them without log, and every such apply logs the
// shared Warn line with the error.
func TestPFController_ApplyRules_ConnLogUnavailable(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	var buf bytes.Buffer
	ctrl.logger = captureLogger(&buf)
	ctrl.SetConnSink(&pflogTestSink{})
	ctrl.openLog = func() (*pflogReader, error) {
		return nil, errors.New("policy: pf: pflog: no free bpf device")
	}

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("1/0")); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: tcp443UnloggedText},
		runnerCall{Args: []string{"-E"}},
	)

	out := buf.String()
	if got := countLines(out, `level=WARN msg="`+connLogUnavailable+`"`); got != 1 {
		t.Errorf("Warn lines %q = %d, want 1:\n%s", connLogUnavailable, got, out)
	}
	if !strings.Contains(out, `error="policy: pf: pflog: no free bpf device"`) {
		t.Errorf("Warn line misses the error:\n%s", out)
	}
	if len(ctrl.logTags) != 0 {
		t.Errorf("logTags = %v, want none", ctrl.logTags)
	}
	// The stored rules carry no tag, so a reload for another reason adds no
	// log keyword either.
	if tag := ctrl.chains["plexd-mesh"][0].LogTag; tag != "" {
		t.Errorf("stored rule 0 LogTag = %q, want empty", tag)
	}

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("2/0")); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	if got := countLines(buf.String(), `msg="`+connLogUnavailable+`"`); got != 2 {
		t.Errorf("Warn lines after a second apply = %d, want 2", got)
	}
}

// Without a sink nobody reads what pf would log, so no reader opens, the
// rules load without log, and nothing is logged at Warn.
func TestPFController_ApplyRules_ConnLogNoSink(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	var buf bytes.Buffer
	ctrl.logger = captureLogger(&buf)
	ctrl.openLog = func() (*pflogReader, error) {
		t.Error("openLog called without a sink")
		return nil, errors.New("no sink")
	}

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("1/0")); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	checkCalls(t, runner,
		runnerCall{Args: []string{"-a", pfAnchor, "-f", "-"}, Stdin: tcp443UnloggedText},
		runnerCall{Args: []string{"-E"}},
	)
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("logged at Warn without a sink:\n%s", buf.String())
	}
}

// A reader whose loop ended, as a read error ends it, is replaced at the next
// logged apply.
func TestPFController_ApplyRules_ConnLogReopens(t *testing.T) {
	ctrl, runner := newTestPFController(t)
	runner.outputs[enableKey] = []byte(tokenOut)
	ctrl.SetConnSink(&pflogTestSink{})
	var readers []*pflogReader
	ctrl.openLog = func() (*pflogReader, error) {
		r, _ := idlePflogReader()
		readers = append(readers, r)
		return r, nil
	}

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("1/0")); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	readers[0].close()

	if err := ctrl.ApplyRules("plexd-mesh", tcp443Rules("2/0")); err != nil {
		t.Fatalf("ApplyRules() second error = %v, want nil", err)
	}
	if len(readers) != 2 {
		t.Fatalf("openLog calls = %d, want 2", len(readers))
	}
	if ctrl.reader != readers[1] {
		t.Error("the controller does not hold the new reader")
	}

	if err := ctrl.DeleteChain("plexd-mesh"); err != nil {
		t.Fatalf("DeleteChain() error = %v, want nil", err)
	}
	if readers[1].running() {
		t.Error("the new reader still runs after the last chain was deleted")
	}
}

// A rule whose source does not parse is refused before anything reaches
// pfctl, so the kernel keeps the rules it held.
func TestPFController_ApplyRules_InvalidSource(t *testing.T) {
	ctrl, runner := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", SrcIP: "not-an-ip", Action: "allow"}})
	want := "policy: pf: apply rules: rule 0:"
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("ApplyRules() error = %v, want prefix %q", err, want)
	}

	checkCalls(t, runner)
}

func TestPFController_ApplyRules_InvalidAddress(t *testing.T) {
	ctrl, _ := newTestPFController(t)

	err := ctrl.ApplyRules("plexd-mesh", []FirewallRule{{Interface: "utun4", DstIP: "bogus", Action: "allow"}})
	want := `policy: pf: apply rules: rule 0: policy: firewall rule: invalid IP address "bogus"`
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
	// sixRules yields the relay probe line, the keep state and no state pass
	// out lines, the flags A/A mirror, a udp mirror with a port range, the
	// ICMP mirror and the inet block out lines.
	ctrl.chains["plexd-mesh"] = sixRules
	// The second chain carries the lines sixRules cannot produce: inet6,
	// icmp6 and the ICMPv6 mirror, the IPv6 wildcard, a flags A/A mirror with
	// a port range, the lines of an allow without a family, and the default
	// deny with its block out line from (utun5).
	ctrl.chains["plexd-v6"] = []FirewallRule{
		{Interface: "utun5", SrcIP: "fd00::/64", DstIP: "fd00::1", Port: 443, Protocol: "tcp", Action: "allow"},
		{Interface: "utun5", SrcIP: "fd00::/64", DstIP: "fd00::1/128", Protocol: "icmp", Action: "allow"},
		{Interface: "utun5", SrcIP: "::/0", DstIP: "fd00::/64", Port: 53, PortTo: 60, Protocol: "udp", Action: "allow"},
		{Interface: "utun5", SrcIP: "fd00::/64", DstIP: "fd00::1", Port: 8000, PortTo: 8080, Protocol: "tcp", Action: "allow"},
		{Interface: "utun5", Action: "allow"},
		{Interface: "utun5", Action: "deny"},
	}
	// The third chain carries the logged lines: the tcp SYN line with flags
	// S/SA, the logged keep state line, logged udp and icmp6 lines without
	// state, and the protocol-less logged pass in line.
	ctrl.chains["plexd-log"] = []FirewallRule{
		{Interface: "utun6", SrcIP: "10.2.0.0/24", DstIP: "10.3.0.5", Port: 443, Protocol: "tcp", Action: "allow", LogTag: "1/0"},
		{Interface: "utun6", SrcIP: "10.2.0.0/24", DstIP: "10.3.0.0/24", Port: 53, Protocol: "udp", Action: "allow", LogTag: "1/1"},
		{Interface: "utun6", SrcIP: "10.2.0.9", DstIP: "10.3.0.0/24", Action: "allow", LogTag: "1/2"},
		{Interface: "utun6", SrcIP: "fd00:3::/64", DstIP: "fd00:3::1", Protocol: "icmp", Action: "allow", LogTag: "1/3"},
		{Interface: "utun6", Action: "deny"},
	}

	text, _ := ctrl.render()

	// The anchor has to hold every line form, or pfctl would pass without
	// having seen one.
	lines := strings.Split(string(text), "\n")
	for _, form := range []string{
		"pass out quick on utun4 proto udp from (utun4) to any port 9 no state",
		"pass out quick on utun5 proto udp from (utun5) to any port 9 no state",
		"pass out quick on utun4 inet proto tcp from 10.0.0.0/24 to 10.1.0.5 port 443 keep state",
		"pass out quick on utun4 inet proto udp from 10.0.0.0/24 to 10.1.0.0/24 port 53:60 no state",
		"pass out quick on utun5 inet6 proto tcp from fd00::1 port 8000:8080 to fd00::/64 flags A/A no state",
		"pass out quick on utun4 inet proto icmp from 10.1.0.5 to 10.0.0.0/24 icmp-type { echorep, unreach, timex, paramprob } no state",
		"pass out quick on utun5 inet6 proto icmp6 from fd00::1 to fd00::/64 icmp6-type { echorep, unreach, toobig, timex, paramprob } no state",
		"block out quick on utun5 from (utun5) to any",
		"pass in log quick on utun6 inet proto tcp from 10.2.0.0/24 to 10.3.0.5 port 443 flags S/SA no state",
		"pass out log quick on utun6 inet proto tcp from 10.2.0.0/24 to 10.3.0.5 port 443 keep state",
		"pass in log quick on utun6 inet proto udp from 10.2.0.0/24 to 10.3.0.0/24 port 53 no state",
		"pass out log quick on utun6 inet proto udp from 10.2.0.0/24 to 10.3.0.0/24 port 53 no state",
		"pass in log quick on utun6 inet proto tcp from 10.2.0.9 to 10.3.0.0/24 flags S/SA no state",
		"pass in log quick on utun6 inet from 10.2.0.9 to 10.3.0.0/24 no state",
		"pass out log quick on utun6 inet from 10.2.0.9 to 10.3.0.0/24 no state",
		"pass in log quick on utun6 inet6 proto icmp6 from fd00:3::/64 to fd00:3::1 no state",
	} {
		if !slices.Contains(lines, form) {
			t.Errorf("rendered anchor misses %q:\n%s", form, text)
		}
	}

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
		{Interface: "plexd99", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1/128", Port: 44301, Protocol: "tcp", Action: "allow"},
		{Interface: "plexd99", Action: "deny"},
	}
	if err := ctrl.ApplyRules("plexd-test", rules); err != nil {
		t.Fatalf("ApplyRules() error = %v, want nil", err)
	}
	if err := ctrl.AddNATMasquerade("plexd99"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	// pfctl prints its own normalised form: block becomes "block drop", a
	// single port "port = 443", a pass rule with state carries "flags S/SA",
	// and a dynamic pool a trailing "round-robin". The two inet lines that
	// pass and block inbound are the ones this test asserted before IPv6 was
	// rendered. The other lines are read off pfctl's printer, which drops a
	// host mask (fd00:99::1/128 prints as fd00:99::1), prints "all" for from
	// any to any without ports, names a protocol as /etc/protocols does (58
	// is ipv6-icmp), and loads an icmp-type or icmp6-type list as one rule
	// per type. The IPv6 rule's port has no /etc/services name, so its lines
	// read the same whether pfctl prints a port by number or by service
	// name. The relay probe's port has one, discard, so the probe line is
	// accepted in either spelling. These normalised forms are what
	// macos-latest must confirm; where it prints another form, that form is
	// the one to assert.
	loaded := pfctlOut("-a", pfAnchor, "-s", "rules")
	wants := []string{
		"pass in quick on plexd99 inet proto tcp from 10.255.252.0/30 to 10.255.252.4/30",
		"block drop in quick on plexd99 inet from 10.255.252.8/30 to any",
		"block drop out quick on plexd99 inet from 10.255.252.8/30 to any",
		"pass in quick on plexd99 inet6 proto tcp from fd00:99::/64 to fd00:99::1 port = 44301",
		"pass out quick on plexd99 inet6 proto tcp from fd00:99::/64 to fd00:99::1 port = 44301 flags S/SA keep state",
		"pass out quick on plexd99 inet6 proto tcp from fd00:99::1 port = 44301 to fd00:99::/64 flags A/A no state",
		"block drop in quick on plexd99 all",
		"block drop out quick on plexd99 from (plexd99) to any",
	}
	for _, typ := range []string{"echorep", "unreach", "timex", "paramprob"} {
		wants = append(wants, "pass out quick on plexd99 inet proto icmp from 10.255.252.4/30 to 10.255.252.0/30 icmp-type "+typ+" no state")
	}
	for _, typ := range []string{"echorep", "unreach", "toobig", "timex", "paramprob"} {
		wants = append(wants, "pass out quick on plexd99 inet6 proto ipv6-icmp from fd00:99::1 to fd00:99::/64 icmp6-type "+typ+" no state")
	}
	for _, want := range wants {
		if !strings.Contains(loaded, want) {
			t.Errorf("loaded rules miss %q:\n%s", want, loaded)
		}
	}

	// The relay probe line is the only pass out line whose source is the
	// interface's own addresses: the pass out pair the anchor opened with
	// before #178 is gone.
	probe := []string{
		"pass out quick on plexd99 proto udp from (plexd99) to any port = discard no state",
		"pass out quick on plexd99 proto udp from (plexd99) to any port = 9 no state",
	}
	probes := 0
	for _, line := range strings.Split(loaded, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pass out ") || !strings.Contains(line, "from (plexd99)") {
			continue
		}
		if !slices.Contains(probe, line) {
			t.Errorf("loaded rules pass %q, want only the relay probe line from (plexd99)", line)
			continue
		}
		probes++
	}
	if probes != 1 {
		t.Errorf("loaded rules hold %d relay probe lines, want 1, in one of %q:\n%s", probes, probe, loaded)
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
