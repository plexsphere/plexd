//go:build windows

package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// psKey builds the answer-map key for a PowerShell invocation.
func psKey(script string) string {
	return commandKey(powershellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

var (
	getKey    = psKey(psGetNetNat)
	newKey    = psKey(fmt.Sprintf(psNewNetNat, "10.0.0.0/16"))
	removeKey = psKey(psRemoveNetNat)
)

// checkNATCalls asserts that exactly the wanted scripts ran, in order, each
// with the flags the service depends on. Every test pins the whole list: a
// spurious call would drop or rebuild the object the host translates through.
func checkNATCalls(t *testing.T, runner *recordingRunner, scripts ...string) {
	t.Helper()

	got := runner.callsFor(powershellPath())
	if len(got) != len(scripts) {
		t.Fatalf("powershell calls = %d, want %d: %+v", len(got), len(scripts), got)
	}
	for i := range got {
		want := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", scripts[i]}
		if !slices.Equal(got[i].Args, want) {
			t.Errorf("call %d args = %v, want %v", i, got[i].Args, want)
		}
	}
}

func TestNetNat_Add_Creates(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	// The script swallows the absent case, so Get-NetNat succeeds with no
	// output rather than failing with a localized message.
	runner.outputs[getKey] = nil

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	checkNATCalls(t, runner,
		psGetNetNat,
		"New-NetNat -Name plexd -InternalIPInterfaceAddressPrefix 10.0.0.0/16 | Out-Null",
	)
}

func TestNetNat_Add_AlreadyConfigured(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	// Get-NetNat ends its output in CRLF, which the comparison has to survive.
	runner.outputs[getKey] = []byte("10.0.0.0/16\r\n")

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	checkNATCalls(t, runner, psGetNetNat)
}

func TestNetNat_Add_PrefixChanged(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	runner.outputs[getKey] = []byte("10.9.0.0/16\r\n")

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	checkNATCalls(t, runner,
		psGetNetNat,
		psRemoveNetNat,
		"New-NetNat -Name plexd -InternalIPInterfaceAddressPrefix 10.0.0.0/16 | Out-Null",
	)
}

func TestNetNat_Add_MeshPrefixUnresolvable(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	ctrl.meshIface = "plexd7"

	err := ctrl.AddNATMasquerade("Ethernet")
	want := `bridge: add NAT masquerade on "Ethernet": resolve mesh prefix for "plexd7":`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("AddNATMasquerade() error = %v, want one starting with %q", err, want)
	}

	// Without a source prefix there is nothing to translate, so no NetNat
	// object may be touched.
	checkNATCalls(t, runner)
}

func TestNetNat_Add_GetFails(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	runner.outputs[getKey] = []byte("Get-NetNat : Access is denied.")
	runner.errs[getKey] = errors.New("exit status 1")

	err := ctrl.AddNATMasquerade("Ethernet")
	want := fmt.Sprintf(`bridge: add NAT masquerade on "Ethernet": powershell -Command %q: exit status 1: Get-NetNat : Access is denied.`, psGetNetNat)
	if err == nil || err.Error() != want {
		t.Fatalf("AddNATMasquerade() error = %v, want %q", err, want)
	}

	// A failure that is not "no such object" leaves the host's own NAT alone.
	checkNATCalls(t, runner, psGetNetNat)
}

func TestNetNat_Add_NewFails(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	runner.outputs[newKey] = []byte("New-NetNat : The NAT already exists")
	runner.errs[newKey] = errors.New("exit status 1")

	err := ctrl.AddNATMasquerade("Ethernet")
	want := `bridge: add NAT masquerade on "Ethernet": powershell -Command "New-NetNat`
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("AddNATMasquerade() error = %v, want one starting with %q", err, want)
	}
}

func TestNetNat_Add_EmptyInterface(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)

	// WinNAT translates by source prefix, so the egress interface is not part
	// of the object and an empty name changes nothing.
	if err := ctrl.AddNATMasquerade(""); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}

	checkNATCalls(t, runner,
		psGetNetNat,
		"New-NetNat -Name plexd -InternalIPInterfaceAddressPrefix 10.0.0.0/16 | Out-Null",
	)
}

func TestNetNat_Remove(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)

	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}

	checkNATCalls(t, runner, psRemoveNetNat)
}

func TestNetNat_Remove_Fails(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)
	runner.outputs[removeKey] = []byte("Remove-NetNat : Access is denied.")
	runner.errs[removeKey] = errors.New("exit status 1")

	err := ctrl.RemoveNATMasquerade("Ethernet")
	want := fmt.Sprintf(`bridge: remove NAT masquerade on "Ethernet": powershell -Command %q: exit status 1:`, psRemoveNetNat)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("RemoveNATMasquerade() error = %v, want one starting with %q", err, want)
	}

	checkNATCalls(t, runner, psRemoveNetNat)
}

// An object that is not there is recognised by the CDXML query error id, not
// by the message that carries it: that message is localized, so a match on its
// text would leave bridge mode unusable on every non-English Windows install.
// Both cmdlets have to carry the guard, because both are run against a name
// the host may not know, and the explicit exit, because a caught error alone
// leaves $? false and -Command then exits 1 with no output.
func TestNetNat_AbsentObjectRecognisedWithoutMessageText(t *testing.T) {
	for _, script := range []string{psGetNetNat, psRemoveNetNat} {
		if !strings.Contains(script, "$_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*'") {
			t.Errorf("script %q does not swallow the CDXML not-found error id", script)
		}
		if !strings.HasPrefix(script, "$ErrorActionPreference = 'Stop'; try {") {
			t.Errorf("script %q does not make the cmdlet error catchable", script)
		}
		if !strings.HasSuffix(script, "; exit 0") {
			t.Errorf("script %q does not set its exit code, so a swallowed miss would exit 1", script)
		}
		if strings.Contains(script, "MSFT_NetNat objects") {
			t.Errorf("script %q matches on a localized message", script)
		}
	}
}

func TestNetNat_CommandsCarryDeadline(t *testing.T) {
	ctrl, _, runner := newTestWFPController(t)

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
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

// TestWFPController_RealNAT drives the host's WinNAT. The source prefix is one
// no adapter on the machine running the test carries, so nothing of its own
// traffic is translated, and the object is removed again.
func TestWFPController_RealNAT(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WFP=1 in an elevated shell to program the filter engine")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("programming the filter engine needs Administrator")
	}

	ctrl := NewWFPController(testLogger(), "unused")
	ctrl.meshPrefix = func(string) (netip.Prefix, error) {
		return netip.MustParsePrefix("10.255.252.0/30"), nil
	}

	// netNat queries the host through PowerShell directly, because the
	// controller's own commands are what the test is checking.
	netNat := func(script string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), powershellTimeout)
		defer cancel()
		out, err := execCommand(ctx, nil, powershellPath(), "-NoProfile", "-NonInteractive", "-Command", script)
		return strings.TrimSpace(string(out)), err
	}

	t.Cleanup(func() {
		// The script is idempotent, so a test that removed the object already
		// leaves the cleanup nothing to do and no failure to accept.
		if out, err := netNat(psRemoveNetNat); err != nil {
			t.Errorf("cleanup %s: %v\n%s", psRemoveNetNat, err, out)
		}
	})

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	out, err := netNat(psGetNetNat)
	if err != nil {
		t.Fatalf("%s: %v\n%s", psGetNetNat, err, out)
	}
	if out != "10.255.252.0/30" {
		t.Errorf("InternalIPInterfaceAddressPrefix = %q, want %q", out, "10.255.252.0/30")
	}

	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("second AddNATMasquerade() error = %v, want nil", err)
	}

	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}
	// The object is gone, which the script reports as an empty success rather
	// than as the localized error the cmdlet raises on its own.
	out, err = netNat(psGetNetNat)
	if err != nil {
		t.Errorf("%s after removal = %v\n%s", psGetNetNat, err, out)
	}
	if out != "" {
		t.Errorf("%s after removal printed %q, want nothing", psGetNetNat, out)
	}

	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("second RemoveNATMasquerade() error = %v, want nil", err)
	}
}
