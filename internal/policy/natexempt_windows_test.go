//go:build windows

package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/plexsphere/plexd/internal/wintundll"
)

// The tunnel link the unit tests exempt, its LUID, and the blocks its name
// leads to. The 32-bit FNV-1a hash of the name is 426730136, which is block
// 15512 of 16128, so the search starts at 169.254.243.96/30 and goes on to
// 169.254.243.100/30.
const (
	exemptTestIface = "wg-s2s-a0a0a0e1"
	exemptTestLUID  = 77
)

var (
	exemptTestMesh  = netip.MustParsePrefix("10.42.0.0/16")
	exemptTestBlock = netip.MustParsePrefix("169.254.243.96/30")
	exemptTestAddr  = netip.MustParsePrefix("169.254.243.97/30")
	exemptNextBlock = netip.MustParsePrefix("169.254.243.100/30")
	exemptNextAddr  = netip.MustParsePrefix("169.254.243.101/30")

	// exemptNewScript creates the object of exemptTestIface for its first
	// block.
	exemptNewScript = "New-NetNat -Name plexd-exempt-wg-s2s-a0a0a0e1 -InternalIPInterfaceAddressPrefix 169.254.243.96/30 | Out-Null"
	// exemptRemoveScript removes the object of exemptTestIface and takes an
	// absent one for a success.
	exemptRemoveScript = psAbsentOK + "Remove-NetNat -Name plexd-exempt-wg-s2s-a0a0a0e1 -Confirm:$false" + psAbsentOKEnd
	// exemptResetScript removes every exemption object.
	exemptResetScript = "Get-NetNat | Where-Object { $_.Name -like 'plexd-exempt-*' } | Remove-NetNat -Confirm:$false"
)

// addressCall records one call of the addAddress or removeAddress seam and
// how many PowerShell commands had run before it, so a test sees the order of
// the address and the object.
type addressCall struct {
	luid    uint64
	prefix  netip.Prefix
	scripts int
}

// exemptFixture is a controller on the mesh interface plexd0, whose prefix is
// 10.42.0.0/16, with every seam of an exemption recorded or faked. The host
// carries the addresses in host, and the seams fail with the errors a test
// sets.
type exemptFixture struct {
	ctrl   *WFPController
	runner *recordingRunner
	logs   *bytes.Buffer

	host      []netip.Prefix
	hostErr   error
	addErr    error
	removeErr error

	added, removed []addressCall
}

func newExemptFixture(t *testing.T) *exemptFixture {
	t.Helper()

	ctrl, _, runner := newTestWFPController(t)
	f := &exemptFixture{
		ctrl:   ctrl,
		runner: runner,
		logs:   &bytes.Buffer{},
		host: []netip.Prefix{
			netip.MustParsePrefix("10.42.0.1/16"),
			netip.MustParsePrefix("192.168.1.20/24"),
			netip.MustParsePrefix("127.0.0.1/8"),
		},
	}
	ctrl.logger = slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctrl.meshPrefix = func(name string) (netip.Prefix, error) {
		if name != "plexd0" {
			return netip.Prefix{}, fmt.Errorf("interface %q has no IPv4 address", name)
		}
		return exemptTestMesh, nil
	}
	lookup := ctrl.lookupIface
	ctrl.lookupIface = func(name string) (ifaceIDs, error) {
		if name == exemptTestIface {
			return ifaceIDs{index: 31, luid: exemptTestLUID}, nil
		}
		return lookup(name)
	}
	ctrl.addAddress = func(luid uint64, prefix netip.Prefix) error {
		f.added = append(f.added, addressCall{luid: luid, prefix: prefix, scripts: len(runner.callsFor(powershellPath()))})
		return f.addErr
	}
	ctrl.removeAddress = func(luid uint64, prefix netip.Prefix) error {
		f.removed = append(f.removed, addressCall{luid: luid, prefix: prefix, scripts: len(runner.callsFor(powershellPath()))})
		return f.removeErr
	}
	ctrl.hostPrefixes = func() ([]netip.Prefix, error) {
		return f.host, f.hostErr
	}
	return f
}

// list makes the list script print one line per object, in CRLF as
// PowerShell ends its lines.
func (f *exemptFixture) list(objects ...string) {
	if len(objects) == 0 {
		f.runner.outputs[psKey(psListNetNat)] = nil
		return
	}
	f.runner.outputs[psKey(psListNetNat)] = []byte(strings.Join(objects, "\r\n") + "\r\n")
}

// checkAddresses asserts the address calls by LUID and prefix, in order.
func checkAddresses(t *testing.T, what string, got []addressCall, want ...netip.Prefix) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s calls = %+v, want %v", what, got, want)
	}
	for i := range got {
		if got[i].luid != exemptTestLUID || got[i].prefix != want[i] {
			t.Errorf("%s call %d = LUID %d, %s, want LUID %d, %s", what, i, got[i].luid, got[i].prefix, exemptTestLUID, want[i])
		}
	}
}

// checkNotExempted asserts that no line of the log reports an exemption.
func (f *exemptFixture) checkNotExempted(t *testing.T) {
	t.Helper()

	if strings.Contains(f.logs.String(), "tunnel exempted from NAT") {
		t.Errorf("logged an exemption that did not happen:\n%s", f.logs.String())
	}
}

func TestExemptBlock(t *testing.T) {
	for _, tt := range []struct {
		n    uint32
		want string
	}{
		{0, "169.254.1.0/30"},
		{1, "169.254.1.4/30"},
		{63, "169.254.1.252/30"},
		{64, "169.254.2.0/30"},
		{15512, "169.254.243.96/30"},
		{16127, "169.254.252.252/30"},
	} {
		if got := exemptBlock(tt.n); got.String() != tt.want {
			t.Errorf("exemptBlock(%d) = %s, want %s", tt.n, got, tt.want)
		}
	}

	// The start of the search is the 32-bit FNV-1a hash of the name modulo
	// 16128. The second name is the tunnel of TestMeshSourceRewrite_RealWintun.
	for _, tt := range []struct {
		iface string
		n     uint32
		block string
	}{
		{exemptTestIface, 15512, "169.254.243.96/30"},
		{"wg-s2s-0000c1c1", 239, "169.254.4.188/30"},
	} {
		n := exemptBlockStart(tt.iface)
		if n != tt.n {
			t.Errorf("exemptBlockStart(%q) = %d, want %d", tt.iface, n, tt.n)
		}
		if got := exemptBlock(n); got.String() != tt.block {
			t.Errorf("first block of %q = %s, want %s", tt.iface, got, tt.block)
		}
	}
}

func TestParseNetNatList(t *testing.T) {
	out := []byte("plexd|10.42.0.0/16\r\n\r\nplexd-exempt-wg-s2s-a0a0a0e1|169.254.243.96/30\r\nlegacy|\r\nno separator\r\n")

	got := parseNetNatList(out)
	want := []netNatObject{
		{name: "plexd", prefix: exemptTestMesh},
		{name: "plexd-exempt-wg-s2s-a0a0a0e1", prefix: exemptTestBlock},
		{name: "legacy"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseNetNatList() = %+v, want %+v", got, want)
	}
}

// Without an object outside plexd-exempt-* that covers the mesh prefix there
// is no bridge NAT, and an object for the link's prefix alone would break the
// replies to what a mesh node opens toward the site. So nothing may be
// created, and the list is all that runs.
func TestNATExempt_NoBridgeNAT(t *testing.T) {
	for _, tt := range []struct {
		name    string
		objects []string
	}{
		{"no object", nil},
		{"another prefix", []string{"nat|172.20.0.0/16"}},
		{"only an exemption covers the mesh", []string{"plexd-exempt-wg-s2s-b0b0b0e1|10.42.0.0/16"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newExemptFixture(t)
			f.list(tt.objects...)

			if err := f.ctrl.ExemptFromNAT(exemptTestIface); err != nil {
				t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
			}

			checkNATCalls(t, f.runner, psListNetNat)
			checkAddresses(t, "addAddress", f.added)
			checkAddresses(t, "removeAddress", f.removed)
			f.checkNotExempted(t)
		})
	}
}

func TestNATExempt_Creates(t *testing.T) {
	for _, tt := range []struct {
		name    string
		objects []string
	}{
		{"plexd's object", []string{"plexd|10.42.0.0/16"}},
		{"an object that covers the mesh prefix", []string{"nat|172.20.0.0/16", "wide|10.0.0.0/8"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newExemptFixture(t)
			f.list(tt.objects...)

			if err := f.ctrl.ExemptFromNAT(exemptTestIface); err != nil {
				t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
			}

			checkNATCalls(t, f.runner, psListNetNat, exemptNewScript)
			checkAddresses(t, "addAddress", f.added, exemptTestAddr)
			checkAddresses(t, "removeAddress", f.removed)
			// The address is on the link before the object names its
			// prefix.
			if f.added[0].scripts != 1 {
				t.Errorf("addAddress ran after %d PowerShell commands, want 1, the list alone", f.added[0].scripts)
			}

			want := `level=INFO msg="tunnel exempted from NAT" component=bridge interface=wg-s2s-a0a0a0e1 prefix=169.254.243.96/30 nat=plexd-exempt-wg-s2s-a0a0a0e1`
			if !strings.Contains(f.logs.String(), want) {
				t.Errorf("log = %q, want a line holding %q", f.logs.String(), want)
			}
		})
	}
}

// A block another object or an address of the host overlaps would put two
// adapters on one prefix, so the search goes on to the next one.
func TestNATExempt_TakesNextBlock(t *testing.T) {
	for _, tt := range []struct {
		name    string
		objects []string
		host    []netip.Prefix
	}{
		{
			name:    "another tunnel's object",
			objects: []string{"plexd|10.42.0.0/16", "plexd-exempt-wg-s2s-b0b0b0e1|169.254.243.96/30"},
		},
		{
			name:    "an object inside the block",
			objects: []string{"plexd|10.42.0.0/16", "other|169.254.243.98/31"},
		},
		{
			name:    "a host address on the block",
			objects: []string{"plexd|10.42.0.0/16"},
			host:    []netip.Prefix{netip.MustParsePrefix("169.254.243.97/30")},
		},
		{
			name:    "a host address inside the block",
			objects: []string{"plexd|10.42.0.0/16"},
			host:    []netip.Prefix{netip.MustParsePrefix("169.254.243.99/32")},
		},
		{
			name:    "an autoconfiguration address inside the block",
			objects: []string{"plexd|10.42.0.0/16"},
			host:    []netip.Prefix{netip.MustParsePrefix("169.254.243.98/16")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newExemptFixture(t)
			f.list(tt.objects...)
			f.host = append(f.host, tt.host...)

			if err := f.ctrl.ExemptFromNAT(exemptTestIface); err != nil {
				t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
			}

			checkNATCalls(t, f.runner, psListNetNat,
				"New-NetNat -Name plexd-exempt-wg-s2s-a0a0a0e1 -InternalIPInterfaceAddressPrefix 169.254.243.100/30 | Out-Null")
			checkAddresses(t, "addAddress", f.added, exemptNextAddr)
			checkAddresses(t, "removeAddress", f.removed)
			if !strings.Contains(f.logs.String(), "prefix="+exemptNextBlock.String()) {
				t.Errorf("log = %q, want the exemption with %s", f.logs.String(), exemptNextBlock)
			}
		})
	}
}

// An autoconfiguration address is on-link to all of 169.254.0.0/16, the
// address Windows gives a tunnel's link before it carries one of its own.
// Read as its prefix it would overlap every block, so it rules out only the
// block that holds it.
func TestNATExempt_AutoconfigurationAddressOutsideTheBlock(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	f.host = append(f.host, netip.MustParsePrefix("169.254.12.34/16"))

	if err := f.ctrl.ExemptFromNAT(exemptTestIface); err != nil {
		t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
	}

	checkNATCalls(t, f.runner, psListNetNat, exemptNewScript)
	checkAddresses(t, "addAddress", f.added, exemptTestAddr)
}

// The search goes on from the last block to the first.
func TestNATExempt_WrapsAround(t *testing.T) {
	f := newExemptFixture(t)
	// Every block from 169.254.128.0 on is taken, the first block of the name
	// among them.
	f.list("plexd|10.42.0.0/16", "upper|169.254.128.0/17")

	if err := f.ctrl.ExemptFromNAT(exemptTestIface); err != nil {
		t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
	}

	checkNATCalls(t, f.runner, psListNetNat,
		"New-NetNat -Name plexd-exempt-wg-s2s-a0a0a0e1 -InternalIPInterfaceAddressPrefix 169.254.1.0/30 | Out-Null")
	checkAddresses(t, "addAddress", f.added, netip.MustParsePrefix("169.254.1.1/30"))
}

func TestNATExempt_NoFreeBlock(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16", "linklocal|169.254.0.0/16")

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: no free 169.254 /30`
	if err == nil || err.Error() != want {
		t.Fatalf("ExemptFromNAT() error = %v, want %q", err, want)
	}

	checkNATCalls(t, f.runner, psListNetNat)
	checkAddresses(t, "addAddress", f.added)
	f.checkNotExempted(t)
}

// An object of the link already exempts it. Its address is on the link since
// the object was made, so nothing is added and nothing is made again.
func TestNATExempt_AlreadyExempted(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16", "plexd-exempt-wg-s2s-a0a0a0e1|169.254.243.96/30")

	if err := f.ctrl.ExemptFromNAT(exemptTestIface); err != nil {
		t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
	}

	checkNATCalls(t, f.runner, psListNetNat)
	checkAddresses(t, "addAddress", f.added)
	checkAddresses(t, "removeAddress", f.removed)
	f.checkNotExempted(t)
}

// The name becomes PowerShell text, so a name outside the set a link's name
// is made of is refused before anything runs.
func TestNATExempt_InvalidName(t *testing.T) {
	for _, name := range []string{"", "wg-s2s-a0a0a0e10", `x'; Remove-Item C:\`} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			f := newExemptFixture(t)
			f.list("plexd|10.42.0.0/16")

			err := f.ctrl.ExemptFromNAT(name)
			want := fmt.Sprintf("bridge: exempt %q from NAT: invalid interface name", name)
			if err == nil || err.Error() != want {
				t.Errorf("ExemptFromNAT() error = %v, want %q", err, want)
			}

			err = f.ctrl.UnexemptFromNAT(name)
			want = fmt.Sprintf("bridge: unexempt %q from NAT: invalid interface name", name)
			if err == nil || err.Error() != want {
				t.Errorf("UnexemptFromNAT() error = %v, want %q", err, want)
			}

			checkNATCalls(t, f.runner)
			checkAddresses(t, "addAddress", f.added)
			checkAddresses(t, "removeAddress", f.removed)
		})
	}
}

func TestNATExempt_ListFails(t *testing.T) {
	f := newExemptFixture(t)
	f.runner.outputs[psKey(psListNetNat)] = []byte("Get-NetNat : Access is denied.")
	f.runner.errs[psKey(psListNetNat)] = errors.New("exit status 1")

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := fmt.Sprintf(`bridge: exempt "wg-s2s-a0a0a0e1" from NAT: powershell -Command %q: exit status 1: Get-NetNat : Access is denied.`, psListNetNat)
	if err == nil || err.Error() != want {
		t.Fatalf("ExemptFromNAT() error = %v, want %q", err, want)
	}

	checkNATCalls(t, f.runner, psListNetNat)
	checkAddresses(t, "addAddress", f.added)
	f.checkNotExempted(t)
}

func TestNATExempt_MeshPrefixFails(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	cause := errors.New("interface \"plexd0\" has no IPv4 address")
	f.ctrl.meshPrefix = func(string) (netip.Prefix, error) { return netip.Prefix{}, cause }

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: resolve mesh prefix for "plexd0": ` + cause.Error()
	if err == nil || err.Error() != want || !errors.Is(err, cause) {
		t.Fatalf("ExemptFromNAT() error = %v, want %q wrapping the cause", err, want)
	}

	// Without the mesh prefix nothing tells whether a bridge NAT exists, so
	// no command runs.
	checkNATCalls(t, f.runner)
	checkAddresses(t, "addAddress", f.added)
}

func TestNATExempt_HostPrefixesFails(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	f.hostErr = errors.New("GetUnicastIpAddressTable: not enough memory")

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: read the host's addresses: ` + f.hostErr.Error()
	if err == nil || err.Error() != want || !errors.Is(err, f.hostErr) {
		t.Fatalf("ExemptFromNAT() error = %v, want %q wrapping the cause", err, want)
	}

	checkNATCalls(t, f.runner, psListNetNat)
	checkAddresses(t, "addAddress", f.added)
}

func TestNATExempt_AddFails(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	f.addErr = windows.ERROR_ACCESS_DENIED

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: add 169.254.243.97/30: `
	if err == nil || !strings.HasPrefix(err.Error(), want) || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("ExemptFromNAT() error = %v, want one starting with %q wrapping ERROR_ACCESS_DENIED", err, want)
	}

	// An object without the address on the link would exempt nothing.
	checkNATCalls(t, f.runner, psListNetNat)
	checkAddresses(t, "addAddress", f.added, exemptTestAddr)
	checkAddresses(t, "removeAddress", f.removed)
	f.checkNotExempted(t)
}

func TestNATExempt_LookupFails(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	cause := errors.New("no such network interface")
	f.ctrl.lookupIface = func(string) (ifaceIDs, error) { return ifaceIDs{}, cause }

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: add 169.254.243.97/30: no such network interface`
	if err == nil || err.Error() != want || !errors.Is(err, cause) {
		t.Fatalf("ExemptFromNAT() error = %v, want %q wrapping the cause", err, want)
	}

	checkNATCalls(t, f.runner, psListNetNat)
	checkAddresses(t, "addAddress", f.added)
}

// A host that takes no further object, a client edition among them, refuses
// New-NetNat. The address alone exempts nothing, so it goes again, and the
// error names the way out.
func TestNATExempt_NewNetNatFails(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	f.runner.outputs[psKey(exemptNewScript)] = []byte("Windows System Error 52,New-NetNat")
	f.runner.errs[psKey(exemptNewScript)] = errors.New("exit status 1")

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	want := fmt.Sprintf(`bridge: exempt "wg-s2s-a0a0a0e1" from NAT: powershell -Command %q: exit status 1: Windows System Error 52,New-NetNat`+
		" (a NetNat object covers the mesh prefix 10.42.0.0/16 and this host took no further one; bridge.enable_nat: false serves tunnels without bridge NAT)",
		exemptNewScript)
	if err == nil || err.Error() != want {
		t.Fatalf("ExemptFromNAT() error = %v, want %q", err, want)
	}

	checkNATCalls(t, f.runner, psListNetNat, exemptNewScript)
	checkAddresses(t, "addAddress", f.added, exemptTestAddr)
	checkAddresses(t, "removeAddress", f.removed, exemptTestAddr)
	if f.removed[0].scripts != 2 {
		t.Errorf("removeAddress ran after %d PowerShell commands, want 2, after the failed New-NetNat", f.removed[0].scripts)
	}
	f.checkNotExempted(t)
}

// A removal that fails as well is reported beside the cause, which stays the
// error's first line.
func TestNATExempt_NewNetNatAndRemovalFail(t *testing.T) {
	f := newExemptFixture(t)
	f.list("plexd|10.42.0.0/16")
	f.runner.outputs[psKey(exemptNewScript)] = []byte("Windows System Error 52,New-NetNat")
	f.runner.errs[psKey(exemptNewScript)] = errors.New("exit status 1")
	f.removeErr = windows.ERROR_NOT_FOUND

	err := f.ctrl.ExemptFromNAT(exemptTestIface)
	if err == nil {
		t.Fatal("ExemptFromNAT() error = nil, want the failed New-NetNat")
	}
	first, rest, _ := strings.Cut(err.Error(), "\n")
	if !strings.HasSuffix(first, "bridge.enable_nat: false serves tunnels without bridge NAT)") {
		t.Errorf("first line of the error = %q, want the failed New-NetNat and its hint", first)
	}
	wantRest := `bridge: exempt "wg-s2s-a0a0a0e1" from NAT: remove 169.254.243.97/30: `
	if !strings.HasPrefix(rest, wantRest) || !errors.Is(err, windows.ERROR_NOT_FOUND) {
		t.Errorf("rest of the error = %q, want one starting with %q wrapping the cause", rest, wantRest)
	}
}

func TestNATUnexempt_Removes(t *testing.T) {
	f := newExemptFixture(t)

	// The script swallows the absent case, so a link without an object
	// succeeds with no output, which is what an unmapped command returns.
	if err := f.ctrl.UnexemptFromNAT(exemptTestIface); err != nil {
		t.Fatalf("UnexemptFromNAT() error = %v, want nil", err)
	}

	checkNATCalls(t, f.runner, exemptRemoveScript)
	checkAddresses(t, "removeAddress", f.removed)
	want := `level=DEBUG msg="NAT exemption removed" component=bridge interface=wg-s2s-a0a0a0e1 nat=plexd-exempt-wg-s2s-a0a0a0e1`
	if !strings.Contains(f.logs.String(), want) {
		t.Errorf("log = %q, want a line holding %q", f.logs.String(), want)
	}
}

func TestNATUnexempt_Fails(t *testing.T) {
	f := newExemptFixture(t)
	f.runner.outputs[psKey(exemptRemoveScript)] = []byte("Remove-NetNat : Access is denied.")
	f.runner.errs[psKey(exemptRemoveScript)] = errors.New("exit status 1")

	err := f.ctrl.UnexemptFromNAT(exemptTestIface)
	want := fmt.Sprintf(`bridge: unexempt "wg-s2s-a0a0a0e1" from NAT: powershell -Command %q: exit status 1: Remove-NetNat : Access is denied.`, exemptRemoveScript)
	if err == nil || err.Error() != want {
		t.Fatalf("UnexemptFromNAT() error = %v, want %q", err, want)
	}

	checkNATCalls(t, f.runner, exemptRemoveScript)
	if strings.Contains(f.logs.String(), "NAT exemption removed") {
		t.Errorf("logged a removal that failed:\n%s", f.logs.String())
	}
}

func TestNATReset(t *testing.T) {
	f := newExemptFixture(t)

	if err := f.ctrl.ResetNATExemptions(); err != nil {
		t.Fatalf("ResetNATExemptions() error = %v, want nil", err)
	}

	checkNATCalls(t, f.runner, exemptResetScript)
	want := `level=DEBUG msg="NAT exemptions reset" component=bridge`
	if !strings.Contains(f.logs.String(), want) {
		t.Errorf("log = %q, want a line holding %q", f.logs.String(), want)
	}
}

func TestNATReset_Fails(t *testing.T) {
	f := newExemptFixture(t)
	f.runner.outputs[psKey(exemptResetScript)] = []byte("Remove-NetNat : Access is denied.")
	f.runner.errs[psKey(exemptResetScript)] = errors.New("exit status 1")

	err := f.ctrl.ResetNATExemptions()
	want := fmt.Sprintf(`bridge: reset NAT exemptions: powershell -Command %q: exit status 1: Remove-NetNat : Access is denied.`, exemptResetScript)
	if err == nil || err.Error() != want {
		t.Fatalf("ResetNATExemptions() error = %v, want %q", err, want)
	}

	checkNATCalls(t, f.runner, exemptResetScript)
}

// The adapters and objects of TestWFPController_RealNATExemption. The mesh
// adapter carries exemptRealMesh and is the controller's mesh interface. The
// link stands for a tunnel's link and carries no address, as a tunnel's link
// on Windows does. The test makes exemptRealLeftover, as a killed process
// would leave it, and exemptRealKeep, whose name no reset may touch. No other
// test uses 10.255.243.0/24.
const (
	exemptRealMeshAdapter = "plexd-exmesh"
	exemptRealLink        = "plexd-exlink"
	exemptRealLeftover    = "plexd-exempt-leftover"
	exemptRealKeep        = "plexd-test-keep"
)

var (
	exemptRealMesh           = netip.MustParsePrefix("10.255.243.1/24")
	exemptRealLeftoverPrefix = netip.MustParsePrefix("10.255.243.248/30")
	exemptRealKeepPrefix     = netip.MustParsePrefix("10.255.243.252/30")
)

// newExemptTestAdapter creates a Wintun adapter and assigns it addr unless
// addr is the zero prefix. The adapter goes when the test ends, and the
// address with it.
func newExemptTestAdapter(t *testing.T, name string, addr netip.Prefix) winipcfg.LUID {
	t.Helper()

	dev, err := tun.CreateTUN(name, tunTestMTU)
	if err != nil {
		t.Fatalf("create the Wintun adapter %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := dev.Close(); err != nil {
			t.Errorf("close the Wintun adapter %s: %v", name, err)
		}
	})
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		t.Fatalf("tun.CreateTUN returned a %T, want a *tun.NativeTun", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	if addr.IsValid() {
		if err := luid.SetIPAddresses([]netip.Prefix{addr}); err != nil {
			t.Fatalf("assign %s to %s: %v", addr, name, err)
		}
	}
	return luid
}

// hostPowerShell runs script directly, as TestWFPController_RealNAT does,
// because the controller's own commands are what the test checks.
func hostPowerShell(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), powershellTimeout)
	defer cancel()
	out, err := execCommand(ctx, nil, powershellPath(), "-NoProfile", "-NonInteractive", "-Command", script)
	return strings.TrimSpace(string(out)), err
}

// hostNetNats returns the host's NetNat objects as the list script prints
// them, name|prefix, sorted.
func hostNetNats(t *testing.T) []string {
	t.Helper()

	out, err := hostPowerShell(psListNetNat)
	if err != nil {
		t.Fatalf("%s: %v\n%s", psListNetNat, err, out)
	}
	var objects []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			objects = append(objects, line)
		}
	}
	slices.Sort(objects)
	return objects
}

// netNatPrefix returns the prefix the object of that name translates.
func netNatPrefix(objects []string, name string) (string, bool) {
	for _, obj := range objects {
		if n, prefix, _ := strings.Cut(obj, "|"); n == name {
			return prefix, true
		}
	}
	return "", false
}

// adapterAddresses returns the IPv4 addresses of the adapter, each with its
// on-link prefix length.
func adapterAddresses(t *testing.T, luid winipcfg.LUID) []netip.Prefix {
	t.Helper()

	rows, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		t.Fatalf("read the host's IPv4 addresses: %v", err)
	}
	var addrs []netip.Prefix
	for i := range rows {
		if rows[i].InterfaceLUID == luid {
			addrs = append(addrs, netip.PrefixFrom(rows[i].Address.Addr(), int(rows[i].OnLinkPrefixLength)))
		}
	}
	return addrs
}

// exemptionAddresses returns the addresses of the adapter that an exemption
// adds, the 169.254 ones with length 30. An autoconfiguration address, which
// Windows may give the adapter meanwhile, has length 16.
func exemptionAddresses(t *testing.T, luid winipcfg.LUID) []netip.Prefix {
	t.Helper()

	var addrs []netip.Prefix
	for _, p := range adapterAddresses(t, luid) {
		if p.Bits() == 30 && linkLocalV4.Contains(p.Addr()) {
			addrs = append(addrs, p)
		}
	}
	return addrs
}

// TestWFPController_RealNATExemption drives the host's WinNAT with two Wintun
// adapters of its own: a mesh adapter on 10.255.243.0/24, the object
// AddNATMasquerade makes for it, and the exemption of a link beside it. It
// creates and removes NetNat objects, which needs Administrator, and every
// object and adapter it made goes when it ends, also when it fails.
func TestWFPController_RealNATExemption(t *testing.T) {
	// Gated like TestWFPController_RealNAT: the CI runner is already
	// elevated, and without the variable the ordinary test step would create
	// adapters and NetNat objects.
	if os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WFP=1 in an elevated shell to program the filter engine")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter and a NetNat object need Administrator")
	}

	// The test removes the objects of its names when it ends, so it must not
	// find one it did not make, nor one that already covers its mesh prefix.
	before := hostNetNats(t)
	t.Logf("NetNat objects before the test: %q", before)
	for _, obj := range before {
		name, prefix, _ := strings.Cut(obj, "|")
		if name == netNatName || strings.HasPrefix(name, netNatExemptPrefix) || name == exemptRealKeep {
			t.Fatalf("the host already holds the NetNat object %q, which the test would remove", obj)
		}
		if p, err := netip.ParsePrefix(prefix); err == nil && p.Overlaps(exemptRealMesh.Masked()) {
			t.Fatalf("the host already holds the NetNat object %q, which covers the test's mesh prefix", obj)
		}
	}

	// The Wintun loader looks for its DLL beside the executable.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("path of the test binary: %v", err)
	}
	if _, _, err := wintundll.Ensure(filepath.Dir(exe)); err != nil {
		t.Fatalf("write wintun.dll beside the test binary: %v", err)
	}
	newExemptTestAdapter(t, exemptRealMeshAdapter, exemptRealMesh)
	link := newExemptTestAdapter(t, exemptRealLink, netip.Prefix{})

	// Registered after the adapters, so the objects go before the adapters
	// do. Every script takes an absent object for a success, so a check that
	// removed an object already leaves the cleanup nothing to do.
	t.Cleanup(func() {
		for _, script := range []string{
			psRemoveNetNat,
			psRemoveNetNatExempt(exemptRealLink),
			psAbsentOK + "Remove-NetNat -Name " + exemptRealLeftover + " -Confirm:$false" + psAbsentOKEnd,
			psAbsentOK + "Remove-NetNat -Name " + exemptRealKeep + " -Confirm:$false" + psAbsentOKEnd,
		} {
			if out, err := hostPowerShell(script); err != nil {
				t.Errorf("cleanup %s: %v\n%s", script, err, out)
			}
		}
	})

	ctrl := NewWFPController(tunTestLogger(t), exemptRealMeshAdapter)
	t.Logf("%s carries %v", exemptRealLink, adapterAddresses(t, link))

	t.Log("without an object for the mesh prefix there is no bridge NAT, and ExemptFromNAT creates nothing")
	if err := ctrl.ExemptFromNAT(exemptRealLink); err != nil {
		t.Fatalf("ExemptFromNAT() without the bridge NAT: error = %v, want nil", err)
	}
	if got := hostNetNats(t); !slices.Equal(got, before) {
		t.Errorf("NetNat objects after ExemptFromNAT without the bridge NAT = %q, want them unchanged, %q", got, before)
	}
	if got := exemptionAddresses(t, link); len(got) != 0 {
		t.Errorf("%s carries %v after ExemptFromNAT without the bridge NAT, want no 169.254 /30", exemptRealLink, got)
	}

	t.Log("beside the object for the mesh prefix, ExemptFromNAT creates one for a 169.254 /30 the link carries")
	if err := ctrl.AddNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("AddNATMasquerade() error = %v, want nil", err)
	}
	withMesh := hostNetNats(t)
	if prefix, ok := netNatPrefix(withMesh, netNatName); !ok || prefix != "10.255.243.0/24" {
		t.Fatalf("NetNat objects after AddNATMasquerade = %q, want %s for 10.255.243.0/24", withMesh, netNatName)
	}

	if err := ctrl.ExemptFromNAT(exemptRealLink); err != nil {
		t.Fatalf("ExemptFromNAT() error = %v, want nil", err)
	}
	exempted := hostNetNats(t)
	name := netNatExemptName(exemptRealLink)
	text, ok := netNatPrefix(exempted, name)
	if !ok {
		t.Fatalf("NetNat objects after ExemptFromNAT = %q, want %s", exempted, name)
	}
	block, err := netip.ParsePrefix(text)
	if err != nil || block.Bits() != 30 || !linkLocalV4.Contains(block.Addr()) {
		t.Fatalf("%s translates %q, want a 169.254 /30", name, text)
	}
	if len(exempted) != len(withMesh)+1 {
		t.Errorf("NetNat objects after ExemptFromNAT = %q, want those of before, %q, and %s alone", exempted, withMesh, name)
	}
	if prefix, ok := netNatPrefix(exempted, netNatName); !ok || prefix != "10.255.243.0/24" {
		t.Errorf("NetNat objects after ExemptFromNAT = %q, want %s for 10.255.243.0/24 left in place", exempted, netNatName)
	}
	addrs := exemptionAddresses(t, link)
	if want := netip.PrefixFrom(block.Addr().Next(), 30); !slices.Equal(addrs, []netip.Prefix{want}) {
		t.Errorf("%s carries %v after ExemptFromNAT, want %s", exemptRealLink, adapterAddresses(t, link), want)
	}
	t.Logf("%s exempted with %s, carries %v", exemptRealLink, block, adapterAddresses(t, link))

	t.Log("a second ExemptFromNAT changes nothing")
	if err := ctrl.ExemptFromNAT(exemptRealLink); err != nil {
		t.Fatalf("second ExemptFromNAT() error = %v, want nil", err)
	}
	if got := hostNetNats(t); !slices.Equal(got, exempted) {
		t.Errorf("NetNat objects after the second ExemptFromNAT = %q, want them unchanged, %q", got, exempted)
	}
	if got := exemptionAddresses(t, link); !slices.Equal(got, addrs) {
		t.Errorf("%s carries %v after the second ExemptFromNAT, want %v", exemptRealLink, got, addrs)
	}

	t.Log("UnexemptFromNAT removes the object, and a second call finds none")
	if err := ctrl.UnexemptFromNAT(exemptRealLink); err != nil {
		t.Fatalf("UnexemptFromNAT() error = %v, want nil", err)
	}
	if got := hostNetNats(t); !slices.Equal(got, withMesh) {
		t.Errorf("NetNat objects after UnexemptFromNAT = %q, want %q", got, withMesh)
	}
	if err := ctrl.UnexemptFromNAT(exemptRealLink); err != nil {
		t.Errorf("second UnexemptFromNAT() error = %v, want nil", err)
	}
	if err := ctrl.RemoveNATMasquerade("Ethernet"); err != nil {
		t.Fatalf("RemoveNATMasquerade() error = %v, want nil", err)
	}

	t.Log("ResetNATExemptions removes an exemption a killed process left and no object of another name")
	keepScript := "New-NetNat -Name " + exemptRealKeep + " -InternalIPInterfaceAddressPrefix " + exemptRealKeepPrefix.String() + " | Out-Null"
	if out, err := hostPowerShell(keepScript); err != nil {
		t.Fatalf("%s: %v\n%s", keepScript, err, out)
	}
	keep := exemptRealKeep + "|" + exemptRealKeepPrefix.String()
	// Without an exemption object the reset hands Remove-NetNat no input,
	// which must remove nothing.
	if err := ctrl.ResetNATExemptions(); err != nil {
		t.Fatalf("ResetNATExemptions() without an exemption: error = %v, want nil", err)
	}
	if got := hostNetNats(t); !slices.Contains(got, keep) {
		t.Errorf("NetNat objects after ResetNATExemptions without an exemption = %q, want %q left in place", got, keep)
	}

	leftoverScript := "New-NetNat -Name " + exemptRealLeftover + " -InternalIPInterfaceAddressPrefix " + exemptRealLeftoverPrefix.String() + " | Out-Null"
	if out, err := hostPowerShell(leftoverScript); err != nil {
		t.Fatalf("%s: %v\n%s", leftoverScript, err, out)
	}
	if err := ctrl.ResetNATExemptions(); err != nil {
		t.Fatalf("ResetNATExemptions() error = %v, want nil", err)
	}
	after := hostNetNats(t)
	if _, ok := netNatPrefix(after, exemptRealLeftover); ok {
		t.Errorf("NetNat objects after ResetNATExemptions = %q, want %s removed", after, exemptRealLeftover)
	}
	if !slices.Contains(after, keep) {
		t.Errorf("NetNat objects after ResetNATExemptions = %q, want %q left in place", after, keep)
	}
}
