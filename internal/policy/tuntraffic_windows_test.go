//go:build windows

package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/plexsphere/plexd/internal/wintundll"
)

// TestWFPController_RealTraffic drives the host's filter engine with traffic
// through a Wintun adapter the test creates. Its rules name that adapter
// alone, so nothing else on the machine running the test is filtered. The
// Windows Firewall blocks the unsolicited packets the test injects on its
// own, so the CI step turns its profiles off first.
func TestWFPController_RealTraffic(t *testing.T) {
	// Gated like TestWFPController_Real: the CI runner is already elevated,
	// and without the variable the ordinary test step would create an
	// adapter and install filters.
	if os.Getenv("PLEXD_TEST_REAL_WFP") != "1" {
		t.Skip("set PLEXD_TEST_REAL_WFP=1 in an elevated shell to program the filter engine")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a Wintun adapter and programming the filter engine need Administrator")
	}

	// The Wintun loader looks for its DLL beside the executable.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("path of the test binary: %v", err)
	}
	if _, _, err := wintundll.Ensure(filepath.Dir(exe)); err != nil {
		t.Fatalf("write wintun.dll beside the test binary: %v", err)
	}

	const name = "plexd-fwtest"
	dev, err := tun.CreateTUN(name, tunTestMTU)
	if err != nil {
		t.Fatalf("create the Wintun adapter %s: %v", name, err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		t.Fatalf("tun.CreateTUN returned a %T, want a *tun.NativeTun", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	if err := luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(tunNodeAddr, 30)}); err != nil {
		t.Fatalf("assign %s/30 to %s: %v", tunNodeAddr, name, err)
	}

	runTunTrafficChecks(t, tunHarness{
		ctrl:   NewWFPController(testLogger(), name),
		dev:    dev,
		offset: 0,
		iface:  name,
	})
}
