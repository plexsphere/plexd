//go:build darwin

package policy

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// TestPFController_RealTraffic drives the host's pf with traffic through a
// utun the test creates. Its rules name that utun alone, so nothing else on
// the machine running the test is filtered.
func TestPFController_RealTraffic(t *testing.T) {
	// Gated like TestPFController_Real: sudo go test ./... on a developer's
	// Mac should not enable pf and load an anchor unasked.
	if os.Getenv("PLEXD_TEST_REAL_PF") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PF=1 to load a real pf anchor")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and loading a pf anchor need root; run with sudo")
	}

	// "utun" asks for the next free unit.
	dev, err := tun.CreateTUN("utun", tunTestMTU)
	if err != nil {
		t.Fatalf("create a utun: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	name, err := dev.Name()
	if err != nil {
		t.Fatalf("name of the utun: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{name, "inet", tunNodeAddr.String(), tunPeerAddr.String(), "up"}
	if out, err := execCommand(ctx, nil, "/sbin/ifconfig", args...); err != nil {
		t.Fatalf("/sbin/ifconfig %v: %v\n%s", args, err, out)
	}

	// wireguard-go's utun writes the address family in front of each
	// packet, so a buffer needs room for it.
	runTunTrafficChecks(t, tunHarness{
		ctrl:   NewPFController(testLogger()),
		dev:    dev,
		offset: 4,
		iface:  name,
	})
}
