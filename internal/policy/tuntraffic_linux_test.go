//go:build linux

package policy

import (
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// TestNftablesController_RealTraffic runs the traffic checks the macOS and
// Windows backends run, through a TUN device in a fresh network namespace N.
// The device, its address and every rule live in N, never in the host's
// namespace, which may run a live plexd0.
func TestNftablesController_RealTraffic(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_NFTABLES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_NFTABLES=1 to load real nftables rules in test network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating network namespaces and loading nftables rules needs root; run with sudo")
	}

	n := newRealNetns(t, "N")

	// A TUN device belongs to the namespace of the thread that creates it.
	var dev tun.Device
	if err := n.do(func() error {
		var err error
		dev, err = tun.CreateTUN("plexdtun0", tunTestMTU)
		return err
	}); err != nil {
		t.Fatalf("namespace N: create the TUN device plexdtun0: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })

	n.addAddr(t, "plexdtun0", tunNodeAddr.String()+"/30")
	n.up(t, "lo", "plexdtun0")

	// wireguard-go's Linux device writes a virtio header in front of each
	// packet, so a buffer needs room for it.
	runTunTrafficChecks(t, tunHarness{
		ctrl:   NewNftablesController(testLogger()),
		dev:    dev,
		offset: 16,
		iface:  "plexdtun0",
		do:     n.do,
	})
}
