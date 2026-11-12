//go:build linux

package policy

import (
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// tunUDPLogsEveryPacket tells runTunConnLogChecks that NFLOG reports a UDP
// flow once: after its first reply, conntrack sees its later datagrams as
// established, which the log rule's ct state new does not match.
const tunUDPLogsEveryPacket = false

// newTunTestHarness creates a fresh network namespace N with a TUN device
// that carries N's address, and an nftables controller whose calls run in N.
// The device, its address and every rule live in N, never in the host's
// namespace, which may run a live plexd0.
func newTunTestHarness(t *testing.T) tunHarness {
	t.Helper()

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
	return tunHarness{
		ctrl:   NewNftablesController(tunTestLogger(t)),
		dev:    dev,
		offset: 16,
		iface:  "plexdtun0",
		do:     n.do,
	}
}

// TestNftablesController_RealTraffic runs the traffic checks the macOS and
// Windows backends run, through a TUN device in a fresh network namespace N.
func TestNftablesController_RealTraffic(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_NFTABLES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_NFTABLES=1 to load real nftables rules in test network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating network namespaces and loading nftables rules needs root; run with sudo")
	}

	runTunTrafficChecks(t, newTunTestHarness(t))
}

// TestNftablesController_RealConnLog runs the connection-log checks the macOS
// and Windows backends run, through a TUN device in a fresh network namespace
// N. The controller's NFLOG reader opens in N, where ApplyRules runs, so it
// reads only what N's log rules send.
func TestNftablesController_RealConnLog(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_NFTABLES") != "1" {
		t.Skip("set PLEXD_TEST_REAL_NFTABLES=1 to load real nftables rules in test network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating network namespaces and loading nftables rules needs root; run with sudo")
	}

	runTunConnLogChecks(t, newTunTestHarness(t))
}
