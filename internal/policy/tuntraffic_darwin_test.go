//go:build darwin

package policy

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// tunUDPLogsEveryPacket tells runTunConnLogChecks that pf reports every UDP
// datagram its stateless lines pass, not only the first of a flow.
const tunUDPLogsEveryPacket = true

// newTunTestHarness creates a utun that carries N's address, with P's as its
// peer, and a pf controller. The rules the checks apply name that utun alone,
// so nothing else on the machine running the test is filtered.
func newTunTestHarness(t *testing.T) tunHarness {
	t.Helper()

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
	return tunHarness{
		ctrl:   NewPFController(tunTestLogger(t)),
		dev:    dev,
		offset: 4,
		iface:  name,
		// plexd's UDP lines keep no state, and pf logs every packet a
		// logged line without state passes.
	}
}

// TestPFController_RealTraffic drives the host's pf with traffic through a
// utun the test creates.
func TestPFController_RealTraffic(t *testing.T) {
	// Gated like TestPFController_Real: sudo go test ./... on a developer's
	// Mac should not enable pf and load an anchor unasked.
	if os.Getenv("PLEXD_TEST_REAL_PF") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PF=1 to load a real pf anchor")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and loading a pf anchor need root; run with sudo")
	}

	runTunTrafficChecks(t, newTunTestHarness(t))
}

// TestPFController_RealConnLog runs the connection-log checks through a utun
// the test creates, which the controller reads from pflog0 through a BPF
// device. A connection reported under the right tag also proves that the
// number the controller gives a logged line is the one pf logs it under: a
// wrong number reports the connection under another rule's tag, or not at
// all.
func TestPFController_RealConnLog(t *testing.T) {
	// Gated like TestPFController_Real: sudo go test ./... on a developer's
	// Mac should not enable pf and load an anchor unasked.
	if os.Getenv("PLEXD_TEST_REAL_PF") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PF=1 to load a real pf anchor")
	}
	if os.Geteuid() != 0 {
		t.Skip("creating a utun and loading a pf anchor need root; run with sudo")
	}

	// XNU creates no pflog instance at boot. Where an earlier run left
	// pflog0 behind, the check below shows less: that the controller found
	// it, not that it created it.
	_, err := net.InterfaceByName(pflogIface)
	t.Logf("%s exists before the first logged apply: %t", pflogIface, err == nil)

	h := newTunTestHarness(t)
	h.ctrl = pfLoggedApplyHook{
		PFController: h.ctrl.(*PFController),
		afterLogged: func() {
			if _, err := net.InterfaceByName(pflogIface); err != nil {
				t.Errorf("after an apply with a logged rule: %s: %v, want the interface the controller reads", pflogIface, err)
			}
		},
	}
	runTunConnLogChecks(t, h)
}

// pfLoggedApplyHook calls afterLogged once each ApplyRules that holds a
// logged rule has succeeded, so a test can look at the host while the
// controller logs. Every other method is the PFController's own.
type pfLoggedApplyHook struct {
	*PFController
	afterLogged func()
}

func (c pfLoggedApplyHook) ApplyRules(chain string, rules []FirewallRule) error {
	if err := c.PFController.ApplyRules(chain, rules); err != nil {
		return err
	}
	if hasLogTags(rules) {
		c.afterLogged()
	}
	return nil
}
