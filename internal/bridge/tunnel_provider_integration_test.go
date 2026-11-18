package bridge

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Integration tests — the tunnel providers under the site-to-site manager
// ---------------------------------------------------------------------------

// providerFixture is a SiteToSiteManager over the real IPsecProvider and
// OpenVPNProvider, which run their commands through one mock executor and
// keep their files in temporary directories.
type providerFixture struct {
	*s2sFixture
	runner  *mockCommandExecutor
	handle  *mockCommandHandle
	swanctl string
	tunnels string
}

// newProviderFixture builds the manager over the real providers and sets it
// up. swanctl --list-conns lists dc-east's connection.
func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	pf := &providerFixture{
		runner:  newMockCommandExecutor(),
		handle:  &mockCommandHandle{},
		swanctl: filepath.Join(t.TempDir(), "swanctl"),
		tunnels: filepath.Join(t.TempDir(), "tunnels"),
	}
	pf.runner.startHandle = pf.handle
	pf.runner.runOutputs["swanctl --list-conns"] = swanctlListConns(s2sID2)
	pf.s2sFixture = buildS2SFixture(t, func(d *SiteToSiteDeps) {
		d.Providers = map[string]TunnelProvider{
			api.SiteToSiteKindIPsec:   NewIPsecProvider(pf.runner, pf.swanctl, discardLogger()),
			api.SiteToSiteKindOpenVPN: NewOpenVPNProvider(pf.runner, pf.tunnels, discardLogger()),
		}
	})
	if err := pf.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return pf
}

// commands returns the command lines the executor ran.
func (pf *providerFixture) commands() [][]string {
	return callLines(pf.runner.allCalls())
}

// TestTunnelProviderIntegration_Lifecycle drives an ipsec and an openvpn
// tunnel through pulls of a real Reconciler: the providers write their files
// and run their commands under the links the manager created, and a tunnel
// the pull drops loses its files and its daemon's side.
func TestTunnelProviderIntegration_Lifecycle(t *testing.T) {
	pf := newProviderFixture(t)
	fetcher := &integrationStateFetcher{state: siteToSiteState(s2sInventory(), dcEast, office)}
	rec := runSiteToSiteReconciler(t, fetcher, pf.mgr)

	waitForCondition(t, 2*time.Second, func() bool {
		return tunnelHealth(pf.mgr, s2sID2) == api.SiteToSiteHealthUp && tunnelHealth(pf.mgr, s2sID3) == api.SiteToSiteHealthUp
	})

	conn, err := os.ReadFile(filepath.Join(pf.swanctl, "plexd-"+s2sID2+".conf"))
	if err != nil {
		t.Fatalf("read dc-east's connection file: %v", err)
	}
	for _, want := range []string{
		"remote_addrs = 203.0.113.10\n",
		"if_id_in = 2694881506\n",
		"local_ts = " + s2sMeshCIDR + "\n",
		"remote_ts = 10.30.0.0/16,10.31.0.0/16\n",
		"secret = 0x" + hex.EncodeToString([]byte(s2sIKEKey)) + "\n",
	} {
		if !strings.Contains(string(conn), want) {
			t.Errorf("connection file lacks %q:\n%s", want, conn)
		}
	}
	confPath := filepath.Join(pf.tunnels, "plexd-openvpn-"+s2sID3+".conf")
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read office's configuration: %v", err)
	}
	for _, want := range []string{"dev " + s2sTunIface + "\n", "remote vpn.office.example.com 1194\n"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("configuration lacks %q:\n%s", want, conf)
		}
	}
	key, err := os.ReadFile(filepath.Join(pf.tunnels, "plexd-openvpn-"+s2sID3+".key"))
	if err != nil || string(key) != openvpnTestKey+"\n" {
		t.Errorf("office's key file = %q, %v, want the static key", key, err)
	}
	wantCommands := [][]string{
		swanctlLoad,
		{"Run", "swanctl", "--list-conns"},
		{"Start", "openvpn", "--config", confPath},
	}
	if got := pf.commands(); !slices.EqualFunc(got, wantCommands, slices.Equal) {
		t.Errorf("commands =\n  %q\nwant\n  %q", got, wantCommands)
	}
	if got := pf.vpn.vpnMethods(); !slices.Equal(got, []string{"RemoveTunnelInterfaces", "CreateXfrmInterface", "CreateTunInterface"}) {
		t.Errorf("controller calls = %q, want the cleanup and the two links", got)
	}

	// dc-east leaves the pull: its file is gone, strongSwan loads it away
	// and its connection is terminated; office stays.
	pf.runner.mu.Lock()
	pf.runner.callList = nil
	pf.runner.mu.Unlock()
	fetcher.setState(siteToSiteState(s2sInventory(), office))
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return len(tunnelIDs(pf.mgr)) == 1
	})
	requireNoFile(t, filepath.Join(pf.swanctl, "plexd-"+s2sID2+".conf"))
	if got, want := pf.commands(), [][]string{swanctlLoad, swanctlTerminate(s2sID2)}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("commands = %q, want %q", got, want)
	}
	if pf.handle.stopCalls() != 0 {
		t.Errorf("openvpn stops = %d, want office left running", pf.handle.stopCalls())
	}

	// office leaves the pull: its process stops and its files are gone.
	fetcher.setState(siteToSiteState(s2sInventory()))
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return pf.handle.stopCalls() == 1
	})
	if got := dirNames(t, pf.tunnels); len(got) != 0 {
		t.Errorf("tunnel directory holds %q, want nothing", got)
	}
}

// TestTunnelProviderIntegration_ClientMissing serves an ipsec and an openvpn
// tunnel on a host without swanctl and openvpn: both read client_missing,
// leave no file and no link, and come up on a later pull once the clients
// are installed.
func TestTunnelProviderIntegration_ClientMissing(t *testing.T) {
	pf := newProviderFixture(t)
	pf.runner.runErrors["swanctl --load-all --clear --noprompt"] = &exec.Error{Name: "swanctl", Err: exec.ErrNotFound}
	pf.runner.startErr = &exec.Error{Name: "openvpn", Err: exec.ErrNotFound}
	fetcher := &integrationStateFetcher{state: siteToSiteState(s2sInventory(), dcEast, office)}
	rec := runSiteToSiteReconciler(t, fetcher, pf.mgr)

	waitForCondition(t, 2*time.Second, func() bool {
		return len(tunnelIDs(pf.mgr)) == 2
	})
	requireTunnelDown(t, pf.mgr, s2sID2, SiteToSiteReasonClientMissing)
	requireTunnelDown(t, pf.mgr, s2sID3, SiteToSiteReasonClientMissing)
	requireNoFile(t, filepath.Join(pf.swanctl, "plexd-"+s2sID2+".conf"))
	if got := dirNames(t, pf.tunnels); len(got) != 0 {
		t.Errorf("tunnel directory holds %q, want nothing", got)
	}
	var links []string
	for _, c := range pf.vpn.vpnCallsFor("RemoveTunnelInterface") {
		links = append(links, c.Args[0].(string))
	}
	if !slices.Equal(links, []string{s2sXfrmIface, s2sTunIface}) {
		t.Errorf("links removed = %q, want both links of the failed attempts", links)
	}

	// The clients are installed; the bridge block is the same.
	pf.runner.mu.Lock()
	delete(pf.runner.runErrors, "swanctl --load-all --clear --noprompt")
	pf.runner.startErr = nil
	pf.runner.mu.Unlock()
	pf.clock.Add(5 * time.Second)
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return tunnelHealth(pf.mgr, s2sID2) == api.SiteToSiteHealthUp && tunnelHealth(pf.mgr, s2sID3) == api.SiteToSiteHealthUp
	})
	if _, err := os.Stat(filepath.Join(pf.swanctl, "plexd-"+s2sID2+".conf")); err != nil {
		t.Errorf("dc-east's connection file: %v", err)
	}
	if err := pf.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if pf.handle.stopCalls() != 1 {
		t.Errorf("openvpn stops after Teardown = %d, want 1", pf.handle.stopCalls())
	}
}
