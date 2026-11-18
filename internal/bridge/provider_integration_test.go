// Integration tests — UserAccess with the vendor clients
package bridge

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// newVendorFixture returns a manager whose clients are the real Tailscale and
// NetBird clients over runner, set up, with the Secret value listed in its
// inventory as ts-join and nb-setup version 2.
func newVendorFixture(t *testing.T, runner *mockCommandExecutor, value string) *uaFixture {
	t.Helper()
	logger, _ := newRelayLogger()
	fx := newUAFixture(t, func(d *UserAccessDeps) {
		d.Clients = map[string]UserAccessClient{
			api.UserAccessKindTailscale: NewTailscaleProvider(runner, logger),
			api.UserAccessKindNetbird:   NewNetbirdProvider(runner, logger),
		}
	})
	fx.secrets.set("ts-join", 2, value)
	fx.secrets.set("nb-setup", 2, value)
	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "ts-join", Version: 2}, {Name: "nb-setup", Version: 2}})
	return fx
}

// TestProviderIntegration_Tailscale serves a tailscale provider through the
// real TailscaleProvider: the daemon runs under the manager's context, the
// join runs with the Secret's trimmed value and advertises the mesh CIDR, and
// Teardown leaves the tailnet and stops the daemon.
func TestProviderIntegration_Tailscale(t *testing.T) {
	runner := newMockCommandExecutor()
	handle := &mockCommandHandle{}
	runner.startHandle = handle
	runner.runOutputs[commandKey("tailscale", "status", "--json")] = []byte(`{"TailscaleIPs":["100.64.0.7"]}`)
	fx := newVendorFixture(t, runner, " tskey-auth-0123\n")

	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))

	if p := requireUp(t, fx.mgr, uaID2); p.Interface != "tailscale0" {
		t.Errorf("provider = %+v, want up on tailscale0", p)
	}
	calls := runner.allCalls()
	want := [][]string{
		{"Start", "tailscaled", "--state=mem:"},
		{"Run", "tailscale", "up", "--authkey=tskey-auth-0123", "--accept-routes", "--advertise-routes=" + uaMeshCIDR},
		{"Run", "tailscale", "status", "--json"},
	}
	if got := callLines(calls); !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Fatalf("commands =\n  %q\nwant\n  %q", got, want)
	}
	assertCallDeadline(t, calls[0], 0, 0)
	for _, c := range calls[1:] {
		assertCallDeadline(t, c, vendorJoinTimeout-5*time.Second, vendorJoinTimeout)
	}
	if c := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "tailscale0" {
		t.Errorf("AddMeshSourceRewrite calls = %+v, want tailscale0", c)
	}

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	calls = runner.allCalls()
	if last := callLines(calls[len(calls)-1:]); !slices.Equal(last[0], []string{"Run", "tailscale", "down"}) {
		t.Errorf("last command = %q, want tailscale down", last[0])
	}
	if handle.stopCalls() != 1 {
		t.Errorf("daemon stops = %d, want 1", handle.stopCalls())
	}
	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "tailscale0" {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want tailscale0", c)
	}
}

// TestProviderIntegration_Netbird serves a netbird provider through the real
// NetbirdProvider: it joins with the Secret's value and serves on the
// interface the client reports.
func TestProviderIntegration_Netbird(t *testing.T) {
	runner := newMockCommandExecutor()
	runner.runOutputs[commandKey("netbird", "status", "--json")] = []byte(`{"ip":"100.119.0.5/16","connected":true,"interface":{"name":"wt0"}}`)
	fx := newVendorFixture(t, runner, "nb-setup-key\n")

	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID3, "netbird", api.UserAccessKindNetbird, "nb-setup")))

	if p := requireUp(t, fx.mgr, uaID3); p.Interface != "wt0" {
		t.Errorf("provider = %+v, want up on wt0", p)
	}
	want := [][]string{
		{"Run", "netbird", "up", "--setup-key", "nb-setup-key"},
		{"Run", "netbird", "status", "--json"},
	}
	if got := callLines(runner.allCalls()); !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Fatalf("commands =\n  %q\nwant\n  %q", got, want)
	}
	if c := fx.routes.callsFor("EnableForwarding"); len(c) != 1 || c[0].Args[1] != "wt0" {
		t.Errorf("EnableForwarding calls = %+v, want (plexd0, wt0)", c)
	}

	// A netbird down that fails is part of Teardown's error, and the rewrite
	// is removed all the same.
	runner.runErrors[commandKey("netbird", "down")] = errors.New("exit status 1")
	err := fx.mgr.Teardown()
	if err == nil || !strings.Contains(err.Error(), "bridge: netbird: down failed") {
		t.Errorf("Teardown = %v, want the failed netbird down", err)
	}
	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "wt0" {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want wt0", c)
	}
}

// TestProviderIntegration_ClientMissing serves each vendor kind on a host
// without its binary: the provider reads client_missing.
func TestProviderIntegration_ClientMissing(t *testing.T) {
	for _, tc := range []struct {
		kind, secret string
		inject       func(*mockCommandExecutor)
	}{
		{api.UserAccessKindTailscale, "ts-join", func(r *mockCommandExecutor) {
			r.startErr = &exec.Error{Name: "tailscaled", Err: exec.ErrNotFound}
		}},
		{api.UserAccessKindNetbird, "nb-setup", func(r *mockCommandExecutor) {
			r.runErrors[commandKey("netbird", "up", "--setup-key", "join-key")] = &exec.Error{Name: "netbird", Err: exec.ErrNotFound}
		}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			runner := newMockCommandExecutor()
			tc.inject(runner)
			fx := newVendorFixture(t, runner, "join-key")
			fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "vendor", tc.kind, tc.secret)))
			requireDown(t, fx.mgr, uaID2, UserAccessReasonClientMissing)
			if got := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(got) != 0 {
				t.Errorf("AddMeshSourceRewrite calls = %+v, want none", got)
			}
		})
	}
}

// TestProviderIntegration_NoInterface serves a netbird provider whose client
// reports no interface after it joined: the client leaves the network again,
// and the provider reads join_failed.
func TestProviderIntegration_NoInterface(t *testing.T) {
	runner := newMockCommandExecutor()
	runner.runOutputs[commandKey("netbird", "status", "--json")] = []byte(`{"ip":"100.119.0.5/16","connected":true}`)
	fx := newVendorFixture(t, runner, "join-key")

	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID3, "netbird", api.UserAccessKindNetbird, "nb-setup")))

	requireDown(t, fx.mgr, uaID3, UserAccessReasonJoinFailed)
	calls := runner.allCalls()
	if last := callLines(calls[len(calls)-1:]); !slices.Equal(last[0], []string{"Run", "netbird", "down"}) {
		t.Errorf("last command = %q, want netbird down", last[0])
	}
	if got := fx.routes.callsFor("EnableForwarding"); len(got) != 0 {
		t.Errorf("EnableForwarding calls = %+v, want none", got)
	}
}
