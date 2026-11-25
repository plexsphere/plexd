package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/wireguard"
)

const (
	// startMeshIP is the address seedIdentity writes, and movedMeshIP the one
	// a pull moves the node to.
	startMeshIP = "100.64.0.7"
	movedMeshIP = "100.64.0.9"

	meshAddressNoMeshIPMsg     = "state pull carried no mesh_ip; keeping the address"
	meshAddressRefusedMsg      = "mesh address from state pull refused"
	meshAddressUnappliableMsg  = "mesh address cannot be applied while plexd runs; restart plexd to use it"
	meshAddressNotAppliedMsg   = "mesh address not applied; retrying on the next pull"
	meshAddressChangedMsg      = "mesh address changed from state pull"
	meshAddressNotPersistedMsg = "mesh address not persisted; retrying on the next pull"
)

// meshAddressFollowerNames are the followers plexd up builds on a macOS or
// Windows bridge whose resolver listens, in the order it builds them.
var meshAddressFollowerNames = []string{"mesh-dns", "sessions", "site-to-site", "mesh-rewriter"}

// meshAddressFixture runs meshAddressDispatchHandler over a seeded identity,
// with an interface and the four followers that each add "<name> <address>"
// to order, and the commits added as "commit <address>".
type meshAddressFixture struct {
	order   *callLog
	own     *ownMeshIP
	logs    *recordingHandler
	dataDir string

	// ifaceErr is what the interface returns, and followerErr what each
	// follower returns, by name. A subtest sets them between pulls.
	ifaceErr    error
	followerErr map[string]error

	handler reconcile.DispatchHandler
}

// newMeshAddressFixture builds the handler. withInterface false builds it
// without an interface, as plexd up does when WireGuard did not come up.
func newMeshAddressFixture(t *testing.T, withInterface bool) *meshAddressFixture {
	t.Helper()
	f := &meshAddressFixture{
		order:       &callLog{},
		own:         newOwnMeshIP(startMeshIP),
		logs:        newRecordingHandler(),
		dataDir:     t.TempDir(),
		followerErr: map[string]error{},
	}
	seedIdentity(t, f.dataDir, upTestNodeID, upTestNSK)

	old := commitMeshIP
	t.Cleanup(func() { commitMeshIP = old })
	commitMeshIP = func(dataDir, meshIP string) error {
		f.order.add("commit " + meshIP)
		return registration.CommitMeshIP(dataDir, meshIP)
	}

	deps := meshAddressDeps{
		Own:       f.own,
		DataDir:   f.dataDir,
		Persisted: startMeshIP,
		Logger:    slog.New(f.logs),
	}
	if withInterface {
		deps.Interface = func(addr netip.Addr) error {
			f.order.add("interface " + addr.String())
			return f.ifaceErr
		}
	}
	for _, name := range meshAddressFollowerNames {
		deps.Followers = append(deps.Followers, meshAddressFollower{
			name: name,
			apply: func(_ context.Context, addr netip.Addr) error {
				f.order.add(name + " " + addr.String())
				return f.followerErr[name]
			},
		})
	}
	f.handler = meshAddressDispatchHandler(deps)
	return f
}

// pull runs the handler on a pull that carries meshIP.
func (f *meshAddressFixture) pull(meshIP string) {
	f.handler(context.Background(), &api.NodeStateSnapshot{MeshIP: meshIP})
}

// takeCalls returns the calls since the last takeCalls and forgets them.
func (f *meshAddressFixture) takeCalls() []string {
	calls := f.order.snapshot()
	f.order = &callLog{}
	return calls
}

// persistedMeshIP returns the mesh_ip identity.json holds.
func (f *meshAddressFixture) persistedMeshIP(t *testing.T) string {
	t.Helper()
	id, err := registration.LoadIdentity(f.dataDir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	return id.MeshIP
}

// assertOwn fails the test unless ownMeshIP holds want.
func (f *meshAddressFixture) assertOwn(t *testing.T, want string) {
	t.Helper()
	addr, ok := f.own.Addr()
	if !ok || addr != netip.MustParseAddr(want) || f.own.String() != want {
		t.Errorf("ownMeshIP = (%s, %v) %q, want %s", addr, ok, f.own.String(), want)
	}
}

// appliedCalls returns the calls a move to addr makes, in order: the
// interface when there is one, the four followers, then the commit.
func appliedCalls(addr string, withInterface bool) []string {
	var calls []string
	if withInterface {
		calls = append(calls, "interface "+addr)
	}
	for _, name := range meshAddressFollowerNames {
		calls = append(calls, name+" "+addr)
	}
	return append(calls, "commit "+addr)
}

func TestMeshAddressDispatchHandler(t *testing.T) {
	t.Run("a pull without mesh_ip calls nothing and logs at Debug", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)

		f.pull("")

		if calls := f.takeCalls(); len(calls) != 0 {
			t.Errorf("calls = %v, want none", calls)
		}
		if n := f.logs.count(slog.LevelDebug, meshAddressNoMeshIPMsg); n != 1 {
			t.Errorf("Debug %q logged %d times, want 1", meshAddressNoMeshIPMsg, n)
		}
		if n := f.logs.countAt(slog.LevelInfo) + f.logs.countAt(slog.LevelWarn) + f.logs.countAt(slog.LevelError); n != 0 {
			t.Errorf("logged %d records above Debug, want none", n)
		}
		f.assertOwn(t, startMeshIP)
	})

	t.Run("the address in use calls nothing", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)

		f.pull(startMeshIP)

		if calls := f.takeCalls(); len(calls) != 0 {
			t.Errorf("calls = %v, want no interface, follower or commit call", calls)
		}
		if n := f.logs.countAt(slog.LevelInfo) + f.logs.countAt(slog.LevelWarn) + f.logs.countAt(slog.LevelError); n != 0 {
			t.Errorf("logged %d records above Debug, want none", n)
		}
		f.assertOwn(t, startMeshIP)
	})

	t.Run("a new address moves the interface, the followers and the identity once", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)

		f.pull(movedMeshIP)

		if calls, want := f.takeCalls(), appliedCalls(movedMeshIP, true); !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v", calls, want)
		}
		f.assertOwn(t, movedMeshIP)
		attrs := f.logs.attrsOf(slog.LevelInfo, meshAddressChangedMsg)
		if attrs == nil || attrs["previous_mesh_ip"] != startMeshIP || attrs["mesh_ip"] != movedMeshIP {
			t.Errorf("Info %q attrs = %v, want previous_mesh_ip %s and mesh_ip %s", meshAddressChangedMsg, attrs, startMeshIP, movedMeshIP)
		}
		if got := f.persistedMeshIP(t); got != movedMeshIP {
			t.Errorf("identity.json mesh_ip = %q, want %q", got, movedMeshIP)
		}

		f.pull(movedMeshIP)
		if calls := f.takeCalls(); len(calls) != 0 {
			t.Errorf("calls on the same pull again = %v, want none", calls)
		}
		if n := f.logs.count(slog.LevelInfo, meshAddressChangedMsg); n != 1 {
			t.Errorf("Info %q logged %d times over two pulls, want 1", meshAddressChangedMsg, n)
		}
	})

	t.Run("a value that is no mesh address is refused once per value", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)

		for i, value := range []string{"not-an-ip", "0.0.0.0", "224.0.0.1"} {
			for range 3 {
				f.pull(value)
			}
			if n := f.logs.count(slog.LevelWarn, meshAddressRefusedMsg); n != i+1 {
				t.Errorf("after three pulls of %q: Warn %q logged %d times, want %d, once per value", value, meshAddressRefusedMsg, n, i+1)
			}
		}

		if attrs := f.logs.attrsOf(slog.LevelWarn, meshAddressRefusedMsg); attrs == nil || attrs["mesh_ip"] != "not-an-ip" || attrs["error"] == "" {
			t.Errorf("Warn %q attrs = %v, want mesh_ip not-an-ip and the error", meshAddressRefusedMsg, attrs)
		}
		if calls := f.takeCalls(); len(calls) != 0 {
			t.Errorf("calls = %v, want none", calls)
		}
		f.assertOwn(t, startMeshIP)
		if got := f.persistedMeshIP(t); got != startMeshIP {
			t.Errorf("identity.json mesh_ip = %q, want %q", got, startMeshIP)
		}
	})

	t.Run("an address the interface refuses is refused and not committed", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)
		f.ifaceErr = fmt.Errorf("wireguard: readdress: %w: 192.168.1.5 lies outside the mesh prefix 100.64.0.0/10", wireguard.ErrMeshAddressInvalid)

		f.pull("192.168.1.5")
		f.pull("192.168.1.5")

		if calls, want := f.takeCalls(), []string{"interface 192.168.1.5", "interface 192.168.1.5"}; !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v: no commit and no follower call", calls, want)
		}
		if n := f.logs.count(slog.LevelWarn, meshAddressRefusedMsg); n != 1 {
			t.Errorf("Warn %q logged %d times over two pulls, want 1", meshAddressRefusedMsg, n)
		}
		attrs := f.logs.attrsOf(slog.LevelWarn, meshAddressRefusedMsg)
		if attrs == nil || attrs["mesh_ip"] != "192.168.1.5" || !strings.Contains(attrs["error"], wireguard.ErrMeshAddressInvalid.Error()) {
			t.Errorf("Warn %q attrs = %v, want mesh_ip 192.168.1.5 and the interface's error", meshAddressRefusedMsg, attrs)
		}
		f.assertOwn(t, startMeshIP)
		if got := f.persistedMeshIP(t); got != startMeshIP {
			t.Errorf("identity.json mesh_ip = %q, want %q", got, startMeshIP)
		}
	})

	t.Run("an interface that cannot follow commits the address for the next start", func(t *testing.T) {
		tests := []struct {
			name          string
			withInterface bool
			ifaceErr      error
			wantCalls     []string
		}{
			{
				name:      "no interface",
				wantCalls: []string{"commit " + movedMeshIP},
			},
			{
				name:          "an interface that cannot replace its address",
				withInterface: true,
				ifaceErr:      fmt.Errorf("wireguard: readdress: %w", wireguard.ErrReaddressUnsupported),
				wantCalls: []string{
					"interface " + movedMeshIP, "commit " + movedMeshIP,
					"interface " + movedMeshIP,
					"interface " + movedMeshIP,
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newMeshAddressFixture(t, tt.withInterface)
				f.ifaceErr = tt.ifaceErr

				for range 3 {
					f.pull(movedMeshIP)
				}

				if calls := f.takeCalls(); !slices.Equal(calls, tt.wantCalls) {
					t.Errorf("calls = %v, want %v: one commit and no follower call", calls, tt.wantCalls)
				}
				if got := f.persistedMeshIP(t); got != movedMeshIP {
					t.Errorf("identity.json mesh_ip = %q, want %q", got, movedMeshIP)
				}
				f.assertOwn(t, startMeshIP)
				if n := f.logs.count(slog.LevelError, meshAddressUnappliableMsg); n != 1 {
					t.Errorf("Error %q logged %d times over three pulls, want 1", meshAddressUnappliableMsg, n)
				}
				if attrs := f.logs.attrsOf(slog.LevelError, meshAddressUnappliableMsg); attrs == nil || attrs["mesh_ip"] != movedMeshIP {
					t.Errorf("Error %q attrs = %v, want mesh_ip %s", meshAddressUnappliableMsg, attrs, movedMeshIP)
				}
				if n := f.logs.count(slog.LevelInfo, meshAddressChangedMsg); n != 0 {
					t.Errorf("Info %q logged %d times, want none", meshAddressChangedMsg, n)
				}
			})
		}
	})

	t.Run("an interface that fails is tried again on every pull", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)
		f.ifaceErr = errors.New("netlink: operation not permitted")

		for range 3 {
			f.pull(movedMeshIP)
		}

		want := []string{"interface " + movedMeshIP, "interface " + movedMeshIP, "interface " + movedMeshIP}
		if calls := f.takeCalls(); !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v: the interface on every pull, no follower and no commit", calls, want)
		}
		if n := f.logs.count(slog.LevelError, meshAddressNotAppliedMsg); n != 1 {
			t.Errorf("Error %q logged %d times over three pulls, want 1", meshAddressNotAppliedMsg, n)
		}
		if n := f.logs.count(slog.LevelDebug, meshAddressNotAppliedMsg); n != 2 {
			t.Errorf("Debug %q logged %d times over three pulls, want 2 for the repeats", meshAddressNotAppliedMsg, n)
		}
		attrs := f.logs.attrsOf(slog.LevelError, meshAddressNotAppliedMsg)
		if attrs == nil || attrs["step"] != "interface" || attrs["mesh_ip"] != movedMeshIP || attrs["error"] != "netlink: operation not permitted" {
			t.Errorf("Error %q attrs = %v, want step interface, mesh_ip %s and the error", meshAddressNotAppliedMsg, attrs, movedMeshIP)
		}
		f.assertOwn(t, startMeshIP)
		if got := f.persistedMeshIP(t); got != startMeshIP {
			t.Errorf("identity.json mesh_ip = %q, want %q", got, startMeshIP)
		}

		f.ifaceErr = nil
		f.pull(movedMeshIP)
		if calls, want := f.takeCalls(), appliedCalls(movedMeshIP, true); !slices.Equal(calls, want) {
			t.Errorf("calls once the interface takes the address = %v, want %v", calls, want)
		}
		f.assertOwn(t, movedMeshIP)
	})

	t.Run("a failed follower is tried again alone and does not stop the others", func(t *testing.T) {
		f := newMeshAddressFixture(t, true)
		f.followerErr["sessions"] = errors.New("sessions refused")

		f.pull(movedMeshIP)

		if calls, want := f.takeCalls(), appliedCalls(movedMeshIP, true); !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v: the followers after the failed one still called", calls, want)
		}
		attrs := f.logs.attrsOf(slog.LevelError, meshAddressNotAppliedMsg)
		if attrs == nil || attrs["step"] != "sessions" || attrs["mesh_ip"] != movedMeshIP || attrs["error"] != "sessions refused" {
			t.Errorf("Error %q attrs = %v, want step sessions, mesh_ip %s and the error", meshAddressNotAppliedMsg, attrs, movedMeshIP)
		}
		f.assertOwn(t, movedMeshIP)

		f.pull(movedMeshIP)
		if calls, want := f.takeCalls(), []string{"sessions " + movedMeshIP}; !slices.Equal(calls, want) {
			t.Errorf("calls on the next pull = %v, want %v: only the failed follower", calls, want)
		}
		if n := f.logs.count(slog.LevelError, meshAddressNotAppliedMsg); n != 1 {
			t.Errorf("Error %q logged %d times over two pulls, want 1", meshAddressNotAppliedMsg, n)
		}
		if n := f.logs.count(slog.LevelDebug, meshAddressNotAppliedMsg); n != 1 {
			t.Errorf("Debug %q logged %d times over two pulls, want 1 for the repeat", meshAddressNotAppliedMsg, n)
		}

		delete(f.followerErr, "sessions")
		f.pull(movedMeshIP)
		f.pull(movedMeshIP)
		if calls, want := f.takeCalls(), []string{"sessions " + movedMeshIP}; !slices.Equal(calls, want) {
			t.Errorf("calls once the follower succeeds = %v, want %v and then nothing", calls, want)
		}
	})

	t.Run("a failed commit is tried again on every pull until one succeeds", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permission bits are not enforced on windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions, so the commit cannot fail")
		}
		f := newMeshAddressFixture(t, true)
		if err := os.Chmod(f.dataDir, 0o500); err != nil {
			t.Fatalf("chmod 0500: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(f.dataDir, 0o700) })

		f.pull(movedMeshIP)
		if calls, want := f.takeCalls(), appliedCalls(movedMeshIP, true); !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v", calls, want)
		}
		for range 2 {
			f.pull(movedMeshIP)
			if calls, want := f.takeCalls(), []string{"commit " + movedMeshIP}; !slices.Equal(calls, want) {
				t.Errorf("calls on a later pull = %v, want %v: a new commit attempt", calls, want)
			}
		}
		if n := f.logs.count(slog.LevelWarn, meshAddressNotPersistedMsg); n != 3 {
			t.Errorf("Warn %q logged %d times over three pulls, want 3", meshAddressNotPersistedMsg, n)
		}
		attrs := f.logs.attrsOf(slog.LevelWarn, meshAddressNotPersistedMsg)
		if attrs == nil || attrs["mesh_ip"] != movedMeshIP || !strings.HasPrefix(attrs["error"], "registration: commit mesh ip:") {
			t.Errorf("Warn %q attrs = %v, want mesh_ip %s and the commit's error", meshAddressNotPersistedMsg, attrs, movedMeshIP)
		}
		if got := f.persistedMeshIP(t); got != startMeshIP {
			t.Errorf("identity.json mesh_ip = %q, want %q while the data dir refuses writes", got, startMeshIP)
		}

		if err := os.Chmod(f.dataDir, 0o700); err != nil {
			t.Fatalf("chmod 0700: %v", err)
		}
		f.pull(movedMeshIP)
		f.pull(movedMeshIP)
		if calls, want := f.takeCalls(), []string{"commit " + movedMeshIP}; !slices.Equal(calls, want) {
			t.Errorf("calls once the data dir takes writes = %v, want %v and then nothing", calls, want)
		}
		if got := f.persistedMeshIP(t); got != movedMeshIP {
			t.Errorf("identity.json mesh_ip = %q, want %q", got, movedMeshIP)
		}
		if n := f.logs.count(slog.LevelWarn, meshAddressNotPersistedMsg); n != 3 {
			t.Errorf("Warn %q logged %d times in all, want still 3", meshAddressNotPersistedMsg, n)
		}
	})
}

func TestOwnMeshIP(t *testing.T) {
	own := newOwnMeshIP("::ffff:100.64.0.7")
	if addr, ok := own.Addr(); !ok || addr != netip.MustParseAddr(startMeshIP) {
		t.Errorf("Addr() = (%s, %v), want (%s, true), unmapped", addr, ok, startMeshIP)
	}

	unparsable := newOwnMeshIP("not-an-address")
	if addr, ok := unparsable.Addr(); ok || addr.IsValid() {
		t.Errorf("Addr() of an identity address that does not parse = (%s, %v), want no address", addr, ok)
	}
	if got := unparsable.String(); got != "not-an-address" {
		t.Errorf("String() = %q, want the identity's text", got)
	}

	// The reconcile goroutine sets the address while action and dial
	// goroutines read it; go test -race checks the guard.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			_, _ = own.Addr()
			_ = own.String()
		}
	}()
	own.Set(netip.MustParseAddr("::ffff:" + movedMeshIP))
	wg.Wait()
	if addr, ok := own.Addr(); !ok || addr != netip.MustParseAddr(movedMeshIP) || own.String() != movedMeshIP {
		t.Errorf("after Set: (%s, %v) %q, want %s unmapped", addr, ok, own.String(), movedMeshIP)
	}
}
