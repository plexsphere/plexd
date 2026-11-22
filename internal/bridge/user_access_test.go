package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

// mockUserAccessClient is a test double for UserAccessClient. Start records
// the key and the mesh CIDR it was handed and, without startErr, reports
// iface as its interface until Stop.
type mockUserAccessClient struct {
	name     string
	iface    string
	startErr error
	stopErr  error
	// startHook, when set, runs inside Start before it returns.
	startHook func()

	mu      sync.Mutex
	starts  []clientStart
	stops   int
	running bool
}

// clientStart records one call to Start.
type clientStart struct {
	key      string
	meshCIDR string
	ctx      context.Context
}

func newMockUserAccessClient(name, iface string) *mockUserAccessClient {
	return &mockUserAccessClient{name: name, iface: iface}
}

func (c *mockUserAccessClient) Name() string { return c.name }

func (c *mockUserAccessClient) Start(ctx context.Context, key, meshCIDR string) error {
	c.mu.Lock()
	c.starts = append(c.starts, clientStart{key: key, meshCIDR: meshCIDR, ctx: ctx})
	hook, err := c.startHook, c.startErr
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()
	return nil
}

func (c *mockUserAccessClient) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stops++
	c.running = false
	return c.stopErr
}

func (c *mockUserAccessClient) Status() ProviderStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return ProviderStatus{}
	}
	return ProviderStatus{Running: true, InterfaceName: c.iface}
}

func (c *mockUserAccessClient) startCalls() []clientStart {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.starts)
}

func (c *mockUserAccessClient) stopCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stops
}

func (c *mockUserAccessClient) set(f func(c *mockUserAccessClient)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

var _ UserAccessClient = (*mockUserAccessClient)(nil)

// fakeSecretValues is a test double for SecretValueFetcher: it answers each
// name and version with the value set for it, or with err, and records the
// fetches.
type fakeSecretValues struct {
	mu     sync.Mutex
	values map[certVersion][]byte
	err    error
	calls  []certVersion
}

var _ SecretValueFetcher = (*fakeSecretValues)(nil)

func (f *fakeSecretValues) FetchSecretValue(_ context.Context, name string, version int) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, certVersion{name, version})
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[certVersion{name, version}]
	if !ok {
		return nil, fmt.Errorf("fake: %w", api.ErrNotFound)
	}
	return bytes.Clone(v), nil
}

func (f *fakeSecretValues) set(name string, version int, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.values == nil {
		f.values = make(map[certVersion][]byte)
	}
	f.values[certVersion{name, version}] = []byte(value)
}

func (f *fakeSecretValues) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeSecretValues) fetches() []certVersion {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const (
	uaMesh     = "plexd0"
	uaMeshCIDR = "10.99.0.0/24"

	uaID1 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1"
	uaID2 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2"
	uaID3 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e3"

	uaIface1 = "wg-ua-a0a0a0e1"
	uaIface2 = "wg-ua-a0a0a0e2"
)

// uaFixture is a UserAccessManager over recording doubles, a key store in a
// temporary directory, a settable clock and a log buffer.
type uaFixture struct {
	mgr       *UserAccessManager
	access    *mockAccessController
	routes    *mockRouteController
	rewriter  *mockMeshSourceRewriter
	keys      *InterfaceKeyStore
	keyDir    string
	secrets   *fakeSecretValues
	tailscale *mockUserAccessClient
	netbird   *mockUserAccessClient
	clock     *relayClock
	logs      *relayLog
}

// buildUAFixture builds the fixture without setting the manager up; adjust
// changes the dependencies first. The manager is torn down when the test
// ends.
func buildUAFixture(t *testing.T, adjust func(*UserAccessDeps)) *uaFixture {
	t.Helper()
	logger, logs := newRelayLogger()
	fx := &uaFixture{
		access:    &mockAccessController{},
		routes:    &mockRouteController{},
		rewriter:  &mockMeshSourceRewriter{},
		keyDir:    filepath.Join(t.TempDir(), "user-access"),
		secrets:   &fakeSecretValues{},
		tailscale: newMockUserAccessClient("tailscale", "tailscale0"),
		netbird:   newMockUserAccessClient("netbird", "wt0"),
		clock:     &relayClock{now: relayStart},
		logs:      logs,
	}
	fx.keys = NewInterfaceKeyStore(fx.keyDir)
	deps := UserAccessDeps{
		Access:   fx.access,
		Routes:   fx.routes,
		Rewriter: fx.rewriter,
		Keys:     fx.keys,
		Secrets:  fx.secrets,
		Clients: map[string]UserAccessClient{
			api.UserAccessKindTailscale: fx.tailscale,
			api.UserAccessKindNetbird:   fx.netbird,
		},
		MeshInterface: uaMesh,
		MeshCIDR:      uaMeshCIDR,
		Logger:        logger,
	}
	if adjust != nil {
		adjust(&deps)
	}
	fx.mgr = NewUserAccessManager(deps)
	fx.mgr.now = fx.clock.Now
	t.Cleanup(func() {
		_ = fx.mgr.Teardown()
		// Without ReleaseForwarding, as on Linux, the manager never switches
		// forwarding off: the knob there is the mesh interface's own.
		if got := fx.routes.callsFor("DisableForwarding"); !deps.ReleaseForwarding && len(got) != 0 {
			t.Errorf("DisableForwarding calls = %+v without ReleaseForwarding, want none", got)
		}
	})
	return fx
}

// newUAFixture builds the fixture, sets the manager up and clears the calls
// Setup made.
func newUAFixture(t *testing.T, adjust func(*UserAccessDeps)) *uaFixture {
	t.Helper()
	fx := buildUAFixture(t, adjust)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	fx.reset()
	return fx
}

// reset clears the calls every double recorded.
func (fx *uaFixture) reset() {
	fx.access.resetAccess()
	fx.routes.reset()
	fx.rewriter.reset()
}

// calls returns the methods every controller double recorded, prefixed with
// the double's name, so a test can want none at all.
func (fx *uaFixture) calls() []string {
	var out []string
	for _, m := range fx.access.accessMethods() {
		out = append(out, "access."+m)
	}
	for _, m := range fx.routes.methods() {
		out = append(out, "routes."+m)
	}
	for _, m := range fx.rewriter.methods() {
		out = append(out, "rewriter."+m)
	}
	return out
}

// requireNoCalls fails unless no controller method was called since reset.
func (fx *uaFixture) requireNoCalls(t *testing.T, what string) {
	t.Helper()
	if got := fx.calls(); len(got) != 0 {
		t.Fatalf("%s called %q, want no controller method", what, got)
	}
}

// keyFiles returns the names of the key files in the store's directory.
func (fx *uaFixture) keyFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(fx.keyDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read key directory: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// storedKey returns the key the store keeps for id, read through a second
// store over the same directory.
func (fx *uaFixture) storedKey(t *testing.T, id string) []byte {
	t.Helper()
	key, err := NewInterfaceKeyStore(fx.keyDir).LoadOrCreate(id)
	if err != nil {
		t.Fatalf("LoadOrCreate(%s): %v", id, err)
	}
	return key[:]
}

// providerInfo returns the status of the provider with id, failing when the
// manager reports none.
func providerInfo(t *testing.T, mgr *UserAccessManager, id string) api.UserAccessProviderInfo {
	t.Helper()
	info := mgr.UserAccessStatus()
	if info == nil {
		t.Fatal("UserAccessStatus() = nil, want the active manager's status")
	}
	for _, p := range info.Providers {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no status for provider %s in %+v", id, info.Providers)
	return api.UserAccessProviderInfo{}
}

// requireDown fails unless the provider with id is down for reason.
func requireDown(t *testing.T, mgr *UserAccessManager, id, reason string) {
	t.Helper()
	if p := providerInfo(t, mgr, id); p.Health != api.UserAccessHealthDown || p.Reason != reason {
		t.Fatalf("provider %s = %+v, want down for %s", id, p, reason)
	}
}

// requireUp fails unless the provider with id is up.
func requireUp(t *testing.T, mgr *UserAccessManager, id string) api.UserAccessProviderInfo {
	t.Helper()
	p := providerInfo(t, mgr, id)
	if p.Health != api.UserAccessHealthUp || p.Reason != "" {
		t.Fatalf("provider %s = %+v, want up", id, p)
	}
	return p
}

// providerIDs returns the ids the manager reports, in order.
func providerIDs(mgr *UserAccessManager) []string {
	info := mgr.UserAccessStatus()
	if info == nil {
		return nil
	}
	var ids []string
	for _, p := range info.Providers {
		ids = append(ids, p.ID)
	}
	return ids
}

// deviceKey returns a valid device public key: 32 bytes of b, base64.
func deviceKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

// uaDevice returns a device with a key of b at address.
func uaDevice(slug string, b byte, address string) api.UserAccessDevice {
	return api.UserAccessDevice{ID: "dev-" + slug, Slug: slug, PublicKey: deviceKey(b), Address: address}
}

// wgProvider returns a wireguard provider entry.
func wgProvider(id, slug string, port int, pool string, devices ...api.UserAccessDevice) api.UserAccessProvider {
	return api.UserAccessProvider{
		ID:          id,
		Slug:        slug,
		Kind:        api.UserAccessKindWireGuard,
		ListenPort:  port,
		AddressPool: pool,
		MaxDevices:  64,
		Devices:     devices,
	}
}

// vendorProvider returns a tailscale or netbird provider entry.
func vendorProvider(id, slug, kind, secret string) api.UserAccessProvider {
	return api.UserAccessProvider{ID: id, Slug: slug, Kind: kind, AuthSecretName: secret}
}

// uaBlock returns an enabled block listing providers.
func uaBlock(providers ...api.UserAccessProvider) api.UserAccessConfig {
	return api.UserAccessConfig{Enabled: true, Providers: providers}
}

var (
	alice = uaDevice("alice-laptop", 1, "10.99.0.2")
	bob   = uaDevice("bob-phone", 2, "10.99.0.3")
	carol = uaDevice("carol-tablet", 3, "10.99.0.4")

	fieldTeam = wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", alice, bob)
)

// configuredPeers returns the ConfigurePeer calls as "iface key allowed-ips
// psk" lines.
func configuredPeers(access *mockAccessController) []string {
	var out []string
	for _, c := range access.accessCallsFor("ConfigurePeer") {
		out = append(out, fmt.Sprintf("%s %s %v %q", c.Args[0], c.Args[1], c.Args[2], c.Args[3]))
	}
	return out
}

// ---------------------------------------------------------------------------
// Setup and CleanupUserAccess
// ---------------------------------------------------------------------------

func TestCleanupUserAccess(t *testing.T) {
	t.Run("access and rewriter", func(t *testing.T) {
		access, rewriter := &mockAccessController{}, &mockMeshSourceRewriter{}
		if err := CleanupUserAccess(access, rewriter); err != nil {
			t.Fatalf("CleanupUserAccess: %v", err)
		}
		if got := access.accessMethods(); !slices.Equal(got, []string{"RemoveInterfaces"}) {
			t.Errorf("access calls = %q, want RemoveInterfaces alone", got)
		}
		if c := access.accessCallsFor("RemoveInterfaces"); len(c) != 1 || c[0].Args[0] != "wg-ua-" {
			t.Errorf("RemoveInterfaces calls = %+v, want one with the prefix wg-ua-", c)
		}
		if got := rewriter.methods(); !slices.Equal(got, []string{"ResetMeshSourceRewrite"}) {
			t.Errorf("rewriter calls = %q, want ResetMeshSourceRewrite alone", got)
		}
	})

	t.Run("nil rewriter", func(t *testing.T) {
		access := &mockAccessController{}
		if err := CleanupUserAccess(access, nil); err != nil {
			t.Fatalf("CleanupUserAccess: %v", err)
		}
		if got := access.accessMethods(); !slices.Equal(got, []string{"RemoveInterfaces"}) {
			t.Errorf("access calls = %q, want RemoveInterfaces alone", got)
		}
	})

	t.Run("nil access", func(t *testing.T) {
		rewriter := &mockMeshSourceRewriter{}
		if err := CleanupUserAccess(nil, rewriter); err != nil {
			t.Fatalf("CleanupUserAccess: %v", err)
		}
		if got := rewriter.methods(); !slices.Equal(got, []string{"ResetMeshSourceRewrite"}) {
			t.Errorf("rewriter calls = %q, want ResetMeshSourceRewrite alone", got)
		}
	})

	t.Run("errors are joined", func(t *testing.T) {
		errRemove, errReset := errors.New("remove failed"), errors.New("reset failed")
		access := &mockAccessController{removeInterfacesErr: errRemove}
		rewriter := &mockMeshSourceRewriter{resetMeshSourceRewriteErr: errReset}
		err := CleanupUserAccess(access, rewriter)
		if !errors.Is(err, errRemove) || !errors.Is(err, errReset) {
			t.Errorf("CleanupUserAccess = %v, want both errors", err)
		}
		if len(rewriter.methods()) != 1 {
			t.Error("a failed RemoveInterfaces skipped ResetMeshSourceRewrite")
		}
	})
}

func TestUserAccessManager_SetupCleansUp(t *testing.T) {
	fx := buildUAFixture(t, nil)
	if fx.mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus() before Setup is not nil")
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if c := fx.access.accessCallsFor("RemoveInterfaces"); len(c) != 1 || c[0].Args[0] != "wg-ua-" {
		t.Errorf("RemoveInterfaces calls = %+v, want one with the prefix wg-ua-", c)
	}
	if got := fx.rewriter.methods(); !slices.Equal(got, []string{"ResetMeshSourceRewrite"}) {
		t.Errorf("rewriter calls = %q, want ResetMeshSourceRewrite", got)
	}
	if info := fx.mgr.UserAccessStatus(); info == nil || info.Enabled || len(info.Providers) != 0 {
		t.Errorf("UserAccessStatus() after Setup = %+v, want a status without providers", info)
	}
	if got := logLines(fx.logs, "level=INFO", `msg="user access manager started"`, "component=bridge"); got != 1 {
		t.Errorf("%d 'user access manager started' lines, want 1:\n%s", got, fx.logs.String())
	}
}

func TestUserAccessManager_SetupReturnsTheCleanupError(t *testing.T) {
	for name, adjust := range map[string]func(*uaFixture, error){
		"RemoveInterfaces":       func(fx *uaFixture, err error) { fx.access.removeInterfacesErr = err },
		"ResetMeshSourceRewrite": func(fx *uaFixture, err error) { fx.rewriter.resetMeshSourceRewriteErr = err },
	} {
		t.Run(name, func(t *testing.T) {
			fx := buildUAFixture(t, nil)
			errCleanup := errors.New("cleanup failed")
			adjust(fx, errCleanup)
			err := fx.mgr.Setup()
			if !errors.Is(err, errCleanup) {
				t.Fatalf("Setup = %v, want the cleanup's error", err)
			}
			if !strings.HasPrefix(err.Error(), "bridge: user access: clean up: ") {
				t.Errorf("Setup = %q, want the prefix %q", err, "bridge: user access: clean up: ")
			}
			if fx.mgr.UserAccessStatus() != nil {
				t.Error("UserAccessStatus() after a failed Setup is not nil")
			}
			fx.reset()
			fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
			fx.requireNoCalls(t, "Apply after a failed Setup")
		})
	}
}

// ---------------------------------------------------------------------------
// Apply: wireguard
// ---------------------------------------------------------------------------

// TestUserAccessManager_ApplyBringsUpAWireGuardProvider checks the calls that
// bring a wireguard provider up: its interface with the stored key, its port
// and the first host address of its pool, forwarding and the source rewrite
// into the mesh, and each device as a /32 peer.
func TestUserAccessManager_ApplyBringsUpAWireGuardProvider(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))

	create := fx.access.accessCallsFor("CreateInterface")
	if len(create) != 1 {
		t.Fatalf("CreateInterface calls = %d, want 1", len(create))
	}
	if name := create[0].Args[0]; name != uaIface1 {
		t.Errorf("CreateInterface name = %v, want %s", name, uaIface1)
	}
	if key := create[0].Args[1].([]byte); !bytes.Equal(key, fx.storedKey(t, uaID1)) {
		t.Error("CreateInterface key is not the key the store keeps for the provider")
	}
	if port := create[0].Args[2]; port != 51821 {
		t.Errorf("CreateInterface listenPort = %v, want 51821", port)
	}
	if addr := create[0].Args[3]; addr != "10.99.0.1/24" {
		t.Errorf("CreateInterface address = %v, want 10.99.0.1/24", addr)
	}
	if c := fx.routes.callsFor("EnableForwarding"); len(c) != 1 || c[0].Args[0] != uaMesh || c[0].Args[1] != uaIface1 {
		t.Errorf("EnableForwarding calls = %+v, want one (%s, %s)", c, uaMesh, uaIface1)
	}
	if c := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != uaIface1 || c[0].Args[1] != uaMesh {
		t.Errorf("AddMeshSourceRewrite calls = %+v, want one (%s, %s)", c, uaIface1, uaMesh)
	}
	want := []string{
		fmt.Sprintf("%s %s [10.99.0.2/32] %q", uaIface1, alice.PublicKey, ""),
		fmt.Sprintf("%s %s [10.99.0.3/32] %q", uaIface1, bob.PublicKey, ""),
	}
	if got := configuredPeers(fx.access); !slices.Equal(got, want) {
		t.Errorf("ConfigurePeer calls =\n  %q\nwant\n  %q", got, want)
	}
	if got := fx.routes.callsFor("DisableForwarding"); len(got) != 0 {
		t.Errorf("DisableForwarding calls = %+v, want none", got)
	}

	info := fx.mgr.UserAccessStatus()
	wantInfo := &api.UserAccessInfo{Enabled: true, Providers: []api.UserAccessProviderInfo{{
		ID: uaID1, Slug: "field-team", Kind: api.UserAccessKindWireGuard, Interface: uaIface1,
		Health: api.UserAccessHealthUp, ListenPort: 51821, Devices: 2,
	}}}
	if fmt.Sprint(info) != fmt.Sprint(wantInfo) {
		t.Errorf("UserAccessStatus() = %+v, want %+v", info, wantInfo)
	}
	if got := logLines(fx.logs, "level=INFO", `msg="user access provider up"`, "component=bridge",
		"provider_id="+uaID1, "slug=field-team", "kind=wireguard", "interface="+uaIface1, "listen_port=51821"); got != 1 {
		t.Errorf("%d 'user access provider up' lines, want 1:\n%s", got, fx.logs.String())
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{uaID1 + ".key"}) {
		t.Errorf("key files = %q, want the provider's", got)
	}
	assertPerm(t, filepath.Join(fx.keyDir, uaID1+".key"), 0600)
	// The log never carries key material.
	if strings.Contains(fx.logs.String(), base64.StdEncoding.EncodeToString(fx.storedKey(t, uaID1))) {
		t.Error("the log carries the interface's private key")
	}
}

// TestUserAccessManager_KernelNames checks that forwarding and the source
// rewrite of a wireguard provider take the name the operating system knows
// its interface by, utunN on macOS, while its devices and its status keep the
// configured name, and that its removal uses the kernel name it was brought
// up with, although the controller no longer maps the configured one.
func TestUserAccessManager_KernelNames(t *testing.T) {
	var namer *namerAccessController
	fx := newUAFixture(t, func(d *UserAccessDeps) {
		namer = &namerAccessController{
			mockAccessController: d.Access.(*mockAccessController),
			names:                map[string]string{uaIface1: "utun7"},
		}
		d.Access = namer
		d.MeshInterface = "utun4"
	})
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))

	if c := fx.routes.callsFor("EnableForwarding"); len(c) != 1 || c[0].Args[0] != "utun4" || c[0].Args[1] != "utun7" {
		t.Errorf("EnableForwarding calls = %+v, want one (utun4, utun7)", c)
	}
	if c := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "utun7" || c[0].Args[1] != "utun4" {
		t.Errorf("AddMeshSourceRewrite calls = %+v, want one (utun7, utun4)", c)
	}
	want := []string{
		fmt.Sprintf("%s %s [10.99.0.2/32] %q", uaIface1, alice.PublicKey, ""),
		fmt.Sprintf("%s %s [10.99.0.3/32] %q", uaIface1, bob.PublicKey, ""),
	}
	if got := configuredPeers(fx.access); !slices.Equal(got, want) {
		t.Errorf("ConfigurePeer calls =\n  %q\nwant\n  %q", got, want)
	}
	if p := requireUp(t, fx.mgr, uaID1); p.Interface != uaIface1 {
		t.Errorf("status interface = %q, want the configured %s", p.Interface, uaIface1)
	}

	namer.unmap(uaIface1)
	fx.reset()
	fx.mgr.Apply(t.Context(), uaBlock())

	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "utun7" || c[0].Args[1] != "utun4" {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want one (utun7, utun4)", c)
	}
	if c := fx.access.accessCallsFor("RemoveInterface"); len(c) != 1 || c[0].Args[0] != uaIface1 {
		t.Errorf("RemoveInterface calls = %+v, want one for the configured %s", c, uaIface1)
	}
}

// TestUserAccessManager_ReleaseForwarding checks that with ReleaseForwarding,
// as on macOS, where one forwarding knob serves the whole host, the manager
// gives back each forwarding pair it claimed: when a provider that is up is
// removed, once per provider Teardown stops, and when a bring-up fails after
// its forwarding was switched on.
func TestUserAccessManager_ReleaseForwarding(t *testing.T) {
	release := func(d *UserAccessDeps) { d.ReleaseForwarding = true }

	t.Run("a removed provider", func(t *testing.T) {
		fx := newUAFixture(t, release)
		fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
		requireUp(t, fx.mgr, uaID1)
		if got := routeCalls(fx.routes, "DisableForwarding"); len(got) != 0 {
			t.Fatalf("DisableForwarding calls = %q while the provider is up, want none", got)
		}

		fx.mgr.Apply(t.Context(), uaBlock())
		if got := routeCalls(fx.routes, "DisableForwarding"); !slices.Equal(got, []string{uaMesh + " " + uaIface1}) {
			t.Errorf("DisableForwarding calls = %q, want (%s, %s)", got, uaMesh, uaIface1)
		}
	})

	t.Run("teardown", func(t *testing.T) {
		fx := newUAFixture(t, release)
		fx.secrets.set("nb-setup", 1, "join-key")
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("nb-setup", 1))
		fx.mgr.Apply(t.Context(), uaBlock(
			fieldTeam,
			wgProvider(uaID2, "ops", 51822, "10.98.0.0/24"),
			vendorProvider(uaID3, "vendor", api.UserAccessKindNetbird, "nb-setup"),
		))
		for _, id := range []string{uaID1, uaID2, uaID3} {
			requireUp(t, fx.mgr, id)
		}

		if err := fx.mgr.Teardown(); err != nil {
			t.Fatalf("Teardown() error = %v, want nil", err)
		}
		got := routeCalls(fx.routes, "DisableForwarding")
		slices.Sort(got)
		want := []string{uaMesh + " " + uaIface1, uaMesh + " " + uaIface2, uaMesh + " wt0"}
		if !slices.Equal(got, want) {
			t.Errorf("DisableForwarding calls = %q, want one per provider %q", got, want)
		}
	})

	t.Run("a rewrite that fails after forwarding", func(t *testing.T) {
		fx := newUAFixture(t, release)
		fx.rewriter.addMeshSourceRewriteErr = errors.New("boom")
		fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))

		requireDown(t, fx.mgr, uaID1, UserAccessReasonSetupFailed)
		if got := routeCalls(fx.routes, "EnableForwarding"); !slices.Equal(got, []string{uaMesh + " " + uaIface1}) {
			t.Errorf("EnableForwarding calls = %q, want (%s, %s)", got, uaMesh, uaIface1)
		}
		if got := routeCalls(fx.routes, "DisableForwarding"); !slices.Equal(got, []string{uaMesh + " " + uaIface1}) {
			t.Errorf("DisableForwarding calls = %q, want (%s, %s)", got, uaMesh, uaIface1)
		}
	})

	t.Run("a release that fails after a failed bring-up", func(t *testing.T) {
		fx := newUAFixture(t, release)
		fx.rewriter.addMeshSourceRewriteErr = errors.New("boom")
		fx.routes.disableForwardingErr = errors.New("sysctl refused")
		fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))

		requireDown(t, fx.mgr, uaID1, UserAccessReasonSetupFailed)
		if got := logLines(fx.logs, "level=ERROR", `msg="bridge: user access: release forwarding failed"`, "component=bridge",
			"provider_id="+uaID1, "interface="+uaIface1, "release forwarding "+uaIface1+": sysctl refused"); got != 1 {
			t.Errorf("%d 'release forwarding failed' lines, want 1:\n%s", got, fx.logs.String())
		}
	})

	t.Run("teardown returns the release error", func(t *testing.T) {
		fx := newUAFixture(t, release)
		fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
		requireUp(t, fx.mgr, uaID1)
		errRefused := errors.New("sysctl refused")
		fx.routes.disableForwardingErr = errRefused

		err := fx.mgr.Teardown()
		if !errors.Is(err, errRefused) || !strings.Contains(err.Error(), "bridge: user access: release forwarding "+uaIface1+": ") {
			t.Errorf("Teardown() error = %v, want the release error of %s", err, uaIface1)
		}
	})
}

// TestUserAccessManager_ApplyDiffsDevicesAndRebuilds checks that an unchanged
// block calls nothing, that devices are diffed by public key on the running
// interface, and that a changed listen_port or address_pool rebuilds the
// interface with the kept key.
func TestUserAccessManager_ApplyDiffsDevicesAndRebuilds(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	key := fx.storedKey(t, uaID1)
	fx.reset()

	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	fx.requireNoCalls(t, "a second Apply of the same block")

	// A slug or max_devices change is no change of the interface.
	renamed := fieldTeam
	renamed.Slug, renamed.MaxDevices = "field-crew", 128
	fx.mgr.Apply(t.Context(), uaBlock(renamed))
	fx.requireNoCalls(t, "an Apply that renames the provider")
	if p := requireUp(t, fx.mgr, uaID1); p.Slug != "field-crew" {
		t.Errorf("slug = %q, want the renamed one", p.Slug)
	}
	// The status read the interface's handshakes.
	fx.reset()

	fx.mgr.Apply(t.Context(), uaBlock(wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", alice)))
	if got := fx.calls(); !slices.Equal(got, []string{"access.RemovePeer"}) {
		t.Fatalf("calls for a block without bob = %q, want RemovePeer alone", got)
	}
	if c := fx.access.accessCallsFor("RemovePeer"); c[0].Args[0] != uaIface1 || c[0].Args[1] != bob.PublicKey {
		t.Errorf("RemovePeer(%v, %v), want (%s, bob's key)", c[0].Args[0], c[0].Args[1], uaIface1)
	}
	if p := requireUp(t, fx.mgr, uaID1); p.Devices != 1 {
		t.Errorf("devices = %d, want 1", p.Devices)
	}
	fx.reset()

	// A device that moved to another address is configured again: the
	// controller replaces its allowed IPs.
	moved := uaDevice("alice-laptop", 1, "10.99.0.20")
	fx.mgr.Apply(t.Context(), uaBlock(wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", moved, carol)))
	want := []string{
		fmt.Sprintf("%s %s [10.99.0.20/32] %q", uaIface1, alice.PublicKey, ""),
		fmt.Sprintf("%s %s [10.99.0.4/32] %q", uaIface1, carol.PublicKey, ""),
	}
	if got := configuredPeers(fx.access); !slices.Equal(got, want) {
		t.Errorf("ConfigurePeer calls =\n  %q\nwant\n  %q", got, want)
	}
	if got := fx.calls(); len(got) != 2 {
		t.Errorf("calls = %q, want the two ConfigurePeer calls alone", got)
	}
	fx.reset()

	for _, tc := range []struct {
		name     string
		entry    api.UserAccessProvider
		wantPort int
		wantAddr string
	}{
		{"listen_port", wgProvider(uaID1, "field-team", 51900, "10.99.0.0/24", alice), 51900, "10.99.0.1/24"},
		{"address_pool", wgProvider(uaID1, "field-team", 51900, "10.77.0.0/16", uaDevice("alice-laptop", 1, "10.77.0.2")), 51900, "10.77.0.1/16"},
	} {
		fx.mgr.Apply(t.Context(), uaBlock(tc.entry))
		wantCalls := []string{
			"access.RemoveInterface", "access.CreateInterface", "access.ConfigurePeer",
			"routes.EnableForwarding",
			"rewriter.RemoveMeshSourceRewrite", "rewriter.AddMeshSourceRewrite",
		}
		got := fx.calls()
		if !slices.Equal(got, wantCalls) {
			t.Errorf("%s: calls = %q, want %q", tc.name, got, wantCalls)
		}
		create := fx.access.accessCallsFor("CreateInterface")
		if len(create) != 1 {
			t.Fatalf("%s: CreateInterface calls = %d, want 1", tc.name, len(create))
		}
		if !bytes.Equal(create[0].Args[1].([]byte), key) {
			t.Errorf("%s: the rebuilt interface has another key", tc.name)
		}
		if create[0].Args[2] != tc.wantPort || create[0].Args[3] != tc.wantAddr {
			t.Errorf("%s: CreateInterface(%v, %v), want (%d, %s)", tc.name, create[0].Args[2], create[0].Args[3], tc.wantPort, tc.wantAddr)
		}
		requireUp(t, fx.mgr, uaID1)
		fx.reset()
	}
	if got := logLines(fx.logs, `msg="user access provider removed"`); got != 0 {
		t.Errorf("%d 'user access provider removed' lines for a rebuild, want 0:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="user access provider up"`); got != 3 {
		t.Errorf("%d 'user access provider up' lines, want 3 (the first and two rebuilds):\n%s", got, fx.logs.String())
	}
}

// TestUserAccessManager_ApplyTearsDownAndPrunes checks that a provider the
// block no longer lists loses its interface, its rewrite and its key, that a
// block with Enabled false removes the interfaces and keeps the keys, and
// that the zero block deletes every key.
func TestUserAccessManager_ApplyTearsDownAndPrunes(t *testing.T) {
	fx := newUAFixture(t, nil)
	second := wgProvider(uaID2, "office", 51822, "10.98.0.0/24")
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam, second))
	requireUp(t, fx.mgr, uaID1)
	requireUp(t, fx.mgr, uaID2)
	if got := fx.keyFiles(t); !slices.Equal(got, []string{uaID1 + ".key", uaID2 + ".key"}) {
		t.Fatalf("key files = %q, want both providers'", got)
	}
	fx.reset()

	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	if got := fx.calls(); !slices.Equal(got, []string{"access.RemoveInterface", "rewriter.RemoveMeshSourceRewrite"}) {
		t.Errorf("calls = %q, want the second provider's interface and rewrite removed", got)
	}
	if c := fx.access.accessCallsFor("RemoveInterface"); len(c) != 1 || c[0].Args[0] != uaIface2 {
		t.Errorf("RemoveInterface calls = %+v, want %s", c, uaIface2)
	}
	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != uaIface2 || c[0].Args[1] != uaMesh {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want (%s, %s)", c, uaIface2, uaMesh)
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{uaID1 + ".key"}) {
		t.Errorf("key files = %q, want the listed provider's alone", got)
	}
	if got := providerIDs(fx.mgr); !slices.Equal(got, []string{uaID1}) {
		t.Errorf("providers = %q, want the listed one", got)
	}
	if got := logLines(fx.logs, "level=INFO", `msg="user access provider removed"`, "component=bridge", "provider_id="+uaID2, "interface="+uaIface2); got != 1 {
		t.Errorf("%d 'user access provider removed' lines, want 1:\n%s", got, fx.logs.String())
	}
	fx.reset()

	disabled := uaBlock(fieldTeam)
	disabled.Enabled = false
	fx.mgr.Apply(t.Context(), disabled)
	if c := fx.access.accessCallsFor("RemoveInterface"); len(c) != 1 || c[0].Args[0] != uaIface1 {
		t.Errorf("RemoveInterface calls = %+v, want %s", c, uaIface1)
	}
	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != uaIface1 {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want %s", c, uaIface1)
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{uaID1 + ".key"}) {
		t.Errorf("key files after a block with Enabled false = %q, want the listed provider's kept", got)
	}
	if info := fx.mgr.UserAccessStatus(); info == nil || info.Enabled || len(info.Providers) != 0 {
		t.Errorf("UserAccessStatus() = %+v, want not enabled and no providers", info)
	}
	fx.reset()

	fx.mgr.Apply(t.Context(), api.UserAccessConfig{})
	fx.requireNoCalls(t, "the zero block after a disabled one")
	if got := fx.keyFiles(t); len(got) != 0 {
		t.Errorf("key files after the zero block = %q, want none", got)
	}
	if got := fx.routes.callsFor("DisableForwarding"); len(got) != 0 {
		t.Errorf("DisableForwarding calls = %+v, want none", got)
	}
}

// TestUserAccessManager_ApplyEmptyBlocks applies an empty provider list and
// the zero block to a manager that holds nothing.
func TestUserAccessManager_ApplyEmptyBlocks(t *testing.T) {
	for name, block := range map[string]api.UserAccessConfig{
		"empty providers": {Enabled: true, Providers: []api.UserAccessProvider{}},
		"zero block":      {},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newUAFixture(t, nil)
			fx.mgr.Apply(t.Context(), block)
			fx.requireNoCalls(t, "Apply of "+name)
			if info := fx.mgr.UserAccessStatus(); info == nil || len(info.Providers) != 0 || info.Enabled != block.Enabled {
				t.Errorf("UserAccessStatus() = %+v, want Enabled %v and no providers", info, block.Enabled)
			}
			if got := fx.mgr.ProviderReports(); got == nil || len(got) != 0 {
				t.Errorf("ProviderReports() = %#v, want an empty list from the active manager", got)
			}
			if got := fx.keyFiles(t); len(got) != 0 {
				t.Errorf("key files = %q, want none", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reasons
// ---------------------------------------------------------------------------

// TestUserAccessManager_WireGuardReasons checks the reason each failing step
// of a wireguard bring-up gives, and that a step after the interface was
// created removes it again.
func TestUserAccessManager_WireGuardReasons(t *testing.T) {
	errBoom := errors.New("boom")
	tests := []struct {
		name          string
		inject        func(*uaFixture)
		reason        string
		wantCreate    bool
		wantRemoveIfc bool
	}{
		{"port in use", func(fx *uaFixture) {
			fx.access.createInterfaceErr = fmt.Errorf("bridge: access: bring up: %w", ErrListenPortInUse)
		}, UserAccessReasonBindFailed, true, true},
		{"other create error", func(fx *uaFixture) { fx.access.createInterfaceErr = errBoom }, UserAccessReasonSetupFailed, true, true},
		{"forwarding error", func(fx *uaFixture) { fx.routes.enableForwardingErr = errBoom }, UserAccessReasonSetupFailed, true, true},
		{"rewrite error", func(fx *uaFixture) { fx.rewriter.addMeshSourceRewriteErr = errBoom }, UserAccessReasonSetupFailed, true, true},
		{"unreadable key", func(fx *uaFixture) {
			if err := os.MkdirAll(fx.keyDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fx.keyDir, uaID1+".key"), []byte("not-a-key"), 0600); err != nil {
				t.Fatal(err)
			}
		}, UserAccessReasonKeyUnavailable, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newUAFixture(t, nil)
			tt.inject(fx)
			fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))

			requireDown(t, fx.mgr, uaID1, tt.reason)
			if p := providerInfo(t, fx.mgr, uaID1); p.Interface != "" || p.Devices != 0 {
				t.Errorf("provider = %+v, want no interface and no devices while down", p)
			}
			if got := len(fx.access.accessCallsFor("CreateInterface")) == 1; got != tt.wantCreate {
				t.Errorf("CreateInterface called: %v, want %v", got, tt.wantCreate)
			}
			if c := fx.access.accessCallsFor("RemoveInterface"); (len(c) == 1 && c[0].Args[0] == uaIface1) != tt.wantRemoveIfc {
				t.Errorf("RemoveInterface calls = %+v, want the interface removed: %v", c, tt.wantRemoveIfc)
			}
			if got := fx.access.accessCallsFor("ConfigurePeer"); len(got) != 0 {
				t.Errorf("ConfigurePeer calls = %d, want none", len(got))
			}
			if got := logLines(fx.logs, "level=WARN", `msg="user access provider down"`, "component=bridge",
				"provider_id="+uaID1, "slug=field-team", "kind=wireguard", "reason="+tt.reason, "error="); got != 1 {
				t.Errorf("%d 'user access provider down' lines, want 1:\n%s", got, fx.logs.String())
			}
			if tt.reason == UserAccessReasonKeyUnavailable {
				if data, _ := os.ReadFile(filepath.Join(fx.keyDir, uaID1+".key")); string(data) != "not-a-key" {
					t.Errorf("key file = %q, want it untouched", data)
				}
			}
		})
	}
}

// TestUserAccessManager_InvalidProviders checks every case of a provider's
// own checks, and that an entry with an invalid or repeated id gets no state.
func TestUserAccessManager_InvalidProviders(t *testing.T) {
	// The last 8 hex digits of this id are those of uaID1.
	const clashID = "0190a8b8-ffff-7a0a-8a0a-0000a0a0a0e1"
	tests := []struct {
		name    string
		entries []api.UserAccessProvider
		id      string // the provider that reads invalid_provider
	}{
		{"listen_port 0", []api.UserAccessProvider{wgProvider(uaID1, "a", 0, "10.99.0.0/24")}, uaID1},
		{"listen_port 65536", []api.UserAccessProvider{wgProvider(uaID1, "a", 65536, "10.99.0.0/24")}, uaID1},
		{"no address_pool", []api.UserAccessProvider{wgProvider(uaID1, "a", 51821, "")}, uaID1},
		{"address_pool not a prefix", []api.UserAccessProvider{wgProvider(uaID1, "a", 51821, "10.99.0.0")}, uaID1},
		{"IPv6 address_pool", []api.UserAccessProvider{wgProvider(uaID1, "a", 51821, "fd00::/64")}, uaID1},
		{"address_pool /31", []api.UserAccessProvider{wgProvider(uaID1, "a", 51821, "10.99.0.0/31")}, uaID1},
		{"interface name of an earlier provider", []api.UserAccessProvider{
			wgProvider(uaID1, "a", 51821, "10.99.0.0/24"),
			wgProvider(clashID, "b", 51822, "10.98.0.0/24"),
		}, clashID},
		{"auth_secret_name outside the grammar", []api.UserAccessProvider{vendorProvider(uaID2, "t", api.UserAccessKindTailscale, "TS Join")}, uaID2},
		{"no auth_secret_name", []api.UserAccessProvider{vendorProvider(uaID2, "t", api.UserAccessKindNetbird, "")}, uaID2},
		{"kind of an earlier provider", []api.UserAccessProvider{
			vendorProvider(uaID2, "t1", api.UserAccessKindTailscale, "ts-join"),
			vendorProvider(uaID3, "t2", api.UserAccessKindTailscale, "ts-join"),
		}, uaID3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newUAFixture(t, nil)
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
			fx.secrets.set("ts-join", 1, "tskey")
			fx.mgr.Apply(t.Context(), uaBlock(tt.entries...))
			requireDown(t, fx.mgr, tt.id, UserAccessReasonInvalidProvider)
			if got := logLines(fx.logs, `msg="user access provider down"`, "provider_id="+tt.id, "reason=invalid_provider"); got != 1 {
				t.Errorf("%d down lines for the provider, want 1:\n%s", got, fx.logs.String())
			}
			// The earlier provider is served.
			if tt.id != tt.entries[0].ID {
				requireUp(t, fx.mgr, tt.entries[0].ID)
			} else if got := fx.calls(); len(got) != 0 {
				t.Errorf("calls = %q, want none for an invalid provider", got)
			}
		})
	}

	t.Run("invalid and repeated ids", func(t *testing.T) {
		fx := newUAFixture(t, nil)
		repeated := wgProvider(strings.ToUpper(uaID1), "again", 51830, "10.97.0.0/24")
		block := uaBlock(
			wgProvider("not-a-uuid", "nouuid", 51829, "10.96.0.0/24"),
			fieldTeam,
			repeated,
			wgProvider("00000000-0000-0000-0000-000000000000", "zero", 51831, "10.95.0.0/24"),
		)
		fx.mgr.Apply(t.Context(), block)
		if got := providerIDs(fx.mgr); !slices.Equal(got, []string{uaID1}) {
			t.Errorf("providers = %q, want field-team alone", got)
		}
		requireUp(t, fx.mgr, uaID1)
		if got := len(fx.access.accessCallsFor("CreateInterface")); got != 1 {
			t.Errorf("CreateInterface calls = %d, want 1", got)
		}
		for _, id := range []string{"not-a-uuid", strings.ToUpper(uaID1), "00000000-0000-0000-0000-000000000000"} {
			if got := logLines(fx.logs, "level=WARN", `msg="user access provider down"`, "provider_id="+id, "reason=invalid_provider"); got != 1 {
				t.Errorf("%d down lines for %s, want 1:\n%s", got, id, fx.logs.String())
			}
		}
		// An unchanged block logs nothing again.
		fx.mgr.Apply(t.Context(), block)
		if got := logLines(fx.logs, `msg="user access provider down"`); got != 3 {
			t.Errorf("%d down lines after a second Apply, want still 3:\n%s", got, fx.logs.String())
		}
	})
}

// TestUserAccessManager_KindNotServed checks that a nil Rewriter serves no
// kind, and that an unknown kind and a vendor kind without a client are not
// served either.
func TestUserAccessManager_KindNotServed(t *testing.T) {
	block := uaBlock(
		fieldTeam,
		vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join"),
		vendorProvider(uaID3, "netbird", api.UserAccessKindNetbird, "nb-setup"),
	)
	inventory := []api.NodeStateSecret{{Name: "ts-join", Version: 1}, {Name: "nb-setup", Version: 1}}

	t.Run("nil Rewriter", func(t *testing.T) {
		fx := newUAFixture(t, func(d *UserAccessDeps) { d.Rewriter = nil })
		fx.secrets.set("ts-join", 1, "tskey")
		fx.secrets.set("nb-setup", 1, "nbkey")
		fx.mgr.SyncSecretInventory(t.Context(), inventory)
		fx.mgr.Apply(t.Context(), block)
		for _, id := range []string{uaID1, uaID2, uaID3} {
			requireDown(t, fx.mgr, id, UserAccessReasonKindNotServed)
		}
		fx.requireNoCalls(t, "Apply without a Rewriter")
		if len(fx.secrets.fetches()) != 0 || len(fx.tailscale.startCalls()) != 0 || len(fx.netbird.startCalls()) != 0 {
			t.Error("a vendor provider was fetched or started without a Rewriter")
		}
		// Key files are still pruned and kept by the block.
		if got := fx.keyFiles(t); len(got) != 0 {
			t.Errorf("key files = %q, want none: no wireguard provider came up", got)
		}
	})

	t.Run("unknown kind", func(t *testing.T) {
		fx := newUAFixture(t, nil)
		fx.mgr.Apply(t.Context(), uaBlock(api.UserAccessProvider{ID: uaID1, Slug: "vpn", Kind: "openvpn"}))
		requireDown(t, fx.mgr, uaID1, UserAccessReasonKindNotServed)
		fx.requireNoCalls(t, "Apply of an openvpn provider")
	})

	t.Run("no client", func(t *testing.T) {
		fx := newUAFixture(t, func(d *UserAccessDeps) { delete(d.Clients, api.UserAccessKindNetbird) })
		fx.secrets.set("nb-setup", 1, "nbkey")
		fx.mgr.SyncSecretInventory(t.Context(), inventory)
		fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID3, "netbird", api.UserAccessKindNetbird, "nb-setup")))
		requireDown(t, fx.mgr, uaID3, UserAccessReasonKindNotServed)
		if len(fx.secrets.fetches()) != 0 {
			t.Error("the Secret of a kind without a client was fetched")
		}
	})
}

// TestUserAccessManager_OneFailingProviderLeavesTheOthersUp brings up a block
// in which one wireguard provider cannot bind and one vendor provider has no
// Secret: the other wireguard provider and the other vendor provider are up.
func TestUserAccessManager_OneFailingProviderLeavesTheOthersUp(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.access.createInterfaceErrFor = map[string]error{uaIface1: fmt.Errorf("bind: %w", ErrListenPortInUse)}
	fx.secrets.set("nb-setup", 1, "nbkey")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("nb-setup", 1))
	fx.mgr.Apply(t.Context(), uaBlock(
		fieldTeam,
		wgProvider(uaID2, "office", 51822, "10.98.0.0/24", uaDevice("dave", 4, "10.98.0.2")),
		vendorProvider(uaID3, "tailnet", api.UserAccessKindTailscale, "ts-join"),
		vendorProvider("0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4", "netbird", api.UserAccessKindNetbird, "nb-setup"),
	))

	requireDown(t, fx.mgr, uaID1, UserAccessReasonBindFailed)
	if p := requireUp(t, fx.mgr, uaID2); p.Interface != uaIface2 || p.Devices != 1 {
		t.Errorf("office = %+v, want up on %s with its device", p, uaIface2)
	}
	requireDown(t, fx.mgr, uaID3, UserAccessReasonAuthSecretNotListed)
	if p := requireUp(t, fx.mgr, "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4"); p.Interface != "wt0" {
		t.Errorf("netbird = %+v, want up on wt0", p)
	}
	if got := providerIDs(fx.mgr); !slices.Equal(got, []string{uaID1, uaID2, uaID3, "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4"}) {
		t.Errorf("providers = %q, want all four in block order", got)
	}
}

// TestUserAccessManager_SkipsDevicesItCannotServe checks that a device the
// provider cannot serve is skipped with one Warn while the provider is up and
// its other devices are configured.
func TestUserAccessManager_SkipsDevicesItCannotServe(t *testing.T) {
	devices := []api.UserAccessDevice{
		alice,
		{ID: "dev-bad-key", Slug: "bad-key", PublicKey: "not-a-key", Address: "10.99.0.5"},
		{ID: "dev-short-key", Slug: "short-key", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 31)), Address: "10.99.0.6"},
		uaDevice("outside", 5, "10.98.0.7"),
		uaDevice("v6", 6, "fd00::7"),
		uaDevice("no-address", 7, "not-an-address"),
		uaDevice("interface", 8, "10.99.0.1"),
		uaDevice("same-key", 1, "10.99.0.9"),
		uaDevice("same-address", 9, "10.99.0.2"),
		bob,
	}
	fx := newUAFixture(t, nil)
	block := uaBlock(wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", devices...))
	fx.mgr.Apply(t.Context(), block)

	if p := requireUp(t, fx.mgr, uaID1); p.Devices != 2 {
		t.Errorf("devices = %d, want 2", p.Devices)
	}
	want := []string{
		fmt.Sprintf("%s %s [10.99.0.2/32] %q", uaIface1, alice.PublicKey, ""),
		fmt.Sprintf("%s %s [10.99.0.3/32] %q", uaIface1, bob.PublicKey, ""),
	}
	if got := configuredPeers(fx.access); !slices.Equal(got, want) {
		t.Errorf("ConfigurePeer calls =\n  %q\nwant\n  %q", got, want)
	}
	for _, tc := range []struct{ device, reason string }{
		{"dev-bad-key", "invalid_public_key"},
		{"dev-short-key", "invalid_public_key"},
		{"dev-outside", "address_outside_pool"},
		{"dev-v6", "invalid_address"},
		{"dev-no-address", "invalid_address"},
		{"dev-interface", "address_is_interface"},
		{"dev-same-key", "duplicate_public_key"},
		{"dev-same-address", "duplicate_address"},
	} {
		if got := logLines(fx.logs, "level=WARN", `msg="user access device not served"`, "component=bridge",
			"provider_id="+uaID1, "device_id="+tc.device+" ", "reason="+tc.reason); got != 1 {
			t.Errorf("%d 'device not served' lines for %s with %s, want 1:\n%s", got, tc.device, tc.reason, fx.logs.String())
		}
	}

	// An unchanged block logs no skip again.
	fx.reset()
	fx.mgr.Apply(t.Context(), block)
	fx.requireNoCalls(t, "a second Apply")
	if got := logLines(fx.logs, `msg="user access device not served"`); got != 8 {
		t.Errorf("%d 'device not served' lines after a second Apply, want still 8", got)
	}

	// A device the controller fails to configure is skipped, and tried again
	// by the next Apply.
	fx.access.configurePeerErrFor = map[string]error{carol.PublicKey: errors.New("netlink: boom")}
	withCarol := uaBlock(wgProvider(uaID1, "field-team", 51821, "10.99.0.0/24", alice, bob, carol))
	fx.mgr.Apply(t.Context(), withCarol)
	requireUp(t, fx.mgr, uaID1)
	if got := logLines(fx.logs, `msg="user access device not served"`, "device_id=dev-carol-tablet", "reason=configure_failed", "error="); got != 1 {
		t.Errorf("%d configure_failed lines, want 1:\n%s", got, fx.logs.String())
	}
	fx.access.configurePeerErrFor = nil
	fx.reset()
	fx.mgr.Apply(t.Context(), withCarol)
	if got := configuredPeers(fx.access); len(got) != 1 || !strings.Contains(got[0], carol.PublicKey) {
		t.Errorf("ConfigurePeer calls = %q, want carol again", got)
	}
	if p := requireUp(t, fx.mgr, uaID1); p.Devices != 3 {
		t.Errorf("devices = %d, want 3", p.Devices)
	}
}

// ---------------------------------------------------------------------------
// Vendor providers
// ---------------------------------------------------------------------------

func TestUserAccessManager_VendorProviderUp(t *testing.T) {
	for _, tc := range []struct {
		kind, secret, iface string
		client              func(*uaFixture) *mockUserAccessClient
	}{
		{api.UserAccessKindTailscale, "ts-join", "tailscale0", func(fx *uaFixture) *mockUserAccessClient { return fx.tailscale }},
		{api.UserAccessKindNetbird, "nb-setup", "wt0", func(fx *uaFixture) *mockUserAccessClient { return fx.netbird }},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			fx := newUAFixture(t, nil)
			const value = "  join-key-1234\n"
			fx.secrets.set(tc.secret, 3, value)
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf(tc.secret, 3))
			fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "vendor", tc.kind, tc.secret)))

			client := tc.client(fx)
			if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{tc.secret, 3}}) {
				t.Errorf("fetches = %v, want the listed version", got)
			}
			starts := client.startCalls()
			if len(starts) != 1 || starts[0].key != "join-key-1234" || starts[0].meshCIDR != uaMeshCIDR {
				t.Fatalf("Start calls = %+v, want one with the trimmed key and %s", starts, uaMeshCIDR)
			}
			if _, ok := starts[0].ctx.Deadline(); ok {
				t.Error("the client starts under a context with a deadline, want the manager's")
			}
			if c := fx.routes.callsFor("EnableForwarding"); len(c) != 1 || c[0].Args[0] != uaMesh || c[0].Args[1] != tc.iface {
				t.Errorf("EnableForwarding calls = %+v, want (%s, %s)", c, uaMesh, tc.iface)
			}
			if c := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != tc.iface || c[0].Args[1] != uaMesh {
				t.Errorf("AddMeshSourceRewrite calls = %+v, want (%s, %s)", c, tc.iface, uaMesh)
			}
			if len(fx.access.accessMethods()) != 0 {
				t.Errorf("access calls = %q, want none for a vendor provider", fx.access.accessMethods())
			}
			p := requireUp(t, fx.mgr, uaID2)
			if p.Interface != tc.iface || p.ListenPort != 0 || p.Devices != 0 {
				t.Errorf("provider = %+v, want up on %s without port or devices", p, tc.iface)
			}
			if got := logLines(fx.logs, "level=INFO", `msg="user access provider up"`, "provider_id="+uaID2, "kind="+tc.kind, "interface="+tc.iface); got != 1 {
				t.Errorf("%d up lines, want 1:\n%s", got, fx.logs.String())
			}
			if strings.Contains(fx.logs.String(), "listen_port") {
				t.Error("the up line of a vendor provider names a listen_port")
			}
			if strings.Contains(fx.logs.String(), "join-key-1234") {
				t.Error("the log carries the Secret's value")
			}

			// A new version of the Secret leaves the join alone.
			fx.secrets.set(tc.secret, 4, "join-key-5678")
			fx.reset()
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf(tc.secret, 4))
			fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "vendor", tc.kind, tc.secret)))
			fx.requireNoCalls(t, "a new Secret version")
			if len(client.startCalls()) != 1 || client.stopCalls() != 0 {
				t.Errorf("starts, stops = %d, %d after a new Secret version, want 1, 0", len(client.startCalls()), client.stopCalls())
			}

			// Another auth_secret_name restarts the client with the version
			// the inventory lists.
			fx.secrets.set("other", 2, "join-key-other")
			fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: tc.secret, Version: 4}, {Name: "other", Version: 2}})
			fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "vendor", tc.kind, "other")))
			if client.stopCalls() != 1 {
				t.Errorf("stops = %d after a changed auth_secret_name, want 1", client.stopCalls())
			}
			starts = client.startCalls()
			if len(starts) != 2 || starts[1].key != "join-key-other" {
				t.Errorf("Start calls = %+v, want a second with the other Secret's value", starts)
			}
			if got := fx.rewriter.methods(); !slices.Equal(got, []string{"RemoveMeshSourceRewrite", "AddMeshSourceRewrite"}) {
				t.Errorf("rewriter calls = %q, want the rewrite removed and added again", got)
			}
			requireUp(t, fx.mgr, uaID2)

			// Removing the provider stops its client and removes its rewrite.
			fx.reset()
			fx.mgr.Apply(t.Context(), uaBlock())
			if client.stopCalls() != 2 {
				t.Errorf("stops = %d after the provider was removed, want 2", client.stopCalls())
			}
			if got := fx.calls(); !slices.Equal(got, []string{"rewriter.RemoveMeshSourceRewrite"}) {
				t.Errorf("calls = %q, want the rewrite removed alone", got)
			}
			if got := logLines(fx.logs, `msg="user access provider removed"`, "provider_id="+uaID2, "interface="+tc.iface); got != 1 {
				t.Errorf("%d removed lines, want 1:\n%s", got, fx.logs.String())
			}
		})
	}
}

func TestUserAccessManager_VendorReasons(t *testing.T) {
	errBoom := errors.New("boom")
	tests := []struct {
		name      string
		kind      string
		adjust    func(*UserAccessDeps)
		inject    func(*uaFixture)
		inventory []api.NodeStateSecret
		reason    string
		wantFetch bool
		wantStart bool
		wantStops int
	}{
		{
			name: "no mesh CIDR", kind: api.UserAccessKindTailscale,
			adjust:    func(d *UserAccessDeps) { d.MeshCIDR = "" },
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonSetupFailed,
		},
		{
			name: "not listed", kind: api.UserAccessKindTailscale,
			inventory: inventoryOf("other", 1),
			reason:    UserAccessReasonAuthSecretNotListed,
		},
		{
			name: "fetch refused", kind: api.UserAccessKindTailscale,
			inject: func(fx *uaFixture) {
				fx.secrets.setErr(fmt.Errorf("fetch secret: %w", &api.APIError{StatusCode: 403, Message: "forbidden"}))
			},
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonAuthSecretUnreadable, wantFetch: true,
		},
		{
			name: "client missing", kind: api.UserAccessKindNetbird,
			inject: func(fx *uaFixture) {
				fx.netbird.startErr = fmt.Errorf("bridge: netbird: up failed: %w", &exec.Error{Name: "netbird", Err: exec.ErrNotFound})
			},
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonClientMissing, wantFetch: true, wantStart: true,
		},
		{
			name: "join refused", kind: api.UserAccessKindTailscale,
			inject:    func(fx *uaFixture) { fx.tailscale.startErr = errBoom },
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonJoinFailed, wantFetch: true, wantStart: true,
		},
		{
			name: "no interface", kind: api.UserAccessKindTailscale,
			inject:    func(fx *uaFixture) { fx.tailscale.iface = "" },
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonJoinFailed, wantFetch: true, wantStart: true, wantStops: 1,
		},
		{
			name: "forwarding error", kind: api.UserAccessKindTailscale,
			inject:    func(fx *uaFixture) { fx.routes.enableForwardingErr = errBoom },
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonSetupFailed, wantFetch: true, wantStart: true, wantStops: 1,
		},
		{
			name: "rewrite error", kind: api.UserAccessKindNetbird,
			inject:    func(fx *uaFixture) { fx.rewriter.addMeshSourceRewriteErr = errBoom },
			inventory: inventoryOf("ts-join", 1),
			reason:    UserAccessReasonSetupFailed, wantFetch: true, wantStart: true, wantStops: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newUAFixture(t, tt.adjust)
			fx.secrets.set("ts-join", 1, "tskey")
			if tt.inject != nil {
				tt.inject(fx)
			}
			client := fx.tailscale
			if tt.kind == api.UserAccessKindNetbird {
				client = fx.netbird
			}
			fx.mgr.SyncSecretInventory(t.Context(), tt.inventory)
			fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "vendor", tt.kind, "ts-join")))

			requireDown(t, fx.mgr, uaID2, tt.reason)
			if got := len(fx.secrets.fetches()) > 0; got != tt.wantFetch {
				t.Errorf("fetched: %v, want %v", got, tt.wantFetch)
			}
			if got := len(client.startCalls()) > 0; got != tt.wantStart {
				t.Errorf("started: %v, want %v", got, tt.wantStart)
			}
			if got := client.stopCalls(); got != tt.wantStops {
				t.Errorf("stops = %d, want %d", got, tt.wantStops)
			}
			if p := providerInfo(t, fx.mgr, uaID2); p.Interface != "" {
				t.Errorf("provider = %+v, want no interface while down", p)
			}
			if got := logLines(fx.logs, "level=WARN", `msg="user access provider down"`, "provider_id="+uaID2, "kind="+tt.kind, "reason="+tt.reason); got != 1 {
				t.Errorf("%d down lines, want 1:\n%s", got, fx.logs.String())
			}
			if strings.Contains(fx.logs.String(), "tskey") {
				t.Error("the log carries the Secret's value")
			}
		})
	}

	// A netbird provider needs no mesh CIDR: NetBird defines the route.
	t.Run("netbird without a mesh CIDR", func(t *testing.T) {
		fx := newUAFixture(t, func(d *UserAccessDeps) { d.MeshCIDR = "" })
		fx.secrets.set("nb-setup", 1, "nbkey")
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("nb-setup", 1))
		fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID3, "netbird", api.UserAccessKindNetbird, "nb-setup")))
		requireUp(t, fx.mgr, uaID3)
		if starts := fx.netbird.startCalls(); len(starts) != 1 || starts[0].meshCIDR != "" {
			t.Errorf("Start calls = %+v, want one without a mesh CIDR", starts)
		}
	})
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

// TestUserAccessManager_SyncSecretInventoryRetries checks that a provider
// down for auth_secret_not_listed is brought up once the inventory lists its
// Secret and its next attempt is due on the manager's clock, not before.
func TestUserAccessManager_SyncSecretInventoryRetries(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.secrets.set("ts-join", 1, "tskey")
	fx.mgr.SyncSecretInventory(t.Context(), nil)
	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	requireDown(t, fx.mgr, uaID2, UserAccessReasonAuthSecretNotListed)

	fx.clock.Add(4 * time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	requireDown(t, fx.mgr, uaID2, UserAccessReasonAuthSecretNotListed)
	if len(fx.secrets.fetches()) != 0 {
		t.Fatalf("fetches = %v before the 5 s delay passed, want none", fx.secrets.fetches())
	}

	fx.clock.Add(time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	requireUp(t, fx.mgr, uaID2)
	if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{"ts-join", 1}}) {
		t.Errorf("fetches = %v, want the listed version once", got)
	}
	if got := logLines(fx.logs, `msg="user access provider down"`); got != 1 {
		t.Errorf("%d down lines, want 1:\n%s", got, fx.logs.String())
	}
}

// TestUserAccessManager_RetryDelays checks the delays between the attempts of
// a provider that keeps failing: 5 s doubling to 60 s, and the Retry-After of
// an API error when that is longer, and that the down line is logged once.
func TestUserAccessManager_RetryDelays(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.secrets.set("ts-join", 1, "tskey")
	fx.tailscale.startErr = errors.New("coordination server unreachable")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	started := 1
	requireDelay := func(d time.Duration) {
		t.Helper()
		fx.clock.Add(d - time.Second)
		fx.mgr.Retry(t.Context())
		if got := len(fx.tailscale.startCalls()); got != started {
			t.Fatalf("%v after the failure: %d starts, want %d", d-time.Second, got, started)
		}
		fx.clock.Add(time.Second)
		fx.mgr.Retry(t.Context())
		started++
		if got := len(fx.tailscale.startCalls()); got != started {
			t.Fatalf("%v after the failure: %d starts, want %d", d, got, started)
		}
	}
	for _, d := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second} {
		requireDelay(d)
	}
	requireDown(t, fx.mgr, uaID2, UserAccessReasonJoinFailed)
	if got := logLines(fx.logs, `msg="user access provider down"`, "reason=join_failed"); got != 1 {
		t.Errorf("%d down lines across the retries, want 1:\n%s", got, fx.logs.String())
	}

	// A fetch refused with a Retry-After longer than the delay waits for it.
	fx.secrets.setErr(&api.APIError{StatusCode: 429, Message: "rate limited", RetryAfter: 120 * time.Second})
	fx.clock.Add(60 * time.Second)
	fx.mgr.Retry(t.Context())
	requireDown(t, fx.mgr, uaID2, UserAccessReasonAuthSecretUnreadable)
	fetched := len(fx.secrets.fetches())
	fx.clock.Add(119 * time.Second)
	fx.mgr.Retry(t.Context())
	if got := len(fx.secrets.fetches()); got != fetched {
		t.Fatalf("%d fetches 119 s after a Retry-After of 120 s, want %d", got, fetched)
	}
	fx.secrets.setErr(nil)
	fx.tailscale.set(func(c *mockUserAccessClient) { c.startErr = nil })
	fx.clock.Add(time.Second)
	fx.mgr.Retry(t.Context())
	requireUp(t, fx.mgr, uaID2)
	if got := logLines(fx.logs, `msg="user access provider down"`); got != 2 {
		t.Errorf("%d down lines, want one per reason:\n%s", got, fx.logs.String())
	}
}

// TestUserAccessManager_RetryBringsUpAWireGuardProvider retries a provider
// whose port was taken, and attempts a changed entry at once.
func TestUserAccessManager_RetryBringsUpAWireGuardProvider(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.access.createInterfaceErr = fmt.Errorf("bind: %w", ErrListenPortInUse)
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	requireDown(t, fx.mgr, uaID1, UserAccessReasonBindFailed)

	// A pull without a secrets block retries through the pull handler.
	handler := UserAccessPullHandler(fx.mgr)
	fx.clock.Add(4 * time.Second)
	handler(t.Context(), &api.NodeStateSnapshot{})
	if got := len(fx.access.accessCallsFor("CreateInterface")); got != 1 {
		t.Fatalf("CreateInterface calls = %d before the delay, want 1", got)
	}
	fx.clock.Add(time.Second)
	handler(t.Context(), &api.NodeStateSnapshot{})
	if got := len(fx.access.accessCallsFor("CreateInterface")); got != 2 {
		t.Fatalf("CreateInterface calls = %d after the delay, want 2", got)
	}
	requireDown(t, fx.mgr, uaID1, UserAccessReasonBindFailed)

	// A changed listen_port is attempted at once, with the backoff reset.
	fx.access.createInterfaceErr = nil
	fx.mgr.Apply(t.Context(), uaBlock(wgProvider(uaID1, "field-team", 51900, "10.99.0.0/24", alice, bob)))
	if got := len(fx.access.accessCallsFor("CreateInterface")); got != 3 {
		t.Fatalf("CreateInterface calls = %d after the changed entry, want 3", got)
	}
	if p := requireUp(t, fx.mgr, uaID1); p.ListenPort != 51900 || p.Devices != 2 {
		t.Errorf("provider = %+v, want up on 51900 with both devices", p)
	}
}

// TestUserAccessManager_NeverRetriesInvalidOrNotServed checks that Retry and
// SyncSecretInventory never bring up a provider down for invalid_provider or
// kind_not_served.
func TestUserAccessManager_NeverRetriesInvalidOrNotServed(t *testing.T) {
	fx := newUAFixture(t, func(d *UserAccessDeps) { delete(d.Clients, api.UserAccessKindNetbird) })
	fx.secrets.set("nb-setup", 1, "nbkey")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("nb-setup", 1))
	fx.mgr.Apply(t.Context(), uaBlock(
		wgProvider(uaID1, "field-team", 0, "10.99.0.0/24"),
		api.UserAccessProvider{ID: uaID2, Slug: "vpn", Kind: "openvpn"},
		vendorProvider(uaID3, "netbird", api.UserAccessKindNetbird, "nb-setup"),
	))
	requireDown(t, fx.mgr, uaID1, UserAccessReasonInvalidProvider)
	requireDown(t, fx.mgr, uaID2, UserAccessReasonKindNotServed)
	requireDown(t, fx.mgr, uaID3, UserAccessReasonKindNotServed)

	// Make a retry observable. With a netbird client in place, an attempt
	// on the netbird provider would fetch its Secret and start the client,
	// and every attempt on any provider counts in its attempts.
	fx.mgr.mu.Lock()
	fx.mgr.clients[api.UserAccessKindNetbird] = fx.netbird
	attempts := make(map[string]int)
	for _, p := range fx.mgr.providers {
		attempts[p.entry.ID] = p.attempts
	}
	fx.mgr.mu.Unlock()

	for range 3 {
		fx.clock.Add(time.Hour)
		fx.mgr.Retry(t.Context())
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("nb-setup", 1))
	}
	fx.requireNoCalls(t, "Retry")
	if len(fx.secrets.fetches()) != 0 {
		t.Errorf("fetches = %v, want none", fx.secrets.fetches())
	}
	if starts := fx.netbird.startCalls(); len(starts) != 0 {
		t.Errorf("netbird starts = %d, want none", len(starts))
	}
	fx.mgr.mu.Lock()
	for _, p := range fx.mgr.providers {
		if p.attempts != attempts[p.entry.ID] {
			t.Errorf("provider %s: attempts = %d after Retry, want %d", p.entry.ID, p.attempts, attempts[p.entry.ID])
		}
	}
	fx.mgr.mu.Unlock()
	requireDown(t, fx.mgr, uaID1, UserAccessReasonInvalidProvider)
	requireDown(t, fx.mgr, uaID3, UserAccessReasonKindNotServed)
	if got := logLines(fx.logs, `msg="user access provider down"`); got != 3 {
		t.Errorf("%d down lines, want 3:\n%s", got, fx.logs.String())
	}
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

func TestUserAccessManager_Teardown(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.secrets.set("ts-join", 1, "tskey")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam, vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	requireUp(t, fx.mgr, uaID1)
	requireUp(t, fx.mgr, uaID2)
	runCtx := fx.tailscale.startCalls()[0].ctx
	fx.reset()

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if fx.tailscale.stopCalls() != 1 {
		t.Errorf("client stops = %d, want 1", fx.tailscale.stopCalls())
	}
	if c := fx.access.accessCallsFor("RemoveInterface"); len(c) != 1 || c[0].Args[0] != uaIface1 {
		t.Errorf("RemoveInterface calls = %+v, want %s", c, uaIface1)
	}
	var rewrites []string
	for _, c := range fx.rewriter.callsFor("RemoveMeshSourceRewrite") {
		rewrites = append(rewrites, c.Args[0].(string))
	}
	if !slices.Equal(rewrites, []string{uaIface1, "tailscale0"}) {
		t.Errorf("rewrites removed = %q, want both providers'", rewrites)
	}
	if got := fx.routes.callsFor("DisableForwarding"); len(got) != 0 {
		t.Errorf("DisableForwarding calls = %+v, want none", got)
	}
	if runCtx.Err() == nil {
		t.Error("the context the clients run under is not cancelled")
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{uaID1 + ".key"}) {
		t.Errorf("key files after Teardown = %q, want the provider's kept", got)
	}
	if fx.mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus() after Teardown is not nil")
	}
	if got := logLines(fx.logs, `msg="user access manager stopped"`, "component=bridge"); got != 1 {
		t.Errorf("%d 'user access manager stopped' lines, want 1:\n%s", got, fx.logs.String())
	}

	// Inactive, the manager does nothing.
	fx.reset()
	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	fx.clock.Add(time.Hour)
	fx.mgr.Retry(t.Context())
	fx.requireNoCalls(t, "the inactive manager")
	if fx.mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus() of the inactive manager is not nil")
	}
}

func TestUserAccessManager_TeardownJoinsErrors(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.secrets.set("ts-join", 1, "tskey")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))
	fx.mgr.Apply(t.Context(), uaBlock(fieldTeam, vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	errIface, errStop, errRewrite := errors.New("remove iface"), errors.New("stop client"), errors.New("remove rewrite")
	fx.access.removeInterfaceErr = errIface
	fx.tailscale.set(func(c *mockUserAccessClient) { c.stopErr = errStop })
	fx.rewriter.removeMeshSourceRewriteErr = errRewrite

	err := fx.mgr.Teardown()
	for _, want := range []error{errIface, errStop, errRewrite} {
		if !errors.Is(err, want) {
			t.Errorf("Teardown = %v, want it to wrap %v", err, want)
		}
	}
	if got := len(fx.rewriter.callsFor("RemoveMeshSourceRewrite")); got != 2 {
		t.Errorf("RemoveMeshSourceRewrite calls = %d, want 2: a failure does not stop the cleanup", got)
	}
	if fx.mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus() after a failed Teardown is not nil")
	}
	if err := fx.mgr.Teardown(); err != nil {
		t.Errorf("second Teardown = %v, want nil", err)
	}
}

// TestUserAccessManager_TeardownDuringAJoin tears the manager down while a
// client starts outside the manager's mutex: the join that finishes after
// Teardown stops the client it started, and serves nothing.
func TestUserAccessManager_TeardownDuringAJoin(t *testing.T) {
	fx := newUAFixture(t, nil)
	fx.secrets.set("ts-join", 1, "tskey")
	started, release := make(chan struct{}), make(chan struct{})
	fx.tailscale.startHook = func() {
		close(started)
		<-release
	}
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("ts-join", 1))

	done := make(chan struct{})
	go func() {
		defer close(done)
		fx.mgr.Apply(context.Background(), uaBlock(vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	}()
	<-started
	// The join runs outside the mutex: the status reads the provider's
	// absence and Teardown completes.
	if info := fx.mgr.UserAccessStatus(); info == nil || len(info.Providers) != 0 {
		t.Errorf("UserAccessStatus() during the first join = %+v, want no provider yet", info)
	}
	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if fx.tailscale.stopCalls() != 0 {
		t.Errorf("client stops = %d before the join returned, want 0", fx.tailscale.stopCalls())
	}
	close(release)
	<-done

	if fx.tailscale.stopCalls() != 1 {
		t.Errorf("client stops = %d after the join returned, want 1", fx.tailscale.stopCalls())
	}
	if got := fx.routes.callsFor("EnableForwarding"); len(got) != 0 {
		t.Errorf("EnableForwarding calls = %+v, want none after Teardown", got)
	}
	if got := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(got) != 0 {
		t.Errorf("AddMeshSourceRewrite calls = %+v, want none after Teardown", got)
	}
	if fx.mgr.UserAccessStatus() != nil {
		t.Error("UserAccessStatus() after Teardown is not nil")
	}
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func TestUserAccessPullHandler(t *testing.T) {
	fx := newUAFixture(t, nil)
	handler := UserAccessPullHandler(fx.mgr)
	fx.secrets.set("ts-join", 1, "tskey")
	fx.tailscale.startErr = errors.New("join refused")

	inventory := inventoryOf("ts-join", 1)
	handler(t.Context(), &api.NodeStateSnapshot{Secrets: &inventory})
	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")))
	requireDown(t, fx.mgr, uaID2, UserAccessReasonJoinFailed)

	// A nil snapshot changes nothing; a pull without a secrets block keeps
	// the inventory the manager holds, so the retry fetches the listed
	// version.
	fx.tailscale.set(func(c *mockUserAccessClient) { c.startErr = nil })
	fx.clock.Add(5 * time.Second)
	handler(t.Context(), nil)
	requireDown(t, fx.mgr, uaID2, UserAccessReasonJoinFailed)
	handler(t.Context(), &api.NodeStateSnapshot{})
	requireUp(t, fx.mgr, uaID2)
	if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{"ts-join", 1}, {"ts-join", 1}}) {
		t.Errorf("fetches = %v, want the held version twice", got)
	}

	// An empty inventory replaces the held one: the next join finds the
	// Secret not listed.
	fx.mgr.Apply(t.Context(), uaBlock(vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join-2")))
	empty := []api.NodeStateSecret{}
	handler(t.Context(), &api.NodeStateSnapshot{Secrets: &empty})
	requireDown(t, fx.mgr, uaID2, UserAccessReasonAuthSecretNotListed)
}

func TestUserAccessReconcileHandler(t *testing.T) {
	withProviders := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{UserAccess: &api.UserAccessConfig{
		Enabled:   true,
		Providers: []api.UserAccessProvider{fieldTeam, vendorProvider(uaID2, "tailnet", api.UserAccessKindTailscale, "ts-join")},
	}}}
	bridgeChanged := reconcile.StateDiff{BridgeChanged: true}

	t.Run("with a manager", func(t *testing.T) {
		fx := newUAFixture(t, nil)
		handler := UserAccessReconcileHandler(fx.mgr, discardLogger())
		if err := handler(t.Context(), withProviders, bridgeChanged); err != nil {
			t.Fatalf("handler = %v, want nil", err)
		}
		requireUp(t, fx.mgr, uaID1)
		// The vendor provider is down without an inventory, and the handler
		// still returns nil.
		requireDown(t, fx.mgr, uaID2, UserAccessReasonAuthSecretNotListed)

		// A nil snapshot changes nothing.
		fx.reset()
		if err := handler(t.Context(), nil, bridgeChanged); err != nil {
			t.Fatalf("handler(nil) = %v, want nil", err)
		}
		fx.requireNoCalls(t, "a nil snapshot")
		requireUp(t, fx.mgr, uaID1)

		// A block with Enabled false serves nothing and keeps the keys.
		disabled := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{UserAccess: &api.UserAccessConfig{Providers: withProviders.Bridge.UserAccess.Providers}}}
		if err := handler(t.Context(), disabled, bridgeChanged); err != nil {
			t.Fatalf("handler(disabled) = %v, want nil", err)
		}
		if got := providerIDs(fx.mgr); len(got) != 0 {
			t.Errorf("providers after a disabled block = %q, want none", got)
		}
		if got := fx.keyFiles(t); len(got) != 1 {
			t.Errorf("key files after a disabled block = %q, want field-team's kept", got)
		}
	})

	for name, desired := range map[string]*api.NodeStateSnapshot{
		"nil Bridge":     {},
		"nil UserAccess": {Bridge: &api.BridgeSnapshot{}},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newUAFixture(t, nil)
			handler := UserAccessReconcileHandler(fx.mgr, discardLogger())
			if err := handler(t.Context(), withProviders, bridgeChanged); err != nil {
				t.Fatalf("handler: %v", err)
			}
			fx.reset()
			if err := handler(t.Context(), desired, bridgeChanged); err != nil {
				t.Fatalf("handler(%s) = %v, want nil", name, err)
			}
			if got := providerIDs(fx.mgr); len(got) != 0 {
				t.Errorf("providers = %q, want none", got)
			}
			if c := fx.access.accessCallsFor("RemoveInterface"); len(c) != 1 {
				t.Errorf("RemoveInterface calls = %d, want 1", len(c))
			}
			if got := fx.keyFiles(t); len(got) != 0 {
				t.Errorf("key files after the zero block = %q, want none", got)
			}
		})
	}

	t.Run("opted out", func(t *testing.T) {
		logger, logs := newRelayLogger()
		handler := UserAccessReconcileHandler(nil, logger)
		if err := handler(t.Context(), withProviders, bridgeChanged); err != nil {
			t.Fatalf("handler = %v, want nil", err)
		}
		const warn = `msg="user access: the control plane enables user access, but bridge.user_access_enabled is false"`
		if got := logLines(logs, "level=WARN", warn, "component=bridge", "providers=2"); got != 1 {
			t.Errorf("%d opted-out Warn lines with providers=2, want 1:\n%s", got, logs.String())
		}
		if got := logLines(logs); got != 1 {
			t.Errorf("%d log lines, want only the Warn:\n%s", got, logs.String())
		}

		disabled := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{UserAccess: &api.UserAccessConfig{Providers: withProviders.Bridge.UserAccess.Providers}}}
		for _, tc := range []struct {
			name    string
			desired *api.NodeStateSnapshot
			diff    reconcile.StateDiff
		}{
			{"nil snapshot", nil, bridgeChanged},
			{"nil Bridge", &api.NodeStateSnapshot{}, bridgeChanged},
			{"nil UserAccess", &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{}}, bridgeChanged},
			{"not enabled with providers", disabled, bridgeChanged},
			{"enabled without providers", &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{UserAccess: &api.UserAccessConfig{Enabled: true}}}, bridgeChanged},
			{"enabled with providers, no bridge drift", withProviders, reconcile.StateDiff{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				logger, logs := newRelayLogger()
				handler := UserAccessReconcileHandler(nil, logger)
				if err := handler(t.Context(), tc.desired, tc.diff); err != nil {
					t.Errorf("handler = %v, want nil", err)
				}
				if got := logs.String(); got != "" {
					t.Errorf("logs = %q, want none", got)
				}
			})
		}
	})
}
