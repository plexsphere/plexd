package bridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

// tunnelCreate records one call to CreateTunnel.
type tunnelCreate struct {
	cfg TunnelConfig
	ctx context.Context
}

// tunnelEstablished records one call to Established.
type tunnelEstablished struct {
	tunnelID string
	ctx      context.Context
}

// mockTunnelProvider is a test double for TunnelProvider. It records every
// call and returns the error set for its method.
type mockTunnelProvider struct {
	name string

	mu             sync.Mutex
	createErr      error
	removeErr      error
	resetErr       error
	established    bool
	establishedErr error
	methods        []string
	creates        []tunnelCreate
	removes        []string
	resets         []context.Context
	establishes    []tunnelEstablished
	// establishedHook, when set, runs inside Established, outside mu,
	// before it returns.
	establishedHook func()
}

var _ TunnelProvider = (*mockTunnelProvider)(nil)

func (p *mockTunnelProvider) Name() string { return p.name }

func (p *mockTunnelProvider) CreateTunnel(ctx context.Context, cfg TunnelConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.methods = append(p.methods, "CreateTunnel")
	p.creates = append(p.creates, tunnelCreate{cfg: cfg, ctx: ctx})
	return p.createErr
}

func (p *mockTunnelProvider) RemoveTunnel(_ context.Context, tunnelID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.methods = append(p.methods, "RemoveTunnel")
	p.removes = append(p.removes, tunnelID)
	return p.removeErr
}

func (p *mockTunnelProvider) Established(ctx context.Context, tunnelID string) (bool, error) {
	p.mu.Lock()
	p.methods = append(p.methods, "Established")
	p.establishes = append(p.establishes, tunnelEstablished{tunnelID: tunnelID, ctx: ctx})
	hook, established, err := p.establishedHook, p.established, p.establishedErr
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	return established, err
}

func (p *mockTunnelProvider) Reset(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.methods = append(p.methods, "Reset")
	p.resets = append(p.resets, ctx)
	return p.resetErr
}

// set runs f on the provider under its mutex.
func (p *mockTunnelProvider) set(f func(p *mockTunnelProvider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

// calls returns the methods of the recorded calls, in order.
func (p *mockTunnelProvider) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.methods)
}

// createCalls returns the recorded CreateTunnel calls.
func (p *mockTunnelProvider) createCalls() []tunnelCreate {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.creates)
}

// removeCalls returns the ids of the recorded RemoveTunnel calls.
func (p *mockTunnelProvider) removeCalls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.removes)
}

// resetCalls returns the contexts of the recorded Reset calls.
func (p *mockTunnelProvider) resetCalls() []context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.resets)
}

// establishedCalls returns the recorded Established calls.
func (p *mockTunnelProvider) establishedCalls() []tunnelEstablished {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.establishes)
}

// reset clears the recorded calls.
func (p *mockTunnelProvider) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.methods, p.creates, p.removes, p.resets, p.establishes = nil, nil, nil, nil, nil
}

// resolveCall records one call to fakeResolver.Resolve.
type resolveCall struct {
	host        string
	hasDeadline bool
	deadlineIn  time.Duration
}

// fakeResolver is a test double for SiteToSiteDeps.Resolve: it answers each
// host with the addresses set for it, or with err, and records the calls.
type fakeResolver struct {
	mu    sync.Mutex
	addrs map[string][]netip.Addr
	err   error
	// hook, when set, runs inside Resolve before it returns.
	hook  func()
	calls []resolveCall
}

func (r *fakeResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	c := resolveCall{host: host}
	if d, ok := ctx.Deadline(); ok {
		c.hasDeadline, c.deadlineIn = true, time.Until(d)
	}
	r.calls = append(r.calls, c)
	hook, addrs, err := r.hook, slices.Clone(r.addrs[host]), r.err
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// set runs f on the resolver under its mutex.
func (r *fakeResolver) set(f func(r *fakeResolver)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}

// resolved returns the hosts of the recorded calls, in order.
func (r *fakeResolver) resolved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var hosts []string
	for _, c := range r.calls {
		hosts = append(hosts, c.host)
	}
	return hosts
}

// callSequence keeps, in the order they were made, the calls of the doubles
// sequencedRoutes and sequencedRewriter wrap. Each double records its own
// calls alone, so only a sequence they share shows the order across them.
type callSequence struct {
	mu    sync.Mutex
	calls []string
}

// add appends call to the sequence.
func (s *callSequence) add(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

// list returns the calls in the order they were made.
func (s *callSequence) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// reset clears the sequence.
func (s *callSequence) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// sequencedRoutes adds each call the manager makes for a tunnel to seq,
// prefixed with "routes.", and passes it on to the RouteController it wraps.
// The NAT methods, which the manager does not call, go to that controller
// alone.
type sequencedRoutes struct {
	RouteController
	seq *callSequence
}

func (r sequencedRoutes) EnableForwarding(meshIface, accessIface string) error {
	r.seq.add("routes.EnableForwarding")
	return r.RouteController.EnableForwarding(meshIface, accessIface)
}

func (r sequencedRoutes) DisableForwarding(meshIface, accessIface string) error {
	r.seq.add("routes.DisableForwarding")
	return r.RouteController.DisableForwarding(meshIface, accessIface)
}

func (r sequencedRoutes) AddRoute(subnet, iface string) error {
	r.seq.add("routes.AddRoute")
	return r.RouteController.AddRoute(subnet, iface)
}

func (r sequencedRoutes) RemoveRoute(subnet, iface string) error {
	r.seq.add("routes.RemoveRoute")
	return r.RouteController.RemoveRoute(subnet, iface)
}

// sequencedRewriter adds each call the manager makes for a tunnel to seq,
// prefixed with "rewriter.", and passes it on to the MeshSourceRewriter it
// wraps. ResetMeshSourceRewrite, which the manager does not call, goes to
// that rewriter alone.
type sequencedRewriter struct {
	MeshSourceRewriter
	seq *callSequence
}

func (r sequencedRewriter) AddMeshSourceRewrite(fromIface, meshIface string) error {
	r.seq.add("rewriter.AddMeshSourceRewrite")
	return r.MeshSourceRewriter.AddMeshSourceRewrite(fromIface, meshIface)
}

func (r sequencedRewriter) RemoveMeshSourceRewrite(fromIface, meshIface string) error {
	r.seq.add("rewriter.RemoveMeshSourceRewrite")
	return r.MeshSourceRewriter.RemoveMeshSourceRewrite(fromIface, meshIface)
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const (
	s2sMesh     = "plexd0"
	s2sMeshCIDR = "10.99.0.0/24"

	s2sID1 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1"
	s2sID2 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2"
	s2sID3 = "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e3"

	s2sWGIface   = "wg-s2s-a0a0a0e1"
	s2sXfrmIface = "xf-s2s-a0a0a0e2"
	s2sTunIface  = "ov-s2s-a0a0a0e3"

	// s2sRemoteKey is the remote site's public key of the contract's
	// example.
	s2sRemoteKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	// s2sIKEKey is the IKE pre-shared key of dc-east's Secret.
	s2sIKEKey = "dc-east-ike-key"
)

var (
	// s2sPSK is the preshared key of branch-berlin's Secret, in the form wg
	// genpsk prints.
	s2sPSK = deviceKey(0x42)

	// branchBerlin is the wireguard tunnel of the contract's example, with a
	// second subnet; its remote host resolves to an IPv6 and an IPv4
	// address.
	branchBerlin = api.SiteToSiteTunnel{
		ID:              s2sID1,
		Slug:            "branch-berlin",
		Kind:            api.SiteToSiteKindWireGuard,
		RemoteHost:      "vpn.branch.example.com",
		RemotePort:      51820,
		AllowedSubnets:  []string{"10.20.0.0/16", "10.21.0.0/16"},
		ListenPort:      51830,
		RemotePublicKey: s2sRemoteKey,
		AuthSecretName:  "branch-berlin-psk",
	}
	// dcEast is the ipsec tunnel of the contract's example.
	dcEast = api.SiteToSiteTunnel{
		ID:             s2sID2,
		Slug:           "dc-east",
		Kind:           api.SiteToSiteKindIPsec,
		RemoteHost:     "203.0.113.10",
		RemotePort:     500,
		AllowedSubnets: []string{"10.30.0.0/16", "10.31.0.0/16"},
		AuthSecretName: "dc-east-ike",
	}
	// office is an openvpn tunnel to a host name.
	office = api.SiteToSiteTunnel{
		ID:             s2sID3,
		Slug:           "office",
		Kind:           api.SiteToSiteKindOpenVPN,
		RemoteHost:     "vpn.office.example.com",
		RemotePort:     1194,
		AllowedSubnets: []string{"10.40.0.0/16"},
		AuthSecretName: "office-ovpn",
	}
)

// s2sBlock returns an enabled block listing tunnels.
func s2sBlock(tunnels ...api.SiteToSiteTunnel) api.SiteToSiteConfig {
	return api.SiteToSiteConfig{Enabled: true, Tunnels: tunnels}
}

// s2sInventory lists the Secrets of the three fixture tunnels at version 1.
func s2sInventory() []api.NodeStateSecret {
	return []api.NodeStateSecret{
		{Name: "branch-berlin-psk", Version: 1},
		{Name: "dc-east-ike", Version: 1},
		{Name: "office-ovpn", Version: 1},
	}
}

// s2sFixture is a SiteToSiteManager over recording doubles, a key store in
// a temporary directory, a fake resolver, a settable clock and a log
// buffer.
type s2sFixture struct {
	mgr      *SiteToSiteManager
	vpn      *mockVPNController
	routes   *mockRouteController
	rewriter *mockMeshSourceRewriter
	keyDir   string
	secrets  *fakeSecretValues
	ipsec    *mockTunnelProvider
	openvpn  *mockTunnelProvider
	resolver *fakeResolver
	clock    *relayClock
	logs     *relayLog
	// exempter is the recording NATExempter exemptNAT handed the manager;
	// nil without one, as on Linux and macOS.
	exempter *mockNATExempter
}

// exemptNAT hands the manager a recording NATExempter, as plexd up does on
// Windows. buildS2SFixture keeps it as the fixture's exempter.
func exemptNAT(d *SiteToSiteDeps) { d.NATExempter = &mockNATExempter{} }

// buildS2SFixture builds the fixture without setting the manager up; adjust
// changes the dependencies first. The fixture's Secrets hold a value for each
// tunnel's Secret at version 1, with surrounding white space. The manager is
// torn down when the test ends.
func buildS2SFixture(t *testing.T, adjust func(*SiteToSiteDeps)) *s2sFixture {
	t.Helper()
	logger, logs := newRelayLogger()
	fx := &s2sFixture{
		vpn:      &mockVPNController{},
		routes:   &mockRouteController{},
		rewriter: &mockMeshSourceRewriter{},
		keyDir:   filepath.Join(t.TempDir(), "site-to-site"),
		secrets:  &fakeSecretValues{},
		ipsec:    &mockTunnelProvider{name: "ipsec"},
		openvpn:  &mockTunnelProvider{name: "openvpn"},
		resolver: &fakeResolver{addrs: map[string][]netip.Addr{
			"vpn.branch.example.com": {netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("198.51.100.7")},
			"vpn.office.example.com": {netip.MustParseAddr("198.51.100.30")},
		}},
		clock: &relayClock{now: relayStart},
		logs:  logs,
	}
	fx.secrets.set("branch-berlin-psk", 1, "  "+s2sPSK+"\n")
	fx.secrets.set("dc-east-ike", 1, s2sIKEKey+"\n")
	fx.secrets.set("office-ovpn", 1, openvpnTestKey+"\n")
	deps := SiteToSiteDeps{
		VPN:      fx.vpn,
		Routes:   fx.routes,
		Rewriter: fx.rewriter,
		Keys:     NewInterfaceKeyStore(fx.keyDir),
		Secrets:  fx.secrets,
		Providers: map[string]TunnelProvider{
			api.SiteToSiteKindIPsec:   fx.ipsec,
			api.SiteToSiteKindOpenVPN: fx.openvpn,
		},
		Resolve:       fx.resolver.Resolve,
		MeshInterface: s2sMesh,
		MeshCIDR:      s2sMeshCIDR,
		Logger:        logger,
	}
	if adjust != nil {
		adjust(&deps)
	}
	if e, ok := deps.NATExempter.(*mockNATExempter); ok {
		fx.exempter = e
		e.snapshot = fx.controllerCalls
	}
	fx.mgr = NewSiteToSiteManager(deps)
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

// newS2SFixture builds the fixture, sets the manager up, hands it the
// inventory that lists every fixture Secret at version 1, and clears the
// calls Setup made.
func newS2SFixture(t *testing.T, adjust func(*SiteToSiteDeps)) *s2sFixture {
	t.Helper()
	fx := buildS2SFixture(t, adjust)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	fx.mgr.SyncSecretInventory(t.Context(), s2sInventory())
	fx.reset()
	return fx
}

// reset clears the calls every double recorded.
func (fx *s2sFixture) reset() {
	fx.vpn.resetVPN()
	fx.routes.reset()
	fx.rewriter.reset()
	fx.ipsec.reset()
	fx.openvpn.reset()
	if fx.exempter != nil {
		fx.exempter.reset()
	}
}

// calls returns the methods every controller and provider double recorded,
// prefixed with the double's name, so a test can want none at all.
func (fx *s2sFixture) calls() []string {
	out := fx.controllerCalls()
	out = append(out, prefixedMethods("ipsec", fx.ipsec.calls())...)
	out = append(out, prefixedMethods("openvpn", fx.openvpn.calls())...)
	if fx.exempter != nil {
		out = append(out, prefixedMethods("exempter", fx.exempter.methods())...)
	}
	return out
}

// controllerCalls returns the methods the vpn, routes and rewriter doubles
// recorded, prefixed with the double's name. Each double records its own
// calls alone, so the recording NATExempter keeps this at each of its calls:
// it is what places an exemption call among the calls of the others.
func (fx *s2sFixture) controllerCalls() []string {
	out := prefixedMethods("vpn", fx.vpn.vpnMethods())
	out = append(out, prefixedMethods("routes", fx.routes.methods())...)
	return append(out, prefixedMethods("rewriter", fx.rewriter.methods())...)
}

// prefixedMethods returns methods, each prefixed with name and a dot.
func prefixedMethods(name string, methods []string) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, name+"."+m)
	}
	return out
}

// requireNoCalls fails unless no controller or provider method was called
// since reset.
func (fx *s2sFixture) requireNoCalls(t *testing.T, what string) {
	t.Helper()
	if got := fx.calls(); len(got) != 0 {
		t.Fatalf("%s called %q, want no controller or provider method", what, got)
	}
}

// keyFiles returns the names of the key files in the store's directory.
func (fx *s2sFixture) keyFiles(t *testing.T) []string {
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
func (fx *s2sFixture) storedKey(t *testing.T, id string) []byte {
	t.Helper()
	key, err := NewInterfaceKeyStore(fx.keyDir).LoadOrCreate(id)
	if err != nil {
		t.Fatalf("LoadOrCreate(%s): %v", id, err)
	}
	return key[:]
}

// routeCalls returns the calls of method on routes as "subnet iface" lines.
func routeCalls(routes *mockRouteController, method string) []string {
	var out []string
	for _, c := range routes.callsFor(method) {
		out = append(out, fmt.Sprintf("%s %s", c.Args[0], c.Args[1]))
	}
	return out
}

// tunnelInfo returns the status of the tunnel with id, failing when the
// manager reports none.
func tunnelInfo(t *testing.T, mgr *SiteToSiteManager, id string) api.SiteToSiteTunnelInfo {
	t.Helper()
	info := mgr.SiteToSiteStatus()
	if info == nil {
		t.Fatal("SiteToSiteStatus() = nil, want the active manager's status")
	}
	for _, ti := range info.Tunnels {
		if ti.ID == id {
			return ti
		}
	}
	t.Fatalf("no status for tunnel %s in %+v", id, info.Tunnels)
	return api.SiteToSiteTunnelInfo{}
}

// requireTunnelDown fails unless the tunnel with id is down for reason,
// without an interface.
func requireTunnelDown(t *testing.T, mgr *SiteToSiteManager, id, reason string) {
	t.Helper()
	ti := tunnelInfo(t, mgr, id)
	if ti.Health != api.SiteToSiteHealthDown || ti.Reason != reason || ti.Interface != "" || ti.Established {
		t.Fatalf("tunnel %s = %+v, want down for %s without an interface", id, ti, reason)
	}
}

// requireTunnelUp fails unless the tunnel with id is up.
func requireTunnelUp(t *testing.T, mgr *SiteToSiteManager, id string) api.SiteToSiteTunnelInfo {
	t.Helper()
	ti := tunnelInfo(t, mgr, id)
	if ti.Health != api.SiteToSiteHealthUp || ti.Reason != "" {
		t.Fatalf("tunnel %s = %+v, want up", id, ti)
	}
	return ti
}

// tunnelIDs returns the ids the manager reports, in order. It reads what the
// manager holds rather than its status, which asks each tunnel that is up
// whether its remote site answers, so a test that calls or polls it adds no
// device read and no provider command to the calls it checks.
func tunnelIDs(mgr *SiteToSiteManager) []string {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.active {
		return nil
	}
	var ids []string
	for _, t := range mgr.tunnels {
		if t.settled {
			ids = append(ids, t.entry.ID)
		}
	}
	return ids
}

// heldPublicKey returns the public key the manager holds for the tunnel with
// id while it is up, "" otherwise.
func heldPublicKey(mgr *SiteToSiteManager, id string) string {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for _, t := range mgr.tunnels {
		if t.entry.ID == id {
			return t.publicKey
		}
	}
	return ""
}

// publicKeyOf returns the public half of the private key raw.
func publicKeyOf(t *testing.T, raw []byte) string {
	t.Helper()
	key, err := wgtypes.NewKey(raw)
	if err != nil {
		t.Fatalf("parse the stored key: %v", err)
	}
	return key.PublicKey().String()
}

// ---------------------------------------------------------------------------
// Setup and CleanupSiteToSite
// ---------------------------------------------------------------------------

func TestCleanupSiteToSite(t *testing.T) {
	t.Run("controller and providers", func(t *testing.T) {
		vpn := &mockVPNController{}
		ipsec, openvpn := &mockTunnelProvider{name: "ipsec"}, &mockTunnelProvider{name: "openvpn"}
		providers := map[string]TunnelProvider{"ipsec": ipsec, "openvpn": openvpn}
		if err := CleanupSiteToSite(vpn, providers, nil); err != nil {
			t.Fatalf("CleanupSiteToSite: %v", err)
		}
		c := vpn.vpnCallsFor("RemoveTunnelInterfaces")
		if len(c) != 1 || !slices.Equal(c[0].Args[0].([]string), []string{"wg-s2s-", "xf-s2s-", "ov-s2s-"}) {
			t.Errorf("RemoveTunnelInterfaces calls = %+v, want one with wg-s2s-, xf-s2s- and ov-s2s-", c)
		}
		if got := vpn.vpnMethods(); len(got) != 1 {
			t.Errorf("controller calls = %q, want RemoveTunnelInterfaces alone", got)
		}
		for _, p := range []*mockTunnelProvider{ipsec, openvpn} {
			if got := p.calls(); !slices.Equal(got, []string{"Reset"}) {
				t.Errorf("%s calls = %q, want Reset alone", p.name, got)
			}
			d, ok := p.resetCalls()[0].Deadline()
			if !ok || time.Until(d) <= 29*time.Second || time.Until(d) > 30*time.Second {
				t.Errorf("%s Reset ran under a deadline %v away, want one of 30 s", p.name, time.Until(d))
			}
		}
	})

	t.Run("nil controller", func(t *testing.T) {
		ipsec := &mockTunnelProvider{name: "ipsec"}
		if err := CleanupSiteToSite(nil, map[string]TunnelProvider{"ipsec": ipsec}, nil); err != nil {
			t.Fatalf("CleanupSiteToSite: %v", err)
		}
		if got := ipsec.calls(); !slices.Equal(got, []string{"Reset"}) {
			t.Errorf("ipsec calls = %q, want Reset alone", got)
		}
	})

	t.Run("errors are joined", func(t *testing.T) {
		errRemove, errReset := errors.New("remove failed"), errors.New("reset failed")
		vpn := &mockVPNController{removeAllErr: errRemove}
		ipsec, openvpn := &mockTunnelProvider{name: "ipsec", resetErr: errReset}, &mockTunnelProvider{name: "openvpn"}
		err := CleanupSiteToSite(vpn, map[string]TunnelProvider{"ipsec": ipsec, "openvpn": openvpn}, nil)
		if !errors.Is(err, errRemove) || !errors.Is(err, errReset) {
			t.Errorf("CleanupSiteToSite = %v, want both errors", err)
		}
		if len(ipsec.calls()) != 1 || len(openvpn.calls()) != 1 {
			t.Error("a failed step skipped a later one")
		}
	})

	t.Run("exempter", func(t *testing.T) {
		vpn, exempter := &mockVPNController{}, &mockNATExempter{}
		ipsec := &mockTunnelProvider{name: "ipsec"}
		if err := CleanupSiteToSite(vpn, map[string]TunnelProvider{"ipsec": ipsec}, exempter); err != nil {
			t.Fatalf("CleanupSiteToSite: %v", err)
		}
		if got := exempter.methods(); !slices.Equal(got, []string{"ResetNATExemptions"}) {
			t.Errorf("exempter calls = %q, want ResetNATExemptions alone", got)
		}
		if got := vpn.vpnMethods(); !slices.Equal(got, []string{"RemoveTunnelInterfaces"}) {
			t.Errorf("controller calls = %q, want RemoveTunnelInterfaces alone", got)
		}
		if got := ipsec.calls(); !slices.Equal(got, []string{"Reset"}) {
			t.Errorf("ipsec calls = %q, want Reset alone", got)
		}
	})

	t.Run("an exempter's error is joined", func(t *testing.T) {
		errRemove, errExempt := errors.New("remove failed"), errors.New("Remove-NetNat failed")
		vpn := &mockVPNController{removeAllErr: errRemove}
		exempter := &mockNATExempter{resetNATExemptionsErr: errExempt}
		err := CleanupSiteToSite(vpn, nil, exempter)
		if !errors.Is(err, errRemove) || !errors.Is(err, errExempt) {
			t.Errorf("CleanupSiteToSite = %v, want both errors", err)
		}
		if err != nil && !strings.Contains(err.Error(), "reset the NAT exemptions: Remove-NetNat failed") {
			t.Errorf("CleanupSiteToSite = %q, want the reset's error as %q", err, "reset the NAT exemptions: Remove-NetNat failed")
		}
		if got := exempter.methods(); !slices.Equal(got, []string{"ResetNATExemptions"}) {
			t.Errorf("exempter calls = %q, want ResetNATExemptions after the failed removal", got)
		}
	})
}

func TestSiteToSiteManager_SetupCleansUp(t *testing.T) {
	fx := buildS2SFixture(t, nil)
	if fx.mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus() before Setup is not nil")
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if c := fx.vpn.vpnCallsFor("RemoveTunnelInterfaces"); len(c) != 1 || !slices.Equal(c[0].Args[0].([]string), SiteToSiteInterfacePrefixes) {
		t.Errorf("RemoveTunnelInterfaces calls = %+v, want one with the three prefixes", c)
	}
	for _, p := range []*mockTunnelProvider{fx.ipsec, fx.openvpn} {
		if got := p.calls(); !slices.Equal(got, []string{"Reset"}) {
			t.Errorf("%s calls = %q, want Reset", p.name, got)
		}
	}
	if got := fx.rewriter.methods(); len(got) != 0 {
		t.Errorf("rewriter calls = %q, want none: the user access cleanup resets the table", got)
	}
	if info := fx.mgr.SiteToSiteStatus(); info == nil || info.Enabled || len(info.Tunnels) != 0 {
		t.Errorf("SiteToSiteStatus() after Setup = %+v, want a status without tunnels", info)
	}
	if got := logLines(fx.logs, "level=INFO", `msg="site-to-site manager started"`, "component=bridge"); got != 1 {
		t.Errorf("%d 'site-to-site manager started' lines, want 1:\n%s", got, fx.logs.String())
	}
	// A second Setup changes nothing.
	fx.reset()
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	fx.requireNoCalls(t, "a second Setup")
}

func TestSiteToSiteManager_SetupReturnsTheCleanupError(t *testing.T) {
	for name, adjust := range map[string]func(*s2sFixture, error){
		"RemoveTunnelInterfaces": func(fx *s2sFixture, err error) { fx.vpn.removeAllErr = err },
		"Reset":                  func(fx *s2sFixture, err error) { fx.openvpn.resetErr = err },
	} {
		t.Run(name, func(t *testing.T) {
			fx := buildS2SFixture(t, nil)
			errCleanup := errors.New("cleanup failed")
			adjust(fx, errCleanup)
			err := fx.mgr.Setup()
			if !errors.Is(err, errCleanup) {
				t.Fatalf("Setup = %v, want the cleanup's error", err)
			}
			if !strings.HasPrefix(err.Error(), "bridge: site-to-site: clean up: ") {
				t.Errorf("Setup = %q, want the prefix %q", err, "bridge: site-to-site: clean up: ")
			}
			if fx.mgr.SiteToSiteStatus() != nil {
				t.Error("SiteToSiteStatus() after a failed Setup is not nil")
			}
			fx.reset()
			fx.mgr.SyncSecretInventory(t.Context(), s2sInventory())
			fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
			fx.requireNoCalls(t, "Apply after a failed Setup")
		})
	}
}

// TestSiteToSiteManager_SetupResetsTheNATExemptions checks that Setup with a
// NATExempter resets the exemptions a killed process left behind, once, and
// that a failed reset fails Setup and leaves the manager inactive.
func TestSiteToSiteManager_SetupResetsTheNATExemptions(t *testing.T) {
	t.Run("reset", func(t *testing.T) {
		fx := buildS2SFixture(t, exemptNAT)
		if err := fx.mgr.Setup(); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		if got := fx.exempter.methods(); !slices.Equal(got, []string{"ResetNATExemptions"}) {
			t.Errorf("exempter calls = %q, want ResetNATExemptions once", got)
		}
		// A second Setup changes nothing.
		fx.reset()
		if err := fx.mgr.Setup(); err != nil {
			t.Fatalf("second Setup: %v", err)
		}
		fx.requireNoCalls(t, "a second Setup")
	})

	t.Run("reset fails", func(t *testing.T) {
		fx := buildS2SFixture(t, exemptNAT)
		errReset := errors.New("Remove-NetNat failed")
		fx.exempter.resetNATExemptionsErr = errReset
		err := fx.mgr.Setup()
		if !errors.Is(err, errReset) {
			t.Fatalf("Setup = %v, want the reset's error", err)
		}
		if want := "bridge: site-to-site: clean up: reset the NAT exemptions: "; !strings.HasPrefix(err.Error(), want) {
			t.Errorf("Setup = %q, want the prefix %q", err, want)
		}
		if got := fx.exempter.methods(); !slices.Equal(got, []string{"ResetNATExemptions"}) {
			t.Errorf("exempter calls = %q, want ResetNATExemptions once", got)
		}
		if fx.mgr.SiteToSiteStatus() != nil {
			t.Error("SiteToSiteStatus() after a failed Setup is not nil")
		}
	})
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

// TestSiteToSiteManager_ApplyBringsUpAWireGuardTunnel checks the calls that
// bring a wireguard tunnel up: its interface with the stored key on its
// port, the remote peer with its key, its subnets, the resolved endpoint
// and the fetched preshared key, forwarding and the source rewrite into the
// mesh, and a route for each subnet.
func TestSiteToSiteManager_ApplyBringsUpAWireGuardTunnel(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

	create := fx.vpn.vpnCallsFor("CreateTunnelInterface")
	if len(create) != 1 {
		t.Fatalf("CreateTunnelInterface calls = %d, want 1", len(create))
	}
	if name := create[0].Args[0]; name != s2sWGIface {
		t.Errorf("CreateTunnelInterface name = %v, want %s", name, s2sWGIface)
	}
	key := fx.storedKey(t, s2sID1)
	if got := create[0].Args[1].([]byte); !slices.Equal(got, key) {
		t.Error("CreateTunnelInterface key is not the key the store keeps for the tunnel")
	}
	if port := create[0].Args[2]; port != 51830 {
		t.Errorf("CreateTunnelInterface listenPort = %v, want 51830", port)
	}
	peer := fx.vpn.vpnCallsFor("ConfigureTunnelPeer")
	if len(peer) != 1 {
		t.Fatalf("ConfigureTunnelPeer calls = %d, want 1", len(peer))
	}
	if got, want := fmt.Sprint(peer[0].Args), fmt.Sprint([]any{s2sWGIface, s2sRemoteKey, []string{"10.20.0.0/16", "10.21.0.0/16"}, "198.51.100.7:51820", s2sPSK}); got != want {
		t.Errorf("ConfigureTunnelPeer(%s), want (%s)", got, want)
	}
	if got := routeCalls(fx.routes, "EnableForwarding"); !slices.Equal(got, []string{s2sMesh + " " + s2sWGIface}) {
		t.Errorf("EnableForwarding calls = %q, want (%s, %s)", got, s2sMesh, s2sWGIface)
	}
	if c := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != s2sWGIface || c[0].Args[1] != s2sMesh {
		t.Errorf("AddMeshSourceRewrite calls = %+v, want one (%s, %s)", c, s2sWGIface, s2sMesh)
	}
	if got := routeCalls(fx.routes, "AddRoute"); !slices.Equal(got, []string{"10.20.0.0/16 " + s2sWGIface, "10.21.0.0/16 " + s2sWGIface}) {
		t.Errorf("AddRoute calls = %q, want one per subnet on %s", got, s2sWGIface)
	}
	if got := fx.calls(); len(got) != 6 {
		t.Errorf("calls = %q, want the six of the bring-up alone", got)
	}
	if got := fx.resolver.resolved(); !slices.Equal(got, []string{"vpn.branch.example.com"}) {
		t.Errorf("resolved = %q, want the remote host once", got)
	}
	if c := fx.resolver.calls[0]; !c.hasDeadline || c.deadlineIn <= 4*time.Second || c.deadlineIn > 5*time.Second {
		t.Errorf("Resolve ran under a deadline %v away (set: %v), want one of 5 s", c.deadlineIn, c.hasDeadline)
	}
	if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{"branch-berlin-psk", 1}}) {
		t.Errorf("fetches = %v, want the listed version", got)
	}

	want := &api.SiteToSiteInfo{Enabled: true, Tunnels: []api.SiteToSiteTunnelInfo{{
		ID: s2sID1, Slug: "branch-berlin", Kind: api.SiteToSiteKindWireGuard, Interface: s2sWGIface,
		Health: api.SiteToSiteHealthUp, ListenPort: 51830,
		RemoteHost: "vpn.branch.example.com", RemotePort: 51820, AllowedSubnets: []string{"10.20.0.0/16", "10.21.0.0/16"},
	}}}
	if got := fx.mgr.SiteToSiteStatus(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("SiteToSiteStatus() = %+v, want %+v", got, want)
	}
	if got := heldPublicKey(fx.mgr, s2sID1); got != publicKeyOf(t, key) {
		t.Errorf("held public key = %q, want the public half of the stored key", got)
	}
	if got := logLines(fx.logs, "level=INFO", `msg="site-to-site tunnel up"`, "component=bridge",
		"tunnel_id="+s2sID1, "slug=branch-berlin", "kind=wireguard", "interface="+s2sWGIface, "listen_port=51830"); got != 1 {
		t.Errorf("%d 'site-to-site tunnel up' lines, want 1:\n%s", got, fx.logs.String())
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{s2sID1 + ".key"}) {
		t.Errorf("key files = %q, want the tunnel's", got)
	}
	assertPerm(t, filepath.Join(fx.keyDir, s2sID1+".key"), 0600)
	// The log never carries key material or the Secret's value.
	if logs := fx.logs.String(); strings.Contains(logs, base64.StdEncoding.EncodeToString(key)) || strings.Contains(logs, s2sPSK) {
		t.Error("the log carries the interface's private key or the preshared key")
	}
}

// TestSiteToSiteManager_KernelNames checks that forwarding, the source
// rewrite and the routes of a wireguard tunnel take the name the operating
// system knows its interface by, utunN on macOS, while its peer and its
// status keep the configured name, and that its removal uses the kernel name
// it was brought up with, although the controller no longer maps the
// configured one.
func TestSiteToSiteManager_KernelNames(t *testing.T) {
	var namer *namerVPNController
	fx := newS2SFixture(t, func(d *SiteToSiteDeps) {
		namer = &namerVPNController{
			mockVPNController: d.VPN.(*mockVPNController),
			names:             map[string]string{s2sWGIface: "utun8"},
		}
		d.VPN = namer
	})
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

	if got := routeCalls(fx.routes, "EnableForwarding"); !slices.Equal(got, []string{s2sMesh + " utun8"}) {
		t.Errorf("EnableForwarding calls = %q, want (%s, utun8)", got, s2sMesh)
	}
	if c := fx.rewriter.callsFor("AddMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "utun8" || c[0].Args[1] != s2sMesh {
		t.Errorf("AddMeshSourceRewrite calls = %+v, want one (utun8, %s)", c, s2sMesh)
	}
	if got := routeCalls(fx.routes, "AddRoute"); !slices.Equal(got, []string{"10.20.0.0/16 utun8", "10.21.0.0/16 utun8"}) {
		t.Errorf("AddRoute calls = %q, want one per subnet on utun8", got)
	}
	if peer := fx.vpn.vpnCallsFor("ConfigureTunnelPeer"); len(peer) != 1 || peer[0].Args[0] != s2sWGIface {
		t.Errorf("ConfigureTunnelPeer calls = %+v, want one on the configured %s", peer, s2sWGIface)
	}
	if ti := requireTunnelUp(t, fx.mgr, s2sID1); ti.Interface != s2sWGIface {
		t.Errorf("status interface = %q, want the configured %s", ti.Interface, s2sWGIface)
	}

	namer.unmap(s2sWGIface)
	fx.reset()
	fx.mgr.Apply(t.Context(), s2sBlock())

	if got := routeCalls(fx.routes, "RemoveRoute"); !slices.Equal(got, []string{"10.20.0.0/16 utun8", "10.21.0.0/16 utun8"}) {
		t.Errorf("RemoveRoute calls = %q, want one per subnet on utun8", got)
	}
	if c := fx.rewriter.callsFor("RemoveMeshSourceRewrite"); len(c) != 1 || c[0].Args[0] != "utun8" || c[0].Args[1] != s2sMesh {
		t.Errorf("RemoveMeshSourceRewrite calls = %+v, want one (utun8, %s)", c, s2sMesh)
	}
	if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
		t.Errorf("RemoveTunnelInterface calls = %+v, want one for the configured %s", c, s2sWGIface)
	}
}

// TestSiteToSiteManager_ReleaseForwarding checks that with
// ReleaseForwarding, as on macOS, where one forwarding knob serves the whole
// host, the manager gives back each forwarding pair it claimed: when a tunnel
// that is up is removed, once per tunnel Teardown stops, and when a bring-up
// fails after its forwarding was switched on.
func TestSiteToSiteManager_ReleaseForwarding(t *testing.T) {
	release := func(d *SiteToSiteDeps) { d.ReleaseForwarding = true }

	t.Run("a removed tunnel", func(t *testing.T) {
		fx := newS2SFixture(t, release)
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
		requireTunnelUp(t, fx.mgr, s2sID1)
		if got := routeCalls(fx.routes, "DisableForwarding"); len(got) != 0 {
			t.Fatalf("DisableForwarding calls = %q while the tunnel is up, want none", got)
		}

		fx.mgr.Apply(t.Context(), s2sBlock())
		if got := routeCalls(fx.routes, "DisableForwarding"); !slices.Equal(got, []string{s2sMesh + " " + s2sWGIface}) {
			t.Errorf("DisableForwarding calls = %q, want (%s, %s)", got, s2sMesh, s2sWGIface)
		}
	})

	t.Run("teardown", func(t *testing.T) {
		fx := newS2SFixture(t, release)
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))
		for _, id := range []string{s2sID1, s2sID2, s2sID3} {
			requireTunnelUp(t, fx.mgr, id)
		}

		if err := fx.mgr.Teardown(); err != nil {
			t.Fatalf("Teardown() error = %v, want nil", err)
		}
		got := routeCalls(fx.routes, "DisableForwarding")
		slices.Sort(got)
		want := []string{s2sMesh + " " + s2sTunIface, s2sMesh + " " + s2sWGIface, s2sMesh + " " + s2sXfrmIface}
		if !slices.Equal(got, want) {
			t.Errorf("DisableForwarding calls = %q, want one per tunnel %q", got, want)
		}
	})

	for name, inject := range map[string]func(*s2sFixture){
		"a rewrite that fails after forwarding": func(fx *s2sFixture) { fx.rewriter.addMeshSourceRewriteErr = errors.New("boom") },
		"a route that fails after forwarding":   func(fx *s2sFixture) { fx.routes.addRouteErr = errors.New("boom") },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newS2SFixture(t, release)
			inject(fx)
			fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

			requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
			if got := routeCalls(fx.routes, "DisableForwarding"); !slices.Equal(got, []string{s2sMesh + " " + s2sWGIface}) {
				t.Errorf("DisableForwarding calls = %q, want (%s, %s)", got, s2sMesh, s2sWGIface)
			}
		})
	}

	t.Run("forwarding that fails", func(t *testing.T) {
		fx := newS2SFixture(t, release)
		fx.routes.enableForwardingErr = errors.New("boom")
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
		if got := routeCalls(fx.routes, "DisableForwarding"); len(got) != 0 {
			t.Errorf("DisableForwarding calls = %q for a pair that was never claimed, want none", got)
		}
	})

	t.Run("a release that fails after a failed bring-up", func(t *testing.T) {
		fx := newS2SFixture(t, release)
		fx.rewriter.addMeshSourceRewriteErr = errors.New("boom")
		fx.routes.disableForwardingErr = errors.New("sysctl refused")
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
		if got := logLines(fx.logs, "level=ERROR", `msg="bridge: site-to-site: release forwarding failed"`, "component=bridge",
			"tunnel_id="+s2sID1, "interface="+s2sWGIface, "release forwarding "+s2sWGIface+": sysctl refused"); got != 1 {
			t.Errorf("%d 'release forwarding failed' lines, want 1:\n%s", got, fx.logs.String())
		}
	})

	t.Run("teardown returns the release error", func(t *testing.T) {
		fx := newS2SFixture(t, release)
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
		requireTunnelUp(t, fx.mgr, s2sID1)
		errRefused := errors.New("sysctl refused")
		fx.routes.disableForwardingErr = errRefused

		err := fx.mgr.Teardown()
		if !errors.Is(err, errRefused) || !strings.Contains(err.Error(), "bridge: site-to-site: release forwarding "+s2sWGIface+": ") {
			t.Errorf("Teardown() error = %v, want the release error of %s", err, s2sWGIface)
		}
	})
}

// TestSiteToSiteManager_NATExemption checks the exemption of a tunnel's link
// from the host's NAT, which a NATExempter adds on Windows: where it sits
// among the calls that bring a tunnel up and remove it, what a failure of the
// exemption and a failure after it undo, and the error Teardown returns for a
// failed removal. The recording exempter keeps the calls the vpn, routes and
// rewriter doubles had recorded at each of its own calls, since each double
// records its own calls alone. That places each exemption call among the
// others but not those among themselves, so the order test also wraps the
// routes and rewriter doubles in a sequence they share.
func TestSiteToSiteManager_NATExemption(t *testing.T) {
	t.Run("order", func(t *testing.T) {
		seq := &callSequence{}
		fx := newS2SFixture(t, func(d *SiteToSiteDeps) {
			exemptNAT(d)
			d.Routes = sequencedRoutes{RouteController: d.Routes, seq: seq}
			d.Rewriter = sequencedRewriter{MeshSourceRewriter: d.Rewriter, seq: seq}
		})
		seq.reset()
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

		if c := fx.exempter.callsFor("ExemptFromNAT"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
			t.Fatalf("ExemptFromNAT calls = %+v, want one for %s", c, s2sWGIface)
		}
		before := []string{"vpn.CreateTunnelInterface", "vpn.ConfigureTunnelPeer"}
		if got := fx.exempter.snapshots("ExemptFromNAT")[0]; !slices.Equal(got, before) {
			t.Errorf("calls before ExemptFromNAT = %q, want %q: the link and its peer first, forwarding, the rewrite and the routes after", got, before)
		}
		after := []string{"routes.EnableForwarding", "rewriter.AddMeshSourceRewrite", "routes.AddRoute", "routes.AddRoute"}
		if got := seq.list(); !slices.Equal(got, after) {
			t.Errorf("route and rewrite calls in order = %q, want %q: forwarding, then the rewrite, then the routes", got, after)
		}
		want := []string{
			"vpn.CreateTunnelInterface", "vpn.ConfigureTunnelPeer",
			"routes.EnableForwarding", "routes.AddRoute", "routes.AddRoute",
			"rewriter.AddMeshSourceRewrite",
			"exempter.ExemptFromNAT",
		}
		if got := fx.calls(); !slices.Equal(got, want) {
			t.Errorf("calls = %q, want %q", got, want)
		}
		requireTunnelUp(t, fx.mgr, s2sID1)

		fx.reset()
		seq.reset()
		fx.mgr.Apply(t.Context(), s2sBlock())

		if c := fx.exempter.callsFor("UnexemptFromNAT"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
			t.Fatalf("UnexemptFromNAT calls = %+v, want one for %s", c, s2sWGIface)
		}
		before = []string{"routes.RemoveRoute", "routes.RemoveRoute", "rewriter.RemoveMeshSourceRewrite"}
		if got := fx.exempter.snapshots("UnexemptFromNAT")[0]; !slices.Equal(got, before) {
			t.Errorf("calls before UnexemptFromNAT = %q, want %q: the routes and the rewrite first, the link after", got, before)
		}
		if got := seq.list(); !slices.Equal(got, before) {
			t.Errorf("route and rewrite calls in order = %q, want %q: the routes, then the rewrite", got, before)
		}
		want = []string{
			"vpn.RemoveTunnelInterface",
			"routes.RemoveRoute", "routes.RemoveRoute",
			"rewriter.RemoveMeshSourceRewrite",
			"exempter.UnexemptFromNAT",
		}
		if got := fx.calls(); !slices.Equal(got, want) {
			t.Errorf("calls = %q, want %q", got, want)
		}
	})

	t.Run("an exemption that fails", func(t *testing.T) {
		fx := newS2SFixture(t, exemptNAT)
		fx.exempter.set(func(m *mockNATExempter) { m.exemptFromNATErr = errors.New("New-NetNat failed") })
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
		if got := logLines(fx.logs, "level=WARN", `msg="site-to-site tunnel down"`, "tunnel_id="+s2sID1,
			"reason=setup_failed", `error="exempt from NAT: New-NetNat failed"`); got != 1 {
			t.Errorf("%d 'site-to-site tunnel down' lines with the exemption's error, want 1:\n%s", got, fx.logs.String())
		}
		// The link is removed, and neither forwarding nor a removal of the
		// exemption that never was follows.
		want := []string{
			"vpn.CreateTunnelInterface", "vpn.ConfigureTunnelPeer", "vpn.RemoveTunnelInterface",
			"exempter.ExemptFromNAT",
		}
		if got := fx.calls(); !slices.Equal(got, want) {
			t.Errorf("calls = %q, want %q", got, want)
		}
		if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
			t.Errorf("RemoveTunnelInterface calls = %+v, want the attempt's link %s removed", c, s2sWGIface)
		}

		// Retry tries again after 5 s, and once the exemption succeeds the
		// tunnel comes up.
		fx.clock.Add(4 * time.Second)
		fx.mgr.Retry(t.Context())
		if got := len(fx.exempter.callsFor("ExemptFromNAT")); got != 1 {
			t.Fatalf("4 s after the failure: %d ExemptFromNAT calls, want 1", got)
		}
		fx.clock.Add(time.Second)
		fx.mgr.Retry(t.Context())
		if got := len(fx.exempter.callsFor("ExemptFromNAT")); got != 2 {
			t.Fatalf("5 s after the failure: %d ExemptFromNAT calls, want 2", got)
		}
		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
		fx.exempter.set(func(m *mockNATExempter) { m.exemptFromNATErr = nil })
		fx.clock.Add(10 * time.Second)
		fx.mgr.Retry(t.Context())
		requireTunnelUp(t, fx.mgr, s2sID1)
	})

	for name, inject := range map[string]func(*s2sFixture){
		"forwarding that fails after the exemption": func(fx *s2sFixture) { fx.routes.enableForwardingErr = errors.New("boom") },
		"a rewrite that fails after the exemption":  func(fx *s2sFixture) { fx.rewriter.addMeshSourceRewriteErr = errors.New("boom") },
		"a route that fails after the exemption":    func(fx *s2sFixture) { fx.routes.addRouteErr = errors.New("boom") },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newS2SFixture(t, exemptNAT)
			inject(fx)
			fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))

			requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
			if got := fx.exempter.methods(); !slices.Equal(got, []string{"ExemptFromNAT", "UnexemptFromNAT"}) {
				t.Errorf("exempter calls = %q, want the exemption and its removal once", got)
			}
			if c := fx.exempter.callsFor("UnexemptFromNAT"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
				t.Fatalf("UnexemptFromNAT calls = %+v, want one for %s", c, s2sWGIface)
			}
			// The exemption goes before the link does.
			if got := fx.exempter.snapshots("UnexemptFromNAT")[0]; slices.Contains(got, "vpn.RemoveTunnelInterface") {
				t.Errorf("calls before UnexemptFromNAT = %q, want the link removed after it", got)
			}
			if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
				t.Errorf("RemoveTunnelInterface calls = %+v, want the attempt's link %s removed", c, s2sWGIface)
			}
		})
	}

	t.Run("teardown", func(t *testing.T) {
		fx := newS2SFixture(t, exemptNAT)
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))
		fx.reset()

		if err := fx.mgr.Teardown(); err != nil {
			t.Fatalf("Teardown() error = %v, want nil", err)
		}
		var unexempted []string
		for _, c := range fx.exempter.callsFor("UnexemptFromNAT") {
			unexempted = append(unexempted, c.Args[0].(string))
		}
		if want := []string{s2sWGIface, s2sXfrmIface, s2sTunIface}; !slices.Equal(unexempted, want) {
			t.Errorf("UnexemptFromNAT calls = %q, want one per tunnel %q", unexempted, want)
		}
	})

	t.Run("teardown returns the removal's error", func(t *testing.T) {
		fx := newS2SFixture(t, exemptNAT)
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
		requireTunnelUp(t, fx.mgr, s2sID1)
		errUnexempt := errors.New("Remove-NetNat failed")
		fx.exempter.set(func(m *mockNATExempter) { m.unexemptFromNATErr = errUnexempt })
		fx.reset()

		err := fx.mgr.Teardown()
		if !errors.Is(err, errUnexempt) {
			t.Fatalf("Teardown() error = %v, want the removal's error", err)
		}
		if want := "bridge: site-to-site: remove NAT exemption " + s2sWGIface + ": "; !strings.Contains(err.Error(), want) {
			t.Errorf("Teardown() error = %q, want it to hold %q", err, want)
		}
		if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
			t.Errorf("RemoveTunnelInterface calls = %+v, want the link removed after the failure", c)
		}
	})
}

// TestSiteToSiteManager_ApplyBringsUpIPsecAndOpenVPNTunnels checks the link
// of each other kind, the provider's call with the mesh CIDR as its local
// subnet, and the contexts the providers run under.
func TestSiteToSiteManager_ApplyBringsUpIPsecAndOpenVPNTunnels(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.Apply(t.Context(), s2sBlock(dcEast, office))

	if c := fx.vpn.vpnCallsFor("CreateXfrmInterface"); len(c) != 1 || c[0].Args[0] != s2sXfrmIface || c[0].Args[1] != uint32(2694881506) {
		t.Errorf("CreateXfrmInterface calls = %+v, want one (%s, 2694881506)", c, s2sXfrmIface)
	}
	if c := fx.vpn.vpnCallsFor("CreateTunInterface"); len(c) != 1 || c[0].Args[0] != s2sTunIface {
		t.Errorf("CreateTunInterface calls = %+v, want one (%s)", c, s2sTunIface)
	}
	if got := fx.vpn.vpnMethods(); !slices.Equal(got, []string{"CreateXfrmInterface", "CreateTunInterface"}) {
		t.Errorf("controller calls = %q, want the two links alone", got)
	}

	ipsec := fx.ipsec.createCalls()
	if len(ipsec) != 1 {
		t.Fatalf("ipsec CreateTunnel calls = %d, want 1", len(ipsec))
	}
	wantIPsec := TunnelConfig{
		TunnelID: s2sID2, InterfaceName: s2sXfrmIface, InterfaceID: 2694881506,
		RemoteHost: "203.0.113.10", RemotePort: 500,
		LocalSubnets: []string{s2sMeshCIDR}, RemoteSubnets: []string{"10.30.0.0/16", "10.31.0.0/16"},
		Key: s2sIKEKey,
	}
	if fmt.Sprint(ipsec[0].cfg) != fmt.Sprint(wantIPsec) {
		t.Errorf("ipsec CreateTunnel(%+v), want (%+v)", ipsec[0].cfg, wantIPsec)
	}
	if d, ok := ipsec[0].ctx.Deadline(); !ok || time.Until(d) <= 29*time.Second || time.Until(d) > 30*time.Second {
		t.Errorf("ipsec CreateTunnel ran under a deadline %v away (set: %v), want one of 30 s", time.Until(d), ok)
	}

	openvpn := fx.openvpn.createCalls()
	if len(openvpn) != 1 {
		t.Fatalf("openvpn CreateTunnel calls = %d, want 1", len(openvpn))
	}
	wantOpenVPN := TunnelConfig{
		TunnelID: s2sID3, InterfaceName: s2sTunIface,
		RemoteHost: "vpn.office.example.com", RemotePort: 1194,
		LocalSubnets: []string{s2sMeshCIDR}, RemoteSubnets: []string{"10.40.0.0/16"},
		Key: openvpnTestKey,
	}
	if fmt.Sprint(openvpn[0].cfg) != fmt.Sprint(wantOpenVPN) {
		t.Errorf("openvpn CreateTunnel(%+v), want (%+v)", openvpn[0].cfg, wantOpenVPN)
	}
	// The openvpn process runs under the manager's context, which only
	// Teardown ends.
	runCtx := openvpn[0].ctx
	if _, ok := runCtx.Deadline(); ok || runCtx.Err() != nil {
		t.Errorf("openvpn CreateTunnel ran under a context with a deadline or ended, want the manager's")
	}

	// The IP address is not resolved; the host name is, and the daemon gets
	// the name.
	if got := fx.resolver.resolved(); !slices.Equal(got, []string{"vpn.office.example.com"}) {
		t.Errorf("resolved = %q, want the openvpn tunnel's host alone", got)
	}
	if got := routeCalls(fx.routes, "EnableForwarding"); !slices.Equal(got, []string{s2sMesh + " " + s2sXfrmIface, s2sMesh + " " + s2sTunIface}) {
		t.Errorf("EnableForwarding calls = %q", got)
	}
	var rewrites []string
	for _, c := range fx.rewriter.callsFor("AddMeshSourceRewrite") {
		rewrites = append(rewrites, fmt.Sprintf("%s %s", c.Args[0], c.Args[1]))
	}
	if !slices.Equal(rewrites, []string{s2sXfrmIface + " " + s2sMesh, s2sTunIface + " " + s2sMesh}) {
		t.Errorf("AddMeshSourceRewrite calls = %q", rewrites)
	}
	wantRoutes := []string{"10.30.0.0/16 " + s2sXfrmIface, "10.31.0.0/16 " + s2sXfrmIface, "10.40.0.0/16 " + s2sTunIface}
	if got := routeCalls(fx.routes, "AddRoute"); !slices.Equal(got, wantRoutes) {
		t.Errorf("AddRoute calls = %q, want %q", got, wantRoutes)
	}

	if ti := requireTunnelUp(t, fx.mgr, s2sID2); ti.Interface != s2sXfrmIface || ti.ListenPort != 0 {
		t.Errorf("dc-east = %+v, want up on %s without a port", ti, s2sXfrmIface)
	}
	if ti := requireTunnelUp(t, fx.mgr, s2sID3); ti.Interface != s2sTunIface || ti.ListenPort != 0 {
		t.Errorf("office = %+v, want up on %s without a port", ti, s2sTunIface)
	}
	if heldPublicKey(fx.mgr, s2sID2) != "" || heldPublicKey(fx.mgr, s2sID3) != "" {
		t.Error("an ipsec or openvpn tunnel holds a public key")
	}
	if got := fx.keyFiles(t); len(got) != 0 {
		t.Errorf("key files = %q, want none without a wireguard tunnel", got)
	}
	if got := logLines(fx.logs, `msg="site-to-site tunnel up"`, "kind=ipsec", "interface="+s2sXfrmIface); got != 1 {
		t.Errorf("%d up lines for dc-east, want 1:\n%s", got, fx.logs.String())
	}
	if strings.Contains(fx.logs.String(), "listen_port") {
		t.Error("the up line of an ipsec or openvpn tunnel names a listen_port")
	}
	if logs := fx.logs.String(); strings.Contains(logs, s2sIKEKey) || strings.Contains(logs, "6acef03f62675b4b") {
		t.Error("the log carries a Secret's value")
	}

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if runCtx.Err() == nil {
		t.Error("the context the openvpn process runs under is not cancelled by Teardown")
	}
}

// TestSiteToSiteManager_ApplyKeepsAndRebuilds checks that an unchanged block
// calls nothing, that a changed slug is taken over in place, and that a
// changed remote_port, allowed_subnets order or auth_secret_name each tear
// the tunnel down and bring it up with the same key.
func TestSiteToSiteManager_ApplyKeepsAndRebuilds(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.secrets.set("branch-berlin-psk-2", 4, s2sPSK)
	fx.mgr.SyncSecretInventory(t.Context(), append(s2sInventory(), api.NodeStateSecret{Name: "branch-berlin-psk-2", Version: 4}))
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	key := fx.storedKey(t, s2sID1)
	resolved, fetched := len(fx.resolver.resolved()), len(fx.secrets.fetches())
	fx.reset()

	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	fx.requireNoCalls(t, "a second Apply of the same block")
	if len(fx.resolver.resolved()) != resolved || len(fx.secrets.fetches()) != fetched {
		t.Error("a second Apply of the same block resolved or fetched again")
	}

	renamed := branchBerlin
	renamed.Slug = "branch-berlin-mitte"
	fx.mgr.Apply(t.Context(), s2sBlock(renamed, dcEast))
	fx.requireNoCalls(t, "an Apply that renames the tunnel")
	if ti := requireTunnelUp(t, fx.mgr, s2sID1); ti.Slug != "branch-berlin-mitte" {
		t.Errorf("slug = %q, want the renamed one", ti.Slug)
	}

	reordered := renamed
	reordered.AllowedSubnets = []string{"10.21.0.0/16", "10.20.0.0/16"}
	otherPort := reordered
	otherPort.RemotePort = 51821
	otherSecret := otherPort
	otherSecret.AuthSecretName = "branch-berlin-psk-2"
	for _, tc := range []struct {
		name  string
		entry api.SiteToSiteTunnel
	}{
		{"allowed_subnets order", reordered},
		{"remote_port", otherPort},
		{"auth_secret_name", otherSecret},
	} {
		fx.reset()
		fx.mgr.Apply(t.Context(), s2sBlock(tc.entry, dcEast))
		if got, want := fx.vpn.vpnMethods(), []string{"RemoveTunnelInterface", "CreateTunnelInterface", "ConfigureTunnelPeer"}; !slices.Equal(got, want) {
			t.Errorf("%s: controller calls = %q, want %q", tc.name, got, want)
		}
		if got, want := fx.routes.methods(), []string{"RemoveRoute", "RemoveRoute", "EnableForwarding", "AddRoute", "AddRoute"}; !slices.Equal(got, want) {
			t.Errorf("%s: route calls = %q, want %q", tc.name, got, want)
		}
		if got, want := fx.rewriter.methods(), []string{"RemoveMeshSourceRewrite", "AddMeshSourceRewrite"}; !slices.Equal(got, want) {
			t.Errorf("%s: rewriter calls = %q, want %q", tc.name, got, want)
		}
		if got := fx.ipsec.calls(); len(got) != 0 {
			t.Errorf("%s: ipsec calls = %q, want dc-east left alone", tc.name, got)
		}
		create := fx.vpn.vpnCallsFor("CreateTunnelInterface")
		if len(create) != 1 || !slices.Equal(create[0].Args[1].([]byte), key) {
			t.Errorf("%s: the rebuilt interface has another key", tc.name)
		}
		peer := fx.vpn.vpnCallsFor("ConfigureTunnelPeer")
		if want := fmt.Sprintf("%s:%d", "198.51.100.7", tc.entry.RemotePort); len(peer) != 1 || peer[0].Args[3] != want {
			t.Errorf("%s: ConfigureTunnelPeer = %+v, want the endpoint %s", tc.name, peer, want)
		}
		if got := routeCalls(fx.routes, "AddRoute"); !slices.Equal(got, []string{tc.entry.AllowedSubnets[0] + " " + s2sWGIface, tc.entry.AllowedSubnets[1] + " " + s2sWGIface}) {
			t.Errorf("%s: AddRoute calls = %q, want the entry's subnets in order", tc.name, got)
		}
		requireTunnelUp(t, fx.mgr, s2sID1)
	}
	if got := fx.secrets.fetches(); got[len(got)-1] != (certVersion{"branch-berlin-psk-2", 4}) {
		t.Errorf("fetches = %v, want the new Secret at its listed version last", got)
	}
	if got := logLines(fx.logs, `msg="site-to-site tunnel removed"`); got != 0 {
		t.Errorf("%d 'site-to-site tunnel removed' lines for a rebuild, want 0:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="site-to-site tunnel up"`, "tunnel_id="+s2sID1); got != 4 {
		t.Errorf("%d up lines for branch-berlin, want 4 (the first and three rebuilds):\n%s", got, fx.logs.String())
	}
}

// TestSiteToSiteManager_ApplyTearsDownAndPrunes checks that a tunnel the
// block no longer lists loses its routes, its rewrite, its link and its key,
// that a block with Enabled false removes the links and keeps the keys, and
// that the zero block deletes every key.
func TestSiteToSiteManager_ApplyTearsDownAndPrunes(t *testing.T) {
	fx := newS2SFixture(t, nil)
	second := api.SiteToSiteTunnel{
		ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4", Slug: "branch-hamburg", Kind: api.SiteToSiteKindWireGuard,
		RemoteHost: "198.51.100.40", RemotePort: 51820, AllowedSubnets: []string{"10.50.0.0/16"},
		ListenPort: 51831, RemotePublicKey: deviceKey(0x44),
	}
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, second))
	for _, id := range []string{s2sID1, s2sID2, second.ID} {
		requireTunnelUp(t, fx.mgr, id)
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{s2sID1 + ".key", second.ID + ".key"}) {
		t.Fatalf("key files = %q, want both wireguard tunnels'", got)
	}
	fx.reset()

	// dc-east and branch-hamburg leave the block.
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
	if got := fx.ipsec.removeCalls(); !slices.Equal(got, []string{s2sID2}) {
		t.Errorf("ipsec RemoveTunnel calls = %q, want dc-east's", got)
	}
	wantRoutes := []string{"10.30.0.0/16 " + s2sXfrmIface, "10.31.0.0/16 " + s2sXfrmIface, "10.50.0.0/16 wg-s2s-a0a0a0e4"}
	if got := routeCalls(fx.routes, "RemoveRoute"); !slices.Equal(got, wantRoutes) {
		t.Errorf("RemoveRoute calls = %q, want %q", got, wantRoutes)
	}
	var rewrites, links []string
	for _, c := range fx.rewriter.callsFor("RemoveMeshSourceRewrite") {
		rewrites = append(rewrites, fmt.Sprintf("%s %s", c.Args[0], c.Args[1]))
	}
	for _, c := range fx.vpn.vpnCallsFor("RemoveTunnelInterface") {
		links = append(links, c.Args[0].(string))
	}
	if !slices.Equal(rewrites, []string{s2sXfrmIface + " " + s2sMesh, "wg-s2s-a0a0a0e4 " + s2sMesh}) {
		t.Errorf("RemoveMeshSourceRewrite calls = %q", rewrites)
	}
	if !slices.Equal(links, []string{s2sXfrmIface, "wg-s2s-a0a0a0e4"}) {
		t.Errorf("RemoveTunnelInterface calls = %q", links)
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{s2sID1 + ".key"}) {
		t.Errorf("key files = %q, want the listed tunnel's alone", got)
	}
	if got := tunnelIDs(fx.mgr); !slices.Equal(got, []string{s2sID1}) {
		t.Errorf("tunnels = %q, want the listed one", got)
	}
	for _, line := range []struct{ id, iface string }{{s2sID2, s2sXfrmIface}, {second.ID, "wg-s2s-a0a0a0e4"}} {
		if got := logLines(fx.logs, "level=INFO", `msg="site-to-site tunnel removed"`, "component=bridge", "tunnel_id="+line.id, "interface="+line.iface); got != 1 {
			t.Errorf("%d 'site-to-site tunnel removed' lines for %s, want 1:\n%s", got, line.id, fx.logs.String())
		}
	}
	if got := fx.routes.callsFor("DisableForwarding"); len(got) != 0 {
		t.Errorf("DisableForwarding calls = %+v, want none", got)
	}
	fx.reset()

	disabled := s2sBlock(branchBerlin)
	disabled.Enabled = false
	fx.mgr.Apply(t.Context(), disabled)
	if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
		t.Errorf("RemoveTunnelInterface calls = %+v, want %s", c, s2sWGIface)
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{s2sID1 + ".key"}) {
		t.Errorf("key files after a block with Enabled false = %q, want the listed tunnel's kept", got)
	}
	if info := fx.mgr.SiteToSiteStatus(); info == nil || info.Enabled || len(info.Tunnels) != 0 {
		t.Errorf("SiteToSiteStatus() = %+v, want not enabled and no tunnels", info)
	}
	fx.reset()

	fx.mgr.Apply(t.Context(), api.SiteToSiteConfig{})
	fx.requireNoCalls(t, "the zero block after a disabled one")
	if got := fx.keyFiles(t); len(got) != 0 {
		t.Errorf("key files after the zero block = %q, want none", got)
	}
}

// TestSiteToSiteManager_ApplyEmptyBlocks applies an empty tunnel list and the
// zero block to a manager that holds nothing.
func TestSiteToSiteManager_ApplyEmptyBlocks(t *testing.T) {
	for name, block := range map[string]api.SiteToSiteConfig{
		"empty tunnels": {Enabled: true, Tunnels: []api.SiteToSiteTunnel{}},
		"zero block":    {},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newS2SFixture(t, nil)
			fx.mgr.Apply(t.Context(), block)
			fx.requireNoCalls(t, "Apply of "+name)
			info := fx.mgr.SiteToSiteStatus()
			if info == nil || len(info.Tunnels) != 0 || info.Enabled != block.Enabled {
				t.Errorf("SiteToSiteStatus() = %+v, want Enabled %v and no tunnels", info, block.Enabled)
			}
			if got := fx.keyFiles(t); len(got) != 0 {
				t.Errorf("key files = %q, want none", got)
			}
			if len(fx.resolver.resolved()) != 0 || len(fx.secrets.fetches()) != 0 {
				t.Error("Apply of an empty block resolved or fetched")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reasons
// ---------------------------------------------------------------------------

// TestSiteToSiteManager_LinkReasons checks the reason each failing step of a
// bring-up gives, and that a step after the link was created leaves no link,
// rewrite or route of the attempt.
func TestSiteToSiteManager_LinkReasons(t *testing.T) {
	errBoom := errors.New("boom")
	tests := []struct {
		name   string
		entry  api.SiteToSiteTunnel
		iface  string
		inject func(*s2sFixture)
		reason string
		// routed is how many routes the attempt added before it failed;
		// rewritten whether it added the rewrite.
		routed    int
		rewritten bool
	}{
		{"port in use", branchBerlin, s2sWGIface, func(fx *s2sFixture) {
			fx.vpn.createErr = fmt.Errorf("bridge: vpn: bring up: %w", ErrListenPortInUse)
		}, SiteToSiteReasonBindFailed, 0, false},
		{"other create error", branchBerlin, s2sWGIface, func(fx *s2sFixture) { fx.vpn.createErr = errBoom }, SiteToSiteReasonSetupFailed, 0, false},
		{"configure peer error", branchBerlin, s2sWGIface, func(fx *s2sFixture) { fx.vpn.configureErr = errBoom }, SiteToSiteReasonSetupFailed, 0, false},
		{"xfrm error", dcEast, s2sXfrmIface, func(fx *s2sFixture) { fx.vpn.createXfrmErr = errBoom }, SiteToSiteReasonSetupFailed, 0, false},
		{"tun error", office, s2sTunIface, func(fx *s2sFixture) { fx.vpn.createTunErr = errBoom }, SiteToSiteReasonSetupFailed, 0, false},
		{"forwarding error", branchBerlin, s2sWGIface, func(fx *s2sFixture) { fx.routes.enableForwardingErr = errBoom }, SiteToSiteReasonSetupFailed, 0, false},
		{"rewrite error", dcEast, s2sXfrmIface, func(fx *s2sFixture) { fx.rewriter.addMeshSourceRewriteErr = errBoom }, SiteToSiteReasonSetupFailed, 0, false},
		{"route error", branchBerlin, s2sWGIface, func(fx *s2sFixture) {
			fx.routes.addRouteErrFor = map[string]error{"10.21.0.0/16": errBoom}
		}, SiteToSiteReasonSetupFailed, 1, true},
		{"client missing", dcEast, s2sXfrmIface, func(fx *s2sFixture) {
			fx.ipsec.createErr = fmt.Errorf("bridge: ipsec: load: %w", &exec.Error{Name: "swanctl", Err: exec.ErrNotFound})
		}, SiteToSiteReasonClientMissing, 2, true},
		{"provider error", office, s2sTunIface, func(fx *s2sFixture) { fx.openvpn.createErr = errBoom }, SiteToSiteReasonSetupFailed, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newS2SFixture(t, nil)
			tt.inject(fx)
			fx.mgr.Apply(t.Context(), s2sBlock(tt.entry))

			requireTunnelDown(t, fx.mgr, tt.entry.ID, tt.reason)
			if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 1 || c[0].Args[0] != tt.iface {
				t.Errorf("RemoveTunnelInterface calls = %+v, want the attempt's link %s removed", c, tt.iface)
			}
			removed := routeCalls(fx.routes, "RemoveRoute")
			added := routeCalls(fx.routes, "AddRoute")
			if len(removed) != tt.routed {
				t.Errorf("RemoveRoute calls = %q, want the %d route(s) the attempt added", removed, tt.routed)
			}
			for i, r := range removed {
				if want := added[tt.routed-1-i]; r != want {
					t.Errorf("RemoveRoute %d = %s, want %s: routes are removed in reverse", i, r, want)
				}
			}
			if got := len(fx.rewriter.callsFor("RemoveMeshSourceRewrite")) == 1; got != tt.rewritten {
				t.Errorf("rewrite removed: %v, want %v", got, tt.rewritten)
			}
			if got := fx.routes.callsFor("DisableForwarding"); len(got) != 0 {
				t.Errorf("DisableForwarding calls = %+v, want none", got)
			}
			if got := logLines(fx.logs, "level=WARN", `msg="site-to-site tunnel down"`, "component=bridge",
				"tunnel_id="+tt.entry.ID, "slug="+tt.entry.Slug, "kind="+tt.entry.Kind, "reason="+tt.reason, "error="); got != 1 {
				t.Errorf("%d 'site-to-site tunnel down' lines, want 1:\n%s", got, fx.logs.String())
			}
		})
	}

	t.Run("unreadable key", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		if err := os.MkdirAll(fx.keyDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fx.keyDir, s2sID1+".key"), []byte("not-a-key"), 0600); err != nil {
			t.Fatal(err)
		}
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonKeyUnavailable)
		fx.requireNoCalls(t, "a tunnel without a readable key")
		if data, _ := os.ReadFile(filepath.Join(fx.keyDir, s2sID1+".key")); string(data) != "not-a-key" {
			t.Errorf("key file = %q, want it untouched", data)
		}
	})
}

// TestSiteToSiteManager_KindNotServed checks that a nil Rewriter serves no
// kind, and that an unknown kind and an ipsec tunnel without a provider are
// not served either.
func TestSiteToSiteManager_KindNotServed(t *testing.T) {
	t.Run("nil Rewriter", func(t *testing.T) {
		fx := newS2SFixture(t, func(d *SiteToSiteDeps) { d.Rewriter = nil })
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))
		for _, id := range []string{s2sID1, s2sID2, s2sID3} {
			requireTunnelDown(t, fx.mgr, id, SiteToSiteReasonKindNotServed)
		}
		fx.requireNoCalls(t, "Apply without a Rewriter")
		if len(fx.secrets.fetches()) != 0 || len(fx.resolver.resolved()) != 0 {
			t.Error("a tunnel was resolved or fetched without a Rewriter")
		}
		if got := fx.keyFiles(t); len(got) != 0 {
			t.Errorf("key files = %q, want none: no wireguard tunnel came up", got)
		}
	})

	t.Run("unknown kind", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		gre := dcEast
		gre.Kind = "gre"
		fx.mgr.Apply(t.Context(), s2sBlock(gre))
		requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonKindNotServed)
		fx.requireNoCalls(t, "Apply of a gre tunnel")
	})

	// macOS builds no ipsec and no openvpn provider: their links are Linux
	// kernel features. Its wireguard tunnels come up beside them.
	t.Run("no providers", func(t *testing.T) {
		fx := newS2SFixture(t, func(d *SiteToSiteDeps) { d.Providers = nil })
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))

		// Read before the status, which reads the wireguard tunnel's device.
		if got := fx.vpn.vpnMethods(); !slices.Equal(got, []string{"CreateTunnelInterface", "ConfigureTunnelPeer"}) {
			t.Errorf("VPN calls = %q, want the wireguard tunnel's alone", got)
		}
		requireTunnelUp(t, fx.mgr, s2sID1)
		for id, kind := range map[string]string{s2sID2: "ipsec", s2sID3: "openvpn"} {
			requireTunnelDown(t, fx.mgr, id, SiteToSiteReasonKindNotServed)
			if got := logLines(fx.logs, "level=WARN", `msg="site-to-site tunnel down"`, "tunnel_id="+id,
				"reason=kind_not_served", "no "+kind+" provider is built in"); got != 1 {
				t.Errorf("%d down lines for the %s tunnel, want 1:\n%s", got, kind, fx.logs.String())
			}
		}
	})

	t.Run("no provider", func(t *testing.T) {
		fx := newS2SFixture(t, func(d *SiteToSiteDeps) { delete(d.Providers, api.SiteToSiteKindIPsec) })
		fx.mgr.Apply(t.Context(), s2sBlock(dcEast))
		requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonKindNotServed)
		fx.requireNoCalls(t, "Apply of an ipsec tunnel without a provider")
		if len(fx.secrets.fetches()) != 0 {
			t.Error("the Secret of a kind without a provider was fetched")
		}
	})
}

// TestSiteToSiteManager_RemoteHostUnresolved checks that a name that does
// not resolve and one without an address give remote_host_unresolved before
// any fetch or link, and that an IP address is not resolved at all.
func TestSiteToSiteManager_RemoteHostUnresolved(t *testing.T) {
	for name, adjust := range map[string]func(*fakeResolver){
		"not found": func(r *fakeResolver) {
			r.err = &net.DNSError{Err: "no such host", Name: "vpn.branch.example.com", IsNotFound: true}
		},
		"no address": func(r *fakeResolver) { r.addrs["vpn.branch.example.com"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			fx := newS2SFixture(t, nil)
			fx.resolver.set(adjust)
			fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
			requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonRemoteHostUnresolved)
			fx.requireNoCalls(t, "a tunnel whose host does not resolve")
			if len(fx.secrets.fetches()) != 0 {
				t.Errorf("fetches = %v, want none", fx.secrets.fetches())
			}
		})
	}

	t.Run("an IP address", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		fx.resolver.set(func(r *fakeResolver) { r.err = errors.New("not to be called") })
		literal := branchBerlin
		literal.RemoteHost = "203.0.113.10"
		fx.mgr.Apply(t.Context(), s2sBlock(literal))
		requireTunnelUp(t, fx.mgr, s2sID1)
		if got := fx.resolver.resolved(); len(got) != 0 {
			t.Errorf("resolved = %q, want nothing for an IP address", got)
		}
		if c := fx.vpn.vpnCallsFor("ConfigureTunnelPeer"); len(c) != 1 || c[0].Args[3] != "203.0.113.10:51820" {
			t.Errorf("ConfigureTunnelPeer calls = %+v, want the endpoint 203.0.113.10:51820", c)
		}
	})
}

// TestSiteToSiteManager_InvalidTunnels checks every case of a tunnel's own
// checks, that an entry with an invalid or repeated id gets no state, and
// that an ipsec tunnel without a mesh CIDR reads setup_failed.
func TestSiteToSiteManager_InvalidTunnels(t *testing.T) {
	with := func(base api.SiteToSiteTunnel, f func(*api.SiteToSiteTunnel)) api.SiteToSiteTunnel {
		e := base
		e.AllowedSubnets = slices.Clone(base.AllowedSubnets)
		f(&e)
		return e
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("10.%d.0.0/16", 100+i)
	}
	// The last 8 hex digits of this id are those of s2sID1.
	const clashID = "0190a8b8-ffff-7a0a-8a0a-0000a0a0a0e1"
	tests := []struct {
		name    string
		entries []api.SiteToSiteTunnel
		id      string // the tunnel that reads invalid_tunnel
	}{
		{"remote_host with a space", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.RemoteHost = "vpn branch" })}, s2sID2},
		{"remote_host with a line break", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.RemoteHost = "203.0.113.10\n" })}, s2sID2},
		{"remote_host of 254", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.RemoteHost = strings.Repeat("a", 254) })}, s2sID2},
		{"no remote_host", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.RemoteHost = "" })}, s2sID2},
		{"remote_port 0", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.RemotePort = 0 })}, s2sID2},
		{"remote_port 65536", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.RemotePort = 65536 })}, s2sID2},
		{"no allowed_subnets", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{} })}, s2sID2},
		{"65 allowed_subnets", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = tooMany })}, s2sID2},
		{"a subnet that is no prefix", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"10.30.0.0/16", "not-a-prefix"} })}, s2sID2},
		{"an IPv6 subnet", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"fd00::/64"} })}, s2sID2},
		{"host bits set", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"10.30.0.1/16"} })}, s2sID2},
		{"a repeated subnet", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"10.30.0.0/16", "10.30.0.0/16"} })}, s2sID2},
		{"a subnet inside the mesh", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"10.99.0.0/25"} })}, s2sID2},
		{"the default route", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"0.0.0.0/0"} })}, s2sID2},
		{"a subnet of an earlier tunnel", []api.SiteToSiteTunnel{
			branchBerlin,
			with(dcEast, func(e *api.SiteToSiteTunnel) { e.AllowedSubnets = []string{"10.21.128.0/17"} }),
		}, s2sID2},
		{"zero hex digits", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.ID = "0190a8b8-a0c0-7a0a-8a0a-a0a000000000" })}, "0190a8b8-a0c0-7a0a-8a0a-a0a000000000"},
		{"hex digits of an earlier tunnel of the kind", []api.SiteToSiteTunnel{
			branchBerlin,
			with(branchBerlin, func(e *api.SiteToSiteTunnel) {
				e.ID, e.Slug, e.ListenPort, e.AllowedSubnets = clashID, "clash", 51831, []string{"10.60.0.0/16"}
			}),
		}, clashID},
		{"listen_port 0", []api.SiteToSiteTunnel{with(branchBerlin, func(e *api.SiteToSiteTunnel) { e.ListenPort = 0 })}, s2sID1},
		{"listen_port 65536", []api.SiteToSiteTunnel{with(branchBerlin, func(e *api.SiteToSiteTunnel) { e.ListenPort = 65536 })}, s2sID1},
		{"remote_public_key not base64", []api.SiteToSiteTunnel{with(branchBerlin, func(e *api.SiteToSiteTunnel) { e.RemotePublicKey = "not-a-key" })}, s2sID1},
		{"remote_public_key of 31 bytes", []api.SiteToSiteTunnel{with(branchBerlin, func(e *api.SiteToSiteTunnel) {
			e.RemotePublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31))
		})}, s2sID1},
		{"no remote_public_key", []api.SiteToSiteTunnel{with(branchBerlin, func(e *api.SiteToSiteTunnel) { e.RemotePublicKey = "" })}, s2sID1},
		{"wireguard auth_secret_name outside the grammar", []api.SiteToSiteTunnel{with(branchBerlin, func(e *api.SiteToSiteTunnel) { e.AuthSecretName = "Branch PSK" })}, s2sID1},
		{"ipsec without auth_secret_name", []api.SiteToSiteTunnel{with(dcEast, func(e *api.SiteToSiteTunnel) { e.AuthSecretName = "" })}, s2sID2},
		{"openvpn auth_secret_name outside the grammar", []api.SiteToSiteTunnel{with(office, func(e *api.SiteToSiteTunnel) { e.AuthSecretName = "office/ovpn" })}, s2sID3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newS2SFixture(t, nil)
			fx.mgr.Apply(t.Context(), s2sBlock(tt.entries...))
			requireTunnelDown(t, fx.mgr, tt.id, SiteToSiteReasonInvalidTunnel)
			if got := logLines(fx.logs, "level=WARN", `msg="site-to-site tunnel down"`, "tunnel_id="+tt.id, "reason=invalid_tunnel", "error="); got != 1 {
				t.Errorf("%d down lines for the tunnel, want 1:\n%s", got, fx.logs.String())
			}
			// The earlier tunnel is served.
			if tt.id != tt.entries[0].ID {
				requireTunnelUp(t, fx.mgr, tt.entries[0].ID)
			} else if got := fx.calls(); len(got) != 0 {
				t.Errorf("calls = %q, want none for an invalid tunnel", got)
			}
		})
	}

	t.Run("the same hex digits on another kind", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		sameDigits := with(dcEast, func(e *api.SiteToSiteTunnel) { e.ID = "0190a8b8-ffff-7a0a-8a0a-0000a0a0a0e1" })
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, sameDigits))
		requireTunnelUp(t, fx.mgr, s2sID1)
		if ti := requireTunnelUp(t, fx.mgr, sameDigits.ID); ti.Interface != "xf-s2s-a0a0a0e1" {
			t.Errorf("ipsec tunnel = %+v, want up on xf-s2s-a0a0a0e1", ti)
		}
	})

	t.Run("invalid and repeated ids", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		repeated := with(dcEast, func(e *api.SiteToSiteTunnel) { e.ID, e.Slug = strings.ToUpper(s2sID1), "again" })
		block := s2sBlock(
			with(office, func(e *api.SiteToSiteTunnel) { e.ID, e.Slug = "not-a-uuid", "nouuid" }),
			branchBerlin,
			repeated,
			with(office, func(e *api.SiteToSiteTunnel) { e.ID, e.Slug = "00000000-0000-0000-0000-000000000000", "zero" }),
		)
		fx.mgr.Apply(t.Context(), block)
		// The controller calls are read before the status, which reads the
		// handshake of branch-berlin's interface.
		if got := fx.vpn.vpnMethods(); !slices.Equal(got, []string{"CreateTunnelInterface", "ConfigureTunnelPeer"}) {
			t.Errorf("controller calls = %q, want branch-berlin's alone", got)
		}
		if got := tunnelIDs(fx.mgr); !slices.Equal(got, []string{s2sID1}) {
			t.Errorf("tunnels = %q, want branch-berlin alone", got)
		}
		requireTunnelUp(t, fx.mgr, s2sID1)
		if len(fx.ipsec.calls()) != 0 || len(fx.openvpn.calls()) != 0 {
			t.Error("a provider was called for an entry without state")
		}
		for _, id := range []string{"not-a-uuid", strings.ToUpper(s2sID1), "00000000-0000-0000-0000-000000000000"} {
			if got := logLines(fx.logs, "level=WARN", `msg="site-to-site tunnel down"`, "tunnel_id="+id, "reason=invalid_tunnel"); got != 1 {
				t.Errorf("%d down lines for %s, want 1:\n%s", got, id, fx.logs.String())
			}
		}
		// An unchanged block logs nothing again.
		fx.mgr.Apply(t.Context(), block)
		if got := logLines(fx.logs, `msg="site-to-site tunnel down"`); got != 3 {
			t.Errorf("%d down lines after a second Apply, want still 3:\n%s", got, fx.logs.String())
		}
	})

	t.Run("ipsec without a mesh CIDR", func(t *testing.T) {
		fx := newS2SFixture(t, func(d *SiteToSiteDeps) { d.MeshCIDR = "" })
		fx.mgr.Apply(t.Context(), s2sBlock(dcEast, office))
		requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonSetupFailed)
		if got := fx.ipsec.calls(); len(got) != 0 {
			t.Errorf("ipsec calls = %q, want none", got)
		}
		if got := fx.vpn.vpnCallsFor("CreateXfrmInterface"); len(got) != 0 {
			t.Errorf("CreateXfrmInterface calls = %+v, want none", got)
		}
		// An openvpn tunnel needs no traffic selector.
		requireTunnelUp(t, fx.mgr, s2sID3)
		if c := fx.openvpn.createCalls(); len(c) != 1 || len(c[0].cfg.LocalSubnets) != 0 {
			t.Errorf("openvpn CreateTunnel calls = %+v, want one without a local subnet", c)
		}
	})
}

// TestSiteToSiteManager_SecretPath checks the reasons of the Secret a tunnel
// names, and a wireguard tunnel without one.
func TestSiteToSiteManager_SecretPath(t *testing.T) {
	t.Run("not listed", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("other", 1))
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))
		for _, id := range []string{s2sID1, s2sID2, s2sID3} {
			requireTunnelDown(t, fx.mgr, id, SiteToSiteReasonAuthSecretNotListed)
		}
		fx.requireNoCalls(t, "tunnels whose Secret is not listed")
		if len(fx.secrets.fetches()) != 0 || len(fx.resolver.resolved()) != 0 {
			t.Error("a tunnel whose Secret is not listed was fetched or resolved")
		}
	})

	t.Run("fetch refused", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		fx.secrets.setErr(fmt.Errorf("fetch secret: %w", &api.APIError{StatusCode: 403, Message: "forbidden"}))
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonAuthSecretUnreadable)
		requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretUnreadable)
		fx.requireNoCalls(t, "tunnels whose Secret is unreadable")
	})

	t.Run("no WireGuard preshared key", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		fx.secrets.set("branch-berlin-psk", 1, "not-a-psk")
		fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
		requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonSetupFailed)
		fx.requireNoCalls(t, "a tunnel whose Secret holds no preshared key")
		if strings.Contains(fx.logs.String(), "not-a-psk") {
			t.Error("the log carries the Secret's value")
		}
	})

	t.Run("wireguard without a Secret", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		noPSK := branchBerlin
		noPSK.AuthSecretName = ""
		fx.mgr.Apply(t.Context(), s2sBlock(noPSK))
		requireTunnelUp(t, fx.mgr, s2sID1)
		if len(fx.secrets.fetches()) != 0 {
			t.Errorf("fetches = %v, want none", fx.secrets.fetches())
		}
		if c := fx.vpn.vpnCallsFor("ConfigureTunnelPeer"); len(c) != 1 || c[0].Args[4] != "" {
			t.Errorf("ConfigureTunnelPeer calls = %+v, want one with an empty preshared key", c)
		}
	})

	t.Run("pull handler keeps the held inventory", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		handler := SiteToSitePullHandler(fx.mgr)
		fx.secrets.setErr(errors.New("control plane unreachable"))
		fx.mgr.Apply(t.Context(), s2sBlock(dcEast))
		requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretUnreadable)

		// A pull without a secrets block keeps the inventory the manager
		// holds, so the retry fetches the listed version.
		fx.secrets.setErr(nil)
		fx.clock.Add(5 * time.Second)
		handler(t.Context(), &api.NodeStateSnapshot{})
		requireTunnelUp(t, fx.mgr, s2sID2)
		if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{"dc-east-ike", 1}, {"dc-east-ike", 1}}) {
			t.Errorf("fetches = %v, want the held version twice", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Retry and rebuild
// ---------------------------------------------------------------------------

// TestSiteToSiteManager_SyncSecretInventoryRetries checks that a tunnel down
// for auth_secret_not_listed is brought up once the inventory lists its
// Secret and its next attempt is due on the manager's clock, not before.
func TestSiteToSiteManager_SyncSecretInventoryRetries(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.SyncSecretInventory(t.Context(), nil)
	fx.mgr.Apply(t.Context(), s2sBlock(dcEast))
	requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretNotListed)

	fx.clock.Add(4 * time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("dc-east-ike", 1))
	requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretNotListed)
	if len(fx.secrets.fetches()) != 0 {
		t.Fatalf("fetches = %v before the 5 s delay passed, want none", fx.secrets.fetches())
	}

	fx.clock.Add(time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("dc-east-ike", 1))
	requireTunnelUp(t, fx.mgr, s2sID2)
	if got := fx.secrets.fetches(); !slices.Equal(got, []certVersion{{"dc-east-ike", 1}}) {
		t.Errorf("fetches = %v, want the listed version once", got)
	}
	if got := logLines(fx.logs, `msg="site-to-site tunnel down"`); got != 1 {
		t.Errorf("%d down lines, want 1:\n%s", got, fx.logs.String())
	}
}

// TestSiteToSiteManager_SyncSecretInventoryRebuilds checks that a tunnel that
// is up is rebuilt with the version the inventory lists when that moves, and
// keeps running when the inventory drops its Secret.
func TestSiteToSiteManager_SyncSecretInventoryRebuilds(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	key := fx.storedKey(t, s2sID1)
	rotated := deviceKey(0x43)
	fx.secrets.set("branch-berlin-psk", 2, rotated)
	fx.reset()

	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "branch-berlin-psk", Version: 2}, {Name: "dc-east-ike", Version: 1}})
	if got := fx.secrets.fetches(); got[len(got)-1] != (certVersion{"branch-berlin-psk", 2}) {
		t.Errorf("fetches = %v, want the new version last", got)
	}
	if got, want := fx.vpn.vpnMethods(), []string{"RemoveTunnelInterface", "CreateTunnelInterface", "ConfigureTunnelPeer"}; !slices.Equal(got, want) {
		t.Errorf("controller calls = %q, want the tunnel rebuilt: %q", got, want)
	}
	peer := fx.vpn.vpnCallsFor("ConfigureTunnelPeer")
	if len(peer) != 1 || peer[0].Args[4] != rotated {
		t.Errorf("ConfigureTunnelPeer calls = %+v, want the rotated preshared key", peer)
	}
	if c := fx.vpn.vpnCallsFor("CreateTunnelInterface"); len(c) != 1 || !slices.Equal(c[0].Args[1].([]byte), key) {
		t.Error("the rebuilt interface has another key")
	}
	if got := fx.ipsec.calls(); len(got) != 0 {
		t.Errorf("ipsec calls = %q, want dc-east left alone: its version did not move", got)
	}
	requireTunnelUp(t, fx.mgr, s2sID1)
	requireTunnelUp(t, fx.mgr, s2sID2)
	if strings.Contains(fx.logs.String(), rotated) {
		t.Error("the log carries the rotated preshared key")
	}
	fx.reset()

	// The same inventory again rebuilds nothing.
	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "branch-berlin-psk", Version: 2}, {Name: "dc-east-ike", Version: 1}})
	fx.requireNoCalls(t, "an unchanged inventory")

	// An inventory without the Secrets leaves both tunnels running.
	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{})
	fx.requireNoCalls(t, "an inventory that dropped the Secrets")
	requireTunnelUp(t, fx.mgr, s2sID1)
	requireTunnelUp(t, fx.mgr, s2sID2)
}

// TestSiteToSiteManager_Rebuild checks that Rebuild stops the wireguard tunnel
// that is up and brings it up again with its key, leaves the ipsec tunnel that
// is up and the wireguard tunnel that is down alone, and signals
// ReportChanged, and that it calls nothing on an inactive manager.
func TestSiteToSiteManager_Rebuild(t *testing.T) {
	fx := newS2SFixture(t, nil)
	hamburg := api.SiteToSiteTunnel{
		ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4", Slug: "branch-hamburg", Kind: api.SiteToSiteKindWireGuard,
		RemoteHost: "198.51.100.40", RemotePort: 51820, AllowedSubnets: []string{"10.50.0.0/16"},
		ListenPort: 51831, RemotePublicKey: deviceKey(0x44),
	}
	fx.vpn.createErrFor = map[string]error{"wg-s2s-a0a0a0e4": fmt.Errorf("bind: %w", ErrListenPortInUse)}
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, hamburg))
	requireTunnelUp(t, fx.mgr, s2sID1)
	requireTunnelUp(t, fx.mgr, s2sID2)
	requireTunnelDown(t, fx.mgr, hamburg.ID, SiteToSiteReasonBindFailed)
	attempts := func() int {
		fx.mgr.mu.Lock()
		defer fx.mgr.mu.Unlock()
		for _, tun := range fx.mgr.tunnels {
			if tun.entry.ID == hamburg.ID {
				return tun.attempts
			}
		}
		return -1
	}
	hamburgAttempts := attempts()
	key := fx.storedKey(t, s2sID1)
	fetched := len(fx.secrets.fetches())
	changed := fx.mgr.ReportChanged()
	drain(changed)
	fx.reset()

	fx.mgr.Rebuild(t.Context())
	requireSignal(t, changed, "a Rebuild")
	requireNoSignal(t, changed, "a Rebuild, a second time")
	if got, want := fx.vpn.vpnMethods(), []string{"RemoveTunnelInterface", "CreateTunnelInterface", "ConfigureTunnelPeer"}; !slices.Equal(got, want) {
		t.Errorf("controller calls = %q, want branch-berlin rebuilt: %q", got, want)
	}
	for _, m := range []string{"RemoveTunnelInterface", "CreateTunnelInterface", "ConfigureTunnelPeer"} {
		if c := fx.vpn.vpnCallsFor(m); len(c) != 1 || c[0].Args[0] != s2sWGIface {
			t.Errorf("%s calls = %+v, want one on %s", m, c, s2sWGIface)
		}
	}
	if c := fx.vpn.vpnCallsFor("CreateTunnelInterface"); len(c) != 1 || !slices.Equal(c[0].Args[1].([]byte), key) {
		t.Error("the rebuilt interface has another key")
	}
	if got, want := fx.routes.methods(), []string{"RemoveRoute", "RemoveRoute", "EnableForwarding", "AddRoute", "AddRoute"}; !slices.Equal(got, want) {
		t.Errorf("route calls = %q, want %q", got, want)
	}
	if got, want := fx.rewriter.methods(), []string{"RemoveMeshSourceRewrite", "AddMeshSourceRewrite"}; !slices.Equal(got, want) {
		t.Errorf("rewriter calls = %q, want %q", got, want)
	}
	if got := fx.ipsec.calls(); len(got) != 0 {
		t.Errorf("ipsec calls = %q, want dc-east left alone", got)
	}
	if got := fx.secrets.fetches()[fetched:]; !slices.Equal(got, []certVersion{{"branch-berlin-psk", 1}}) {
		t.Errorf("fetches during Rebuild = %v, want branch-berlin's Secret alone", got)
	}
	if got := attempts(); got != hamburgAttempts {
		t.Errorf("branch-hamburg attempts = %d after Rebuild, want %d", got, hamburgAttempts)
	}
	requireTunnelUp(t, fx.mgr, s2sID1)
	requireTunnelUp(t, fx.mgr, s2sID2)
	requireTunnelDown(t, fx.mgr, hamburg.ID, SiteToSiteReasonBindFailed)
	if got := logLines(fx.logs, `msg="site-to-site tunnel up"`, "tunnel_id="+s2sID1); got != 2 {
		t.Errorf("%d up lines for branch-berlin, want 2 (the first and the rebuild):\n%s", got, fx.logs.String())
	}

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	fx.reset()
	fx.mgr.Rebuild(t.Context())
	fx.requireNoCalls(t, "a Rebuild of the inactive manager")
}

// TestSiteToSiteManager_RebuildCarriesTheNewAddress runs Rebuild over a
// WGVPNController, as plexd up does on macOS: after SetAddress the rebuilt
// interface carries the new address.
func TestSiteToSiteManager_RebuildCarriesTheNewAddress(t *testing.T) {
	wg := &fakeWGController{}
	vpn := NewWGVPNController(wg, "10.99.0.1/32", discardLogger())
	fx := newS2SFixture(t, func(d *SiteToSiteDeps) { d.VPN = vpn })
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
	requireTunnelUp(t, fx.mgr, s2sID1)

	vpn.SetAddress("10.99.0.9/32")
	fx.mgr.Rebuild(t.Context())
	requireTunnelUp(t, fx.mgr, s2sID1)
	var got []string
	for _, c := range wg.wgCallsFor("ConfigureAddress") {
		got = append(got, fmt.Sprintf("%s %s", c.Args[0], c.Args[1]))
	}
	if want := []string{s2sWGIface + " 10.99.0.1/32", s2sWGIface + " 10.99.0.9/32"}; !slices.Equal(got, want) {
		t.Errorf("ConfigureAddress calls = %q, want %q", got, want)
	}
	if c := wg.wgCallsFor("DeleteInterface"); len(c) != 1 || c[0].Args[0] != s2sWGIface {
		t.Errorf("DeleteInterface calls = %+v, want the old interface removed once", c)
	}
}

// TestSiteToSiteManager_RetryDelays checks the delays between the attempts of
// a tunnel that keeps failing: 5 s doubling to 60 s, and the Retry-After of
// an API error when that is longer, and that the down line is logged once
// per reason.
func TestSiteToSiteManager_RetryDelays(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.vpn.createErr = fmt.Errorf("bind: %w", ErrListenPortInUse)
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
	created := 1
	requireDelay := func(d time.Duration) {
		t.Helper()
		fx.clock.Add(d - time.Second)
		fx.mgr.Retry(t.Context())
		if got := len(fx.vpn.vpnCallsFor("CreateTunnelInterface")); got != created {
			t.Fatalf("%v after the failure: %d creates, want %d", d-time.Second, got, created)
		}
		fx.clock.Add(time.Second)
		fx.mgr.Retry(t.Context())
		created++
		if got := len(fx.vpn.vpnCallsFor("CreateTunnelInterface")); got != created {
			t.Fatalf("%v after the failure: %d creates, want %d", d, got, created)
		}
	}
	for _, d := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second} {
		requireDelay(d)
	}
	requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonBindFailed)
	if got := logLines(fx.logs, `msg="site-to-site tunnel down"`, "reason=bind_failed"); got != 1 {
		t.Errorf("%d down lines across the retries, want 1:\n%s", got, fx.logs.String())
	}

	// A fetch refused with a Retry-After longer than the delay waits for it.
	fx.secrets.setErr(&api.APIError{StatusCode: 429, Message: "rate limited", RetryAfter: 120 * time.Second})
	fx.clock.Add(60 * time.Second)
	fx.mgr.Retry(t.Context())
	requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonAuthSecretUnreadable)
	fetched := len(fx.secrets.fetches())
	fx.clock.Add(119 * time.Second)
	fx.mgr.Retry(t.Context())
	if got := len(fx.secrets.fetches()); got != fetched {
		t.Fatalf("%d fetches 119 s after a Retry-After of 120 s, want %d", got, fetched)
	}
	fx.secrets.setErr(nil)
	fx.vpn.set(func(m *mockVPNController) { m.createErr = nil })
	fx.clock.Add(time.Second)
	fx.mgr.Retry(t.Context())
	requireTunnelUp(t, fx.mgr, s2sID1)
	if got := logLines(fx.logs, `msg="site-to-site tunnel down"`); got != 2 {
		t.Errorf("%d down lines, want one per reason:\n%s", got, fx.logs.String())
	}
}

// TestSiteToSiteManager_NeverRetriesInvalidOrNotServed checks that Retry and
// SyncSecretInventory never bring up a tunnel down for invalid_tunnel or
// kind_not_served.
func TestSiteToSiteManager_NeverRetriesInvalidOrNotServed(t *testing.T) {
	fx := newS2SFixture(t, func(d *SiteToSiteDeps) { delete(d.Providers, api.SiteToSiteKindOpenVPN) })
	invalid := branchBerlin
	invalid.ListenPort = 0
	gre := dcEast
	gre.Kind = "gre"
	fx.mgr.Apply(t.Context(), s2sBlock(invalid, gre, office))
	requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonInvalidTunnel)
	requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonKindNotServed)
	requireTunnelDown(t, fx.mgr, s2sID3, SiteToSiteReasonKindNotServed)

	// Make a retry observable: with an openvpn provider in place, an
	// attempt on office would resolve, fetch and call it, and every attempt
	// on any tunnel counts in its attempts.
	fx.mgr.mu.Lock()
	fx.mgr.providers[api.SiteToSiteKindOpenVPN] = fx.openvpn
	attempts := make(map[string]int)
	for _, tun := range fx.mgr.tunnels {
		attempts[tun.entry.ID] = tun.attempts
	}
	fx.mgr.mu.Unlock()

	for range 3 {
		fx.clock.Add(time.Hour)
		fx.mgr.Retry(t.Context())
		fx.mgr.SyncSecretInventory(t.Context(), s2sInventory())
	}
	fx.requireNoCalls(t, "Retry")
	if len(fx.secrets.fetches()) != 0 || len(fx.resolver.resolved()) != 0 {
		t.Error("a tunnel that is not retried was fetched or resolved")
	}
	fx.mgr.mu.Lock()
	for _, tun := range fx.mgr.tunnels {
		if tun.attempts != attempts[tun.entry.ID] {
			t.Errorf("tunnel %s: attempts = %d after Retry, want %d", tun.entry.ID, tun.attempts, attempts[tun.entry.ID])
		}
	}
	fx.mgr.mu.Unlock()
	if got := logLines(fx.logs, `msg="site-to-site tunnel down"`); got != 3 {
		t.Errorf("%d down lines, want 3:\n%s", got, fx.logs.String())
	}
}

// TestSiteToSiteManager_OneFailingTunnelLeavesTheOthersUp brings up a block
// in which one tunnel cannot bind: the others are up.
func TestSiteToSiteManager_OneFailingTunnelLeavesTheOthersUp(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.vpn.createErrFor = map[string]error{s2sWGIface: fmt.Errorf("bind: %w", ErrListenPortInUse)}
	second := api.SiteToSiteTunnel{
		ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e4", Slug: "branch-hamburg", Kind: api.SiteToSiteKindWireGuard,
		RemoteHost: "198.51.100.40", RemotePort: 51820, AllowedSubnets: []string{"10.50.0.0/16"},
		ListenPort: 51831, RemotePublicKey: deviceKey(0x44),
	}
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, second, dcEast, office))

	requireTunnelDown(t, fx.mgr, s2sID1, SiteToSiteReasonBindFailed)
	if ti := requireTunnelUp(t, fx.mgr, second.ID); ti.Interface != "wg-s2s-a0a0a0e4" {
		t.Errorf("branch-hamburg = %+v, want up on wg-s2s-a0a0a0e4", ti)
	}
	requireTunnelUp(t, fx.mgr, s2sID2)
	requireTunnelUp(t, fx.mgr, s2sID3)
	if got := tunnelIDs(fx.mgr); !slices.Equal(got, []string{s2sID1, second.ID, s2sID2, s2sID3}) {
		t.Errorf("tunnels = %q, want all four in block order", got)
	}
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

func TestSiteToSiteManager_Teardown(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast, office))
	for _, id := range []string{s2sID1, s2sID2, s2sID3} {
		requireTunnelUp(t, fx.mgr, id)
	}
	fx.reset()

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := fx.ipsec.removeCalls(); !slices.Equal(got, []string{s2sID2}) {
		t.Errorf("ipsec RemoveTunnel calls = %q, want dc-east's", got)
	}
	if got := fx.openvpn.removeCalls(); !slices.Equal(got, []string{s2sID3}) {
		t.Errorf("openvpn RemoveTunnel calls = %q, want office's", got)
	}
	var links []string
	for _, c := range fx.vpn.vpnCallsFor("RemoveTunnelInterface") {
		links = append(links, c.Args[0].(string))
	}
	if !slices.Equal(links, []string{s2sWGIface, s2sXfrmIface, s2sTunIface}) {
		t.Errorf("links removed = %q, want all three", links)
	}
	if got := len(fx.routes.callsFor("RemoveRoute")); got != 5 {
		t.Errorf("RemoveRoute calls = %d, want one per subnet, 5", got)
	}
	if got := len(fx.rewriter.callsFor("RemoveMeshSourceRewrite")); got != 3 {
		t.Errorf("RemoveMeshSourceRewrite calls = %d, want 3", got)
	}
	if got := fx.routes.callsFor("DisableForwarding"); len(got) != 0 {
		t.Errorf("DisableForwarding calls = %+v, want none", got)
	}
	if got := fx.keyFiles(t); !slices.Equal(got, []string{s2sID1 + ".key"}) {
		t.Errorf("key files after Teardown = %q, want the tunnel's kept", got)
	}
	if fx.mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus() after Teardown is not nil")
	}
	if got := logLines(fx.logs, `msg="site-to-site manager stopped"`, "component=bridge"); got != 1 {
		t.Errorf("%d 'site-to-site manager stopped' lines, want 1:\n%s", got, fx.logs.String())
	}

	// Inactive, the manager does nothing.
	fx.reset()
	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin))
	fx.mgr.SyncSecretInventory(t.Context(), s2sInventory())
	fx.clock.Add(time.Hour)
	fx.mgr.Retry(t.Context())
	fx.requireNoCalls(t, "the inactive manager")
	if fx.mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus() of the inactive manager is not nil")
	}
}

func TestSiteToSiteManager_TeardownJoinsErrors(t *testing.T) {
	fx := newS2SFixture(t, nil)
	fx.mgr.Apply(t.Context(), s2sBlock(branchBerlin, dcEast))
	errLink, errProvider, errRewrite := errors.New("remove link"), errors.New("remove provider"), errors.New("remove rewrite")
	fx.vpn.set(func(m *mockVPNController) { m.removeErr = errLink })
	fx.ipsec.set(func(p *mockTunnelProvider) { p.removeErr = errProvider })
	fx.rewriter.removeMeshSourceRewriteErr = errRewrite

	err := fx.mgr.Teardown()
	for _, want := range []error{errLink, errProvider, errRewrite} {
		if !errors.Is(err, want) {
			t.Errorf("Teardown = %v, want it to wrap %v", err, want)
		}
	}
	if got := len(fx.vpn.vpnCallsFor("RemoveTunnelInterface")); got != 2 {
		t.Errorf("RemoveTunnelInterface calls = %d, want 2: a failure does not stop the cleanup", got)
	}
	if fx.mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus() after a failed Teardown is not nil")
	}
	if err := fx.mgr.Teardown(); err != nil {
		t.Errorf("second Teardown = %v, want nil", err)
	}
}

// TestSiteToSiteManager_TeardownDuringAnAttempt tears the manager down while
// an attempt resolves its remote host outside the manager's mutex: the
// attempt that finishes after Teardown sets nothing up.
func TestSiteToSiteManager_TeardownDuringAnAttempt(t *testing.T) {
	fx := newS2SFixture(t, nil)
	started, release := make(chan struct{}), make(chan struct{})
	fx.resolver.set(func(r *fakeResolver) {
		r.hook = func() {
			close(started)
			<-release
		}
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		fx.mgr.Apply(context.Background(), s2sBlock(branchBerlin))
	}()
	<-started
	// The attempt runs outside the mutex: the status leaves the unsettled
	// tunnel out and Teardown completes.
	if info := fx.mgr.SiteToSiteStatus(); info == nil || len(info.Tunnels) != 0 {
		t.Errorf("SiteToSiteStatus() during the first attempt = %+v, want no tunnel yet", info)
	}
	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	close(release)
	<-done

	fx.requireNoCalls(t, "an attempt that finished after Teardown")
	if len(fx.secrets.fetches()) != 0 {
		t.Errorf("fetches = %v, want none after Teardown", fx.secrets.fetches())
	}
	if fx.mgr.SiteToSiteStatus() != nil {
		t.Error("SiteToSiteStatus() after Teardown is not nil")
	}
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func TestSiteToSitePullHandler(t *testing.T) {
	fx := newS2SFixture(t, nil)
	handler := SiteToSitePullHandler(fx.mgr)
	fx.mgr.SyncSecretInventory(t.Context(), nil)
	fx.mgr.Apply(t.Context(), s2sBlock(dcEast))
	requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretNotListed)

	// A nil snapshot changes nothing.
	fx.clock.Add(5 * time.Second)
	handler(t.Context(), nil)
	requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretNotListed)

	// A pull with an inventory hands it over and retries.
	inventory := inventoryOf("dc-east-ike", 1)
	handler(t.Context(), &api.NodeStateSnapshot{Secrets: &inventory})
	requireTunnelUp(t, fx.mgr, s2sID2)

	// A pull without a secrets block keeps the held inventory: nothing is
	// rebuilt.
	fx.reset()
	handler(t.Context(), &api.NodeStateSnapshot{})
	fx.requireNoCalls(t, "a pull without a secrets block")
	requireTunnelUp(t, fx.mgr, s2sID2)
}

func TestSiteToSiteReconcileHandler(t *testing.T) {
	withTunnels := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{SiteToSite: &api.SiteToSiteConfig{
		Enabled: true,
		Tunnels: []api.SiteToSiteTunnel{branchBerlin, dcEast},
	}}}
	bridgeChanged := reconcile.StateDiff{BridgeChanged: true}

	t.Run("with a manager", func(t *testing.T) {
		fx := newS2SFixture(t, nil)
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("branch-berlin-psk", 1))
		handler := SiteToSiteReconcileHandler(fx.mgr, discardLogger())
		if err := handler(t.Context(), withTunnels, bridgeChanged); err != nil {
			t.Fatalf("handler = %v, want nil", err)
		}
		requireTunnelUp(t, fx.mgr, s2sID1)
		// The ipsec tunnel is down without its Secret, and the handler still
		// returns nil.
		requireTunnelDown(t, fx.mgr, s2sID2, SiteToSiteReasonAuthSecretNotListed)

		// A nil snapshot changes nothing.
		fx.reset()
		if err := handler(t.Context(), nil, bridgeChanged); err != nil {
			t.Fatalf("handler(nil) = %v, want nil", err)
		}
		fx.requireNoCalls(t, "a nil snapshot")
		requireTunnelUp(t, fx.mgr, s2sID1)

		// A block with Enabled false serves nothing and keeps the keys.
		disabled := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{SiteToSite: &api.SiteToSiteConfig{Tunnels: withTunnels.Bridge.SiteToSite.Tunnels}}}
		if err := handler(t.Context(), disabled, bridgeChanged); err != nil {
			t.Fatalf("handler(disabled) = %v, want nil", err)
		}
		if got := tunnelIDs(fx.mgr); len(got) != 0 {
			t.Errorf("tunnels after a disabled block = %q, want none", got)
		}
		if got := fx.keyFiles(t); len(got) != 1 {
			t.Errorf("key files after a disabled block = %q, want branch-berlin's kept", got)
		}
	})

	for name, desired := range map[string]*api.NodeStateSnapshot{
		"nil Bridge":     {},
		"nil SiteToSite": {Bridge: &api.BridgeSnapshot{}},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newS2SFixture(t, nil)
			handler := SiteToSiteReconcileHandler(fx.mgr, discardLogger())
			if err := handler(t.Context(), withTunnels, bridgeChanged); err != nil {
				t.Fatalf("handler: %v", err)
			}
			fx.reset()
			if err := handler(t.Context(), desired, bridgeChanged); err != nil {
				t.Fatalf("handler(%s) = %v, want nil", name, err)
			}
			if got := tunnelIDs(fx.mgr); len(got) != 0 {
				t.Errorf("tunnels = %q, want none", got)
			}
			if c := fx.vpn.vpnCallsFor("RemoveTunnelInterface"); len(c) != 2 {
				t.Errorf("RemoveTunnelInterface calls = %d, want 2", len(c))
			}
			if got := fx.keyFiles(t); len(got) != 0 {
				t.Errorf("key files after the zero block = %q, want none", got)
			}
		})
	}

	t.Run("opted out", func(t *testing.T) {
		logger, logs := newRelayLogger()
		handler := SiteToSiteReconcileHandler(nil, logger)
		if err := handler(t.Context(), withTunnels, bridgeChanged); err != nil {
			t.Fatalf("handler = %v, want nil", err)
		}
		const warn = `msg="site-to-site: the control plane enables site-to-site tunnels, but bridge.site_to_site_enabled is false"`
		if got := logLines(logs, "level=WARN", warn, "component=bridge", "tunnels=2"); got != 1 {
			t.Errorf("%d opted-out Warn lines with tunnels=2, want 1:\n%s", got, logs.String())
		}
		if got := logLines(logs); got != 1 {
			t.Errorf("%d log lines, want only the Warn:\n%s", got, logs.String())
		}

		disabled := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{SiteToSite: &api.SiteToSiteConfig{Tunnels: withTunnels.Bridge.SiteToSite.Tunnels}}}
		for _, tc := range []struct {
			name    string
			desired *api.NodeStateSnapshot
			diff    reconcile.StateDiff
		}{
			{"nil snapshot", nil, bridgeChanged},
			{"nil Bridge", &api.NodeStateSnapshot{}, bridgeChanged},
			{"nil SiteToSite", &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{}}, bridgeChanged},
			{"not enabled with tunnels", disabled, bridgeChanged},
			{"enabled without tunnels", &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{SiteToSite: &api.SiteToSiteConfig{Enabled: true}}}, bridgeChanged},
			{"enabled with tunnels, no bridge drift", withTunnels, reconcile.StateDiff{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				logger, logs := newRelayLogger()
				handler := SiteToSiteReconcileHandler(nil, logger)
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

// TestSiteToSiteReasons_AreReasonTokens checks that every reason the manager
// reports matches the contract's reason grammar, which the control plane
// enforces on a site-to-site status report.
func TestSiteToSiteReasons_AreReasonTokens(t *testing.T) {
	grammar := regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	for _, reason := range []string{
		SiteToSiteReasonInvalidTunnel,
		SiteToSiteReasonKindNotServed,
		SiteToSiteReasonKeyUnavailable,
		SiteToSiteReasonBindFailed,
		SiteToSiteReasonSetupFailed,
		SiteToSiteReasonAuthSecretNotListed,
		SiteToSiteReasonAuthSecretUnreadable,
		SiteToSiteReasonClientMissing,
		SiteToSiteReasonRemoteHostUnresolved,
	} {
		if !grammar.MatchString(reason) {
			t.Errorf("reason %q does not match %s", reason, grammar)
		}
	}
}

func TestSiteToSiteInterfaceNames(t *testing.T) {
	for _, tc := range []struct {
		kind, id, want string
	}{
		{api.SiteToSiteKindWireGuard, s2sID1, "wg-s2s-a0a0a0e1"},
		{api.SiteToSiteKindIPsec, s2sID2, "xf-s2s-a0a0a0e2"},
		{api.SiteToSiteKindOpenVPN, strings.ToUpper(s2sID3), "ov-s2s-a0a0a0e3"},
		{"gre", s2sID1, ""},
	} {
		got := siteToSiteInterfaceName(tc.kind, tc.id)
		if got != tc.want {
			t.Errorf("siteToSiteInterfaceName(%s, %s) = %q, want %q", tc.kind, tc.id, got, tc.want)
		}
		if len(got) > 15 {
			t.Errorf("%q is longer than the kernel's 15 characters", got)
		}
	}
	if got := siteToSiteInterfaceID(s2sID2); got != 2694881506 {
		t.Errorf("siteToSiteInterfaceID(%s) = %d, want 2694881506", s2sID2, got)
	}
}
