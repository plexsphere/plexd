package bridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The reasons a site-to-site tunnel is down for. Each is the reason of the
// tunnel's entry in the node API's status.site-to-site report and of its
// "site-to-site tunnel down" line. invalid_tunnel, setup_failed and
// key_unavailable are plexd's own; the control plane stores any token of the
// reason grammar.
const (
	// SiteToSiteReasonInvalidTunnel: a member of the entry is missing or
	// malformed, or the entry clashes with an earlier one of the block. It is
	// not retried until the entry changes.
	SiteToSiteReasonInvalidTunnel = "invalid_tunnel"
	// SiteToSiteReasonKindNotServed: this plexd serves no tunnel of the kind,
	// because the platform has no mesh source rewrite, the kind is unknown,
	// or no provider of the kind is built in. It is not retried until the
	// entry changes.
	SiteToSiteReasonKindNotServed = "kind_not_served"
	// SiteToSiteReasonKeyUnavailable: the key of a wireguard tunnel's
	// interface could not be read or created.
	SiteToSiteReasonKeyUnavailable = "key_unavailable"
	// SiteToSiteReasonBindFailed: the interface of a wireguard tunnel cannot
	// listen on its port, which another socket holds.
	SiteToSiteReasonBindFailed = "bind_failed"
	// SiteToSiteReasonSetupFailed: the tunnel's link, its peer, its
	// forwarding, its source rewrite, its routes or the daemon's side of it
	// could not be set up, the Secret of a wireguard tunnel holds no
	// preshared key, or an ipsec tunnel has no mesh CIDR as its local
	// traffic selector.
	SiteToSiteReasonSetupFailed = "setup_failed"
	// SiteToSiteReasonAuthSecretNotListed: the secret inventory does not list
	// the Secret the tunnel names.
	SiteToSiteReasonAuthSecretNotListed = "auth_secret_not_listed"
	// SiteToSiteReasonAuthSecretUnreadable: the inventory lists the Secret,
	// but it could not be fetched.
	SiteToSiteReasonAuthSecretUnreadable = "auth_secret_unreadable"
	// SiteToSiteReasonClientMissing: the host has no client of the kind,
	// swanctl for ipsec or openvpn for openvpn.
	SiteToSiteReasonClientMissing = "client_missing"
	// SiteToSiteReasonRemoteHostUnresolved: remote_host is a host name that
	// does not resolve.
	SiteToSiteReasonRemoteHostUnresolved = "remote_host_unresolved"
)

// siteToSiteProviderTimeout bounds what a provider runs for one call that
// ends on its own: the commands of an ipsec tunnel's CreateTunnel, every
// RemoveTunnel, and the resets of CleanupSiteToSite.
const siteToSiteProviderTimeout = 30 * time.Second

// maxSiteToSiteSubnets is the contract's ceiling on a tunnel's
// allowed_subnets.
const maxSiteToSiteSubnets = 64

// siteToSiteEstablishedAge is the oldest latest handshake with the remote
// peer that counts the remote site of a wireguard tunnel as answering.
const siteToSiteEstablishedAge = 180 * time.Second

// siteToSiteEstablishedTimeout bounds one call of a provider's Established.
const siteToSiteEstablishedTimeout = 5 * time.Second

// SiteToSiteDeps are what a SiteToSiteManager serves tunnels with.
type SiteToSiteDeps struct {
	// VPN creates and removes the link of each tunnel: the WireGuard
	// interface of a wireguard tunnel, the xfrm interface of an ipsec tunnel
	// and the tun device of an openvpn tunnel.
	VPN VPNController
	// Routes switches forwarding on between a tunnel's link and the mesh
	// interface and routes the tunnel's allowed_subnets into the link. The
	// manager never switches forwarding off: a tunnel's link is deleted with
	// the tunnel, and the mesh interface's forwarding belongs to the bridge
	// manager.
	Routes RouteController
	// Rewriter rewrites the source of what a tunnel forwards into the mesh to
	// the bridge's mesh address. nil: this platform serves no tunnel; one
	// that passes its checks reads kind_not_served, one that fails them
	// invalid_tunnel.
	Rewriter MeshSourceRewriter
	// Keys keeps the private key of each wireguard tunnel's interface. It
	// must not be nil.
	Keys *InterfaceKeyStore
	// Secrets fetches the key a tunnel's Secret holds. It must not be nil
	// while a tunnel names a Secret the inventory lists.
	Secrets SecretValueFetcher
	// Providers holds the provider of each kind other than wireguard this
	// plexd serves, by kind: ipsec and openvpn. A kind without a provider
	// reads kind_not_served.
	Providers map[string]TunnelProvider
	// Resolve resolves a remote_host that is no IP address. nil resolves
	// with net.DefaultResolver.LookupNetIP(ctx, "ip", host).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// MeshInterface is the name of the mesh interface.
	MeshInterface string
	// MeshCIDR is the Domain mesh prefix: the local traffic selector of an
	// ipsec tunnel, and the prefix no allowed subnet may overlap. Empty when
	// the node has none, which leaves an ipsec tunnel down with
	// setup_failed.
	MeshCIDR string
	Logger   *slog.Logger
}

// SiteToSiteManager serves the site-to-site tunnels of the state pull's
// bridge.site_to_site block: for each a link of its kind, a WireGuard
// interface with a kept key and the remote site as its peer, an xfrm
// interface that strongSwan binds an IKE connection to, or a tun device an
// openvpn process runs on. Each link forwards into the mesh with its source
// rewritten to the bridge's mesh address, and the tunnel's allowed_subnets are
// routed into it. Each tunnel is served on its own, so one that is down leaves
// the others up. SiteToSiteManager is concurrent-safe via mu.
//
// Apply, SyncSecretInventory and Retry are called from the reconciler's
// goroutine alone. They resolve a tunnel's remote host and fetch its Secret
// outside mu, so Teardown and the status readers do not wait for either. The
// status readers, TunnelReports and SiteToSiteStatus, read whether a remote
// site answers outside mu as well, so neither the reconciler nor Teardown
// waits for a device read or a provider's command.
type SiteToSiteManager struct {
	vpn       VPNController
	routes    RouteController
	rewriter  MeshSourceRewriter
	keys      *InterfaceKeyStore
	secrets   SecretValueFetcher
	providers map[string]TunnelProvider
	resolve   func(ctx context.Context, host string) ([]netip.Addr, error)
	meshIface string
	meshCIDR  string
	logger    *slog.Logger
	now       func() time.Time

	// mu protects the fields below from concurrent access by the reconcile
	// loop, Teardown and the status readers.
	mu sync.Mutex

	active bool
	// ctx is the context the openvpn processes run under; Teardown cancels
	// it.
	ctx    context.Context
	cancel context.CancelFunc
	// enabled is the Enabled of the last applied block.
	enabled bool
	// tunnels holds every tunnel of the last applied block with a valid,
	// unrepeated id, in block order; none while the block is not enabled.
	tunnels []*siteToSiteTunnel
	// inventory is the last secret inventory, version by Secret name; nil
	// until the first SyncSecretInventory.
	inventory map[string]int
	// invalidIDs holds the "site-to-site tunnel down" lines of the last Apply
	// for entries without state, so each is logged once.
	invalidIDs map[string]struct{}

	// changed carries ReportChanged's signal; capacity 1.
	changed chan struct{}
}

// siteToSiteTunnel is what the manager holds for one tunnel of the block. Its
// fields are read and written under the manager's mu while the manager holds
// it; Teardown stops the tunnels it detached outside mu.
type siteToSiteTunnel struct {
	// entry is the tunnel as the last Apply listed it; its ID is as pulled.
	entry api.SiteToSiteTunnel
	// key is the id lower-cased, which names the key file, the link and the
	// provider's files.
	key string
	// check is why the entry is invalid_tunnel, nil when it passed its own
	// checks.
	check error

	// settled is false until an attempt to bring the tunnel up has an
	// outcome; an unsettled tunnel is not reported. An attempt resolves and
	// fetches outside mu, which leaves a new or rebuilt tunnel unsettled for
	// a while.
	settled bool
	up      bool
	// reason says why the tunnel is down; empty while it is up.
	reason string
	// attempts counts the consecutive failed attempts; nextAttempt is when
	// Retry may try again.
	attempts    int
	nextAttempt time.Time

	// While the tunnel is up: its link, the public key of a wireguard
	// tunnel's interface, and the version of the Secret it was built with,
	// 0 for a tunnel without one. iface is the name the VPN controller, the
	// provider, the status report and the log lines take.
	iface     string
	publicKey string
	version   int
	// osIface is the name the operating system knows iface by, which
	// forwarding, the source rewrite and the routes take: the utunN behind a
	// wireguard tunnel's interface on macOS, and iface itself everywhere
	// else.
	osIface string
}

// siteToSiteAttempt is one attempt to bring a tunnel up past the checks that
// need no lookup: its remote host is resolved and its Secret fetched outside
// mu, then its link, routes and daemon are set up under mu.
type siteToSiteAttempt struct {
	t     *siteToSiteTunnel
	entry api.SiteToSiteTunnel
	key   string
	// version is the version of the tunnel's Secret the inventory lists, 0
	// for a tunnel without one.
	version int
	// ctx is the manager's context, which an openvpn process runs under.
	ctx context.Context
}

// NewSiteToSiteManager creates a SiteToSiteManager. It serves nothing until
// Setup.
func NewSiteToSiteManager(deps SiteToSiteDeps) *SiteToSiteManager {
	resolve := deps.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	return &SiteToSiteManager{
		vpn:       deps.VPN,
		routes:    deps.Routes,
		rewriter:  deps.Rewriter,
		keys:      deps.Keys,
		secrets:   deps.Secrets,
		providers: deps.Providers,
		resolve:   resolve,
		meshIface: deps.MeshInterface,
		meshCIDR:  deps.MeshCIDR,
		logger:    deps.Logger,
		now:       time.Now,
		changed:   make(chan struct{}, 1),
	}
}

// CleanupSiteToSite removes what a process that was killed left behind: every
// link whose name starts with one of SiteToSiteInterfacePrefixes, through
// vpn.RemoveTunnelInterfaces, and the files of every provider, through its
// Reset, all under a timeout of 30 s. A nil vpn is skipped. Every step runs;
// the errors are joined.
//
// The source rewrites of a killed process are gone before it runs: plexd up
// runs CleanupUserAccess first, which resets the table both managers share.
// Without it a tunnel's next create fails on the name the killed process
// left, and a link of a bridge that opted out since keeps its port open.
func CleanupSiteToSite(vpn VPNController, providers map[string]TunnelProvider) error {
	ctx, cancel := context.WithTimeout(context.Background(), siteToSiteProviderTimeout)
	defer cancel()

	var errs []error
	if vpn != nil {
		if err := vpn.RemoveTunnelInterfaces(SiteToSiteInterfacePrefixes); err != nil {
			errs = append(errs, err)
		}
	}
	for _, kind := range slices.Sorted(maps.Keys(providers)) {
		provider := providers[kind]
		if provider == nil {
			continue
		}
		if err := provider.Reset(ctx); err != nil {
			errs = append(errs, fmt.Errorf("reset the %s provider: %w", kind, err))
		}
	}
	return errors.Join(errs...)
}

// Setup removes what a process that was killed left behind, with
// CleanupSiteToSite, so that a tunnel's link can be created again under its
// name, creates the context the openvpn processes run under, and marks the
// manager active. A failed cleanup fails Setup and leaves the manager
// inactive.
func (m *SiteToSiteManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active {
		return nil
	}
	if err := CleanupSiteToSite(m.vpn, m.providers); err != nil {
		return fmt.Errorf("bridge: site-to-site: clean up: %w", err)
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.active = true

	m.logger.Info("site-to-site manager started", "component", "bridge")
	return nil
}

// Teardown removes every tunnel: the provider's side of it, its routes, its
// source rewrite and its link. It cancels the context the openvpn processes
// run under and marks the manager inactive. It keeps the key files, so a
// wireguard tunnel comes back with its key after a restart. Errors are
// joined; the cleanup continues past a failure. Idempotent: calling Teardown
// when inactive returns nil. It signals ReportChanged when it returns.
func (m *SiteToSiteManager) Teardown() error {
	defer m.signalReport()
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return nil
	}
	held := m.tunnels
	cancel := m.cancel
	m.active = false
	m.enabled = false
	m.tunnels = nil
	m.inventory = nil
	m.invalidIDs = nil
	m.mu.Unlock()

	// Nothing reads the held tunnels once the manager is inactive, and an
	// attempt that finishes now sets nothing up.
	var errs []error
	for _, t := range held {
		if err := m.stopTunnel(t); err != nil {
			errs = append(errs, err)
		}
	}
	cancel()

	if len(errs) == 0 {
		m.logger.Info("site-to-site manager stopped", "component", "bridge")
	}
	return errors.Join(errs...)
}

// Apply serves the block whole. It does nothing while the manager is not
// active.
//
//   - The key files of every tunnel the block lists are kept, whatever
//     Enabled says, and every other key file is deleted; the zero block
//     deletes them all.
//   - A block with Enabled false serves no tunnel.
//   - A held tunnel the block does not serve is torn down.
//   - A held tunnel whose entry is unchanged is kept: the same kind,
//     remote_host, remote_port, allowed_subnets in order, listen_port,
//     remote_public_key and auth_secret_name, and the same verdict of its
//     checks. A changed slug is taken over in place. Any other change tears
//     the tunnel down and brings it up again, a wireguard tunnel with its
//     kept key.
//   - A new tunnel is brought up, in block order.
//
// A tunnel that cannot be brought up is down with its reason, and Retry
// tries again when the reason allows it. Apply signals ReportChanged when it
// returns, after every attempt it started.
func (m *SiteToSiteManager) Apply(ctx context.Context, block api.SiteToSiteConfig) {
	defer m.signalReport()
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	m.enabled = block.Enabled

	keep := make(map[string]struct{})
	for _, e := range block.Tunnels {
		if api.ValidSiteToSiteTunnelID(e.ID) {
			keep[strings.ToLower(e.ID)] = struct{}{}
		}
	}
	var entries []api.SiteToSiteTunnel
	if block.Enabled {
		entries = block.Tunnels
	}
	planned := m.planLocked(entries)

	held := make(map[string]*siteToSiteTunnel, len(m.tunnels))
	for _, t := range m.tunnels {
		held[t.key] = t
	}
	listed := make(map[string]struct{}, len(planned))
	kept := make(map[*siteToSiteTunnel]struct{})
	var next, fresh []*siteToSiteTunnel
	for _, nt := range planned {
		listed[nt.key] = struct{}{}
		if t := held[nt.key]; t != nil && t.unchanged(nt) {
			t.entry = nt.entry
			kept[t] = struct{}{}
			next = append(next, t)
			continue
		}
		next = append(next, nt)
		fresh = append(fresh, nt)
	}

	for _, t := range m.tunnels {
		if _, ok := kept[t]; ok {
			continue
		}
		_, relisted := listed[t.key]
		iface := t.iface
		if err := m.stopTunnel(t); err != nil {
			m.logger.Error("bridge: site-to-site: tear down tunnel failed",
				"component", "bridge",
				"tunnel_id", t.entry.ID,
				"interface", iface,
				"error", err,
			)
		} else if !relisted {
			m.logger.Info("site-to-site tunnel removed",
				"component", "bridge",
				"tunnel_id", t.entry.ID,
				"interface", iface,
			)
		}
	}
	m.tunnels = next

	if err := m.keys.Prune(keep); err != nil {
		m.logger.Error("bridge: site-to-site: prune keys failed",
			"component", "bridge",
			"error", err,
		)
	}

	var attempts []*siteToSiteAttempt
	for _, t := range fresh {
		if a := m.attemptLocked(t); a != nil {
			attempts = append(attempts, a)
		}
	}
	m.mu.Unlock()

	m.runAttempts(ctx, attempts)
}

// SyncSecretInventory replaces the secret inventory the tunnels take their
// Secret's version from, rebuilds every tunnel that is up and whose Secret
// the inventory lists at another version than the one it was built with, and
// then calls Retry. A tunnel whose Secret the inventory no longer lists keeps
// running with the key it has. It does nothing while the manager is not
// active.
func (m *SiteToSiteManager) SyncSecretInventory(ctx context.Context, inventory []api.NodeStateSecret) {
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	m.inventory = secretInventory(inventory)

	var attempts []*siteToSiteAttempt
	for _, t := range m.tunnels {
		if !t.up || t.entry.AuthSecretName == "" {
			continue
		}
		version, listed := m.inventory[t.entry.AuthSecretName]
		if !listed || version == t.version {
			continue
		}
		iface := t.iface
		if err := m.stopTunnel(t); err != nil {
			m.logger.Error("bridge: site-to-site: tear down tunnel failed",
				"component", "bridge",
				"tunnel_id", t.entry.ID,
				"interface", iface,
				"error", err,
			)
		}
		// Unsettled, the tunnel is left out of the reports until the
		// rebuild has an outcome, rather than read down without a reason.
		t.settled = false
		if a := m.attemptLocked(t); a != nil {
			attempts = append(attempts, a)
		}
	}
	m.mu.Unlock()

	m.runAttempts(ctx, attempts)
	m.Retry(ctx)
}

// Retry brings up again every tunnel that is down for bind_failed,
// setup_failed, key_unavailable, auth_secret_not_listed,
// auth_secret_unreadable, client_missing or remote_host_unresolved and whose
// next attempt is due on the manager's clock. The delay after a failed
// attempt is 5 s, doubling per consecutive failure to 60 s, or the
// Retry-After of an API error when that is longer. invalid_tunnel and
// kind_not_served are not retried until the entry changes. It does nothing
// while the manager is not active. It signals ReportChanged when it returns.
func (m *SiteToSiteManager) Retry(ctx context.Context) {
	defer m.signalReport()
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	now := m.now()
	var attempts []*siteToSiteAttempt
	for _, t := range m.tunnels {
		if t.up || !t.settled || !siteToSiteRetryable(t.reason) || now.Before(t.nextAttempt) {
			continue
		}
		if a := m.attemptLocked(t); a != nil {
			attempts = append(attempts, a)
		}
	}
	m.mu.Unlock()

	m.runAttempts(ctx, attempts)
}

// siteToSiteRetryable reports whether Retry brings a tunnel down for reason
// up again.
func siteToSiteRetryable(reason string) bool {
	switch reason {
	case SiteToSiteReasonBindFailed, SiteToSiteReasonSetupFailed, SiteToSiteReasonKeyUnavailable,
		SiteToSiteReasonAuthSecretNotListed, SiteToSiteReasonAuthSecretUnreadable,
		SiteToSiteReasonClientMissing, SiteToSiteReasonRemoteHostUnresolved:
		return true
	}
	return false
}

// TunnelReports returns one report per tunnel of the last applied block with
// a valid id no earlier entry carried, in block order, and nil while the
// manager is not active. A tunnel whose first attempt has no outcome yet,
// because its remote host is resolved or its Secret fetched outside mu, is
// left out until it has one.
//
// A tunnel that is down reports its reason. A tunnel that is up reports
// whether its remote site answers, read outside mu with one device read or
// one provider command: for a wireguard tunnel its latest handshake with the
// remote peer is at most 180 s old on the manager's clock, and it reports the
// public key of its interface; for an ipsec or openvpn tunnel the provider's
// Established says so within 5 s. A failed read counts false.
func (m *SiteToSiteManager) TunnelReports() []SiteToSiteTunnelReport {
	_, views, active := m.settledTunnels()
	if !active {
		return nil
	}
	out := make([]SiteToSiteTunnelReport, 0, len(views))
	for _, v := range views {
		r := SiteToSiteTunnelReport{
			TunnelID: v.entry.ID,
			Kind:     v.entry.Kind,
			Health:   api.SiteToSiteHealthDown,
			Reason:   v.reason,
		}
		if v.up {
			r.Health = api.SiteToSiteHealthUp
			r.PublicKey = v.publicKey
			r.Established = v.established
		}
		out = append(out, r)
	}
	return out
}

// ReportChanged returns the channel the manager signals, without blocking,
// when what TunnelReports returns may have changed: at the end of every
// Apply, every Retry, and so every SyncSecretInventory, and Teardown. Several
// signals before the reader wakes collapse into one. The signals are liberal;
// the reader compares before it acts. A change of whether a remote site
// answers signals nothing.
func (m *SiteToSiteManager) ReportChanged() <-chan struct{} {
	return m.changed
}

// signalReport signals ReportChanged without blocking: a full channel already
// carries the signal.
func (m *SiteToSiteManager) signalReport() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// SiteToSiteStatus returns the site-to-site status for the node API's
// status.site-to-site report: the Enabled of the last applied block and one
// entry per tunnel TunnelReports reports, in block order, with its health,
// the reason of a tunnel that is down, and the link of one that is up and
// whether its remote site answers, read as TunnelReports reads it. It returns
// nil while the manager is not active.
func (m *SiteToSiteManager) SiteToSiteStatus() *api.SiteToSiteInfo {
	enabled, views, active := m.settledTunnels()
	if !active {
		return nil
	}
	info := &api.SiteToSiteInfo{Enabled: enabled}
	for _, v := range views {
		ti := api.SiteToSiteTunnelInfo{
			ID:             v.entry.ID,
			Slug:           v.entry.Slug,
			Kind:           v.entry.Kind,
			Interface:      v.iface,
			Health:         api.SiteToSiteHealthDown,
			Reason:         v.reason,
			RemoteHost:     v.entry.RemoteHost,
			RemotePort:     v.entry.RemotePort,
			AllowedSubnets: append([]string{}, v.entry.AllowedSubnets...),
		}
		if v.up {
			ti.Health = api.SiteToSiteHealthUp
			ti.Established = v.established
		}
		if v.entry.Kind == api.SiteToSiteKindWireGuard {
			ti.ListenPort = v.entry.ListenPort
		}
		info.Tunnels = append(info.Tunnels, ti)
	}
	return info
}

// siteToSiteView is a copy of what the manager holds for one tunnel with a
// settled attempt, taken under mu, and whether the remote site of a tunnel
// that is up answers, read outside it.
type siteToSiteView struct {
	entry       api.SiteToSiteTunnel
	key         string
	up          bool
	reason      string
	iface       string
	publicKey   string
	established bool
}

// settledTunnels returns the Enabled of the last applied block and a view of
// each tunnel the manager holds with a settled attempt, in block order, and
// active false while the manager is not active. It copies the tunnels under
// mu and then reads, outside mu, whether the remote site of each one that is
// up answers. TunnelReports and SiteToSiteStatus both read through it, so
// the report and the local status agree.
func (m *SiteToSiteManager) settledTunnels() (enabled bool, views []siteToSiteView, active bool) {
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return false, nil, false
	}
	enabled = m.enabled
	for _, t := range m.tunnels {
		if !t.settled {
			continue
		}
		views = append(views, siteToSiteView{
			entry:     t.entry,
			key:       t.key,
			up:        t.up,
			reason:    t.reason,
			iface:     t.iface,
			publicKey: t.publicKey,
		})
	}
	m.mu.Unlock()

	for i := range views {
		if views[i].up {
			views[i].established = m.established(views[i])
		}
	}
	return enabled, views, true
}

// established reports whether the remote site of v, a tunnel that is up,
// answers: for a wireguard tunnel its latest handshake with the remote peer,
// read with TunnelPeerHandshake, is at most siteToSiteEstablishedAge old on
// the manager's clock; for an ipsec or openvpn tunnel the provider's
// Established says so, under a timeout of siteToSiteEstablishedTimeout. A
// failed read counts false and is logged at Debug. It runs outside mu: a
// tunnel torn down meanwhile fails its read or reads false.
func (m *SiteToSiteManager) established(v siteToSiteView) bool {
	var ok bool
	var err error
	if v.entry.Kind == api.SiteToSiteKindWireGuard {
		var at time.Time
		at, err = m.vpn.TunnelPeerHandshake(v.iface, v.entry.RemotePublicKey)
		// The controller gives the zero time for a peer that never completed
		// a handshake.
		ok = !at.IsZero() && m.now().Sub(at) <= siteToSiteEstablishedAge
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), siteToSiteEstablishedTimeout)
		ok, err = m.providers[v.entry.Kind].Established(ctx, v.key)
		cancel()
	}
	if err != nil {
		m.logger.Debug("bridge: site-to-site: read established failed",
			"component", "bridge",
			"tunnel_id", v.entry.ID,
			"kind", v.entry.Kind,
			"interface", v.iface,
			"error", err,
		)
		return false
	}
	return ok
}

// planLocked returns the state of each entry with a valid id no earlier entry
// carried, compared without case, in block order, with the verdict of the
// entry's own checks. An entry with an invalid or repeated id gets no state,
// since the control plane refuses a whole report for one; it is logged once
// while the block lists it. The caller holds mu.
//
// An entry claims its valid subnets and its kind's link name, whatever the
// rest of its checks say, so a later entry's verdict depends only on the ids,
// kinds and subnets before it.
func (m *SiteToSiteManager) planLocked(entries []api.SiteToSiteTunnel) []*siteToSiteTunnel {
	var out []*siteToSiteTunnel
	mesh, _ := netip.ParsePrefix(m.meshCIDR)
	seen := make(map[string]struct{})
	logged := make(map[string]struct{})
	var claimed []netip.Prefix
	names := make(map[string]struct{})
	for _, e := range entries {
		var invalid error
		key := strings.ToLower(e.ID)
		if !api.ValidSiteToSiteTunnelID(e.ID) {
			invalid = errors.New("the id is no UUID other than the zero UUID")
		} else if _, dup := seen[key]; dup {
			invalid = errors.New("an earlier tunnel of the block has the same id")
		}
		if invalid != nil {
			line := e.ID + "\x00" + invalid.Error()
			logged[line] = struct{}{}
			if _, ok := m.invalidIDs[line]; !ok {
				m.logDown(e, SiteToSiteReasonInvalidTunnel, invalid)
			}
			continue
		}
		seen[key] = struct{}{}

		check := checkSiteToSiteEntry(e, key, mesh, claimed, names)
		for _, s := range e.AllowedSubnets {
			if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() && p == p.Masked() {
				claimed = append(claimed, p)
			}
		}
		names[siteToSiteNameClaim(e.Kind, key)] = struct{}{}
		out = append(out, &siteToSiteTunnel{entry: e, key: key, check: check})
	}
	m.invalidIDs = logged
	return out
}

// siteToSiteNameClaim identifies the link name a tunnel of kind with the
// lower-cased id key takes: its kind and the last 8 hex digits of its id.
func siteToSiteNameClaim(kind, key string) string {
	return kind + " " + key[len(key)-8:]
}

// checkSiteToSiteEntry runs the checks of an entry with a valid id, lower
// cased as key, and returns why it is invalid_tunnel, or nil. mesh is the
// Domain mesh prefix, invalid when the node has none; claimed holds the
// subnets and names the link names of the earlier tunnels of the block.
func checkSiteToSiteEntry(e api.SiteToSiteTunnel, key string, mesh netip.Prefix, claimed []netip.Prefix, names map[string]struct{}) error {
	if !tunnelRemoteHostPattern.MatchString(e.RemoteHost) {
		return fmt.Errorf("remote_host %q is no host name or IP address", e.RemoteHost)
	}
	if e.RemotePort < 1 || e.RemotePort > 65535 {
		return fmt.Errorf("remote_port %d is outside 1 to 65535", e.RemotePort)
	}
	if n := len(e.AllowedSubnets); n == 0 || n > maxSiteToSiteSubnets {
		return fmt.Errorf("allowed_subnets holds %d subnets, want 1 to %d", n, maxSiteToSiteSubnets)
	}
	own := make(map[netip.Prefix]struct{}, len(e.AllowedSubnets))
	for _, s := range e.AllowedSubnets {
		p, err := netip.ParsePrefix(s)
		switch {
		case err != nil || !p.Addr().Is4():
			return fmt.Errorf("allowed subnet %q is no IPv4 prefix", s)
		case p != p.Masked():
			return fmt.Errorf("allowed subnet %s has host bits set", s)
		}
		if _, dup := own[p]; dup {
			return fmt.Errorf("allowed subnet %s repeats", s)
		}
		own[p] = struct{}{}
		if mesh.IsValid() && mesh.Overlaps(p) {
			return fmt.Errorf("allowed subnet %s overlaps the mesh CIDR %s", s, mesh)
		}
		for _, c := range claimed {
			if c.Overlaps(p) {
				return fmt.Errorf("allowed subnet %s overlaps the subnet %s of an earlier tunnel of the block", s, c)
			}
		}
	}
	if strings.HasSuffix(key, "00000000") {
		return errors.New("the last 8 hex digits of the id are zero")
	}
	if _, taken := names[siteToSiteNameClaim(e.Kind, key)]; taken {
		return fmt.Errorf("an earlier %s tunnel of the block ends its id in the same 8 hex digits", e.Kind)
	}
	switch e.Kind {
	case api.SiteToSiteKindWireGuard:
		if e.ListenPort < 1 || e.ListenPort > 65535 {
			return fmt.Errorf("listen_port %d is outside 1 to 65535", e.ListenPort)
		}
		if !validWireGuardKey(e.RemotePublicKey) {
			return errors.New("remote_public_key is no WireGuard key of 44 characters of standard base64")
		}
		if e.AuthSecretName != "" && !api.ValidSecretName(e.AuthSecretName) {
			return fmt.Errorf("auth_secret_name %q is no Secret name", e.AuthSecretName)
		}
	case api.SiteToSiteKindIPsec, api.SiteToSiteKindOpenVPN:
		if !api.ValidSecretName(e.AuthSecretName) {
			return fmt.Errorf("auth_secret_name %q is no Secret name", e.AuthSecretName)
		}
	}
	return nil
}

// validWireGuardKey reports whether s is a WireGuard key as the contract
// writes one: 44 characters of standard base64 that decode to 32 bytes.
func validWireGuardKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return len(s) == 44 && err == nil && len(raw) == 32
}

// unchanged reports whether the held tunnel t serves nt's entry as it is: the
// same kind, remote_host, remote_port, allowed_subnets in order, listen_port,
// remote_public_key and auth_secret_name, and the same verdict of the checks.
// The slug changes in place.
func (t *siteToSiteTunnel) unchanged(nt *siteToSiteTunnel) bool {
	old, e := t.entry, nt.entry
	return old.Kind == e.Kind &&
		old.RemoteHost == e.RemoteHost &&
		old.RemotePort == e.RemotePort &&
		slices.Equal(old.AllowedSubnets, e.AllowedSubnets) &&
		old.ListenPort == e.ListenPort &&
		old.RemotePublicKey == e.RemotePublicKey &&
		old.AuthSecretName == e.AuthSecretName &&
		errText(t.check) == errText(nt.check)
}

// siteToSiteInterfaceName returns the name of a tunnel's link: the prefix of
// its kind and the last 8 hex digits of its id, lower case, wg-s2s-a0a0a0e1
// for a wireguard tunnel 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1, xf-s2s- for
// the xfrm interface of an ipsec tunnel and ov-s2s- for the tun device of an
// openvpn tunnel. The first digits of a UUIDv7 are its timestamp and repeat
// for tunnels created within a minute. The 15 characters are the kernel's
// limit. It returns "" for any other kind. id is a valid tunnel id.
func siteToSiteInterfaceName(kind, id string) string {
	id = strings.ToLower(id)
	var prefix string
	switch kind {
	case api.SiteToSiteKindWireGuard:
		prefix = SiteToSiteWireGuardPrefix
	case api.SiteToSiteKindIPsec:
		prefix = SiteToSiteXfrmPrefix
	case api.SiteToSiteKindOpenVPN:
		prefix = SiteToSiteTunPrefix
	default:
		return ""
	}
	return prefix + id[len(id)-8:]
}

// siteToSiteInterfaceID returns the id of an ipsec tunnel's xfrm interface:
// the last 8 hex digits of the tunnel's id as a number, 2694881506 for
// 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2. id is a valid tunnel id.
func siteToSiteInterfaceID(id string) uint32 {
	n, _ := strconv.ParseUint(id[len(id)-8:], 16, 32)
	return uint32(n)
}

// attemptLocked runs the checks of a tunnel that need no lookup and returns
// its attempt, or nil when a check put the tunnel down. The caller holds mu.
func (m *SiteToSiteManager) attemptLocked(t *siteToSiteTunnel) *siteToSiteAttempt {
	e := t.entry
	if t.check != nil {
		m.downLocked(t, SiteToSiteReasonInvalidTunnel, t.check)
		return nil
	}
	switch {
	case m.rewriter == nil:
		m.downLocked(t, SiteToSiteReasonKindNotServed, errors.New("this platform has no mesh source rewrite"))
		return nil
	case e.Kind == api.SiteToSiteKindWireGuard:
	case e.Kind == api.SiteToSiteKindIPsec || e.Kind == api.SiteToSiteKindOpenVPN:
		if m.providers[e.Kind] == nil {
			m.downLocked(t, SiteToSiteReasonKindNotServed, fmt.Errorf("no %s provider is built in", e.Kind))
			return nil
		}
	default:
		m.downLocked(t, SiteToSiteReasonKindNotServed, fmt.Errorf("kind %q is not known", e.Kind))
		return nil
	}

	var version int
	if e.AuthSecretName != "" {
		v, listed := m.inventory[e.AuthSecretName]
		if !listed {
			m.downLocked(t, SiteToSiteReasonAuthSecretNotListed, fmt.Errorf("the secret inventory does not list %q", e.AuthSecretName))
			return nil
		}
		version = v
	}
	if e.Kind == api.SiteToSiteKindIPsec && m.meshCIDR == "" {
		m.downLocked(t, SiteToSiteReasonSetupFailed, errors.New("the node has no mesh CIDR as the local traffic selector"))
		return nil
	}
	return &siteToSiteAttempt{t: t, entry: e, key: t.key, version: version, ctx: m.ctx}
}

// runAttempts runs each attempt in turn.
func (m *SiteToSiteManager) runAttempts(ctx context.Context, attempts []*siteToSiteAttempt) {
	for _, a := range attempts {
		m.attempt(ctx, a)
	}
}

// attempt resolves the tunnel's remote host and fetches its Secret outside
// mu, then, under mu, sets up its link, its routes and its daemon. An attempt
// that finds the manager inactive, or the tunnel no longer held, after the
// lookups sets nothing up.
func (m *SiteToSiteManager) attempt(ctx context.Context, a *siteToSiteAttempt) {
	e := a.entry
	addr, err := m.remoteAddr(ctx, e.RemoteHost)
	if err != nil {
		m.attemptFailed(a, SiteToSiteReasonRemoteHostUnresolved, err)
		return
	}

	var secret string
	if e.AuthSecretName != "" {
		// A Teardown during the lookup leaves nothing to fetch for.
		if !m.holds(a.t) {
			return
		}
		value, err := m.secrets.FetchSecretValue(ctx, e.AuthSecretName, a.version)
		if err != nil {
			m.attemptFailed(a, SiteToSiteReasonAuthSecretUnreadable, err)
			return
		}
		// The value is never logged.
		secret = strings.TrimSpace(string(value))
		clear(value)
		if e.Kind == api.SiteToSiteKindWireGuard && !validWireGuardKey(secret) {
			m.attemptFailed(a, SiteToSiteReasonSetupFailed,
				fmt.Errorf("the Secret %q holds no preshared key of 44 characters of standard base64", e.AuthSecretName))
			return
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !slices.Contains(m.tunnels, a.t) {
		return
	}
	m.bringUpLocked(ctx, a, addr, secret)
}

// remoteAddr returns the address of host: host itself when it is an IP
// address, else the address preferIPv4 picks among those Resolve returns
// under a timeout of endpointResolveTimeout.
func (m *SiteToSiteManager) remoteAddr(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	ctx, cancel := context.WithTimeout(ctx, endpointResolveTimeout)
	defer cancel()
	addrs, err := m.resolve(ctx, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %q: no address", host)
	}
	return preferIPv4(addrs), nil
}

// holds reports whether the manager is active and holds t.
func (m *SiteToSiteManager) holds(t *siteToSiteTunnel) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active && slices.Contains(m.tunnels, t)
}

// attemptFailed records an attempt that failed outside mu, unless the
// manager went inactive or no longer holds the tunnel.
func (m *SiteToSiteManager) attemptFailed(a *siteToSiteAttempt, reason string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active && slices.Contains(m.tunnels, a.t) {
		m.downLocked(a.t, reason, err)
	}
}

// bringUpLocked sets up the tunnel of a, whose remote host is addr and whose
// Secret holds secret, empty without one: the link of its kind, a wireguard
// tunnel's peer, forwarding into the mesh, the source rewrite, a route for
// each allowed subnet, and the provider's side of an ipsec or openvpn
// tunnel. A failure undoes what the attempt added, in reverse. The caller
// holds mu.
func (m *SiteToSiteManager) bringUpLocked(ctx context.Context, a *siteToSiteAttempt, addr netip.Addr, secret string) {
	t, e := a.t, a.entry
	name := siteToSiteInterfaceName(e.Kind, a.key)

	var publicKey string
	switch e.Kind {
	case api.SiteToSiteKindWireGuard:
		private, err := m.keys.LoadOrCreate(a.key)
		if err != nil {
			m.downLocked(t, SiteToSiteReasonKeyUnavailable, err)
			return
		}
		if err := m.vpn.CreateTunnelInterface(name, private[:], e.ListenPort); err != nil {
			// The controller removes an interface it created before it
			// fails; this also removes one of the same name it could not
			// create over.
			_ = m.vpn.RemoveTunnelInterface(name)
			reason := SiteToSiteReasonSetupFailed
			if errors.Is(err, ErrListenPortInUse) {
				reason = SiteToSiteReasonBindFailed
			}
			m.downLocked(t, reason, fmt.Errorf("create interface %s: %w", name, err))
			return
		}
		endpoint := net.JoinHostPort(addr.String(), strconv.Itoa(e.RemotePort))
		if err := m.vpn.ConfigureTunnelPeer(name, e.RemotePublicKey, e.AllowedSubnets, endpoint, secret); err != nil {
			_ = m.vpn.RemoveTunnelInterface(name)
			m.downLocked(t, SiteToSiteReasonSetupFailed, fmt.Errorf("configure the remote peer on %s: %w", name, err))
			return
		}
		publicKey = private.PublicKey().String()
	case api.SiteToSiteKindIPsec:
		if err := m.vpn.CreateXfrmInterface(name, siteToSiteInterfaceID(a.key)); err != nil {
			_ = m.vpn.RemoveTunnelInterface(name)
			m.downLocked(t, SiteToSiteReasonSetupFailed, fmt.Errorf("create xfrm interface %s: %w", name, err))
			return
		}
	case api.SiteToSiteKindOpenVPN:
		if err := m.vpn.CreateTunInterface(name); err != nil {
			_ = m.vpn.RemoveTunnelInterface(name)
			m.downLocked(t, SiteToSiteReasonSetupFailed, fmt.Errorf("create tun device %s: %w", name, err))
			return
		}
	}

	osIface := osInterfaceName(m.vpn, name)
	var routed []string
	rewritten := false
	undo := func() {
		for _, s := range slices.Backward(routed) {
			_ = m.routes.RemoveRoute(s, osIface)
		}
		if rewritten {
			_ = m.rewriter.RemoveMeshSourceRewrite(osIface, m.meshIface)
		}
		_ = m.vpn.RemoveTunnelInterface(name)
	}
	if err := m.routes.EnableForwarding(m.meshIface, osIface); err != nil {
		undo()
		m.downLocked(t, SiteToSiteReasonSetupFailed, fmt.Errorf("enable forwarding: %w", err))
		return
	}
	if err := m.rewriter.AddMeshSourceRewrite(osIface, m.meshIface); err != nil {
		undo()
		m.downLocked(t, SiteToSiteReasonSetupFailed, fmt.Errorf("add mesh source rewrite: %w", err))
		return
	}
	rewritten = true
	for _, s := range e.AllowedSubnets {
		if err := m.routes.AddRoute(s, osIface); err != nil {
			undo()
			m.downLocked(t, SiteToSiteReasonSetupFailed, fmt.Errorf("add route %s: %w", s, err))
			return
		}
		routed = append(routed, s)
	}

	if e.Kind != api.SiteToSiteKindWireGuard {
		if err := m.createProviderTunnel(ctx, a, name, secret); err != nil {
			undo()
			reason := SiteToSiteReasonSetupFailed
			if errors.Is(err, exec.ErrNotFound) {
				reason = SiteToSiteReasonClientMissing
			}
			m.downLocked(t, reason, err)
			return
		}
	}

	t.iface, t.osIface = name, osIface
	t.publicKey = publicKey
	t.version = a.version
	m.upLocked(t)
}

// createProviderTunnel hands an ipsec or openvpn tunnel on the link name to
// its provider, with the key its Secret holds and the Domain mesh CIDR as its
// local subnet. The commands of an ipsec tunnel
// run under a timeout of 30 s derived from ctx. An openvpn process runs under
// the manager's context instead, since a process ends with the context it
// started under, and the call itself starts the process and returns.
func (m *SiteToSiteManager) createProviderTunnel(ctx context.Context, a *siteToSiteAttempt, name, secret string) error {
	e := a.entry
	cfg := TunnelConfig{
		TunnelID:      a.key,
		InterfaceName: name,
		RemoteHost:    e.RemoteHost,
		RemotePort:    e.RemotePort,
		RemoteSubnets: slices.Clone(e.AllowedSubnets),
		Key:           secret,
	}
	if m.meshCIDR != "" {
		cfg.LocalSubnets = []string{m.meshCIDR}
	}
	if e.Kind == api.SiteToSiteKindIPsec {
		cfg.InterfaceID = siteToSiteInterfaceID(a.key)
	}

	runCtx := a.ctx
	if e.Kind != api.SiteToSiteKindOpenVPN {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, siteToSiteProviderTimeout)
		defer cancel()
	}
	return m.providers[e.Kind].CreateTunnel(runCtx, cfg)
}

// stopTunnel tears down what t serves on: the provider's side of an ipsec or
// openvpn tunnel, a route for each allowed subnet, the source rewrite and the
// link. A tunnel that is down holds nothing. t reads down afterwards.
func (m *SiteToSiteManager) stopTunnel(t *siteToSiteTunnel) error {
	if !t.up {
		return nil
	}
	e := t.entry
	var errs []error
	if e.Kind != api.SiteToSiteKindWireGuard {
		ctx, cancel := context.WithTimeout(context.Background(), siteToSiteProviderTimeout)
		err := m.providers[e.Kind].RemoveTunnel(ctx, t.key)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("bridge: site-to-site: remove the %s side of %s: %w", e.Kind, t.key, err))
		}
	}
	for _, s := range e.AllowedSubnets {
		if err := m.routes.RemoveRoute(s, t.osIface); err != nil {
			errs = append(errs, fmt.Errorf("bridge: site-to-site: remove route %s via %s: %w", s, t.osIface, err))
		}
	}
	if err := m.rewriter.RemoveMeshSourceRewrite(t.osIface, m.meshIface); err != nil {
		errs = append(errs, fmt.Errorf("bridge: site-to-site: remove mesh source rewrite %s: %w", t.osIface, err))
	}
	if err := m.vpn.RemoveTunnelInterface(t.iface); err != nil {
		errs = append(errs, fmt.Errorf("bridge: site-to-site: remove interface %s: %w", t.iface, err))
	}
	t.up = false
	t.iface, t.osIface, t.publicKey, t.version = "", "", "", 0
	return errors.Join(errs...)
}

// upLocked records that t is up and logs it. The caller holds mu.
func (m *SiteToSiteManager) upLocked(t *siteToSiteTunnel) {
	t.settled, t.up = true, true
	t.reason = ""
	t.attempts, t.nextAttempt = 0, time.Time{}

	attrs := []any{
		"component", "bridge",
		"tunnel_id", t.entry.ID,
		"slug", t.entry.Slug,
		"kind", t.entry.Kind,
		"interface", t.iface,
	}
	if t.entry.Kind == api.SiteToSiteKindWireGuard {
		attrs = append(attrs, "listen_port", t.entry.ListenPort)
	}
	m.logger.Info("site-to-site tunnel up", attrs...)
}

// downLocked records a failed attempt to bring t up: t is down for reason,
// and its next attempt is due after the retry delay. The tunnel's down line
// is logged when the reason changed. The caller holds mu.
func (m *SiteToSiteManager) downLocked(t *siteToSiteTunnel, reason string, err error) {
	changed := !t.settled || t.up || t.reason != reason
	t.settled, t.up = true, false
	t.reason = reason
	t.attempts++
	t.nextAttempt = m.now().Add(certRetryDelay(t.attempts, err))
	if changed {
		m.logDown(t.entry, reason, err)
	}
}

// logDown logs that a tunnel is down for reason.
func (m *SiteToSiteManager) logDown(e api.SiteToSiteTunnel, reason string, err error) {
	m.logger.Warn("site-to-site tunnel down",
		"component", "bridge",
		"tunnel_id", e.ID,
		"slug", e.Slug,
		"kind", e.Kind,
		"reason", reason,
		"error", err,
	)
}
