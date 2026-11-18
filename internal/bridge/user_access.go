// Package bridge provides bridge mode functionality including user access integration.
package bridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The reasons a user access provider is down for. Each is the reason of the
// provider's entry in a user access status report and of its "user access
// provider down" line. invalid_provider, setup_failed and key_unavailable are
// plexd's own; the control plane stores any token of the reason grammar.
const (
	// UserAccessReasonInvalidProvider: a member of the entry is missing or
	// malformed, or the entry clashes with an earlier one of the block. It is
	// not retried until the entry changes.
	UserAccessReasonInvalidProvider = "invalid_provider"
	// UserAccessReasonKindNotServed: this plexd serves no provider of the
	// kind, because the platform has no mesh source rewrite, the kind is
	// unknown, or no client of the kind is built in. It is not retried until
	// the entry changes.
	UserAccessReasonKindNotServed = "kind_not_served"
	// UserAccessReasonKeyUnavailable: the key of a wireguard provider's
	// interface could not be read or created.
	UserAccessReasonKeyUnavailable = "key_unavailable"
	// UserAccessReasonBindFailed: the interface of a wireguard provider
	// cannot listen on its port, which another socket holds.
	UserAccessReasonBindFailed = "bind_failed"
	// UserAccessReasonSetupFailed: the provider's interface, its forwarding
	// or its source rewrite could not be set up, or a tailscale provider has
	// no mesh CIDR to advertise.
	UserAccessReasonSetupFailed = "setup_failed"
	// UserAccessReasonAuthSecretNotListed: the secret inventory does not list
	// the Secret a vendor provider names.
	UserAccessReasonAuthSecretNotListed = "auth_secret_not_listed"
	// UserAccessReasonAuthSecretUnreadable: the inventory lists the Secret,
	// but it could not be fetched.
	UserAccessReasonAuthSecretUnreadable = "auth_secret_unreadable"
	// UserAccessReasonJoinFailed: the vendor client did not join its network
	// with the key, or reports no interface after it did.
	UserAccessReasonJoinFailed = "join_failed"
	// UserAccessReasonClientMissing: the host has no client of the kind.
	UserAccessReasonClientMissing = "client_missing"
)

// The reasons a device of a wireguard provider is not served, the reason of a
// "user access device not served" line. The provider stays up.
const (
	userAccessDeviceInvalidKey       = "invalid_public_key"
	userAccessDeviceInvalidAddress   = "invalid_address"
	userAccessDeviceOutsidePool      = "address_outside_pool"
	userAccessDeviceInterfaceAddress = "address_is_interface"
	userAccessDeviceDuplicateKey     = "duplicate_public_key"
	userAccessDeviceDuplicateAddress = "duplicate_address"
	userAccessDeviceConfigureFailed  = "configure_failed"
)

// SecretValueFetcher reads the value of one version of a Secret the node may
// read: the key a vendor user access provider joins its network with.
type SecretValueFetcher interface {
	FetchSecretValue(ctx context.Context, name string, version int) ([]byte, error)
}

// UserAccessDeps are what a UserAccessManager serves providers with.
type UserAccessDeps struct {
	// Access creates and removes the interfaces of wireguard providers.
	Access AccessController
	// Routes switches forwarding on between a provider's interface and the
	// mesh interface. The manager never switches it off: a provider's
	// interface is deleted with the provider, and the mesh interface's
	// forwarding belongs to the bridge manager.
	Routes RouteController
	// Rewriter rewrites the source of device traffic to the bridge's mesh
	// address. nil: this platform serves no provider; one that passes its
	// checks reads kind_not_served, one that fails them invalid_provider.
	Rewriter MeshSourceRewriter
	// Keys keeps the private key of each wireguard provider's interface. It
	// must not be nil.
	Keys *InterfaceKeyStore
	// Secrets fetches a vendor provider's join key. It must not be nil while
	// Clients holds a client.
	Secrets SecretValueFetcher
	// Clients holds the vendor client of each vendor kind this plexd serves,
	// by kind. A kind without a client reads kind_not_served.
	Clients map[string]UserAccessClient
	// MeshInterface is the name of the mesh interface.
	MeshInterface string
	// MeshCIDR is the Domain mesh prefix a tailscale provider advertises as
	// a route; empty when the node has none, which leaves a tailscale
	// provider down with setup_failed.
	MeshCIDR string
	Logger   *slog.Logger
}

// UserAccessManager serves the user access providers of the state pull's
// bridge.user_access block: a WireGuard interface for each wireguard provider,
// and a joined vendor client for each tailscale or netbird provider, each
// forwarding into the mesh with its source rewritten to the bridge's mesh
// address. Each provider is served on its own, so one that is down leaves the
// others up. UserAccessManager is concurrent-safe via mu.
//
// Apply, SyncSecretInventory and Retry are called from the reconciler's
// goroutine alone. They fetch a Secret and start a vendor client outside mu,
// so Teardown and the status readers do not wait for a join.
type UserAccessManager struct {
	access    AccessController
	routes    RouteController
	rewriter  MeshSourceRewriter
	keys      *InterfaceKeyStore
	secrets   SecretValueFetcher
	clients   map[string]UserAccessClient
	meshIface string
	meshCIDR  string
	logger    *slog.Logger
	now       func() time.Time

	// mu protects the fields below from concurrent access by the reconcile
	// loop, Teardown and the status readers.
	mu sync.Mutex

	active bool
	// ctx is the context the vendor clients run under; Teardown cancels it.
	ctx    context.Context
	cancel context.CancelFunc
	// enabled is the Enabled of the last applied block.
	enabled bool
	// providers holds every provider of the last applied block with a valid,
	// unrepeated id, in block order; none while the block is not enabled.
	providers []*userAccessProvider
	// inventory is the last secret inventory, version by Secret name; nil
	// until the first SyncSecretInventory.
	inventory map[string]int
	// invalidIDs holds the "user access provider down" lines of the last
	// Apply for entries without state, so each is logged once.
	invalidIDs map[string]struct{}

	// changed carries ReportChanged's signal; capacity 1.
	changed chan struct{}
}

// userAccessConnectedAge is the oldest handshake that counts a device of a
// wireguard provider as connected.
const userAccessConnectedAge = 180 * time.Second

// userAccessProvider is what the manager holds for one provider of the block.
// Its fields are read and written under the manager's mu while the manager
// holds it; Teardown stops the providers it detached outside mu.
type userAccessProvider struct {
	// entry is the provider as the last Apply listed it; its ID is as pulled.
	entry api.UserAccessProvider
	// key is the id lower-cased, which names the key file and the interface.
	key string
	// check is why the entry is invalid_provider, nil when it passed its own
	// checks.
	check error

	// settled is false until the first attempt to bring the provider up has
	// an outcome; an unsettled provider is not reported. Only a vendor join,
	// which runs outside mu, leaves a provider unsettled for a while.
	settled bool
	up      bool
	// reason says why the provider is down; empty while it is up.
	reason string
	// attempts counts the consecutive failed attempts; nextAttempt is when
	// Retry may try again.
	attempts    int
	nextAttempt time.Time

	// iface is the interface the provider serves on while it is up: its
	// WireGuard interface, or the one its vendor client reports.
	iface string

	// A wireguard provider while it is up: the public key of its interface,
	// its pool and the interface's address in it, the devices configured on
	// the interface by public key, and the "user access device not served"
	// lines logged for its devices.
	publicKey string
	pool      netip.Prefix
	ifaceAddr netip.Addr
	devices   map[string]userAccessDevice
	skipped   map[deviceSkip]struct{}

	// client is a vendor provider's client while it is up.
	client UserAccessClient
}

// userAccessDevice is a device configured on a provider's interface.
type userAccessDevice struct {
	id      string
	address netip.Addr
}

// deviceSkip identifies a "user access device not served" line.
type deviceSkip struct {
	deviceID string
	reason   string
}

// userAccessJoin is one vendor join that runs outside mu: the fetch of the
// provider's Secret, at the version the inventory lists, and the client's
// start under the manager's context.
type userAccessJoin struct {
	p       *userAccessProvider
	client  UserAccessClient
	secret  string
	version int
	ctx     context.Context
}

// NewUserAccessManager creates a UserAccessManager. It serves nothing until
// Setup.
func NewUserAccessManager(deps UserAccessDeps) *UserAccessManager {
	return &UserAccessManager{
		access:    deps.Access,
		routes:    deps.Routes,
		rewriter:  deps.Rewriter,
		keys:      deps.Keys,
		secrets:   deps.Secrets,
		clients:   deps.Clients,
		meshIface: deps.MeshInterface,
		meshCIDR:  deps.MeshCIDR,
		logger:    deps.Logger,
		now:       time.Now,
		changed:   make(chan struct{}, 1),
	}
}

// Setup removes what a process that was killed left behind, with
// CleanupUserAccess, so that a provider's interface can be created again
// under its name, creates the context the vendor clients run under, and marks
// the manager active. A failed cleanup fails Setup and leaves the manager
// inactive.
func (m *UserAccessManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active {
		return nil
	}
	if err := CleanupUserAccess(m.access, m.rewriter); err != nil {
		return fmt.Errorf("bridge: user access: clean up: %w", err)
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.active = true

	m.logger.Info("user access manager started", "component", "bridge")
	return nil
}

// Teardown stops every vendor client, removes every source rewrite and every
// interface, cancels the context the clients run under and marks the manager
// inactive. It keeps the key files, so a provider comes back with its key
// after a restart. Errors are joined; the cleanup continues past a failure.
// Idempotent: calling Teardown when inactive returns nil. It signals
// ReportChanged when it returns.
func (m *UserAccessManager) Teardown() error {
	defer m.signalReport()
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return nil
	}
	held := m.providers
	cancel := m.cancel
	m.active = false
	m.enabled = false
	m.providers = nil
	m.inventory = nil
	m.invalidIDs = nil
	m.mu.Unlock()

	// Nothing reads the held providers once the manager is inactive, and a
	// join that finishes now stops its own client.
	var errs []error
	for _, p := range held {
		if err := m.stopProvider(p); err != nil {
			errs = append(errs, err)
		}
	}
	cancel()

	if len(errs) == 0 {
		m.logger.Info("user access manager stopped", "component", "bridge")
	}
	return errors.Join(errs...)
}

// Apply serves the block whole. It does nothing while the manager is not
// active.
//
//   - The key files of every provider the block lists are kept, whatever
//     Enabled says, and every other key file is deleted; the zero block
//     deletes them all.
//   - A block with Enabled false serves no provider.
//   - A held provider the block does not serve is torn down.
//   - A held provider whose entry is unchanged is kept: a wireguard provider
//     unchanged in its listen_port and address_pool, a vendor provider
//     unchanged in its auth_secret_name. The devices of a running wireguard
//     interface are brought in line with the entry by public key. Any other
//     change tears the provider down and brings it up again, with its kept
//     key.
//   - A new provider is brought up, in block order.
//
// A provider that cannot be brought up is down with its reason, and Retry
// tries again when the reason allows it. Apply signals ReportChanged when it
// returns, after every join it started.
func (m *UserAccessManager) Apply(ctx context.Context, block api.UserAccessConfig) {
	defer m.signalReport()
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	m.enabled = block.Enabled

	keep := make(map[string]struct{})
	for _, e := range block.Providers {
		if api.ValidUserAccessProviderID(e.ID) {
			keep[strings.ToLower(e.ID)] = struct{}{}
		}
	}
	var entries []api.UserAccessProvider
	if block.Enabled {
		entries = block.Providers
	}
	planned := m.planLocked(entries)

	held := make(map[string]*userAccessProvider, len(m.providers))
	for _, p := range m.providers {
		held[p.key] = p
	}
	listed := make(map[string]struct{}, len(planned))
	kept := make(map[*userAccessProvider]struct{})
	var next, fresh []*userAccessProvider
	for _, np := range planned {
		listed[np.key] = struct{}{}
		if p := held[np.key]; p != nil && p.unchanged(np) {
			p.entry = np.entry
			kept[p] = struct{}{}
			next = append(next, p)
			continue
		}
		next = append(next, np)
		fresh = append(fresh, np)
	}

	for _, p := range m.providers {
		if _, ok := kept[p]; ok {
			continue
		}
		_, relisted := listed[p.key]
		iface := p.iface
		if err := m.stopProvider(p); err != nil {
			m.logger.Error("bridge: user access: tear down provider failed",
				"component", "bridge",
				"provider_id", p.entry.ID,
				"interface", iface,
				"error", err,
			)
		} else if !relisted {
			m.logger.Info("user access provider removed",
				"component", "bridge",
				"provider_id", p.entry.ID,
				"interface", iface,
			)
		}
	}
	m.providers = next

	if err := m.keys.Prune(keep); err != nil {
		m.logger.Error("bridge: user access: prune keys failed",
			"component", "bridge",
			"error", err,
		)
	}

	for _, p := range next {
		if _, ok := kept[p]; ok && p.up && p.entry.Kind == api.UserAccessKindWireGuard {
			m.syncDevicesLocked(p)
		}
	}
	var joins []*userAccessJoin
	for _, p := range fresh {
		if j := m.attemptLocked(p); j != nil {
			joins = append(joins, j)
		}
	}
	m.mu.Unlock()

	m.runJoins(ctx, joins)
}

// SyncSecretInventory replaces the secret inventory the vendor providers take
// their Secret's version from, then calls Retry. A provider that is up keeps
// its join when the inventory lists a new version of its Secret or none; the
// version the inventory lists is used at the next join. It does nothing while
// the manager is not active.
func (m *UserAccessManager) SyncSecretInventory(ctx context.Context, inventory []api.NodeStateSecret) {
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	m.inventory = secretInventory(inventory)
	m.mu.Unlock()

	m.Retry(ctx)
}

// Retry brings up again every provider that is down for bind_failed,
// setup_failed, key_unavailable, auth_secret_not_listed,
// auth_secret_unreadable, join_failed or client_missing and whose next
// attempt is due on the manager's clock. The delay after a failed attempt is
// 5 s, doubling per consecutive failure to 60 s, or the Retry-After of an API
// error when that is longer. invalid_provider and kind_not_served are not
// retried until the entry changes. It does nothing while the manager is not
// active. It signals ReportChanged when it returns.
func (m *UserAccessManager) Retry(ctx context.Context) {
	defer m.signalReport()
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	now := m.now()
	var joins []*userAccessJoin
	for _, p := range m.providers {
		if p.up || !p.settled || !retryable(p.reason) || now.Before(p.nextAttempt) {
			continue
		}
		if j := m.attemptLocked(p); j != nil {
			joins = append(joins, j)
		}
	}
	m.mu.Unlock()

	m.runJoins(ctx, joins)
}

// retryable reports whether Retry brings a provider down for reason up again.
func retryable(reason string) bool {
	switch reason {
	case UserAccessReasonBindFailed, UserAccessReasonSetupFailed, UserAccessReasonKeyUnavailable,
		UserAccessReasonAuthSecretNotListed, UserAccessReasonAuthSecretUnreadable,
		UserAccessReasonJoinFailed, UserAccessReasonClientMissing:
		return true
	}
	return false
}

// ProviderReports returns one report per provider of the last applied block
// with a valid id no earlier entry carried, in block order, and nil while the
// manager is not active. A provider whose first attempt has no outcome yet, a
// vendor provider joining for the first time, is left out until it has one.
//
// A provider that is down reports its reason. A wireguard provider that is up
// reports the public key of its interface and how many of the devices
// configured on it completed a handshake at most 180 s ago on the manager's
// clock, read with one PeerHandshakes call per such provider; a failed read
// counts none.
func (m *UserAccessManager) ProviderReports() []UserAccessProviderReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	out := make([]UserAccessProviderReport, 0, len(m.providers))
	for _, p := range m.providers {
		if !p.settled {
			continue
		}
		r := UserAccessProviderReport{
			ProviderID: p.entry.ID,
			Kind:       p.entry.Kind,
			Health:     api.UserAccessHealthDown,
			Reason:     p.reason,
		}
		if p.up {
			r.Health = api.UserAccessHealthUp
			r.PublicKey = p.publicKey
			r.ConnectedDevices = m.connectedDevicesLocked(p)
		}
		out = append(out, r)
	}
	return out
}

// ReportChanged returns the channel the manager signals, without blocking,
// when what ProviderReports returns may have changed: at the end of every
// Apply, every Retry, and so every SyncSecretInventory, and Teardown. Several
// signals before the reader wakes collapse into one. The signals are liberal;
// the reader compares before it acts. A change of connected devices alone
// signals nothing.
func (m *UserAccessManager) ReportChanged() <-chan struct{} {
	return m.changed
}

// signalReport signals ReportChanged without blocking: a full channel already
// carries the signal.
func (m *UserAccessManager) signalReport() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// connectedDevicesLocked returns how many devices configured on the interface
// of p, a wireguard provider that is up, completed a handshake at most
// userAccessConnectedAge ago on the manager's clock. It reads the interface
// once; a failed read counts none and is logged at Debug. Any other provider
// counts none. The caller holds mu.
func (m *UserAccessManager) connectedDevicesLocked(p *userAccessProvider) int {
	if !p.up || p.entry.Kind != api.UserAccessKindWireGuard {
		return 0
	}
	handshakes, err := m.access.PeerHandshakes(p.iface)
	if err != nil {
		m.logger.Debug("bridge: user access: read handshakes failed",
			"component", "bridge",
			"provider_id", p.entry.ID,
			"interface", p.iface,
			"error", err,
		)
		return 0
	}
	now := m.now()
	n := 0
	for pk := range p.devices {
		// wgctrl gives a zero time for a peer that never completed a
		// handshake.
		if at, ok := handshakes[pk]; ok && !at.IsZero() && now.Sub(at) <= userAccessConnectedAge {
			n++
		}
	}
	return n
}

// UserAccessStatus returns the user access status for the node API's
// status.user-access report: the Enabled of the last applied block and one
// entry per provider the manager holds, in block order, with the count of
// connected devices ProviderReports reports. It returns nil while the manager
// is not active.
func (m *UserAccessManager) UserAccessStatus() *api.UserAccessInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}
	info := &api.UserAccessInfo{Enabled: m.enabled}
	for _, p := range m.providers {
		if !p.settled {
			continue
		}
		pi := api.UserAccessProviderInfo{
			ID:        p.entry.ID,
			Slug:      p.entry.Slug,
			Kind:      p.entry.Kind,
			Interface: p.iface,
			Health:    api.UserAccessHealthDown,
			Reason:    p.reason,
			Devices:   len(p.devices),
		}
		if p.up {
			pi.Health = api.UserAccessHealthUp
			pi.ConnectedDevices = m.connectedDevicesLocked(p)
		}
		if p.entry.Kind == api.UserAccessKindWireGuard {
			pi.ListenPort = p.entry.ListenPort
		}
		info.Providers = append(info.Providers, pi)
	}
	return info
}

// planLocked returns the state of each entry with a valid id no earlier entry
// carried, compared without case, in block order, with the verdict of the
// entry's own checks. An entry with an invalid or repeated id gets no state,
// since the control plane refuses a whole report for one; it is logged once
// while the block lists it. The caller holds mu.
//
// A wireguard entry claims its interface name and a vendor entry its kind,
// whatever the rest of its checks say, so a later entry's verdict depends
// only on the ids and kinds before it.
func (m *UserAccessManager) planLocked(entries []api.UserAccessProvider) []*userAccessProvider {
	var out []*userAccessProvider
	seen := make(map[string]struct{})
	ifaces := make(map[string]struct{})
	kinds := make(map[string]struct{})
	logged := make(map[string]struct{})
	for _, e := range entries {
		var invalid error
		key := strings.ToLower(e.ID)
		if !api.ValidUserAccessProviderID(e.ID) {
			invalid = errors.New("the id is no UUID other than the zero UUID")
		} else if _, dup := seen[key]; dup {
			invalid = errors.New("an earlier provider of the block has the same id")
		}
		if invalid != nil {
			line := e.ID + "\x00" + invalid.Error()
			logged[line] = struct{}{}
			if _, ok := m.invalidIDs[line]; !ok {
				m.logDown(e, UserAccessReasonInvalidProvider, invalid)
			}
			continue
		}
		seen[key] = struct{}{}

		var check error
		switch e.Kind {
		case api.UserAccessKindWireGuard:
			_, _, check = wireGuardEntry(e)
			name := userAccessInterfaceName(key)
			if _, taken := ifaces[name]; taken && check == nil {
				check = fmt.Errorf("an earlier provider of the block takes the interface name %s", name)
			}
			ifaces[name] = struct{}{}
		case api.UserAccessKindTailscale, api.UserAccessKindNetbird:
			if !api.ValidSecretName(e.AuthSecretName) {
				check = fmt.Errorf("auth_secret_name %q is no Secret name", e.AuthSecretName)
			} else if _, taken := kinds[e.Kind]; taken {
				check = fmt.Errorf("an earlier provider of the block has the kind %s", e.Kind)
			}
			kinds[e.Kind] = struct{}{}
		}
		out = append(out, &userAccessProvider{entry: e, key: key, check: check})
	}
	m.invalidIDs = logged
	return out
}

// unchanged reports whether the held provider p serves np's entry as it is:
// same kind, same verdict of the checks, and for a wireguard provider the same
// listen_port and address_pool, for a vendor provider the same
// auth_secret_name. Slug, max_devices and devices change in place.
func (p *userAccessProvider) unchanged(np *userAccessProvider) bool {
	old, e := p.entry, np.entry
	if old.Kind != e.Kind || errText(p.check) != errText(np.check) {
		return false
	}
	switch e.Kind {
	case api.UserAccessKindWireGuard:
		return old.ListenPort == e.ListenPort && old.AddressPool == e.AddressPool
	case api.UserAccessKindTailscale, api.UserAccessKindNetbird:
		return old.AuthSecretName == e.AuthSecretName
	}
	return true
}

// errText returns err's text, or "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// wireGuardEntry checks the members of a wireguard entry and returns its pool,
// masked, and the interface's address in it, the pool's first host address.
func wireGuardEntry(e api.UserAccessProvider) (netip.Prefix, netip.Addr, error) {
	if e.ListenPort < 1 || e.ListenPort > 65535 {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("listen_port %d is outside 1 to 65535", e.ListenPort)
	}
	pool, err := netip.ParsePrefix(e.AddressPool)
	if err != nil || !pool.Addr().Is4() || pool.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("address_pool %q is no IPv4 prefix of length 30 or shorter", e.AddressPool)
	}
	pool = pool.Masked()
	return pool, pool.Addr().Next(), nil
}

// userAccessInterfaceName returns the name of a wireguard provider's
// interface: UserAccessInterfacePrefix and the last 8 hex digits of its id,
// lower case, wg-ua-a0a0a0e1 for 0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1. The
// first digits of a UUIDv7 are its timestamp and repeat for providers created
// within a minute. The 14 characters fit the kernel's limit of 15. id is a
// valid provider id.
func userAccessInterfaceName(id string) string {
	id = strings.ToLower(id)
	return UserAccessInterfacePrefix + id[len(id)-8:]
}

// attemptLocked tries to bring p up. A wireguard provider's attempt completes
// here; a vendor provider's checks run here, and its fetch and start are
// returned as a join to run outside mu, or nil when a check failed. The
// caller holds mu.
func (m *UserAccessManager) attemptLocked(p *userAccessProvider) *userAccessJoin {
	if p.check != nil {
		m.downLocked(p, UserAccessReasonInvalidProvider, p.check)
		return nil
	}
	switch p.entry.Kind {
	case api.UserAccessKindWireGuard:
		if m.rewriter == nil {
			m.downLocked(p, UserAccessReasonKindNotServed, errors.New("this platform has no mesh source rewrite"))
			return nil
		}
		m.bringUpWireGuardLocked(p)
		return nil
	case api.UserAccessKindTailscale, api.UserAccessKindNetbird:
		return m.prepareJoinLocked(p)
	default:
		m.downLocked(p, UserAccessReasonKindNotServed, fmt.Errorf("kind %q is not known", p.entry.Kind))
		return nil
	}
}

// bringUpWireGuardLocked creates a wireguard provider's interface with its
// kept key on its port, with the first host address of its pool, switches
// forwarding on into the mesh, rewrites the source of what the interface
// forwards there, and configures its devices. A failure after the interface
// was created removes it again. The caller holds mu.
func (m *UserAccessManager) bringUpWireGuardLocked(p *userAccessProvider) {
	name := userAccessInterfaceName(p.key)
	pool, addr, _ := wireGuardEntry(p.entry) // checked by planLocked

	key, err := m.keys.LoadOrCreate(p.key)
	if err != nil {
		m.downLocked(p, UserAccessReasonKeyUnavailable, err)
		return
	}
	if err := m.access.CreateInterface(name, key[:], p.entry.ListenPort, netip.PrefixFrom(addr, pool.Bits()).String()); err != nil {
		// The controller removes an interface it created before it fails;
		// this also removes one of the same name it could not create over.
		_ = m.access.RemoveInterface(name)
		reason := UserAccessReasonSetupFailed
		if errors.Is(err, ErrListenPortInUse) {
			reason = UserAccessReasonBindFailed
		}
		m.downLocked(p, reason, err)
		return
	}
	if err := m.forwardIntoMesh(name); err != nil {
		_ = m.access.RemoveInterface(name)
		m.downLocked(p, UserAccessReasonSetupFailed, err)
		return
	}

	p.iface = name
	p.publicKey = key.PublicKey().String()
	p.pool, p.ifaceAddr = pool, addr
	p.devices = make(map[string]userAccessDevice)
	p.skipped = nil
	m.syncDevicesLocked(p)
	m.upLocked(p)
}

// forwardIntoMesh switches forwarding on between iface and the mesh interface
// and rewrites the source of what iface forwards into the mesh.
func (m *UserAccessManager) forwardIntoMesh(iface string) error {
	if err := m.routes.EnableForwarding(m.meshIface, iface); err != nil {
		return fmt.Errorf("enable forwarding: %w", err)
	}
	if err := m.rewriter.AddMeshSourceRewrite(iface, m.meshIface); err != nil {
		return fmt.Errorf("add mesh source rewrite: %w", err)
	}
	return nil
}

// syncDevicesLocked brings the peers of a running wireguard interface in line
// with the devices of p's entry, by public key: a configured device the entry
// no longer lists is removed, and a listed device that is not configured, or
// is configured with another address, is configured with its address as a
// /32. A device whose public key is not 44 characters of standard base64 of
// 32 bytes, whose address is no IPv4 address inside the pool or is the
// interface's address, or that repeats the key or the address of an earlier
// device is skipped, and so is one the controller fails to configure. Each
// skip is logged once while it lasts. The caller holds mu.
func (m *UserAccessManager) syncDevicesLocked(p *userAccessProvider) {
	want := make(map[string]userAccessDevice)
	var order []string
	addrs := make(map[netip.Addr]struct{})
	skipped := make(map[deviceSkip]struct{})
	skip := func(d api.UserAccessDevice, reason string, err error) {
		s := deviceSkip{deviceID: d.ID, reason: reason}
		skipped[s] = struct{}{}
		if _, ok := p.skipped[s]; ok {
			return
		}
		attrs := []any{
			"component", "bridge",
			"provider_id", p.entry.ID,
			"device_id", d.ID,
			"reason", reason,
		}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		m.logger.Warn("user access device not served", attrs...)
	}

	for _, d := range p.entry.Devices {
		raw, err := base64.StdEncoding.DecodeString(d.PublicKey)
		if len(d.PublicKey) != 44 || err != nil || len(raw) != 32 {
			skip(d, userAccessDeviceInvalidKey, nil)
			continue
		}
		pk := base64.StdEncoding.EncodeToString(raw)
		addr, err := netip.ParseAddr(d.Address)
		switch {
		case err != nil || !addr.Is4():
			skip(d, userAccessDeviceInvalidAddress, nil)
			continue
		case !p.pool.Contains(addr):
			skip(d, userAccessDeviceOutsidePool, nil)
			continue
		case addr == p.ifaceAddr:
			skip(d, userAccessDeviceInterfaceAddress, nil)
			continue
		}
		if _, dup := want[pk]; dup {
			skip(d, userAccessDeviceDuplicateKey, nil)
			continue
		}
		if _, dup := addrs[addr]; dup {
			skip(d, userAccessDeviceDuplicateAddress, nil)
			continue
		}
		want[pk] = userAccessDevice{id: d.ID, address: addr}
		addrs[addr] = struct{}{}
		order = append(order, pk)
	}

	for _, pk := range slices.Sorted(maps.Keys(p.devices)) {
		if _, ok := want[pk]; ok {
			continue
		}
		if err := m.access.RemovePeer(p.iface, pk); err != nil {
			m.logger.Error("bridge: user access: remove device failed",
				"component", "bridge",
				"provider_id", p.entry.ID,
				"device_id", p.devices[pk].id,
				"error", err,
			)
			continue
		}
		delete(p.devices, pk)
	}
	for _, pk := range order {
		d := want[pk]
		if cur, ok := p.devices[pk]; ok && cur.address == d.address {
			p.devices[pk] = d
			continue
		}
		if err := m.access.ConfigurePeer(p.iface, pk, []string{d.address.String() + "/32"}, ""); err != nil {
			skip(api.UserAccessDevice{ID: d.id}, userAccessDeviceConfigureFailed, err)
			continue
		}
		p.devices[pk] = d
	}
	p.skipped = skipped
}

// prepareJoinLocked runs the checks of a vendor provider that need no fetch
// and returns its join, or nil when a check put the provider down. The caller
// holds mu.
func (m *UserAccessManager) prepareJoinLocked(p *userAccessProvider) *userAccessJoin {
	client := m.clients[p.entry.Kind]
	switch {
	case m.rewriter == nil:
		m.downLocked(p, UserAccessReasonKindNotServed, errors.New("this platform has no mesh source rewrite"))
		return nil
	case client == nil:
		m.downLocked(p, UserAccessReasonKindNotServed, fmt.Errorf("no %s client is built in", p.entry.Kind))
		return nil
	case p.entry.Kind == api.UserAccessKindTailscale && m.meshCIDR == "":
		// Checked before the inventory: without a route the client would
		// join a tailnet that cannot reach the mesh.
		m.downLocked(p, UserAccessReasonSetupFailed, errors.New("the node has no mesh CIDR to advertise"))
		return nil
	}
	version, listed := m.inventory[p.entry.AuthSecretName]
	if !listed {
		m.downLocked(p, UserAccessReasonAuthSecretNotListed, fmt.Errorf("the secret inventory does not list %q", p.entry.AuthSecretName))
		return nil
	}
	return &userAccessJoin{p: p, client: client, secret: p.entry.AuthSecretName, version: version, ctx: m.ctx}
}

// runJoins runs each join in turn: it fetches the Secret and starts the
// client outside mu, then, under mu, switches forwarding on for the client's
// interface and adds its source rewrite. A join that finishes after Teardown
// stops the client it started.
func (m *UserAccessManager) runJoins(ctx context.Context, joins []*userAccessJoin) {
	for _, j := range joins {
		m.join(ctx, j)
	}
}

// join runs one vendor join.
func (m *UserAccessManager) join(ctx context.Context, j *userAccessJoin) {
	value, err := m.secrets.FetchSecretValue(ctx, j.secret, j.version)
	if err != nil {
		m.joinFailed(j, UserAccessReasonAuthSecretUnreadable, err)
		return
	}
	// The value is never logged.
	key := strings.TrimSpace(string(value))
	clear(value)

	if err := j.client.Start(j.ctx, key, m.meshCIDR); err != nil {
		reason := UserAccessReasonJoinFailed
		if errors.Is(err, exec.ErrNotFound) {
			reason = UserAccessReasonClientMissing
		}
		m.joinFailed(j, reason, err)
		return
	}
	iface := j.client.Status().InterfaceName
	if iface == "" {
		m.stopClient(j)
		m.joinFailed(j, UserAccessReasonJoinFailed, errors.New("the client reports no interface"))
		return
	}

	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		m.stopClient(j)
		return
	}
	if err := m.forwardIntoMesh(iface); err != nil {
		m.mu.Unlock()
		m.stopClient(j)
		m.joinFailed(j, UserAccessReasonSetupFailed, err)
		return
	}
	j.p.iface = iface
	j.p.client = j.client
	m.upLocked(j.p)
	m.mu.Unlock()
}

// joinFailed records a failed join, unless the manager went inactive.
func (m *UserAccessManager) joinFailed(j *userAccessJoin, reason string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		m.downLocked(j.p, reason, err)
	}
}

// stopClient stops the client of a join that does not serve.
func (m *UserAccessManager) stopClient(j *userAccessJoin) {
	if err := j.client.Stop(); err != nil {
		m.logger.Error("bridge: user access: stop client failed",
			"component", "bridge",
			"provider_id", j.p.entry.ID,
			"kind", j.p.entry.Kind,
			"error", err,
		)
	}
}

// stopProvider tears down what p serves on: a vendor provider's client is
// stopped, a wireguard provider's interface removed, and the source rewrite of
// either removed. A provider that is down holds nothing. p reads down
// afterwards.
func (m *UserAccessManager) stopProvider(p *userAccessProvider) error {
	if !p.up {
		return nil
	}
	var errs []error
	if p.client != nil {
		if err := p.client.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("bridge: user access: stop %s client: %w", p.entry.Kind, err))
		}
	} else if err := m.access.RemoveInterface(p.iface); err != nil {
		errs = append(errs, fmt.Errorf("bridge: user access: remove interface %s: %w", p.iface, err))
	}
	if err := m.rewriter.RemoveMeshSourceRewrite(p.iface, m.meshIface); err != nil {
		errs = append(errs, fmt.Errorf("bridge: user access: remove mesh source rewrite %s: %w", p.iface, err))
	}
	p.up = false
	p.iface, p.publicKey, p.client = "", "", nil
	p.devices, p.skipped = nil, nil
	return errors.Join(errs...)
}

// upLocked records that p is up and logs it. The caller holds mu.
func (m *UserAccessManager) upLocked(p *userAccessProvider) {
	p.settled, p.up = true, true
	p.reason = ""
	p.attempts, p.nextAttempt = 0, time.Time{}

	attrs := []any{
		"component", "bridge",
		"provider_id", p.entry.ID,
		"slug", p.entry.Slug,
		"kind", p.entry.Kind,
		"interface", p.iface,
	}
	if p.entry.Kind == api.UserAccessKindWireGuard {
		attrs = append(attrs, "listen_port", p.entry.ListenPort)
	}
	m.logger.Info("user access provider up", attrs...)
}

// downLocked records a failed attempt to bring p up: p is down for reason,
// and its next attempt is due after the retry delay. The provider's down line
// is logged when the reason changed. The caller holds mu.
func (m *UserAccessManager) downLocked(p *userAccessProvider, reason string, err error) {
	changed := !p.settled || p.up || p.reason != reason
	p.settled, p.up = true, false
	p.reason = reason
	p.attempts++
	p.nextAttempt = m.now().Add(certRetryDelay(p.attempts, err))
	if changed {
		m.logDown(p.entry, reason, err)
	}
}

// logDown logs that a provider is down for reason.
func (m *UserAccessManager) logDown(e api.UserAccessProvider, reason string, err error) {
	m.logger.Warn("user access provider down",
		"component", "bridge",
		"provider_id", e.ID,
		"slug", e.Slug,
		"kind", e.Kind,
		"reason", reason,
		"error", err,
	)
}
