package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/registration"
)

// Manager manages the WireGuard interface and peer configuration.
type Manager struct {
	ctrl   WGController
	cfg    Config
	logger *slog.Logger
	peers  *PeerIndex

	// mu guards dial and serializes every mesh peer device write: the
	// reconcile handler, the edge-PSK store and endpoint selection write the
	// same peers from different call paths.
	mu sync.Mutex
	// dial is the endpoint selection state per node ID. Its peer is the last
	// peer written, which SetPeerPSK needs as well: every device write replaces
	// the peer's allowed IPs, so a PSK alone cannot be written without them.
	// syncPeerRoutes routes the routed subnets of these peers.
	dial map[string]*dialState

	// shared is the shared subnets of the last pull, keyed by canonical CIDR.
	// Guarded by mu.
	shared map[string]*sharedSubnet

	// meshPrefix is the prefix the interface address carries, masked: the
	// Domain mesh CIDR, or the mesh IP's host /32 when the identity has no
	// usable CIDR. It is zero until Setup succeeds, and Readdress does not
	// change it.
	meshPrefix netip.Prefix

	// addrMu guards meshIP, which Readdress writes while the round-trip probe
	// reads it. It is held for the read or the write alone, never together
	// with another lock of the manager and never across a controller or
	// router call.
	addrMu sync.Mutex
	// meshIP is the node's own mesh IP as Setup parsed it from the identity,
	// or the address Readdress last replaced it with, the zero address when
	// it does not parse or before Setup succeeds. Read it through MeshIP. The
	// round-trip probe listens on it and sends no probe to it.
	meshIP netip.Addr

	// rttListen opens the round-trip probe's socket (see RunRTTProbe), and
	// rttAddr returns the address a probe to a peer's mesh IP goes to. They
	// default to listenRTT and rttProbeAddr, UDP port RTTProbePort of the
	// mesh IPs; tests replace them to run managers on loopback.
	rttListen func() (net.PacketConn, error)
	rttAddr   func(meshIP netip.Addr) net.Addr

	// rtt is the round-trip probe's state per peer, which MeshPeerStats
	// reports as MeshPeerStat.RTT. It has a mutex of its own.
	rtt rttTable

	// localPrefixes returns the prefixes of this host's interface addresses
	// that a candidate may be on-link with. The reconcile handler reads it to
	// order a peer's on-link candidates first, and endpoint selection reads it
	// to find a local network that makes a relayed peer's direct entry on-link
	// (see localNetworksChanged). It returns nil, nil until SetLocalPrefixes
	// replaces it.
	localPrefixes func() ([]netip.Prefix, error)

	// localNets is the networks of endpoint selection's last successful read
	// of localPrefixes, localAt when it last tried a read, localKnown whether
	// a read has succeeded, and localFailing whether the last read failed (see
	// localNetworksChanged). Only the endpoint selection goroutine touches
	// them, so they need no lock.
	localNets    []netip.Prefix
	localAt      time.Time
	localKnown   bool
	localFailing bool

	// now is the clock of endpoint selection and of the round-trip probe,
	// which reads a probe's send and receive instants from it; tests replace
	// it.
	now func() time.Time

	// sendProbe sends the relay liveness probe to a relayed peer's mesh IP
	// (see checkRelay), and to a bridge of a shared subnet that answers no
	// round-trip probe (see watchBridges). It is nil until SetRelayProbe sets
	// it, and no probe goes out then.
	sendProbe func(meshIP netip.Addr) error

	// detectAfter is the failure-detection time the last pull that carried
	// one delivered (see SetFailureDetection), guarded by mu. It is zero while
	// no pull carried a value, and endpoint selection then keeps the relay
	// liveness probe's fixed windows and its own pass interval, and watches
	// no bridge of a shared subnet.
	detectAfter time.Duration

	// probe measures the uplink: it returns the largest IPv4 packet size, in
	// bytes, that reached a STUN server. It is nil until SetPathMTUProbe sets
	// it, and the interface then keeps DefaultMTU unless Config.MTU pins one.
	probe func(context.Context) (int, error)
	// mtu is the MTU last programmed on the interface, and raiseTo the higher
	// MTU the last probe round asked for, 0 when no raise is pending. Only
	// Setup touches them, and after it returns only the single RunMTUProbe
	// goroutine does, so they need no lock. SetMTU does not take mu, which
	// serializes peer writes only.
	mtu     int
	raiseTo int

	// routeMu guards router and routes, and serializes the route calls of
	// syncPeerRoutes and Teardown. It is taken before mu, never while mu is
	// held, so a route call never holds up a peer write.
	routeMu sync.Mutex
	// router programs the routes of the peers' routed subnets. It is nil
	// until SetPeerRouter sets it, and no route is programmed then.
	router PeerRouter
	// routes is the set of subnets router holds a route for on the mesh
	// interface.
	routes map[string]struct{}
}

// PeerRouter adds and removes the routes that carry a peer's routed subnets
// into the mesh interface. Every bridge.RouteController satisfies it. Both
// calls are idempotent: adding a route that exists and removing one that does
// not return nil.
type PeerRouter interface {
	// AddRoute adds a route for subnet, a CIDR, through the interface the
	// operating system knows as iface.
	AddRoute(subnet, iface string) error
	// RemoveRoute removes the route for subnet through iface.
	RemoveRoute(subnet, iface string) error
}

// NewManager creates a new Manager. Config defaults are applied automatically.
func NewManager(ctrl WGController, cfg Config, logger *slog.Logger) *Manager {
	cfg.ApplyDefaults()
	m := &Manager{
		ctrl:          ctrl,
		cfg:           cfg,
		logger:        logger,
		peers:         NewPeerIndex(),
		dial:          make(map[string]*dialState),
		shared:        make(map[string]*sharedSubnet),
		localPrefixes: func() ([]netip.Prefix, error) { return nil, nil },
		now:           time.Now,
		rttAddr:       rttProbeAddr,
		routes:        make(map[string]struct{}),
	}
	m.rttListen = m.listenRTT
	return m
}

// Setup creates and configures the WireGuard interface using the node identity.
//
// It chooses the interface MTU first: a positive Config.MTU pins it, otherwise
// one round of the path MTU probe sizes it with MeshMTU, and without a probe,
// or when the round fails, it is DefaultMTU. The round runs before
// CreateInterface, so a round that waits out its timeout holds up startup
// without a half-configured interface on the host meanwhile.
func (m *Manager) Setup(ctx context.Context, identity *registration.NodeIdentity) error {
	mtu, source, pathMTU := m.chooseMTU(ctx)

	if err := m.ctrl.CreateInterface(m.cfg.InterfaceName, identity.PrivateKey, m.cfg.ListenPort); err != nil {
		return fmt.Errorf("wireguard: setup: %w", err)
	}

	address := m.interfaceAddress(identity)
	if err := m.ctrl.ConfigureAddress(m.cfg.InterfaceName, address); err != nil {
		return fmt.Errorf("wireguard: setup: %w", err)
	}

	// Every controller creates the device at DefaultMTU, so an MTU nobody
	// pinned needs a write only when it differs, and a node on a full-size
	// uplink makes the calls it made before detection existed.
	if m.cfg.MTU > 0 || mtu != DefaultMTU {
		if err := m.ctrl.SetMTU(m.cfg.InterfaceName, mtu); err != nil {
			return fmt.Errorf("wireguard: setup: %w", err)
		}
		if source == mtuSourceProbe {
			m.warnBelowMinimum(pathMTU)
		}
	}

	if err := m.ctrl.SetInterfaceUp(m.cfg.InterfaceName); err != nil {
		return fmt.Errorf("wireguard: setup: %w", err)
	}

	// interfaceAddress joins the mesh IP with a prefix length, so the parse
	// fails only for an unparseable mesh IP, which leaves the prefix zero.
	if prefix, err := netip.ParsePrefix(address); err == nil {
		m.meshPrefix = prefix.Masked()
	}
	if ip, err := netip.ParseAddr(identity.MeshIP); err == nil {
		m.addrMu.Lock()
		m.meshIP = ip
		m.addrMu.Unlock()
	}
	m.mtu = mtu

	attrs := []any{
		"component", "wireguard",
		"interface", m.cfg.InterfaceName,
		"listen_port", m.cfg.ListenPort,
		"mesh_ip", identity.MeshIP,
		"mtu", mtu,
		"mtu_source", source,
	}
	if source == mtuSourceProbe {
		attrs = append(attrs, "path_mtu", pathMTU)
	}
	m.logger.Info("wireguard interface configured", attrs...)

	return nil
}

// interfaceAddress derives the interface address from the node identity. The
// prefix length comes from the registration domain_mesh_cidr so the kernel
// installs an on-link route for the whole mesh; identities without the field
// (pre-#18) or with an unparseable one fall back to a host /32.
//
// The prefix is only trusted when it actually contains MeshIP and is not
// absurdly broad. The control plane's value flows in unchecked: a "0.0.0.0/0"
// would install an on-link route for all of IPv4 pointed at wg0 (blackholing
// the node's own control-plane connectivity), and a prefix that does not contain
// MeshIP (e.g. 192.168.0.0/16 with a 10.0.0.5 mesh IP) would hijack an unrelated
// subnet — possibly the node's real LAN. Both fall back to a host /32.
func (m *Manager) interfaceAddress(identity *registration.NodeIdentity) string {
	if identity.DomainMeshCIDR == "" {
		return identity.MeshIP + "/32"
	}
	prefix, err := netip.ParsePrefix(identity.DomainMeshCIDR)
	if err != nil {
		m.logger.Warn("invalid domain mesh cidr, falling back to /32",
			"component", "wireguard",
			"domain_mesh_cidr", identity.DomainMeshCIDR,
			"error", err,
		)
		return identity.MeshIP + "/32"
	}
	addr, addrErr := netip.ParseAddr(identity.MeshIP)
	if addrErr != nil || !prefix.Addr().Is4() || !prefix.Contains(addr) || prefix.Bits() < 8 {
		m.logger.Warn("domain mesh cidr does not contain mesh ip or is too broad, falling back to /32",
			"component", "wireguard",
			"domain_mesh_cidr", identity.DomainMeshCIDR,
			"mesh_ip", identity.MeshIP,
		)
		return identity.MeshIP + "/32"
	}
	return fmt.Sprintf("%s/%d", identity.MeshIP, prefix.Bits())
}

// MeshPrefix returns the Domain mesh prefix the interface was set up with, or
// the mesh IP's host /32 when the identity carried no usable domain_mesh_cidr.
// It is the zero prefix before Setup succeeds.
//
// A peer endpoint inside this prefix would be routed through the mesh
// interface itself, so WireGuard would send a peer's encrypted packets into
// its own tunnel; endpoint selection refuses such an endpoint.
func (m *Manager) MeshPrefix() netip.Prefix {
	return m.meshPrefix
}

// MeshIP returns the node's mesh IP the interface carries: the one Setup
// parsed from the identity, or the one Readdress last replaced it with. It is
// the zero address before Setup succeeds and when the identity's mesh IP does
// not parse.
func (m *Manager) MeshIP() netip.Addr {
	m.addrMu.Lock()
	defer m.addrMu.Unlock()
	return m.meshIP
}

// ErrReaddressUnsupported is returned by Readdress while CanReaddress is
// false.
var ErrReaddressUnsupported = errors.New("the mesh address cannot be replaced while plexd runs")

// ErrMeshAddressInvalid is returned by Readdress for an address the mesh
// interface does not take.
var ErrMeshAddressInvalid = errors.New("invalid mesh address")

// CanReaddress reports whether Readdress can replace the mesh IP while plexd
// runs: Setup succeeded, the controller implements AddressReplacer, the mesh
// IP is IPv4, and the interface carries a prefix shorter than /32. Setup
// leaves meshPrefix zero until it succeeds.
//
// DECISION: plexd declares mesh_readdress only when it can follow, and this
// is the test. An interface that carries the host /32 fallback of
// interfaceAddress has no prefix but its own address, so Readdress would
// refuse every move as outside it.
func (m *Manager) CanReaddress() bool {
	if _, ok := m.ctrl.(AddressReplacer); !ok {
		return false
	}
	return m.meshPrefix.IsValid() && m.meshPrefix.Bits() < 32 && m.MeshIP().Is4()
}

// Readdress replaces the mesh IP the interface carries with addr, in place:
// the interface, its peers and their tunnels stay up. In order:
//  1. It returns an error wrapping ErrReaddressUnsupported while CanReaddress
//     is false.
//  2. It returns an error wrapping ErrMeshAddressInvalid when addr, unmapped,
//     is not IPv4, is unspecified, loopback, multicast or link-local, or lies
//     outside MeshPrefix.
//  3. It returns nil without a call when addr is the current mesh IP.
//  4. It replaces the address through the controller (AddressReplacer),
//     both with the prefix length of MeshPrefix. An error is returned wrapped
//     as "wireguard: readdress:" and leaves the mesh IP as it was, so the
//     next call for addr repeats the replace with the same arguments, which
//     succeeds after a call that failed halfway.
//  5. It stores addr as the mesh IP.
//  6. It closes the round-trip probe's socket when one is held, so its reader
//     ends and the next round listens on addr.
//  7. It adds the route of every routed subnet it holds again (see
//     addPeerRoutesAgain).
//  8. It logs wireguard: mesh address replaced at Info.
//
// MeshPrefix does not change. Calls must not overlap: plexd up makes them
// from the dispatch handler of the reconcile loop alone.
//
// DECISION: a node re-addresses only inside the mesh prefix its interface
// was set up with. Every part that copied MeshPrefix at startup stays
// correct, and a pull cannot point the interface at a network of the host.
func (m *Manager) Readdress(addr netip.Addr) error {
	if !m.CanReaddress() {
		return fmt.Errorf("wireguard: readdress: %w", ErrReaddressUnsupported)
	}
	addr = addr.Unmap()
	if fault := meshAddressFault(addr, m.meshPrefix); fault != "" {
		return fmt.Errorf("wireguard: readdress: %w: %s %s", ErrMeshAddressInvalid, addr, fault)
	}
	old := m.MeshIP()
	if addr == old {
		return nil
	}

	bits := m.meshPrefix.Bits()
	replacer := m.ctrl.(AddressReplacer)
	if err := replacer.ReplaceAddress(m.cfg.InterfaceName, netip.PrefixFrom(old, bits).String(), netip.PrefixFrom(addr, bits).String()); err != nil {
		return fmt.Errorf("wireguard: readdress: %w", err)
	}

	m.addrMu.Lock()
	m.meshIP = addr
	m.addrMu.Unlock()

	if conn := m.rtt.socket(); conn != nil {
		_ = conn.Close()
	}

	m.addPeerRoutesAgain()

	m.logger.Info("wireguard: mesh address replaced",
		"component", "wireguard",
		"interface", m.cfg.InterfaceName,
		"previous_mesh_ip", old.String(),
		"mesh_ip", addr.String(),
	)
	return nil
}

// meshAddressFault returns why addr cannot be the mesh IP of an interface
// set up with prefix, or "" when it can.
func meshAddressFault(addr netip.Addr, prefix netip.Prefix) string {
	switch {
	case !addr.Is4():
		return "is not an IPv4 address"
	case addr.IsUnspecified():
		return "is unspecified"
	case addr.IsLoopback():
		return "is a loopback address"
	case addr.IsMulticast():
		return "is a multicast address"
	case addr.IsLinkLocalUnicast():
		return "is a link-local address"
	case !prefix.Contains(addr):
		return "lies outside the mesh prefix " + prefix.String()
	}
	return ""
}

// addPeerRoutesAgain adds the route of every subnet in routes again through
// OSInterfaceName, for Readdress. On macOS the removal of the old address may
// take the routes through the utun with it, which only the CI runner can
// measure, and AddRoute is idempotent, so a route that survived costs one
// call. A subnet whose add fails is logged at Warn and dropped from routes,
// so the next syncPeerRoutes adds it. Without a router it does nothing.
func (m *Manager) addPeerRoutesAgain() {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	if m.router == nil {
		return
	}

	iface := m.OSInterfaceName()
	for _, subnet := range slices.Sorted(maps.Keys(m.routes)) {
		if err := m.router.AddRoute(subnet, iface); err != nil {
			m.logger.Warn("wireguard: peer route failed",
				"component", "wireguard",
				"subnet", subnet,
				"op", "add",
				"error", err,
			)
			delete(m.routes, subnet)
		}
	}
}

// SetLocalPrefixes sets the function the reconcile handler reads this host's
// interface prefixes from, to order a peer's on-link candidates first.
// Endpoint selection reads it too, to try a relayed peer's direct entries
// again when a local network makes one of them on-link. Call it before the
// handler and RunEndpointSelection run.
func (m *Manager) SetLocalPrefixes(fn func() ([]netip.Prefix, error)) {
	m.localPrefixes = fn
}

// SetPeerRouter sets the router the reconcile handler programs the routes of
// the peers' routed subnets with. Call it before the handler runs. Without
// one, the manager programs the routed subnets as allowed IPs and adds no
// route.
func (m *Manager) SetPeerRouter(r PeerRouter) {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	m.router = r
}

// Teardown removes the routes syncPeerRoutes programmed and then deletes the
// WireGuard interface. A route it cannot remove is logged at Warn and stops
// nothing: the delete takes the interface's routes with it.
func (m *Manager) Teardown() error {
	m.removePeerRoutes()
	if err := m.ctrl.DeleteInterface(m.cfg.InterfaceName); err != nil {
		return fmt.Errorf("wireguard: teardown: %w", err)
	}
	return nil
}

// syncPeerRoutes brings the routes on the mesh interface in line with the
// routed subnets of the peers the manager last wrote, the peers of dial: it
// removes the route of every programmed subnet no such peer lists any more,
// then adds one for every listed subnet that has none, each through
// OSInterfaceName, in subnet order. A subnet two peers list is routed once
// and keeps its route until the last of them drops it. A shared subnet is the
// routed subnet of one peer at a time, its holder (see setSharedSubnets), so
// the union, and with it the routes, do not change when the subnet moves
// from one bridge to another. A move of endpoint selection's bridge watch
// (see moveSharedSubnet) makes no route call: it changes the union only when
// a failed handler run left the old holder's record without the subnet, and
// the handler's next run, which the reconciler makes because the run failed,
// routes it.
//
// A call that fails is logged at Error and leaves that subnet's state as it
// was, so the next run tries it again; the failures are returned joined, so
// the reconciler applies the snapshot again. A run that changed a route logs
// the change once at Info. Without a router it does nothing.
//
// The peers are read under mu and the router is called under routeMu alone,
// so a slow route(8) or IP Helper call never holds up a peer write or
// endpoint selection.
func (m *Manager) syncPeerRoutes() error {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	if m.router == nil {
		return nil
	}

	wanted := m.wantedPeerRoutes()
	iface := m.OSInterfaceName()

	var (
		errs           []error
		added, removed []string
	)
	for _, subnet := range slices.Sorted(maps.Keys(m.routes)) {
		if _, ok := wanted[subnet]; ok {
			continue
		}
		if err := m.router.RemoveRoute(subnet, iface); err != nil {
			m.logger.Error("wireguard: peer route failed",
				"component", "wireguard",
				"subnet", subnet,
				"op", "remove",
				"error", err,
			)
			errs = append(errs, fmt.Errorf("wireguard: remove peer route %s: %w", subnet, err))
			continue
		}
		delete(m.routes, subnet)
		removed = append(removed, subnet)
	}
	for _, subnet := range slices.Sorted(maps.Keys(wanted)) {
		if _, ok := m.routes[subnet]; ok {
			continue
		}
		if err := m.router.AddRoute(subnet, iface); err != nil {
			m.logger.Error("wireguard: peer route failed",
				"component", "wireguard",
				"subnet", subnet,
				"op", "add",
				"error", err,
			)
			errs = append(errs, fmt.Errorf("wireguard: add peer route %s: %w", subnet, err))
			continue
		}
		m.routes[subnet] = struct{}{}
		added = append(added, subnet)
	}

	m.logPeerRoutesChanged(added, removed)
	return errors.Join(errs...)
}

// wantedPeerRoutes returns the union of the routed subnets of the peers the
// manager last wrote.
func (m *Manager) wantedPeerRoutes() map[string]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := make(map[string]struct{})
	for _, st := range m.dial {
		for _, subnet := range st.peer.RoutedSubnets {
			wanted[subnet] = struct{}{}
		}
	}
	return wanted
}

// removePeerRoutes removes every route syncPeerRoutes programmed, for
// Teardown. A route it cannot remove is logged at Warn and stays in the set.
func (m *Manager) removePeerRoutes() {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	if m.router == nil || len(m.routes) == 0 {
		return
	}

	iface := m.OSInterfaceName()
	var removed []string
	for _, subnet := range slices.Sorted(maps.Keys(m.routes)) {
		if err := m.router.RemoveRoute(subnet, iface); err != nil {
			m.logger.Warn("wireguard: peer route failed",
				"component", "wireguard",
				"subnet", subnet,
				"op", "remove",
				"error", err,
			)
			continue
		}
		delete(m.routes, subnet)
		removed = append(removed, subnet)
	}
	m.logPeerRoutesChanged(nil, removed)
}

// logPeerRoutesChanged logs the routes a run added and removed, once, and
// nothing when it changed none.
func (m *Manager) logPeerRoutesChanged(added, removed []string) {
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	m.logger.Info("wireguard: peer routes changed",
		"component", "wireguard",
		"added", added,
		"removed", removed,
	)
}

// OSInterfaceName returns the name the operating system knows the managed
// interface by, which is what net.InterfaceByName and the host's own tooling
// resolve. It is Config.InterfaceName everywhere except macOS, where the
// controller creates a utun the kernel names utunN.
//
// Callers that address the interface through plexd keep using
// Config.InterfaceName: the bridge managers and the status report. The policy
// enforcer takes the name this method returns, because pf on macOS matches the
// kernel's name.
func (m *Manager) OSInterfaceName() string {
	if namer, ok := m.ctrl.(OSInterfaceNamer); ok {
		if osName, found := namer.OSInterfaceName(m.cfg.InterfaceName); found {
			return osName
		}
	}
	return m.cfg.InterfaceName
}

// MeshPeerStat is one mesh peer's runtime state, keyed by the control plane's
// node ID instead of the WireGuard public key the device reports.
type MeshPeerStat struct {
	NodeID           string
	Endpoint         netip.AddrPort // invalid when the device knows no endpoint
	LastHandshake    time.Time      // zero when no handshake has completed
	RxBytes, TxBytes uint64
	RTT              time.Duration // zero when the peer holds no value
	// SharedSubnets are the shared subnets whose holder is the peer, sorted
	// by address and then by prefix length, nil when there are none.
	SharedSubnets []string
}

// ErrPeerStatsUnsupported is returned by MeshPeerStats when the controller
// cannot read peer runtime state, or when there is no controller at all.
var ErrPeerStatsUnsupported = errors.New("wireguard: controller cannot read peer stats")

// MeshPeerStats reads the managed interface and returns the state of every
// device peer the peer index maps to a node ID, sorted by NodeID. It returns an
// empty, non-nil slice when no device peer maps.
//
// A device peer whose key the index does not map is dropped. That is the case
// for a key two node IDs share (see PeerIndex.NodeIDsByPublicKey). A peer with no handshake
// is kept, because the tunnel metrics report it; the handshake reporter drops it
// itself. Endpoint passes through as the device reports it, and the consumers
// apply their own wire rules.
//
// RTT is the latest round-trip time the round-trip probe measured to the peer
// (see RunRTTProbe), zero when the peer holds no value. The tunnel metrics
// ignore it. Endpoint selection reads it only in the bridge watch, where a
// value makes the bridge proven, which picks its stimulus and its window (see
// watchBridges).
//
// SharedSubnets are the shared subnets whose holder the peer is when the call
// reads them (see setSharedSubnets), each list the caller's own. They are
// copied under mu, which is released before the round-trip probe's mutex is
// taken: the two are never held together, and no caller holds mu.
func (m *Manager) MeshPeerStats() ([]MeshPeerStat, error) {
	// A nil m.ctrl fails the assertion as well, which is the case plexd up
	// builds where no controller exists for the platform.
	reader, ok := m.ctrl.(PeerStatsReader)
	if !ok {
		return nil, ErrPeerStatsUnsupported
	}

	stats, err := reader.PeerStats(m.cfg.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("wireguard: mesh peer stats: %w", err)
	}

	nodeIDs := m.peers.NodeIDsByPublicKey()
	m.mu.Lock()
	held := m.sharedHeldLocked()
	m.mu.Unlock()

	mesh := make([]MeshPeerStat, 0, len(stats))
	m.rtt.mu.Lock()
	for _, s := range stats {
		nodeID, ok := nodeIDs[s.PublicKey]
		if !ok {
			continue
		}
		mesh = append(mesh, MeshPeerStat{
			NodeID:        nodeID,
			Endpoint:      s.Endpoint,
			LastHandshake: s.LastHandshake,
			RxBytes:       s.RxBytes,
			TxBytes:       s.TxBytes,
			RTT:           m.rtt.value(nodeID),
			SharedSubnets: slices.Clone(held[nodeID]),
		})
	}
	m.rtt.mu.Unlock()
	slices.SortFunc(mesh, func(a, b MeshPeerStat) int {
		return strings.Compare(a.NodeID, b.NodeID)
	})

	return mesh, nil
}

// UpdatePrivateKey installs a rotated private key on the managed interface.
func (m *Manager) UpdatePrivateKey(privateKey []byte) error {
	if err := m.ctrl.SetPrivateKey(m.cfg.InterfaceName, privateKey); err != nil {
		return fmt.Errorf("wireguard: update private key: %w", err)
	}
	return nil
}

// AddPeer adds a peer to the WireGuard interface with the first entry of its
// dial order as the endpoint, starts its endpoint selection, and updates the
// peer index.
func (m *Manager) AddPeer(peer api.Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.programFirst(peer); err != nil {
		return fmt.Errorf("wireguard: add peer: %w", err)
	}

	m.peers.Add(peer.ID, peer.PublicKey)

	m.logger.Debug("peer added",
		"component", "wireguard",
		"peer_id", peer.ID,
	)

	return nil
}

// RemovePeer removes a peer from the WireGuard interface by public key.
func (m *Manager) RemovePeer(publicKey []byte) error {
	if err := m.ctrl.RemovePeer(m.cfg.InterfaceName, publicKey); err != nil {
		return fmt.Errorf("wireguard: remove peer: %w", err)
	}
	return nil
}

// RemovePeerByID removes a peer by its peer ID, looking up the public key in the index.
func (m *Manager) RemovePeerByID(peerID string) error {
	pubKeyB64, ok := m.peers.Lookup(peerID)
	if !ok {
		return fmt.Errorf("wireguard: unknown peer ID: %s", peerID)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("wireguard: decode public key: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctrl.RemovePeer(m.cfg.InterfaceName, pubKeyBytes); err != nil {
		return fmt.Errorf("wireguard: remove peer: %w", err)
	}

	delete(m.dial, peerID)
	m.peers.Remove(peerID)

	m.logger.Debug("peer removed",
		"component", "wireguard",
		"peer_id", peerID,
	)

	return nil
}

// UpdatePeer updates a peer configuration. WireGuard AddPeer is idempotent (upsert).
//
// The first rule that applies decides the write:
//   - A peer with no state, or whose public key changed, starts over from the
//     first entry of its new order, like AddPeer. A rotated key is a new
//     device peer to WireGuard, which has no endpoint yet. The device peer of
//     the old key is removed first: WireGuard moves to the new key only the
//     allowed IPs its write names, so the old key would keep a routed subnet
//     the update no longer lists and could still send from it.
//   - A relayed peer, or one in a direct retry, whose update names relays
//     tries its direct entries again (see retryDirect) when the update adds
//     a direct entry that is neither among its direct entries nor remembered
//     (see dialState.remembered): it tries every direct entry of the update
//     that is not remembered, in the update's order, and ends on the relay
//     relayAfter names. A running retry the update adds nothing to goes on
//     with the entries it had left that the update still lists, from the
//     first of them, or dials that relay at once when none is left. A direct
//     entry the update drops is remembered (see triedAfter), here and in the
//     two rules after this one.
//   - A peer whose programmed entry is one of its Fallbacks, and that is
//     relayed or not connected, moves to the update's first relay at once, on
//     a fresh device peer (see redial), when the update takes its relay
//     away (see relayMoved), and logs the move. A connected peer that is not
//     relayed runs on a path it roamed to (see relayedOver), which the move
//     would cut.
//   - A relayed peer whose relay is still among the update's Fallbacks stays
//     on it, connected or not, even on a standby it moved to on its own: the
//     write carries no endpoint, and the position moves to the relay's in the
//     new order.
//   - A connected peer keeps the endpoint on the device, which may be one
//     WireGuard roamed to: the write carries no endpoint, and the selection
//     resumes from the new order's position of the entry last programmed. A
//     relayed peer gets here only when the update has no Fallbacks, and it
//     stops being relayed.
//   - Any other peer starts over from the first entry of its new order,
//     including a peer in a direct retry whose update names no relays.
//
// A failed write leaves the state as it was.
func (m *Manager) UpdatePeer(peer api.Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keepEndpoint := func() error {
		peerCfg, err := m.peerConfig(peer, "")
		if err != nil {
			return err
		}
		return m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg)
	}

	st, ok := m.dial[peer.ID]

	// The direct retry's rule: the memory the update leaves, and the entries
	// to try. Read now before any write, for the reason the relay move gives.
	var (
		now     time.Time
		tried   map[string]time.Time
		entries []string
		retry   bool
	)
	if ok && st.peer.PublicKey == peer.PublicKey && (st.relayed || st.retrying()) {
		now = m.now()
		tried = triedAfter(st, peer, now)
		next := &dialState{peer: peer, tried: tried}
		added := func(e string) bool { return !slices.Contains(st.direct(), e) && !next.remembered(e, now) }
		switch {
		case slices.ContainsFunc(next.direct(), added):
			entries = next.untried(now)
		case st.retrying():
			entries = slices.DeleteFunc(slices.Clone(next.direct()), func(e string) bool {
				return e != st.endpoint() && !slices.Contains(st.retry, e)
			})
		}
		retry = len(peer.Fallbacks) > 0 && (len(entries) > 0 || st.retrying())
	}

	switch {
	case !ok || st.peer.PublicKey != peer.PublicKey:
		if ok {
			if err := m.removeDevicePeer(st.peer.PublicKey); err != nil {
				return fmt.Errorf("wireguard: update peer: remove the device peer of the rotated key: %w", err)
			}
		}
		if err := m.programFirst(peer); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
	case retry && len(entries) > 0:
		relay := relayAfter(st, peer)
		next, err := m.retryDirect(peer, entries, relay, tried, now)
		if err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		m.dial[peer.ID] = next
		m.logger.Info("wireguard: trying the direct endpoints again",
			"component", "wireguard",
			"peer_id", peer.ID,
			"reason", "pull",
			"endpoint", entries[0],
			"entries", len(entries),
			"relay", relay,
		)
	case retry:
		relay := relayAfter(st, peer)
		if err := m.redial(peer, relay); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		back := &dialState{peer: peer, relayed: true, tried: tried}
		back.onRelay(now, relay)
		m.dial[peer.ID] = back
		m.logger.Info("wireguard: no direct endpoint answered, dialing the relay again",
			"component", "wireguard",
			"peer_id", peer.ID,
			"endpoint", relay,
		)
	case st.onFallback() && (st.relayed || !st.connected) && relayMoved(st, peer):
		from, to := st.endpoint(), peer.Fallbacks[0]
		// Read before the write: the new device peer can complete a
		// handshake before redial returns, and that handshake must
		// count as the new session's.
		now := m.now()
		if err := m.redial(peer, to); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		moved := &dialState{peer: peer, relayed: st.relayed, tried: tried}
		moved.onRelay(now, to)
		m.dial[peer.ID] = moved
		m.logger.Info("wireguard: relay fallback changed, moving to the new relay",
			"component", "wireguard",
			"peer_id", peer.ID,
			"from", from,
			"to", to,
		)
	case st.relayed && slices.Contains(peer.Fallbacks, st.endpoint()):
		relay := st.endpoint()
		if err := keepEndpoint(); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		st.peer = peer
		st.idx = max(slices.Index(st.order(), relay), 0)
		st.tried = tried
	case st.connected:
		if err := keepEndpoint(); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		programmed := st.endpoint()
		st.peer = peer
		st.idx = max(slices.Index(st.order(), programmed), 0)
		st.relayed = false
	default:
		if err := m.programFirst(peer); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
	}

	m.peers.Update(peer.ID, peer.PublicKey)

	m.logger.Debug("peer updated",
		"component", "wireguard",
		"peer_id", peer.ID,
	)

	return nil
}

// relayMoved reports whether an update to peer takes away the relay st has
// programmed: the update names relays, and either that relay is not among
// them, or the first relay changed to one that is not that relay. A standby a
// relayed peer moved to on its own therefore stays while the control plane
// still names the same first relay, or names that standby first, and the peer
// follows the control plane once it names another one. st must be on one of
// its Fallbacks.
func relayMoved(st *dialState, peer api.Peer) bool {
	if len(peer.Fallbacks) == 0 {
		return false
	}
	relay := st.endpoint()
	if !slices.Contains(peer.Fallbacks, relay) {
		return true
	}
	return peer.Fallbacks[0] != st.peer.Fallbacks[0] && peer.Fallbacks[0] != relay
}

// ConfigurePeers bulk-configures all peers. Individual errors are logged but not returned.
func (m *Manager) ConfigurePeers(ctx context.Context, peers []api.Peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers.LoadFromPeers(peers)
	m.dial = make(map[string]*dialState, len(peers))

	for _, peer := range peers {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wireguard: configure peers: %w", err)
		}

		st := &dialState{peer: peer}
		peerCfg, err := m.peerConfig(peer, st.endpoint())
		if err != nil {
			m.logger.Error("failed to convert peer config",
				"component", "wireguard",
				"peer_id", peer.ID,
				"error", err,
			)
			continue
		}

		if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
			m.logger.Error("failed to add peer",
				"component", "wireguard",
				"peer_id", peer.ID,
				"error", err,
			)
			continue
		}
		st.programmedAt = m.now()
		m.dial[peer.ID] = st
	}

	m.logger.Info("peers configured",
		"component", "wireguard",
		"count", len(peers),
	)

	return nil
}

// SetPeerPSK programs psk on the device peer of peerNodeID, when that peer was
// last written with publicKey. A peer not written yet, or written with another
// key, gets nothing: the PSK belongs to a different device peer, and the next
// AddPeer or UpdatePeer for the key takes it from the edge-PSK store.
//
// The write carries the recorded peer's allowed IPs, which every device write
// replaces, and an empty endpoint, which leaves the device's endpoint as it is.
func (m *Manager) SetPeerPSK(peerNodeID, publicKey string, psk []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.dial[peerNodeID]
	if !ok || st.peer.PublicKey != publicKey {
		return nil
	}

	peer := st.peer
	peer.PSK = base64.StdEncoding.EncodeToString(psk)
	peerCfg, err := m.peerConfig(peer, "")
	if err != nil {
		return fmt.Errorf("wireguard: set peer psk: %w", err)
	}
	if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
		return fmt.Errorf("wireguard: set peer psk: %w", err)
	}
	st.peer = peer

	m.logger.Debug("peer psk set",
		"component", "wireguard",
		"peer_id", peerNodeID,
	)
	return nil
}

// removeDevicePeer removes the device peer of publicKey, a base64 key.
// Removing a key the device does not hold is accepted by the userspace
// backend (see UserspaceBackend.RemovePeer), and the Linux module is assumed
// to accept it as well, so a write that failed after the removal can be
// tried again. Callers hold m.mu.
func (m *Manager) removeDevicePeer(publicKey string) error {
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	return m.ctrl.RemovePeer(m.cfg.InterfaceName, key)
}

// programFirst writes peer with the first entry of its dial order and starts
// its endpoint selection over. Callers hold m.mu. A failed write records no
// state, as it adds no index entry.
func (m *Manager) programFirst(peer api.Peer) error {
	st := &dialState{peer: peer}
	peerCfg, err := m.peerConfig(peer, st.endpoint())
	if err != nil {
		return err
	}
	if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
		return err
	}
	st.programmedAt = m.now()
	m.dial[peer.ID] = st
	return nil
}

// retryDirect starts a direct retry for peer, which is relayed or already in
// a retry: it writes peer anew with entries[0] as the endpoint on a fresh
// device peer (see redial) and returns the state that tries entries in order,
// each for directRetryTimeout, and dials relay when none answers (see
// stepRetry). tried is the state's memory. The write replaces the device peer
// and so cuts the relayed session. Writing only the endpoint would keep it,
// but WireGuard moves a peer's endpoint to the source of every authenticated
// packet it receives, so the partner's next packet through the relay would
// put the device back on the relay before the entry was judged. The fresh
// session accepts nothing the partner still sends in the old one.
//
// A failed write returns redial's error unchanged. retryDirect stores
// nothing: the caller does. Callers hold m.mu, pass at least one entry, and
// read now before the call, because the new device peer can complete a
// handshake before redial returns.
func (m *Manager) retryDirect(peer api.Peer, entries []string, relay string, tried map[string]time.Time, now time.Time) (*dialState, error) {
	if err := m.redial(peer, entries[0]); err != nil {
		return nil, err
	}
	st := &dialState{peer: peer, programmedAt: now, recreatedAt: now, retry: entries[1:], retryRelay: relay, tried: tried}
	st.idx = max(slices.Index(st.order(), entries[0]), 0)
	return st, nil
}

// redial writes peer anew with endpoint as the endpoint: it removes the
// device peer and adds it again. A write that only set the endpoint would
// keep the peer's WireGuard session, and a relay drops every
// packet of a session whose handshake it did not forward, while WireGuard
// starts a new handshake on its own only after 15 s of unanswered data, or
// once the session is 120 to 180 s old. The new device peer has no session.
// Its write turns the keepalive interval on, and wireguard-go sends a
// keepalive when that happens, which starts a handshake at once; the Linux
// module is assumed to do the same. Callers hold m.mu.
//
// A failed add leaves the peer off the device until the next attempt, whose
// remove then names a key the device does not hold. The userspace backend
// accepts that (see UserspaceBackend.RemovePeer), and the Linux module is
// assumed to as well.
//
// A direct retry writes its entries the same way, for the reason retryDirect
// gives.
func (m *Manager) redial(peer api.Peer, endpoint string) error {
	peerCfg, err := m.peerConfig(peer, endpoint)
	if err != nil {
		return err
	}
	if err := m.ctrl.RemovePeer(m.cfg.InterfaceName, peerCfg.PublicKey); err != nil {
		return fmt.Errorf("remove device peer: %w", err)
	}
	if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
		return fmt.Errorf("add device peer: %w", err)
	}
	return nil
}

// peerConfig builds the device write for peer with endpoint as its endpoint
// and the configured keepalive interval. Every mesh peer write goes through
// it: both controllers write the interval on every call, so a write that left
// it out would clear the keepalive. An empty endpoint leaves the device peer's
// endpoint as it is.
func (m *Manager) peerConfig(peer api.Peer, endpoint string) (PeerConfig, error) {
	cfg, err := PeerConfigFromAPI(peer)
	if err != nil {
		return PeerConfig{}, err
	}
	cfg.Endpoint = endpoint
	cfg.PersistentKeepalive = int(m.cfg.KeepaliveInterval() / time.Second)
	return cfg, nil
}

// PeerIndex returns the peer index.
func (m *Manager) PeerIndex() *PeerIndex {
	return m.peers
}
