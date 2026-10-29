package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
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
	dial map[string]*dialState

	// meshPrefix is the prefix the interface address carries, masked: the
	// Domain mesh CIDR, or the mesh IP's host /32 when the identity has no
	// usable CIDR. It is zero until Setup succeeds.
	meshPrefix netip.Prefix

	// localPrefixes returns the prefixes of this host's interface addresses
	// that a candidate may be on-link with. It returns nil, nil until
	// SetLocalPrefixes replaces it.
	localPrefixes func() ([]netip.Prefix, error)

	// now is endpoint selection's clock; tests replace it.
	now func() time.Time

	// sendProbe sends the relay liveness probe to a relayed peer's mesh IP
	// (see checkRelay). It is nil until SetRelayProbe sets it, and no probe
	// goes out then.
	sendProbe func(meshIP netip.Addr) error

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
}

// NewManager creates a new Manager. Config defaults are applied automatically.
func NewManager(ctrl WGController, cfg Config, logger *slog.Logger) *Manager {
	cfg.ApplyDefaults()
	return &Manager{
		ctrl:          ctrl,
		cfg:           cfg,
		logger:        logger,
		peers:         NewPeerIndex(),
		dial:          make(map[string]*dialState),
		localPrefixes: func() ([]netip.Prefix, error) { return nil, nil },
		now:           time.Now,
	}
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

// SetLocalPrefixes sets the function the reconcile handler reads this host's
// interface prefixes from, to order a peer's on-link candidates first. Call
// it before the handler runs.
func (m *Manager) SetLocalPrefixes(fn func() ([]netip.Prefix, error)) {
	m.localPrefixes = fn
}

// Teardown deletes the WireGuard interface.
func (m *Manager) Teardown() error {
	if err := m.ctrl.DeleteInterface(m.cfg.InterfaceName); err != nil {
		return fmt.Errorf("wireguard: teardown: %w", err)
	}
	return nil
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
}

// ErrPeerStatsUnsupported is returned by MeshPeerStats when the controller
// cannot read peer runtime state, or when there is no controller at all.
var ErrPeerStatsUnsupported = errors.New("wireguard: controller cannot read peer stats")

// MeshPeerStats reads the managed interface and returns the state of every
// device peer the peer index maps to a node ID, sorted by NodeID. It returns an
// empty, non-nil slice when no device peer maps.
//
// A device peer whose key the index does not map is dropped. That is the case
// for a key left on the device after the peer's key rotated, and for a key two
// node IDs share (see PeerIndex.NodeIDsByPublicKey). A peer with no handshake
// is kept, because the tunnel metrics report it; the handshake reporter drops it
// itself. Endpoint passes through as the device reports it, and the consumers
// apply their own wire rules.
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
	mesh := make([]MeshPeerStat, 0, len(stats))
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
		})
	}
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
//     device peer to WireGuard, which has no endpoint yet.
//   - A peer whose programmed entry is its Fallback, and that is relayed or
//     not connected, moves to a new, non-empty Fallback at once, on a fresh
//     device peer (see redialRelay), and logs the move. A connected peer that
//     is not relayed runs on a path it roamed to (see relayedOver), which the
//     move would cut.
//   - A relayed peer whose Fallback is unchanged stays on its relay, connected
//     or not: the write carries no endpoint, and the position moves to the
//     Fallback's in the new order.
//   - A connected peer keeps the endpoint on the device, which may be one
//     WireGuard roamed to: the write carries no endpoint, and the selection
//     resumes from the new order's position of the entry last programmed. A
//     relayed peer gets here only when its new order has no Fallback, and it
//     stops being relayed.
//   - Any other peer starts over from the first entry of its new order.
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
	switch {
	case !ok || st.peer.PublicKey != peer.PublicKey:
		if err := m.programFirst(peer); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
	case st.onFallback() && (st.relayed || !st.connected) && peer.Fallback != "" && peer.Fallback != st.peer.Fallback:
		// Read before the write: the new device peer can complete a
		// handshake before redialRelay returns, and that handshake must
		// count as the new session's.
		now := m.now()
		if err := m.redialRelay(peer); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		moved := &dialState{peer: peer, relayed: st.relayed}
		moved.onRelay(now)
		m.dial[peer.ID] = moved
		m.logger.Info("wireguard: relay fallback changed, moving to the new relay",
			"component", "wireguard",
			"peer_id", peer.ID,
			"from", st.peer.Fallback,
			"to", peer.Fallback,
		)
	case st.relayed && peer.Fallback == st.peer.Fallback:
		if err := keepEndpoint(); err != nil {
			return fmt.Errorf("wireguard: update peer: %w", err)
		}
		st.peer = peer
		st.idx = max(slices.Index(st.order(), peer.Fallback), 0)
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

// redialRelay writes peer anew with its Fallback, the relay, as the endpoint:
// it removes the device peer and adds it again. A write that only set the
// endpoint would keep the peer's WireGuard session, and a relay drops every
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
func (m *Manager) redialRelay(peer api.Peer) error {
	peerCfg, err := m.peerConfig(peer, peer.Fallback)
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
