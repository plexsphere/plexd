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

	// meshPrefix is the prefix the interface address carries, masked: the
	// Domain mesh CIDR, or the mesh IP's host /32 when the identity has no
	// usable CIDR. It is zero until Setup succeeds.
	meshPrefix netip.Prefix
}

// NewManager creates a new Manager. Config defaults are applied automatically.
func NewManager(ctrl WGController, cfg Config, logger *slog.Logger) *Manager {
	cfg.ApplyDefaults()
	return &Manager{
		ctrl:   ctrl,
		cfg:    cfg,
		logger: logger,
		peers:  NewPeerIndex(),
	}
}

// Setup creates and configures the WireGuard interface using the node identity.
func (m *Manager) Setup(ctx context.Context, identity *registration.NodeIdentity) error {
	if err := m.ctrl.CreateInterface(m.cfg.InterfaceName, identity.PrivateKey, m.cfg.ListenPort); err != nil {
		return fmt.Errorf("wireguard: setup: %w", err)
	}

	address := m.interfaceAddress(identity)
	if err := m.ctrl.ConfigureAddress(m.cfg.InterfaceName, address); err != nil {
		return fmt.Errorf("wireguard: setup: %w", err)
	}

	if m.cfg.MTU > 0 {
		if err := m.ctrl.SetMTU(m.cfg.InterfaceName, m.cfg.MTU); err != nil {
			return fmt.Errorf("wireguard: setup: %w", err)
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

	m.logger.Info("wireguard interface configured",
		"component", "wireguard",
		"interface", m.cfg.InterfaceName,
		"listen_port", m.cfg.ListenPort,
		"mesh_ip", identity.MeshIP,
	)

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

// AddPeer adds a peer to the WireGuard interface and updates the peer index.
func (m *Manager) AddPeer(peer api.Peer) error {
	peerCfg, err := PeerConfigFromAPI(peer)
	if err != nil {
		return fmt.Errorf("wireguard: add peer: %w", err)
	}

	if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
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

	if err := m.ctrl.RemovePeer(m.cfg.InterfaceName, pubKeyBytes); err != nil {
		return fmt.Errorf("wireguard: remove peer: %w", err)
	}

	m.peers.Remove(peerID)

	m.logger.Debug("peer removed",
		"component", "wireguard",
		"peer_id", peerID,
	)

	return nil
}

// UpdatePeer updates a peer configuration. WireGuard AddPeer is idempotent (upsert).
func (m *Manager) UpdatePeer(peer api.Peer) error {
	peerCfg, err := PeerConfigFromAPI(peer)
	if err != nil {
		return fmt.Errorf("wireguard: update peer: %w", err)
	}

	if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
		return fmt.Errorf("wireguard: update peer: %w", err)
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
	m.peers.LoadFromPeers(peers)

	for _, peer := range peers {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wireguard: configure peers: %w", err)
		}

		peerCfg, err := PeerConfigFromAPI(peer)
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
	}

	m.logger.Info("peers configured",
		"component", "wireguard",
		"count", len(peers),
	)

	return nil
}

// PeerIndex returns the peer index.
func (m *Manager) PeerIndex() *PeerIndex {
	return m.peers
}
