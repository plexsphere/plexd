package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/registration"
)

// Manager manages the WireGuard interface and peer configuration.
type Manager struct {
	ctrl   WGController
	cfg    Config
	logger *slog.Logger
	peers  *PeerIndex
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

	if err := m.ctrl.ConfigureAddress(m.cfg.InterfaceName, m.interfaceAddress(identity)); err != nil {
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
// Config.InterfaceName: the policy enforcer, the bridge managers and the
// status report.
func (m *Manager) OSInterfaceName() string {
	if namer, ok := m.ctrl.(OSInterfaceNamer); ok {
		if osName, found := namer.OSInterfaceName(m.cfg.InterfaceName); found {
			return osName
		}
	}
	return m.cfg.InterfaceName
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
