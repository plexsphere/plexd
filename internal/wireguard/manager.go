package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

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

	if err := m.ctrl.ConfigureAddress(m.cfg.InterfaceName, identity.MeshIP+"/32"); err != nil {
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

// Teardown deletes the WireGuard interface.
func (m *Manager) Teardown() error {
	if err := m.ctrl.DeleteInterface(m.cfg.InterfaceName); err != nil {
		return fmt.Errorf("wireguard: teardown: %w", err)
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
