// Package bridge provides bridge mode functionality including user access integration.
package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// errNoJoinKey fails Setup while a provider is set: a UserAccessClient starts
// only with a join key, and this manager has none to hand over.
var errNoJoinKey = errors.New("no join key to start the client with")

// UserAccessManager manages user access integration — a WireGuard interface
// that allows external VPN clients to reach the mesh via a bridge node.
// UserAccessManager is concurrent-safe via mu.
type UserAccessManager struct {
	ctrl     AccessController
	routes   RouteController
	cfg      Config
	logger   *slog.Logger
	provider UserAccessClient // optional, may be nil

	// mu protects active and activePeers from concurrent access by
	// SSE event handlers and the reconcile loop.
	mu sync.Mutex

	// tracked state
	active      bool
	activePeers map[string]struct{} // keyed by public key
}

// NewUserAccessManager creates a new UserAccessManager. The provider parameter
// is optional — pass nil when no external VPN provider is used. This manager
// has no join key to start a provider with, so Setup fails while one is set.
func NewUserAccessManager(ctrl AccessController, routes RouteController, cfg Config, logger *slog.Logger, provider UserAccessClient) *UserAccessManager {
	return &UserAccessManager{
		ctrl:        ctrl,
		routes:      routes,
		cfg:         cfg,
		logger:      logger,
		provider:    provider,
		activePeers: make(map[string]struct{}),
	}
}

// Setup creates the WireGuard interface for user access and enables forwarding.
// When user access is disabled this is a no-op.
func (m *UserAccessManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.UserAccessEnabled {
		return nil
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("bridge: user access: generate key: %w", err)
	}

	if err := m.ctrl.CreateInterface(m.cfg.UserAccessInterfaceName, key[:], m.cfg.UserAccessListenPort, ""); err != nil {
		return fmt.Errorf("bridge: user access: create interface: %w", err)
	}

	if err := m.routes.EnableForwarding(m.cfg.UserAccessInterfaceName, m.cfg.AccessInterface); err != nil {
		// Rollback: remove the interface we just created.
		_ = m.ctrl.RemoveInterface(m.cfg.UserAccessInterfaceName)
		return fmt.Errorf("bridge: user access: enable forwarding: %w", err)
	}

	m.active = true

	if m.provider != nil {
		// The client is not started: it needs a join key, and this
		// manager has none (see errNoJoinKey). Best-effort rollback:
		// disable forwarding and remove interface.
		_ = m.routes.DisableForwarding(m.cfg.UserAccessInterfaceName, m.cfg.AccessInterface)
		_ = m.ctrl.RemoveInterface(m.cfg.UserAccessInterfaceName)
		m.active = false
		return fmt.Errorf("bridge: user access: start provider: %s: %w", m.provider.Name(), errNoJoinKey)
	}

	m.logger.Info("user access interface created",
		"component", "bridge",
		"interface", m.cfg.UserAccessInterfaceName,
		"listen_port", m.cfg.UserAccessListenPort,
	)

	return nil
}

// Teardown removes all tracked peers, disables forwarding, and removes the
// WireGuard interface. Errors are aggregated — cleanup continues even when
// individual operations fail. Idempotent: calling Teardown when inactive
// returns nil.
func (m *UserAccessManager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}

	var errs []error

	if m.provider != nil {
		if err := m.provider.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("bridge: user access: stop provider: %w", err))
		}
	}

	// Remove all tracked peers individually.
	for pk := range m.activePeers {
		if err := m.ctrl.RemovePeer(m.cfg.UserAccessInterfaceName, pk); err != nil {
			errs = append(errs, err)
		}
	}

	// Disable forwarding.
	if err := m.routes.DisableForwarding(m.cfg.UserAccessInterfaceName, m.cfg.AccessInterface); err != nil {
		errs = append(errs, err)
	}

	// Remove interface.
	if err := m.ctrl.RemoveInterface(m.cfg.UserAccessInterfaceName); err != nil {
		errs = append(errs, err)
	}

	m.active = false
	m.activePeers = make(map[string]struct{})

	if len(errs) == 0 {
		m.logger.Info("user access interface removed",
			"component", "bridge",
			"interface", m.cfg.UserAccessInterfaceName,
		)
	}

	return errors.Join(errs...)
}

// AddPeer adds a single user access peer. Returns an error if the maximum
// number of peers has been reached or the peer is already tracked.
func (m *UserAccessManager) AddPeer(peer api.UserAccessPeer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.activePeers[peer.PublicKey]; ok {
		return fmt.Errorf("bridge: user access: peer already exists: %s", peer.PublicKey)
	}
	if len(m.activePeers) >= m.cfg.MaxAccessPeers {
		return fmt.Errorf("bridge: user access: max peers reached (%d)", m.cfg.MaxAccessPeers)
	}

	if err := m.ctrl.ConfigurePeer(m.cfg.UserAccessInterfaceName, peer.PublicKey, peer.AllowedIPs, peer.PSK); err != nil {
		return fmt.Errorf("bridge: user access: configure peer: %w", err)
	}

	m.activePeers[peer.PublicKey] = struct{}{}
	return nil
}

// RemovePeer removes a single user access peer by public key.
// Removing a non-existent peer is a no-op.
func (m *UserAccessManager) RemovePeer(publicKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.activePeers[publicKey]; !ok {
		return
	}
	if err := m.ctrl.RemovePeer(m.cfg.UserAccessInterfaceName, publicKey); err != nil {
		m.logger.Error("bridge: user access: remove peer failed",
			"component", "bridge",
			"public_key", publicKey,
			"error", err,
		)
		return
	}
	delete(m.activePeers, publicKey)
}

// PeerPublicKeys returns the public keys of all active peers.
func (m *UserAccessManager) PeerPublicKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	keys := make([]string, 0, len(m.activePeers))
	for pk := range m.activePeers {
		keys = append(keys, pk)
	}
	return keys
}

// UserAccessStatus returns user access status for heartbeat reporting.
// Returns nil when user access is not active.
func (m *UserAccessManager) UserAccessStatus() *api.UserAccessInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}
	info := &api.UserAccessInfo{
		Enabled:       true,
		InterfaceName: m.cfg.UserAccessInterfaceName,
		PeerCount:     len(m.activePeers),
		ListenPort:    m.cfg.UserAccessListenPort,
	}
	if m.provider != nil {
		info.ProviderName = m.provider.Name()
		status := m.provider.Status()
		if status.Running {
			info.ProviderStatus = "running"
		} else if status.Error != "" {
			info.ProviderStatus = "error"
		} else {
			info.ProviderStatus = "stopped"
		}
	}
	return info
}

// UserAccessCapabilities returns capability metadata for registration.
// Returns nil when user access is not enabled.
func (m *UserAccessManager) UserAccessCapabilities() map[string]string {
	if !m.cfg.UserAccessEnabled {
		return nil
	}
	return map[string]string{
		"user_access":        "true",
		"access_listen_port": strconv.Itoa(m.cfg.UserAccessListenPort),
	}
}
