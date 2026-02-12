package bridge

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// activeTunnel holds the state of a running site-to-site tunnel.
type activeTunnel struct {
	tunnel api.SiteToSiteTunnel
	iface  string
}

// SiteToSiteManager manages site-to-site VPN tunnels — WireGuard interfaces
// that establish VPN connections to external networks via a bridge node.
// SiteToSiteManager is concurrent-safe via mu.
type SiteToSiteManager struct {
	ctrl   VPNController
	routes RouteController
	cfg    Config
	logger *slog.Logger

	// mu protects active, activeTunnels from concurrent access.
	mu sync.Mutex

	// tracked state
	active        bool
	meshIface     string
	activeTunnels map[string]*activeTunnel // keyed by tunnel ID
}

// NewSiteToSiteManager creates a new SiteToSiteManager.
func NewSiteToSiteManager(ctrl VPNController, routes RouteController, cfg Config, logger *slog.Logger) *SiteToSiteManager {
	return &SiteToSiteManager{
		ctrl:          ctrl,
		routes:        routes,
		cfg:           cfg,
		logger:        logger.With("component", "bridge"),
		activeTunnels: make(map[string]*activeTunnel),
	}
}

// Setup initializes the site-to-site manager with the given mesh interface.
// When site-to-site is disabled this is a no-op.
func (m *SiteToSiteManager) Setup(meshIface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.SiteToSiteEnabled {
		return nil
	}

	m.active = true
	m.meshIface = meshIface

	m.logger.Info("site-to-site manager started",
		"max_tunnels", m.cfg.MaxSiteToSiteTunnels,
		"interface_prefix", m.cfg.SiteToSiteInterfacePrefix,
		"mesh_iface", meshIface,
	)

	return nil
}

// Teardown removes all active tunnels, their routes, forwarding, and interfaces.
// Errors are aggregated — cleanup continues even when individual operations fail.
// Idempotent: calling Teardown when inactive returns nil.
func (m *SiteToSiteManager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}

	var errs []error

	for id, at := range m.activeTunnels {
		// Remove routes for remote subnets.
		for _, subnet := range at.tunnel.RemoteSubnets {
			if err := m.routes.RemoveRoute(subnet, at.iface); err != nil {
				errs = append(errs, fmt.Errorf("bridge: site-to-site: remove route %s for tunnel %s: %w", subnet, id, err))
			}
		}
		// Disable forwarding between tunnel and mesh interfaces.
		if err := m.routes.DisableForwarding(at.iface, m.meshIface); err != nil {
			errs = append(errs, fmt.Errorf("bridge: site-to-site: disable forwarding for tunnel %s: %w", id, err))
		}
		// Remove the tunnel interface.
		if err := m.ctrl.RemoveTunnelInterface(at.iface); err != nil {
			errs = append(errs, fmt.Errorf("bridge: site-to-site: remove interface for tunnel %s: %w", id, err))
		}
	}

	m.active = false
	m.activeTunnels = make(map[string]*activeTunnel)

	if len(errs) == 0 {
		m.logger.Info("site-to-site manager stopped")
	}

	return errors.Join(errs...)
}

// AddTunnel establishes a site-to-site tunnel: creates a WireGuard interface,
// configures the remote peer, enables forwarding, and adds routes for remote subnets.
// Returns an error if the manager is inactive, the tunnel ID already exists,
// or the maximum tunnel count is reached.
func (m *SiteToSiteManager) AddTunnel(tunnel api.SiteToSiteTunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return fmt.Errorf("bridge: site-to-site: manager is not active")
	}

	if _, ok := m.activeTunnels[tunnel.TunnelID]; ok {
		return fmt.Errorf("bridge: site-to-site: tunnel already exists: %s", tunnel.TunnelID)
	}
	if len(m.activeTunnels) >= m.cfg.MaxSiteToSiteTunnels {
		return fmt.Errorf("bridge: site-to-site: max tunnels reached (%d)", m.cfg.MaxSiteToSiteTunnels)
	}

	iface := tunnel.InterfaceName

	// Create the WireGuard interface.
	if err := m.ctrl.CreateTunnelInterface(iface, tunnel.ListenPort); err != nil {
		return fmt.Errorf("bridge: site-to-site: create interface for tunnel %s: %w", tunnel.TunnelID, err)
	}

	// Configure the remote peer.
	if err := m.ctrl.ConfigureTunnelPeer(iface, tunnel.RemotePublicKey, tunnel.RemoteSubnets, tunnel.RemoteEndpoint, tunnel.PSK); err != nil {
		// Rollback: remove the interface.
		_ = m.ctrl.RemoveTunnelInterface(iface)
		return fmt.Errorf("bridge: site-to-site: configure peer for tunnel %s: %w", tunnel.TunnelID, err)
	}

	// Enable forwarding between tunnel and mesh interfaces.
	if err := m.routes.EnableForwarding(iface, m.meshIface); err != nil {
		// Rollback: remove peer and interface.
		_ = m.ctrl.RemoveTunnelPeer(iface, tunnel.RemotePublicKey)
		_ = m.ctrl.RemoveTunnelInterface(iface)
		return fmt.Errorf("bridge: site-to-site: enable forwarding for tunnel %s: %w", tunnel.TunnelID, err)
	}

	// Add routes for remote subnets.
	var addedRoutes []string
	for _, subnet := range tunnel.RemoteSubnets {
		if err := m.routes.AddRoute(subnet, iface); err != nil {
			// Rollback added routes.
			for _, added := range addedRoutes {
				_ = m.routes.RemoveRoute(added, iface)
			}
			// Rollback forwarding, peer, and interface.
			_ = m.routes.DisableForwarding(iface, m.meshIface)
			_ = m.ctrl.RemoveTunnelPeer(iface, tunnel.RemotePublicKey)
			_ = m.ctrl.RemoveTunnelInterface(iface)
			return fmt.Errorf("bridge: site-to-site: add route %s for tunnel %s: %w", subnet, tunnel.TunnelID, err)
		}
		addedRoutes = append(addedRoutes, subnet)
	}

	m.activeTunnels[tunnel.TunnelID] = &activeTunnel{
		tunnel: tunnel,
		iface:  iface,
	}

	m.logger.Info("site-to-site tunnel added",
		"tunnel_id", tunnel.TunnelID,
		"interface", iface,
		"remote_endpoint", tunnel.RemoteEndpoint,
		"remote_subnets", tunnel.RemoteSubnets,
	)

	return nil
}

// RemoveTunnel removes a site-to-site tunnel: removes routes, disables forwarding,
// removes the peer, and removes the interface.
// Removing a non-existent tunnel or calling on an inactive manager is a no-op.
func (m *SiteToSiteManager) RemoveTunnel(tunnelID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return
	}
	at, ok := m.activeTunnels[tunnelID]
	if !ok {
		return
	}

	// Remove routes for remote subnets.
	for _, subnet := range at.tunnel.RemoteSubnets {
		if err := m.routes.RemoveRoute(subnet, at.iface); err != nil {
			m.logger.Error("bridge: site-to-site: remove route failed",
				"tunnel_id", tunnelID,
				"subnet", subnet,
				"error", err,
			)
		}
	}

	// Disable forwarding between tunnel and mesh interfaces.
	if err := m.routes.DisableForwarding(at.iface, m.meshIface); err != nil {
		m.logger.Error("bridge: site-to-site: disable forwarding failed",
			"tunnel_id", tunnelID,
			"error", err,
		)
	}

	// Remove the tunnel peer and interface.
	if err := m.ctrl.RemoveTunnelPeer(at.iface, at.tunnel.RemotePublicKey); err != nil {
		m.logger.Error("bridge: site-to-site: remove peer failed",
			"tunnel_id", tunnelID,
			"error", err,
		)
	}
	if err := m.ctrl.RemoveTunnelInterface(at.iface); err != nil {
		m.logger.Error("bridge: site-to-site: remove interface failed",
			"tunnel_id", tunnelID,
			"error", err,
		)
	}

	delete(m.activeTunnels, tunnelID)

	m.logger.Info("site-to-site tunnel removed",
		"tunnel_id", tunnelID,
	)
}

// GetTunnel returns the SiteToSiteTunnel for the given ID and true if it exists,
// or a zero value and false otherwise.
func (m *SiteToSiteManager) GetTunnel(tunnelID string) (api.SiteToSiteTunnel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	at, ok := m.activeTunnels[tunnelID]
	if !ok {
		return api.SiteToSiteTunnel{}, false
	}
	return at.tunnel, true
}

// TunnelIDs returns the IDs of all active tunnels.
func (m *SiteToSiteManager) TunnelIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]string, 0, len(m.activeTunnels))
	for id := range m.activeTunnels {
		ids = append(ids, id)
	}
	return ids
}

// SiteToSiteStatus returns site-to-site status for heartbeat reporting.
// Returns nil when site-to-site is not active.
func (m *SiteToSiteManager) SiteToSiteStatus() *api.SiteToSiteInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}
	return &api.SiteToSiteInfo{
		Enabled:     true,
		TunnelCount: len(m.activeTunnels),
	}
}

// SiteToSiteCapabilities returns capability metadata for registration.
// Returns nil when site-to-site is not enabled.
func (m *SiteToSiteManager) SiteToSiteCapabilities() map[string]string {
	if !m.cfg.SiteToSiteEnabled {
		return nil
	}
	return map[string]string{
		"site_to_site":             "true",
		"max_site_to_site_tunnels": strconv.Itoa(m.cfg.MaxSiteToSiteTunnels),
	}
}
