package bridge

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/plexsphere/plexd/internal/api"
)

// Manager manages bridge mode routing between the mesh and access-side interfaces.
// Manager is not concurrent-safe; it relies on serial invocation from the reconcile loop.
type Manager struct {
	ctrl   RouteController
	cfg    Config
	logger *slog.Logger

	// tracked state
	active        bool
	meshIface     string
	activeRoutes  map[string]struct{}
	natConfigured bool
}

// NewManager creates a new Manager. Config defaults are applied automatically.
func NewManager(ctrl RouteController, cfg Config, logger *slog.Logger) *Manager {
	cfg.ApplyDefaults()
	return &Manager{
		ctrl:         ctrl,
		cfg:          cfg,
		logger:       logger,
		activeRoutes: make(map[string]struct{}),
	}
}

// Setup configures bridge mode routing: enables forwarding, adds routes, and
// optionally configures NAT masquerading. When bridge mode is disabled this is a no-op.
// On partial route failure, previously added routes in this call are rolled back.
func (m *Manager) Setup(meshIface string) error {
	if !m.cfg.Enabled {
		return nil
	}

	m.meshIface = meshIface

	// Enable IP forwarding.
	if err := m.ctrl.EnableForwarding(meshIface, m.cfg.AccessInterface); err != nil {
		return fmt.Errorf("bridge: setup: enable forwarding: %w", err)
	}

	// Add routes with rollback on failure.
	var added []string
	for _, subnet := range m.cfg.AccessSubnets {
		if err := m.ctrl.AddRoute(subnet, m.cfg.AccessInterface); err != nil {
			m.logger.Error("bridge: setup: add route failed, rolling back",
				"component", "bridge",
				"subnet", subnet,
				"error", err,
			)
			m.rollbackSetup(added)
			return fmt.Errorf("bridge: setup: add route %q: %w", subnet, err)
		}
		added = append(added, subnet)
	}

	// Track active routes.
	for _, subnet := range added {
		m.activeRoutes[subnet] = struct{}{}
	}

	// Configure NAT if enabled.
	if m.cfg.natEnabled() {
		if err := m.ctrl.AddNATMasquerade(m.cfg.AccessInterface); err != nil {
			m.logger.Error("bridge: setup: add NAT masquerade failed, rolling back",
				"component", "bridge",
				"error", err,
			)
			m.rollbackSetup(subnetsFromSet(m.activeRoutes))
			m.activeRoutes = make(map[string]struct{})
			return fmt.Errorf("bridge: setup: add NAT masquerade: %w", err)
		}
		m.natConfigured = true
	}

	m.active = true

	m.logger.Info("bridge mode configured",
		"component", "bridge",
		"mesh_iface", meshIface,
		"access_iface", m.cfg.AccessInterface,
		"subnets", m.cfg.AccessSubnets,
		"nat", m.cfg.natEnabled(),
	)

	return nil
}

// rollbackSetup removes the given routes and disables forwarding, logging any errors.
// Used during Setup to undo partial progress on failure.
func (m *Manager) rollbackSetup(subnets []string) {
	for i := len(subnets) - 1; i >= 0; i-- {
		if rerr := m.ctrl.RemoveRoute(subnets[i], m.cfg.AccessInterface); rerr != nil {
			m.logger.Error("bridge: setup: rollback remove route failed",
				"component", "bridge",
				"subnet", subnets[i],
				"error", rerr,
			)
		}
	}
	if derr := m.ctrl.DisableForwarding(m.meshIface, m.cfg.AccessInterface); derr != nil {
		m.logger.Error("bridge: setup: rollback disable forwarding failed",
			"component", "bridge",
			"error", derr,
		)
	}
}

// subnetsFromSet returns the keys of a subnet set as a slice.
func subnetsFromSet(set map[string]struct{}) []string {
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	return result
}

// Teardown removes all bridge-specific routing rules, NAT masquerading, and
// disables forwarding. Idempotent: calling Teardown when inactive returns nil.
// Errors are aggregated via errors.Join; cleanup continues even on failure.
func (m *Manager) Teardown() error {
	if !m.active {
		return nil
	}

	var errs []error

	// Remove all active routes.
	for subnet := range m.activeRoutes {
		if err := m.ctrl.RemoveRoute(subnet, m.cfg.AccessInterface); err != nil {
			m.logger.Error("bridge: teardown: remove route failed",
				"component", "bridge",
				"subnet", subnet,
				"error", err,
			)
			errs = append(errs, err)
		}
	}
	m.activeRoutes = make(map[string]struct{})

	// Remove NAT masquerade if it was configured.
	if m.natConfigured {
		if err := m.ctrl.RemoveNATMasquerade(m.cfg.AccessInterface); err != nil {
			m.logger.Error("bridge: teardown: remove NAT masquerade failed",
				"component", "bridge",
				"error", err,
			)
			errs = append(errs, err)
		}
		m.natConfigured = false
	}

	// Disable forwarding.
	if err := m.ctrl.DisableForwarding(m.meshIface, m.cfg.AccessInterface); err != nil {
		m.logger.Error("bridge: teardown: disable forwarding failed",
			"component", "bridge",
			"error", err,
		)
		errs = append(errs, err)
	}

	m.active = false

	return errors.Join(errs...)
}

// UpdateRoutes computes the diff between current active routes and the desired
// subnets, adding new and removing stale routes.
func (m *Manager) UpdateRoutes(subnets []string) error {
	desired := make(map[string]struct{}, len(subnets))
	for _, s := range subnets {
		desired[s] = struct{}{}
	}

	var errs []error

	// Remove stale routes.
	for subnet := range m.activeRoutes {
		if _, ok := desired[subnet]; !ok {
			if err := m.ctrl.RemoveRoute(subnet, m.cfg.AccessInterface); err != nil {
				m.logger.Error("bridge: update routes: remove stale route failed",
					"component", "bridge",
					"subnet", subnet,
					"error", err,
				)
				errs = append(errs, err)
			} else {
				delete(m.activeRoutes, subnet)
			}
		}
	}

	// Add new routes.
	for _, subnet := range subnets {
		if _, ok := m.activeRoutes[subnet]; !ok {
			if err := m.ctrl.AddRoute(subnet, m.cfg.AccessInterface); err != nil {
				m.logger.Error("bridge: update routes: add route failed",
					"component", "bridge",
					"subnet", subnet,
					"error", err,
				)
				errs = append(errs, err)
			} else {
				m.activeRoutes[subnet] = struct{}{}
			}
		}
	}

	return errors.Join(errs...)
}

// BridgeStatus returns bridge status for heartbeat reporting.
// Returns nil when bridge mode is not active.
func (m *Manager) BridgeStatus() *api.BridgeInfo {
	if !m.active {
		return nil
	}
	return &api.BridgeInfo{
		Enabled:         true,
		AccessInterface: m.cfg.AccessInterface,
		ActiveRoutes:    len(m.activeRoutes),
	}
}

// BridgeCapabilities returns bridge capability metadata for registration.
// Returns nil when bridge mode is disabled.
func (m *Manager) BridgeCapabilities() map[string]string {
	if !m.cfg.Enabled {
		return nil
	}
	caps := map[string]string{
		"bridge":           "true",
		"access_interface": m.cfg.AccessInterface,
	}
	for i, s := range m.cfg.AccessSubnets {
		caps[fmt.Sprintf("access_subnet_%d", i)] = s
	}
	return caps
}
