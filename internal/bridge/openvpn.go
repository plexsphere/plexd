package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
)

// OpenVPNProvider wraps the OpenVPN CLI to manage OpenVPN tunnels for
// site-to-site connectivity. All methods are safe for concurrent use.
type OpenVPNProvider struct {
	exec      CommandExecutor
	routes    RouteController
	logger    *slog.Logger
	configDir string // directory for config files (defaults to DefaultTunnelConfigDir)

	mu      sync.Mutex
	tunnels map[string]*openvpnTunnel
}

// openvpnTunnel tracks the internal state of a single OpenVPN tunnel.
type openvpnTunnel struct {
	cfg       TunnelConfig
	ifaceName string
	handle    CommandHandle
}

// NewOpenVPNProvider creates a new OpenVPNProvider.
func NewOpenVPNProvider(exec CommandExecutor, routes RouteController, logger *slog.Logger) *OpenVPNProvider {
	return &OpenVPNProvider{
		exec:      exec,
		routes:    routes,
		logger:    logger,
		configDir: DefaultTunnelConfigDir,
		tunnels:   make(map[string]*openvpnTunnel),
	}
}

// Name returns the provider identifier.
func (p *OpenVPNProvider) Name() string {
	return "openvpn"
}

// CreateTunnel establishes an OpenVPN tunnel.
func (p *OpenVPNProvider) CreateTunnel(ctx context.Context, cfg TunnelConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.tunnels[cfg.TunnelID]; exists {
		return fmt.Errorf("bridge: openvpn: tunnel %q already exists", cfg.TunnelID)
	}

	if err := ValidateTunnelConfig(cfg); err != nil {
		return fmt.Errorf("bridge: openvpn: %w", err)
	}

	if err := ensureTunnelConfigDir(p.configDir); err != nil {
		return fmt.Errorf("bridge: openvpn: create config dir: %w", err)
	}

	ifaceName := "tun-" + cfg.TunnelID
	confPath := fmt.Sprintf("%s/plexd-openvpn-%s.conf", p.configDir, cfg.TunnelID)
	confContent := generateOpenVPNConfig(cfg, ifaceName)

	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("bridge: openvpn: write config for %q: %w", cfg.TunnelID, err)
	}

	// Start the OpenVPN process (long-running).
	handle, err := p.exec.Start(ctx, "openvpn", "--config", confPath)
	if err != nil {
		_ = os.Remove(confPath)
		return fmt.Errorf("bridge: openvpn: start %q: %w", cfg.TunnelID, err)
	}

	// Add routes for remote subnets.
	for i, subnet := range cfg.RemoteSubnets {
		if err := p.routes.AddRoute(subnet, ifaceName); err != nil {
			// Rollback routes that were already added.
			for j := i - 1; j >= 0; j-- {
				_ = p.routes.RemoveRoute(cfg.RemoteSubnets[j], ifaceName)
			}
			// Stop the process.
			_ = handle.Stop()
			_ = os.Remove(confPath)
			return fmt.Errorf("bridge: openvpn: add route %q for %q: %w", subnet, cfg.TunnelID, err)
		}
	}

	p.tunnels[cfg.TunnelID] = &openvpnTunnel{
		cfg:       cfg,
		ifaceName: ifaceName,
		handle:    handle,
	}

	p.logger.Info("tunnel created",
		"component", "bridge",
		"provider", "openvpn",
		"tunnel_id", cfg.TunnelID,
		"interface", ifaceName,
	)

	return nil
}

// RemoveTunnel tears down an OpenVPN tunnel. Idempotent.
func (p *OpenVPNProvider) RemoveTunnel(tunnelID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.removeTunnelLocked(tunnelID)
}

// removeTunnelLocked removes a tunnel while holding the lock.
func (p *OpenVPNProvider) removeTunnelLocked(tunnelID string) error {
	tun, exists := p.tunnels[tunnelID]
	if !exists {
		return nil
	}

	// Stop the OpenVPN process.
	if err := tun.handle.Stop(); err != nil {
		p.logger.Warn("stop openvpn process failed",
			"component", "bridge",
			"provider", "openvpn",
			"tunnel_id", tunnelID,
			"error", err,
		)
	}

	// Remove routes for remote subnets.
	for _, subnet := range tun.cfg.RemoteSubnets {
		if err := p.routes.RemoveRoute(subnet, tun.ifaceName); err != nil {
			p.logger.Warn("remove route failed",
				"component", "bridge",
				"provider", "openvpn",
				"tunnel_id", tunnelID,
				"subnet", subnet,
				"error", err,
			)
		}
	}

	// Clean up config file.
	confPath := fmt.Sprintf("%s/plexd-openvpn-%s.conf", p.configDir, tunnelID)
	_ = os.Remove(confPath)

	delete(p.tunnels, tunnelID)

	p.logger.Info("tunnel removed",
		"component", "bridge",
		"provider", "openvpn",
		"tunnel_id", tunnelID,
	)

	return nil
}

// TunnelStatus returns the status of the given tunnel.
func (p *OpenVPNProvider) TunnelStatus(tunnelID string) TunnelStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	tun, exists := p.tunnels[tunnelID]
	if !exists {
		return TunnelStatus{TunnelID: tunnelID}
	}

	return TunnelStatus{
		TunnelID:      tunnelID,
		Running:       true,
		InterfaceName: tun.ifaceName,
	}
}

// ActiveTunnels returns the IDs of all active tunnels.
func (p *OpenVPNProvider) ActiveTunnels() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	ids := make([]string, 0, len(p.tunnels))
	for id := range p.tunnels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Stop gracefully shuts down all managed OpenVPN tunnels. Idempotent.
func (p *OpenVPNProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id := range p.tunnels {
		if err := p.removeTunnelLocked(id); err != nil {
			return fmt.Errorf("bridge: openvpn: stop tunnel %q: %w", id, err)
		}
	}
	return nil
}

// generateOpenVPNConfig builds a minimal OpenVPN configuration from the given TunnelConfig.
func generateOpenVPNConfig(cfg TunnelConfig, ifaceName string) string {
	// Split remote endpoint into host and port.
	host := cfg.RemoteEndpoint
	port := "1194"
	if idx := strings.LastIndex(cfg.RemoteEndpoint, ":"); idx >= 0 {
		host = cfg.RemoteEndpoint[:idx]
		port = cfg.RemoteEndpoint[idx+1:]
	}

	var b strings.Builder
	b.WriteString("client\n")
	fmt.Fprintf(&b, "remote %s %s\n", host, port)
	fmt.Fprintf(&b, "dev %s\n", ifaceName)
	b.WriteString("dev-type tun\n")
	b.WriteString("secret [inline]\n")
	b.WriteString("<secret>\n")
	b.WriteString(cfg.PSK)
	b.WriteString("\n")
	b.WriteString("</secret>\n")

	return b.String()
}
