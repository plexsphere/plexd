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

// IPsecProvider wraps strongSwan (swanctl) to manage IPsec tunnels for
// site-to-site connectivity. All methods are safe for concurrent use.
type IPsecProvider struct {
	exec      CommandExecutor
	routes    RouteController
	logger    *slog.Logger
	configDir string // directory for config files (defaults to DefaultTunnelConfigDir)

	mu      sync.Mutex
	tunnels map[string]*ipsecTunnel
}

// ipsecTunnel tracks the internal state of a single IPsec tunnel.
type ipsecTunnel struct {
	cfg       TunnelConfig
	ifaceName string
}

// NewIPsecProvider creates a new IPsecProvider.
func NewIPsecProvider(exec CommandExecutor, routes RouteController, logger *slog.Logger) *IPsecProvider {
	return &IPsecProvider{
		exec:      exec,
		routes:    routes,
		logger:    logger,
		configDir: DefaultTunnelConfigDir,
		tunnels:   make(map[string]*ipsecTunnel),
	}
}

// Name returns the provider identifier.
func (p *IPsecProvider) Name() string {
	return "ipsec"
}

// CreateTunnel establishes an IPsec tunnel via swanctl.
func (p *IPsecProvider) CreateTunnel(ctx context.Context, cfg TunnelConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.tunnels[cfg.TunnelID]; exists {
		return fmt.Errorf("bridge: ipsec: tunnel %q already exists", cfg.TunnelID)
	}

	if err := ValidateTunnelConfig(cfg); err != nil {
		return fmt.Errorf("bridge: ipsec: %w", err)
	}

	if err := ensureTunnelConfigDir(p.configDir); err != nil {
		return fmt.Errorf("bridge: ipsec: create config dir: %w", err)
	}

	confPath := fmt.Sprintf("%s/plexd-ipsec-%s.conf", p.configDir, cfg.TunnelID)
	confContent := generateSwanctlConfig(cfg)

	if err := os.WriteFile(confPath, []byte(confContent), 0600); err != nil {
		return fmt.Errorf("bridge: ipsec: write config for %q: %w", cfg.TunnelID, err)
	}

	// Load the connection configuration.
	if _, err := p.exec.Run(ctx, "swanctl", "--load-conns", "--file", confPath); err != nil {
		_ = os.Remove(confPath)
		return fmt.Errorf("bridge: ipsec: load conns for %q: %w", cfg.TunnelID, err)
	}

	// Initiate the connection.
	if _, err := p.exec.Run(ctx, "swanctl", "--initiate", "--child", cfg.TunnelID); err != nil {
		// Rollback: attempt to terminate and clean up.
		_, _ = p.exec.Run(ctx, "swanctl", "--terminate", "--child", cfg.TunnelID)
		_ = os.Remove(confPath)
		return fmt.Errorf("bridge: ipsec: initiate %q: %w", cfg.TunnelID, err)
	}

	ifaceName := "ipsec-" + cfg.TunnelID

	// Add routes for remote subnets.
	for i, subnet := range cfg.RemoteSubnets {
		if err := p.routes.AddRoute(subnet, ifaceName); err != nil {
			// Rollback routes that were already added.
			for j := i - 1; j >= 0; j-- {
				_ = p.routes.RemoveRoute(cfg.RemoteSubnets[j], ifaceName)
			}
			_, _ = p.exec.Run(ctx, "swanctl", "--terminate", "--child", cfg.TunnelID)
			_ = os.Remove(confPath)
			return fmt.Errorf("bridge: ipsec: add route %q for %q: %w", subnet, cfg.TunnelID, err)
		}
	}

	p.tunnels[cfg.TunnelID] = &ipsecTunnel{
		cfg:       cfg,
		ifaceName: ifaceName,
	}

	p.logger.Info("tunnel created",
		"component", "bridge",
		"provider", "ipsec",
		"tunnel_id", cfg.TunnelID,
		"interface", ifaceName,
	)

	return nil
}

// RemoveTunnel tears down an IPsec tunnel. Idempotent.
func (p *IPsecProvider) RemoveTunnel(tunnelID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.removeTunnelLocked(tunnelID)
}

// removeTunnelLocked removes a tunnel while holding the lock.
func (p *IPsecProvider) removeTunnelLocked(tunnelID string) error {
	tun, exists := p.tunnels[tunnelID]
	if !exists {
		return nil
	}

	ctx := context.Background()

	// Terminate the connection.
	if _, err := p.exec.Run(ctx, "swanctl", "--terminate", "--child", tunnelID); err != nil {
		p.logger.Warn("terminate tunnel failed",
			"component", "bridge",
			"provider", "ipsec",
			"tunnel_id", tunnelID,
			"error", err,
		)
	}

	// Remove routes for remote subnets.
	for _, subnet := range tun.cfg.RemoteSubnets {
		if err := p.routes.RemoveRoute(subnet, tun.ifaceName); err != nil {
			p.logger.Warn("remove route failed",
				"component", "bridge",
				"provider", "ipsec",
				"tunnel_id", tunnelID,
				"subnet", subnet,
				"error", err,
			)
		}
	}

	// Clean up config file.
	confPath := fmt.Sprintf("%s/plexd-ipsec-%s.conf", p.configDir, tunnelID)
	_ = os.Remove(confPath)

	delete(p.tunnels, tunnelID)

	p.logger.Info("tunnel removed",
		"component", "bridge",
		"provider", "ipsec",
		"tunnel_id", tunnelID,
	)

	return nil
}

// TunnelStatus returns the status of the given tunnel.
func (p *IPsecProvider) TunnelStatus(tunnelID string) TunnelStatus {
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
func (p *IPsecProvider) ActiveTunnels() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	ids := make([]string, 0, len(p.tunnels))
	for id := range p.tunnels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Stop gracefully shuts down all managed IPsec tunnels. Idempotent.
func (p *IPsecProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id := range p.tunnels {
		if err := p.removeTunnelLocked(id); err != nil {
			return fmt.Errorf("bridge: ipsec: stop tunnel %q: %w", id, err)
		}
	}
	return nil
}

// generateSwanctlConfig builds a minimal swanctl configuration from the given TunnelConfig.
func generateSwanctlConfig(cfg TunnelConfig) string {
	var b strings.Builder

	b.WriteString("connections {\n")
	fmt.Fprintf(&b, "    %s {\n", cfg.TunnelID)
	fmt.Fprintf(&b, "        remote_addrs = %s\n", cfg.RemoteEndpoint)
	b.WriteString("        local {\n")
	b.WriteString("            auth = psk\n")
	b.WriteString("        }\n")
	b.WriteString("        remote {\n")
	b.WriteString("            auth = psk\n")
	b.WriteString("        }\n")
	b.WriteString("        children {\n")
	fmt.Fprintf(&b, "            %s {\n", cfg.TunnelID)
	fmt.Fprintf(&b, "                local_ts = %s\n", strings.Join(cfg.LocalSubnets, ","))
	fmt.Fprintf(&b, "                remote_ts = %s\n", strings.Join(cfg.RemoteSubnets, ","))
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	fmt.Fprintf(&b, "    ike-%s {\n", cfg.TunnelID)
	fmt.Fprintf(&b, "        secret = %s\n", cfg.PSK)
	b.WriteString("    }\n")
	b.WriteString("}\n")

	return b.String()
}
