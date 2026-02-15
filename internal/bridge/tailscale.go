package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// tailscaleStatus is the subset of "tailscale status --json" output we parse.
type tailscaleStatus struct {
	TailscaleIPs []string `json:"TailscaleIPs"`
}

// TailscaleProvider wraps the Tailscale CLI (tailscale/tailscaled) to join a
// Tailscale network on a bridge node, enabling Tailscale users to access mesh
// resources. TailscaleProvider is concurrent-safe via mu.
type TailscaleProvider struct {
	exec   CommandExecutor
	logger *slog.Logger

	// mu protects running, ip, ifaceName, daemonHandle.
	mu           sync.Mutex
	running      bool
	ip           string
	ifaceName    string
	daemonHandle CommandHandle
}

// NewTailscaleProvider creates a new TailscaleProvider.
func NewTailscaleProvider(exec CommandExecutor, logger *slog.Logger) *TailscaleProvider {
	return &TailscaleProvider{
		exec:   exec,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (p *TailscaleProvider) Name() string {
	return "tailscale"
}

// Start launches tailscaled and joins the Tailscale network using an auth key
// read from the PLEXD_TAILSCALE_AUTH_KEY environment variable.
func (p *TailscaleProvider) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	authKey := os.Getenv("PLEXD_TAILSCALE_AUTH_KEY")
	if authKey == "" {
		return fmt.Errorf("bridge: tailscale: PLEXD_TAILSCALE_AUTH_KEY is not set")
	}

	// Start tailscaled daemon with in-memory state.
	handle, err := p.exec.Start(ctx, "tailscaled", "--state=mem:")
	if err != nil {
		return fmt.Errorf("bridge: tailscale: start tailscaled: %w", err)
	}
	p.daemonHandle = handle

	// Join the Tailscale network.
	if _, err := p.exec.Run(ctx, "tailscale", "up", "--authkey="+authKey, "--accept-routes"); err != nil {
		// Best-effort cleanup of daemon.
		_ = handle.Stop()
		p.daemonHandle = nil
		return fmt.Errorf("bridge: tailscale: tailscale up: %w", err)
	}

	// Query status to discover assigned IP.
	out, err := p.exec.Run(ctx, "tailscale", "status", "--json")
	if err != nil {
		// Best-effort cleanup.
		_, _ = p.exec.Run(ctx, "tailscale", "down")
		_ = handle.Stop()
		p.daemonHandle = nil
		return fmt.Errorf("bridge: tailscale: tailscale status: %w", err)
	}

	var status tailscaleStatus
	if err := json.Unmarshal(out, &status); err != nil {
		// Best-effort cleanup.
		_, _ = p.exec.Run(ctx, "tailscale", "down")
		_ = handle.Stop()
		p.daemonHandle = nil
		return fmt.Errorf("bridge: tailscale: parse status: %w", err)
	}

	if len(status.TailscaleIPs) > 0 {
		p.ip = status.TailscaleIPs[0]
	}
	p.ifaceName = "tailscale0"
	p.running = true

	p.logger.Info("tailscale provider started",
		"component", "bridge",
		"ip", p.ip,
		"interface", p.ifaceName,
	)

	return nil
}

// Stop gracefully shuts down Tailscale and the daemon process.
// Idempotent: calling Stop when not running returns nil.
func (p *TailscaleProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	// Disconnect from Tailscale network.
	if _, err := p.exec.Run(context.Background(), "tailscale", "down"); err != nil {
		p.logger.Error("bridge: tailscale: tailscale down failed",
			"component", "bridge",
			"error", err,
		)
	}

	// Stop daemon.
	if p.daemonHandle != nil {
		if err := p.daemonHandle.Stop(); err != nil {
			p.logger.Error("bridge: tailscale: stop tailscaled failed",
				"component", "bridge",
				"error", err,
			)
		}
		p.daemonHandle = nil
	}

	p.running = false
	p.ip = ""
	p.ifaceName = ""

	p.logger.Info("tailscale provider stopped",
		"component", "bridge",
	)

	return nil
}

// Status returns the current provider status.
func (p *TailscaleProvider) Status() ProviderStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	return ProviderStatus{
		Running:       p.running,
		InterfaceName: p.ifaceName,
		IP:            p.ip,
	}
}
