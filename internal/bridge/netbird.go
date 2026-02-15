package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// netbirdStatusResponse represents the JSON output of `netbird status --json`.
type netbirdStatusResponse struct {
	IP        string `json:"ip"`
	FQDN      string `json:"fqdn"`
	Connected bool   `json:"connected"`
	Interface struct {
		Name string `json:"name"`
	} `json:"interface"`
}

// NetbirdProvider implements UserAccessProvider by wrapping the Netbird CLI.
// It joins a Netbird network using a setup key, enabling Netbird users to
// access mesh resources through the bridge node.
type NetbirdProvider struct {
	exec   CommandExecutor
	logger *slog.Logger

	mu     sync.Mutex
	status ProviderStatus
}

// NewNetbirdProvider returns a new NetbirdProvider that uses the given
// CommandExecutor to invoke the netbird CLI.
func NewNetbirdProvider(exec CommandExecutor, logger *slog.Logger) *NetbirdProvider {
	return &NetbirdProvider{
		exec:   exec,
		logger: logger,
	}
}

// Name returns the provider identifier.
func (n *NetbirdProvider) Name() string {
	return "netbird"
}

// Start launches the Netbird daemon by running `netbird up` with the setup key
// from the PLEXD_NETBIRD_SETUP_KEY environment variable, then queries
// `netbird status --json` to discover the assigned IP and interface name.
func (n *NetbirdProvider) Start(ctx context.Context) error {
	setupKey := os.Getenv("PLEXD_NETBIRD_SETUP_KEY")
	if setupKey == "" {
		return fmt.Errorf("bridge: netbird: PLEXD_NETBIRD_SETUP_KEY environment variable is not set")
	}

	n.logger.Info("starting netbird provider", "component", "bridge", "setup_key_len", len(setupKey))

	// Run netbird up with the setup key.
	out, err := n.exec.Run(ctx, "netbird", "up", "--setup-key", setupKey)
	if err != nil {
		return fmt.Errorf("bridge: netbird: up failed: %w", err)
	}
	n.logger.Debug("netbird up completed", "component", "bridge", "output", string(out))

	// Query netbird status to discover IP and interface.
	statusOut, err := n.exec.Run(ctx, "netbird", "status", "--json")
	if err != nil {
		return fmt.Errorf("bridge: netbird: status failed: %w", err)
	}

	var resp netbirdStatusResponse
	if err := json.Unmarshal(statusOut, &resp); err != nil {
		return fmt.Errorf("bridge: netbird: failed to parse status JSON: %w", err)
	}

	// Strip CIDR prefix from IP if present (e.g. "100.119.0.1/16" -> "100.119.0.1").
	ip := resp.IP
	if idx := strings.Index(ip, "/"); idx != -1 {
		ip = ip[:idx]
	}

	n.mu.Lock()
	n.status = ProviderStatus{
		Running:       true,
		InterfaceName: resp.Interface.Name,
		IP:            ip,
	}
	n.mu.Unlock()

	n.logger.Info("netbird provider started",
		"component", "bridge",
		"ip", ip,
		"interface", resp.Interface.Name,
	)

	return nil
}

// Stop gracefully shuts down Netbird by running `netbird down`.
// Idempotent: calling Stop when not running returns nil.
func (n *NetbirdProvider) Stop() error {
	n.mu.Lock()
	running := n.status.Running
	n.mu.Unlock()

	if !running {
		return nil
	}

	n.logger.Info("stopping netbird provider", "component", "bridge")

	out, err := n.exec.Run(context.Background(), "netbird", "down")
	if err != nil {
		return fmt.Errorf("bridge: netbird: down failed: %w", err)
	}
	n.logger.Debug("netbird down completed", "component", "bridge", "output", string(out))

	n.mu.Lock()
	n.status = ProviderStatus{}
	n.mu.Unlock()

	return nil
}

// Status returns the current provider status.
func (n *NetbirdProvider) Status() ProviderStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status
}
