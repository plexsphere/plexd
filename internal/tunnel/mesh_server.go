package tunnel

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

// MeshServer composes the SSH mesh server with the existing SessionManager,
// managing their lifecycle together.
type MeshServer struct {
	cfg      Config
	ssh      *SSHServer
	sessions *SessionManager
	logger   *slog.Logger
}

// NewMeshServer creates a MeshServer that manages the SSH server and session
// manager. meshIP is the node's registered mesh address, which every session
// listener binds — it is the reachability boundary of an otherwise
// unauthenticated forward, so it comes from the node identity rather than being
// guessed from the SSH listen address, which is empty in both documented
// configurations and would bind every interface on the host.
// If cfg.SSHListenAddr is empty, the SSH server is not created.
func NewMeshServer(cfg Config, meshIP string, hostKey ssh.Signer, verifier JWTVerifier, logger *slog.Logger) *MeshServer {
	cfg.ApplyDefaults()

	m := &MeshServer{
		cfg:      cfg,
		sessions: NewSessionManager(cfg, meshIP, logger),
		logger:   logger.With("component", "tunnel"),
	}

	if cfg.SSHListenAddr != "" && hostKey != nil {
		sshCfg := SSHServerConfig{
			ListenAddr:  cfg.SSHListenAddr,
			MaxSessions: cfg.MaxSessions,
			IdleTimeout: cfg.DefaultTimeout,
		}
		m.ssh = NewSSHServer(sshCfg, hostKey, verifier, logger)
	}

	return m
}

// Start begins the SSH server (if configured) and returns.
func (m *MeshServer) Start(ctx context.Context) error {
	if m.ssh != nil {
		if err := m.ssh.Start(ctx); err != nil {
			return fmt.Errorf("tunnel: mesh server: start ssh: %w", err)
		}
		m.logger.Info("mesh server started", "ssh_addr", m.ssh.Addr())
	}
	return nil
}

// Shutdown gracefully stops the mesh server.
// Ordering: close SSH listener first, then drain session manager.
func (m *MeshServer) Shutdown() error {
	if m.ssh != nil {
		if err := m.ssh.Shutdown(); err != nil {
			m.logger.Error("ssh shutdown error", "error", err)
		}
	}
	m.sessions.Shutdown()
	m.logger.Info("mesh server shutdown complete")
	return nil
}

// SSHServer returns the underlying SSH server, or nil if not configured.
func (m *MeshServer) SSHServer() *SSHServer {
	return m.ssh
}

// SessionManager returns the underlying session manager.
func (m *MeshServer) SessionManager() *SessionManager {
	return m.sessions
}
