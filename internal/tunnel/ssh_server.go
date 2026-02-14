package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultMaxSSHSessions is the default maximum number of concurrent SSH sessions.
const DefaultMaxSSHSessions = 10

// DefaultSSHIdleTimeout is the default idle timeout for SSH connections.
const DefaultSSHIdleTimeout = 30 * time.Minute

// JWTVerifier validates JWT tokens for SSH authentication.
type JWTVerifier interface {
	Verify(token string) error
}

// SSHServerConfig holds the configuration for the SSH mesh server.
type SSHServerConfig struct {
	// MaxSessions is the maximum number of concurrent SSH sessions.
	// Default: 10
	MaxSessions int

	// IdleTimeout is the idle timeout for SSH connections.
	// Default: 30m
	IdleTimeout time.Duration

	// ListenAddr is the address to listen on (mesh IP + port).
	// Required.
	ListenAddr string
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *SSHServerConfig) ApplyDefaults() {
	if c.MaxSessions == 0 {
		c.MaxSessions = DefaultMaxSSHSessions
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultSSHIdleTimeout
	}
}

// Validate checks that configuration values are within acceptable ranges.
func (c *SSHServerConfig) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("tunnel: ssh: config: ListenAddr is required")
	}
	if c.MaxSessions <= 0 {
		return errors.New("tunnel: ssh: config: MaxSessions must be positive")
	}
	if c.IdleTimeout < time.Minute {
		return errors.New("tunnel: ssh: config: IdleTimeout must be at least 1m")
	}
	return nil
}

// SSHServer is a mesh-facing SSH server that authenticates clients via JWT
// and provides direct-tcpip channel forwarding.
type SSHServer struct {
	cfg       SSHServerConfig
	sshConfig *ssh.ServerConfig
	listener  net.Listener
	logger    *slog.Logger
	verifier  JWTVerifier

	mu     sync.Mutex
	sem    chan struct{} // buffered channel semaphore for max sessions
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSSHServer creates a new SSHServer with the given configuration.
func NewSSHServer(cfg SSHServerConfig, hostKey ssh.Signer, verifier JWTVerifier, logger *slog.Logger) *SSHServer {
	cfg.ApplyDefaults()

	s := &SSHServer{
		cfg:      cfg,
		logger:   logger.With("component", "tunnel"),
		verifier: verifier,
		sem:      make(chan struct{}, cfg.MaxSessions),
	}

	sshCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			token := string(key.Marshal())
			if err := verifier.Verify(token); err != nil {
				s.logger.Warn("ssh auth failed",
					"remote_addr", conn.RemoteAddr().String(),
					"user", conn.User(),
					"error", err,
				)
				return nil, fmt.Errorf("tunnel: ssh: auth: %w", err)
			}
			return &ssh.Permissions{}, nil
		},
	}
	sshCfg.AddHostKey(hostKey)

	s.sshConfig = sshCfg
	return s
}

// Start begins listening for SSH connections on the configured address.
func (s *SSHServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("tunnel: ssh: listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop(ctx)

	s.logger.Info("ssh server started", "addr", ln.Addr().String())
	return nil
}

// acceptLoop accepts new TCP connections until the context is cancelled.
func (s *SSHServer) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if we're shutting down.
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.logger.Error("ssh accept error", "error", err)
			return
		}

		select {
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go s.handleConnection(ctx, conn)
		default:
			s.logger.Warn("ssh max sessions reached, rejecting connection",
				"remote_addr", conn.RemoteAddr().String(),
				"max", s.cfg.MaxSessions,
			)
			conn.Close()
		}
	}
}

// handleConnection performs the SSH handshake and handles channels for a single connection.
func (s *SSHServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.sem }()

	srvConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logger.Debug("ssh handshake failed",
			"remote_addr", conn.RemoteAddr().String(),
			"error", err,
		)
		conn.Close()
		return
	}
	defer srvConn.Close()

	// Set idle timeout.
	if err := conn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
		s.logger.Debug("ssh set deadline failed", "error", err)
	}

	// Discard global requests.
	go ssh.DiscardRequests(reqs)

	// Handle channels.
	for newChannel := range chans {
		// Reset idle deadline on channel activity.
		if err := conn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
			s.logger.Debug("ssh reset deadline failed", "error", err)
		}

		switch newChannel.ChannelType() {
		case "direct-tcpip":
			go handleDirectTCPIP(ctx, newChannel, s.logger)
		default:
			if err := newChannel.Reject(ssh.UnknownChannelType, "unknown channel type"); err != nil {
				s.logger.Error("failed to reject channel", "error", err)
			}
		}
	}
}

// Shutdown gracefully stops the SSH server.
func (s *SSHServer) Shutdown() error {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	return nil
}

// Addr returns the listener address or empty string if not started.
func (s *SSHServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}
