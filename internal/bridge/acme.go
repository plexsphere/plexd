package bridge

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACMEConfig holds configuration for automatic TLS certificate management
// via the ACME protocol (e.g., Let's Encrypt).
type ACMEConfig struct {
	// Enabled controls whether ACME certificate management is active.
	Enabled bool
	// CacheDir is the directory for caching certificates on disk.
	// Used by autocert.DirCache.
	CacheDir string
	// AllowedHosts is the whitelist of hostnames for which certificates may be obtained.
	AllowedHosts []string
	// Email is the contact email for the ACME account (optional, used in registration).
	Email string
	// ACMEDirectoryURL overrides the default ACME directory (e.g., for Let's Encrypt staging).
	// Empty means use the default (Let's Encrypt production).
	ACMEDirectoryURL string
}

// ACMEManager manages automatic TLS certificate acquisition and renewal
// via the ACME protocol. It wraps autocert.Manager with DirCache,
// HostWhitelist, and certificate lifecycle management.
// ACMEManager is concurrent-safe via mu.
type ACMEManager struct {
	cfg    ACMEConfig
	logger *slog.Logger

	mu      sync.Mutex
	active  bool
	manager *autocert.Manager // nil until Setup()
}

// NewACMEManager creates a new ACMEManager.
func NewACMEManager(cfg ACMEConfig, logger *slog.Logger) *ACMEManager {
	return &ACMEManager{
		cfg:    cfg,
		logger: logger,
	}
}

// Setup initializes the ACME manager and creates the underlying autocert.Manager.
// When ACME is disabled this is a no-op.
func (m *ACMEManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled {
		return nil
	}

	if m.cfg.CacheDir == "" {
		return fmt.Errorf("bridge: acme: cache directory must be set")
	}
	if len(m.cfg.AllowedHosts) == 0 {
		return fmt.Errorf("bridge: acme: at least one allowed host is required")
	}

	am := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(m.cfg.CacheDir),
		HostPolicy: autocert.HostWhitelist(m.cfg.AllowedHosts...),
	}

	if m.cfg.Email != "" {
		am.Email = m.cfg.Email
	}

	if m.cfg.ACMEDirectoryURL != "" {
		am.Client = &acme.Client{DirectoryURL: m.cfg.ACMEDirectoryURL}
	}

	m.manager = am
	m.active = true

	m.logger.Info("acme manager started",
		"component", "bridge",
		"cache_dir", m.cfg.CacheDir,
		"allowed_hosts", m.cfg.AllowedHosts,
	)

	return nil
}

// Teardown performs idempotent cleanup of the ACME manager.
// Calling Teardown when inactive returns nil.
func (m *ACMEManager) Teardown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}

	m.active = false
	m.manager = nil

	m.logger.Info("acme manager stopped",
		"component", "bridge",
	)

	return nil
}

// TLSConfig returns a *tls.Config with GetCertificate set to the autocert
// manager's GetCertificate. Returns nil if the manager is not active.
// The returned config sets MinVersion to TLS 1.2.
func (m *ACMEManager) TLSConfig() *tls.Config {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}

	return &tls.Config{
		GetCertificate: m.manager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// GetCertificate delegates to the underlying autocert.Manager's GetCertificate.
// Returns an error if the manager is not active.
func (m *ACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	mgr := m.manager
	active := m.active
	m.mu.Unlock()

	if !active {
		return nil, fmt.Errorf("bridge: acme: manager is not active")
	}

	return mgr.GetCertificate(hello)
}

// AllowedHosts returns a copy of the allowed hosts slice.
func (m *ACMEManager) AllowedHosts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	hosts := make([]string, len(m.cfg.AllowedHosts))
	copy(hosts, m.cfg.AllowedHosts)
	return hosts
}

// Active reports whether the ACME manager is currently active.
func (m *ACMEManager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}
