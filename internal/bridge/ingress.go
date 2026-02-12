package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// activeRule holds the state of a running ingress rule.
type activeRule struct {
	rule     api.IngressRule
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{} // closed when accept loop exits
}

// IngressManager manages public ingress — TCP listeners that proxy traffic
// to mesh-internal services via a bridge node.
// IngressManager is concurrent-safe via mu.
type IngressManager struct {
	ctrl        IngressController
	cfg         Config
	logger      *slog.Logger
	dialTimeout time.Duration

	// mu protects active, activeRules from concurrent access by
	// SSE event handlers and the reconcile loop.
	mu sync.Mutex

	// tracked state
	active      bool
	activeRules map[string]*activeRule // keyed by rule ID
	connCount   atomic.Int64          // total active proxy connections across all rules
}

// NewIngressManager creates a new IngressManager.
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger) *IngressManager {
	return &IngressManager{
		ctrl:        ctrl,
		cfg:         cfg,
		logger:      logger,
		dialTimeout: cfg.IngressDialTimeout,
		activeRules: make(map[string]*activeRule),
	}
}

// Setup initializes the ingress manager.
// When ingress is disabled this is a no-op.
func (m *IngressManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.IngressEnabled {
		return nil
	}

	m.active = true

	m.logger.Info("ingress manager started",
		"component", "bridge",
		"max_rules", m.cfg.MaxIngressRules,
		"dial_timeout", m.dialTimeout.String(),
	)

	return nil
}

// Teardown closes all active listeners and cancels proxy connections.
// Errors are aggregated — cleanup continues even when individual operations fail.
// Idempotent: calling Teardown when inactive returns nil.
func (m *IngressManager) Teardown() error {
	m.mu.Lock()

	if !m.active {
		m.mu.Unlock()
		return nil
	}

	var errs []error
	doneChans := make([]chan struct{}, 0, len(m.activeRules))

	for id, ar := range m.activeRules {
		doneChans = append(doneChans, ar.done)
		// Cancel accept loop and proxy connections.
		ar.cancel()
		// Close the listener.
		if err := m.ctrl.Close(ar.listener); err != nil {
			errs = append(errs, fmt.Errorf("bridge: ingress: close rule %s: %w", id, err))
		}
	}

	m.active = false
	m.activeRules = make(map[string]*activeRule)
	m.mu.Unlock()

	// Wait for all accept loop goroutines to exit outside the lock.
	for _, done := range doneChans {
		<-done
	}

	if len(errs) == 0 {
		m.logger.Info("ingress manager stopped",
			"component", "bridge",
		)
	}

	return errors.Join(errs...)
}

// AddRule adds an ingress rule and starts a TCP listener for it.
// Returns an error if the manager is inactive, the rule ID already exists,
// or the maximum rule count is reached.
func (m *IngressManager) AddRule(rule api.IngressRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return fmt.Errorf("bridge: ingress: manager is not active")
	}

	if _, ok := m.activeRules[rule.RuleID]; ok {
		return fmt.Errorf("bridge: ingress: rule already exists: %s", rule.RuleID)
	}
	if len(m.activeRules) >= m.cfg.MaxIngressRules {
		return fmt.Errorf("bridge: ingress: max rules reached (%d)", m.cfg.MaxIngressRules)
	}

	// Build TLS config for terminate mode.
	var tlsCfg *tls.Config
	if rule.Mode == "terminate" {
		cert, err := tls.X509KeyPair([]byte(rule.CertPEM), []byte(rule.KeyPEM))
		if err != nil {
			return fmt.Errorf("bridge: ingress: rule %s: load TLS certificate: %w", rule.RuleID, err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	addr := ":" + strconv.Itoa(rule.ListenPort)
	ln, err := m.ctrl.Listen(addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("bridge: ingress: rule %s: listen on %s: %w", rule.RuleID, addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	ar := &activeRule{
		rule:     rule,
		listener: ln,
		cancel:   cancel,
		done:     make(chan struct{}),
	}

	m.activeRules[rule.RuleID] = ar

	// Start accept loop in a goroutine.
	go m.acceptLoop(ctx, ar)

	m.logger.Info("ingress rule added",
		"component", "bridge",
		"rule_id", rule.RuleID,
		"listen_port", rule.ListenPort,
		"target", rule.TargetAddr,
		"mode", rule.Mode,
	)

	return nil
}

// RemoveRule stops the listener for the given rule ID and removes it.
// Removing a non-existent rule or calling on an inactive manager is a no-op.
func (m *IngressManager) RemoveRule(ruleID string) {
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	ar, ok := m.activeRules[ruleID]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.activeRules, ruleID)
	m.mu.Unlock()

	ar.cancel()
	if err := m.ctrl.Close(ar.listener); err != nil {
		m.logger.Error("bridge: ingress: close rule failed",
			"component", "bridge",
			"rule_id", ruleID,
			"error", err,
		)
	}
	// Wait for the accept loop goroutine to exit.
	<-ar.done

	m.logger.Info("ingress rule removed",
		"component", "bridge",
		"rule_id", ruleID,
	)
}

// GetRule returns the IngressRule for the given ID and true if it exists,
// or a zero value and false otherwise.
func (m *IngressManager) GetRule(ruleID string) (api.IngressRule, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ar, ok := m.activeRules[ruleID]
	if !ok {
		return api.IngressRule{}, false
	}
	return ar.rule, true
}

// RuleIDs returns the IDs of all active rules.
func (m *IngressManager) RuleIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]string, 0, len(m.activeRules))
	for id := range m.activeRules {
		ids = append(ids, id)
	}
	return ids
}

// acceptLoop accepts connections on the listener and proxies them to the target.
func (m *IngressManager) acceptLoop(ctx context.Context, ar *activeRule) {
	defer close(ar.done)
	for {
		conn, err := ar.listener.Accept()
		if err != nil {
			// Context cancelled (clean shutdown) or listener closed.
			return
		}

		m.connCount.Add(1)
		go m.proxyConnection(ctx, ar.rule, conn)
	}
}

// proxyConnection dials the target and relays data bidirectionally.
func (m *IngressManager) proxyConnection(ctx context.Context, rule api.IngressRule, clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		m.connCount.Add(-1)
	}()

	// Dial the target with timeout.
	dialer := net.Dialer{Timeout: m.dialTimeout}
	targetConn, err := dialer.DialContext(ctx, "tcp", rule.TargetAddr)
	if err != nil {
		m.logger.Error("bridge: ingress: dial target failed",
			"component", "bridge",
			"rule_id", rule.RuleID,
			"target", rule.TargetAddr,
			"error", err,
		)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy — spawn both directions before select.
	clientToTarget := make(chan struct{})
	go func() {
		defer close(clientToTarget)
		io.Copy(targetConn, clientConn)
	}()

	targetToClient := make(chan struct{})
	go func() {
		defer close(targetToClient)
		io.Copy(clientConn, targetConn)
	}()

	// When context is cancelled or either copy finishes, close both sides.
	select {
	case <-ctx.Done():
	case <-clientToTarget:
	case <-targetToClient:
	}
}

// IngressStatus returns ingress status for heartbeat reporting.
// Returns nil when ingress is not active.
func (m *IngressManager) IngressStatus() *api.IngressInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}
	return &api.IngressInfo{
		Enabled:         true,
		RuleCount:       len(m.activeRules),
		ConnectionCount: int(m.connCount.Load()),
	}
}

// IngressCapabilities returns capability metadata for registration.
// Returns nil when ingress is not enabled.
func (m *IngressManager) IngressCapabilities() map[string]string {
	if !m.cfg.IngressEnabled {
		return nil
	}
	return map[string]string{
		"ingress":           "true",
		"max_ingress_rules": strconv.Itoa(m.cfg.MaxIngressRules),
	}
}
