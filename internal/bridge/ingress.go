package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// lowPortHint is logged with a listen failure that a missing
// CAP_NET_BIND_SERVICE explains.
const lowPortHint = "ports below 1024 need CAP_NET_BIND_SERVICE"

// The reasons a connection is closed without reaching a target.
const (
	connReasonNoClientHello = "no_client_hello"
	connReasonNoServerName  = "no_server_name"
	connReasonNoMatch       = "no_matching_rule"
	connReasonNotServed     = "rule_not_served"
)

// ingressListener is the one TCP listener of a listen port and the table its
// accept loop routes by.
type ingressListener struct {
	port  int
	ln    net.Listener
	table atomic.Pointer[ingressTable]
	done  chan struct{} // closed when the accept loop exits
}

// notServedKey identifies a "rule not served" line already logged.
type notServedKey struct {
	rule   api.IngressRule
	reason string
}

// IngressManager serves public ingress: one TCP listener per listen port of the
// bridge.ingress block, routing each connection to the target of its rule.
// IngressManager is concurrent-safe via mu.
type IngressManager struct {
	ctrl        IngressController
	cfg         Config
	logger      *slog.Logger
	dialTimeout time.Duration
	peekTimeout time.Duration
	acme        *ACMEManager // optional, may be nil

	// mu protects the fields below from concurrent access by the reconcile
	// loop and status readers.
	mu sync.Mutex

	active bool
	// ctx is the parent of every route's context and is cancelled by
	// Teardown, which closes every connection, also one still in its peek.
	ctx       context.Context
	cancel    context.CancelFunc
	listeners map[int]*ingressListener
	states    []IngressRuleState
	held      map[string]api.IngressRule // the held rules of the last Apply, by id
	heldOrder []string                   // their ids, in block order
	notServed map[notServedKey]struct{}  // the "rule not served" lines of the last Apply

	connCount atomic.Int64 // connections from accept to close, across all ports
}

// NewIngressManager creates a new IngressManager.
// The acme parameter is optional and may be nil.
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger, acme *ACMEManager) *IngressManager {
	return &IngressManager{
		ctrl:        ctrl,
		cfg:         cfg,
		logger:      logger,
		dialTimeout: cfg.IngressDialTimeout,
		peekTimeout: sniPeekTimeout,
		acme:        acme,
		listeners:   make(map[int]*ingressListener),
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
	m.ctx, m.cancel = context.WithCancel(context.Background())

	m.logger.Info("ingress manager started",
		"component", "bridge",
		"max_rules", m.cfg.MaxIngressRules,
		"dial_timeout", m.dialTimeout.String(),
	)

	return nil
}

// Teardown cancels every route, which closes every connection, and closes
// every listener. Errors are aggregated; cleanup continues past a failed
// close. Idempotent: calling Teardown when inactive returns nil.
func (m *IngressManager) Teardown() error {
	m.mu.Lock()

	if !m.active {
		m.mu.Unlock()
		return nil
	}

	m.cancel()
	var errs []error
	closed := m.sortedListeners()
	for _, l := range closed {
		if err := m.closeListener(l); err != nil {
			errs = append(errs, fmt.Errorf("bridge: ingress: close listener %d: %w", l.port, err))
		}
	}

	m.active = false
	m.listeners = make(map[int]*ingressListener)
	m.states = nil
	m.held = nil
	m.heldOrder = nil
	m.notServed = nil
	m.mu.Unlock()

	// Wait for the accept loops outside the lock.
	for _, l := range closed {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port)
	}

	if len(errs) == 0 {
		m.logger.Info("ingress manager stopped",
			"component", "bridge",
		)
	}

	return errors.Join(errs...)
}

// Apply makes the manager serve exactly the given rules.
//
// It plans the block, opens a listener for each port in the plan that has
// none, swaps the routing table of every other port in place, and closes the
// listeners of ports the plan no longer names. A route whose rule is unchanged
// keeps its context and its connections; every other route of the last Apply
// is cancelled, which closes its connections. A failed bind marks the port's
// rules listen_failed and is retried by the next Apply; the other ports are
// served. The result joins the bind errors and is nil when there are none.
func (m *IngressManager) Apply(rules []api.IngressRule) error {
	m.mu.Lock()

	if !m.active {
		m.mu.Unlock()
		return errors.New("bridge: ingress: manager is not active")
	}

	plan := planIngress(rules, m.cfg.MaxIngressRules)

	// Carry the routes of unchanged rules over, with their contexts, and give
	// every other planned route a new one.
	current := make(map[string]*ingressRoute)
	for _, l := range m.listeners {
		for _, r := range l.table.Load().routes() {
			current[r.rule.ID] = r
		}
	}
	carried := make(map[*ingressRoute]struct{})
	for _, t := range plan.tables {
		for _, r := range t.routes() {
			if old, ok := current[r.rule.ID]; ok && old.rule == r.rule {
				r.ctx, r.cancel = old.ctx, old.cancel
				carried[old] = struct{}{}
				continue
			}
			r.ctx, r.cancel = context.WithCancel(m.ctx)
		}
	}
	for _, old := range current {
		if _, ok := carried[old]; !ok {
			old.cancel()
		}
	}

	var errs []error
	failed := make(map[int]struct{})
	for _, port := range slices.Sorted(maps.Keys(plan.tables)) {
		t := plan.tables[port]
		if l, ok := m.listeners[port]; ok {
			l.table.Store(t)
			continue
		}
		addr := ":" + strconv.Itoa(port)
		ln, err := m.ctrl.Listen(addr, nil)
		if err != nil {
			failed[port] = struct{}{}
			for _, r := range t.routes() {
				r.cancel()
			}
			attrs := []any{"component", "bridge", "listen_port", port, "error", err}
			if port < 1024 && errors.Is(err, fs.ErrPermission) {
				attrs = append(attrs, "hint", lowPortHint)
			}
			m.logger.Error("bridge: ingress: listen failed", attrs...)
			errs = append(errs, fmt.Errorf("bridge: ingress: listen on %s: %w", addr, err))
			continue
		}
		l := &ingressListener{port: port, ln: ln, done: make(chan struct{})}
		l.table.Store(t)
		m.listeners[port] = l
		go m.acceptLoop(m.ctx, l)
		m.logger.Info("ingress listener opened", "component", "bridge", "listen_port", port)
	}

	var closed []*ingressListener
	for _, l := range m.sortedListeners() {
		if _, ok := plan.tables[l.port]; ok {
			continue
		}
		delete(m.listeners, l.port)
		if err := m.closeListener(l); err != nil {
			m.logger.Error("bridge: ingress: close listener failed",
				"component", "bridge",
				"listen_port", l.port,
				"error", err,
			)
		}
		closed = append(closed, l)
	}

	for i := range plan.states {
		st := &plan.states[i]
		if _, ok := failed[st.Rule.ListenPort]; ok && st.Served {
			st.Served = false
			st.Reason = IngressReasonListenFailed
		}
	}
	m.logRuleChanges(plan.states)
	m.states = plan.states
	m.mu.Unlock()

	// Wait for the accept loops of closed listeners outside the lock.
	for _, l := range closed {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port)
	}

	return errors.Join(errs...)
}

// logRuleChanges logs the held rules that were added, updated or removed
// since the last Apply, and each rule not served whose value or reason
// changed since then. The caller holds mu.
func (m *IngressManager) logRuleChanges(states []IngressRuleState) {
	held := make(map[string]api.IngressRule)
	var order []string
	notServed := make(map[notServedKey]struct{})

	for _, st := range states {
		r := st.Rule
		if st.Served || st.Reason == IngressReasonModeNotServed || st.Reason == IngressReasonListenFailed {
			held[r.ID] = r
			order = append(order, r.ID)
			if old, ok := m.held[r.ID]; !ok {
				m.logRule("ingress rule added", r)
			} else if old != r {
				m.logRule("ingress rule updated", r)
			}
		}
		if st.Reason == "" {
			continue
		}
		key := notServedKey{rule: r, reason: st.Reason}
		notServed[key] = struct{}{}
		if _, ok := m.notServed[key]; ok {
			continue
		}
		m.logger.Warn("ingress rule not served",
			"component", "bridge",
			"rule_id", r.ID,
			"slug", r.Slug,
			"listen_port", r.ListenPort,
			"reason", st.Reason,
			"detail", st.Detail,
		)
	}
	for _, id := range m.heldOrder {
		if _, ok := held[id]; !ok {
			m.logRule("ingress rule removed", m.held[id])
		}
	}

	m.held = held
	m.heldOrder = order
	m.notServed = notServed
}

func (m *IngressManager) logRule(msg string, r api.IngressRule) {
	m.logger.Info(msg,
		"component", "bridge",
		"rule_id", r.ID,
		"slug", r.Slug,
		"listen_port", r.ListenPort,
		"mode", r.Mode,
		"sni_host", r.SNIHost,
		"target", net.JoinHostPort(r.TargetAddress, strconv.Itoa(r.TargetPort)),
	)
}

// sortedListeners returns the listeners by port. The caller holds mu.
func (m *IngressManager) sortedListeners() []*ingressListener {
	out := make([]*ingressListener, 0, len(m.listeners))
	for _, port := range slices.Sorted(maps.Keys(m.listeners)) {
		out = append(out, m.listeners[port])
	}
	return out
}

// closeListener closes a listener through the controller. When the controller
// fails, the listener is closed directly, so its accept loop ends and the port
// is dropped either way; the controller's error is returned.
func (m *IngressManager) closeListener(l *ingressListener) error {
	err := m.ctrl.Close(l.ln)
	if err != nil {
		_ = l.ln.Close()
	}
	return err
}

// RuleStates returns the outcome of the last Apply, one entry per rule.
func (m *IngressManager) RuleStates() []IngressRuleState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.states)
}

// acceptLoop accepts the connections of one listener until it is closed.
func (m *IngressManager) acceptLoop(ctx context.Context, l *ingressListener) {
	defer close(l.done)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		m.connCount.Add(1)
		go m.serveConn(ctx, l, conn)
	}
}

// serveConn routes one connection by the table its port holds now: to the
// plain rule without reading, or by the server name of its ClientHello.
func (m *IngressManager) serveConn(ctx context.Context, l *ingressListener, conn net.Conn) {
	defer m.connCount.Add(-1)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	table := l.table.Load()
	route := table.plain
	var peeked []byte
	if route == nil {
		name, p, err := peekClientHello(conn, m.peekTimeout)
		var reason string
		switch {
		case err != nil:
			reason = connReasonNoClientHello
		case name == "":
			reason = connReasonNoServerName
		default:
			route = table.match(name)
			switch {
			case route == nil:
				reason = connReasonNoMatch
			case !route.served:
				reason = connReasonNotServed
			}
		}
		if reason != "" {
			m.logger.Debug("ingress connection closed",
				"component", "bridge",
				"listen_port", l.port,
				"remote", conn.RemoteAddr().String(),
				"server_name", name,
				"reason", reason,
			)
			return
		}
		peeked = p
	}

	m.proxy(route, conn, peeked)
}

// proxy dials the route's target, replays the peeked bytes to it, and copies
// both ways until one side ends or the route is cancelled.
func (m *IngressManager) proxy(route *ingressRoute, client net.Conn, peeked []byte) {
	dialer := net.Dialer{Timeout: m.dialTimeout}
	target, err := dialer.DialContext(route.ctx, "tcp", route.target)
	if err != nil {
		m.logger.Error("bridge: ingress: dial target failed",
			"component", "bridge",
			"rule_id", route.rule.ID,
			"slug", route.rule.Slug,
			"target", route.target,
			"error", err,
		)
		return
	}

	var src io.Reader = client
	if len(peeked) > 0 {
		src = newPeekConn(client, peeked)
	}

	clientToTarget := make(chan struct{})
	go func() {
		defer close(clientToTarget)
		_, _ = io.Copy(target, src)
	}()
	targetToClient := make(chan struct{})
	go func() {
		defer close(targetToClient)
		_, _ = io.Copy(client, target)
	}()

	select {
	case <-route.ctx.Done():
	case <-clientToTarget:
	case <-targetToClient:
	}
	_ = target.Close()
	_ = client.Close()
	<-clientToTarget
	<-targetToClient
}

// IngressStatus returns ingress status for heartbeat reporting.
// Returns nil when ingress is not active.
func (m *IngressManager) IngressStatus() *api.IngressInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}
	served := 0
	for _, st := range m.states {
		if st.Served {
			served++
		}
	}
	return &api.IngressInfo{
		Enabled:         true,
		RuleCount:       served,
		ConnectionCount: int(m.connCount.Load()),
		ACMEEnabled:     m.acme != nil,
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
