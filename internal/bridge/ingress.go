package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/plexsphere/plexd/internal/api"
)

// lowPortHint is logged with a listen failure that a missing
// CAP_NET_BIND_SERVICE explains.
const lowPortHint = "ports below 1024 need CAP_NET_BIND_SERVICE"

// ingressHandshakeTimeout bounds the TLS handshake the bridge completes for a
// terminating rule or an ACME challenge, from its start after the ClientHello
// peek to its end. A connection deadline bounds the handshake's reads and
// writes, and the handshake's context bounds the wait for the certificate of
// an acme rule or a challenge, which autocert may spend on an issuance (see
// boundedGetCertificate). An issuance that outlasts it fails that client with
// tls_handshake_failed and continues inside autocert. The bound ends with a
// handshake that succeeded: the plaintext copy that follows has no deadline.
const ingressHandshakeTimeout = 10 * time.Second

// The reasons a connection is closed without reaching a target.
const (
	connReasonNoClientHello      = "no_client_hello"
	connReasonNoServerName       = "no_server_name"
	connReasonNoMatch            = "no_matching_rule"
	connReasonNotServed          = "rule_not_served"
	connReasonNoCertificate      = "no_certificate"
	connReasonTLSHandshakeFailed = "tls_handshake_failed"
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
// A passthrough rule's connection is forwarded unread; a terminate or acme
// rule's connection ends TLS at the bridge, and the plaintext goes to the
// target. IngressManager is concurrent-safe via mu.
type IngressManager struct {
	ctrl             IngressController
	cfg              Config
	logger           *slog.Logger
	dialTimeout      time.Duration
	peekTimeout      time.Duration
	handshakeTimeout time.Duration
	acme             *ACMEManager
	fetcher          CertificateSecretFetcher
	now              func() time.Time

	// mu protects the fields below from concurrent access by the reconcile
	// loop, the connections and status readers.
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
	// inventory is the last secret inventory, version by Secret name; nil
	// until the first SyncSecretInventory.
	inventory map[string]int
	certs     map[string]*certEntry    // by the Secret name a held terminate rule names
	coverage  map[coverageKey]struct{} // the hosts checked against a loaded certificate

	connCount atomic.Int64 // connections from accept to close, across all ports

	// changed carries ReportChanged's signal; capacity 1.
	changed chan struct{}
}

// NewIngressManager creates a new IngressManager. acme holds the account of
// the block's acme rules and certs fetches the certificates of its terminate
// rules; neither may be nil. The manager registers with acme to signal
// ReportChanged when a host's certificate is issued or lost.
func NewIngressManager(ctrl IngressController, cfg Config, logger *slog.Logger, acme *ACMEManager, certs CertificateSecretFetcher) *IngressManager {
	m := &IngressManager{
		ctrl:             ctrl,
		cfg:              cfg,
		logger:           logger,
		dialTimeout:      cfg.IngressDialTimeout,
		peekTimeout:      sniPeekTimeout,
		handshakeTimeout: ingressHandshakeTimeout,
		acme:             acme,
		fetcher:          certs,
		now:              time.Now,
		listeners:        make(map[int]*ingressListener),
		certs:            make(map[string]*certEntry),
		changed:          make(chan struct{}, 1),
	}
	acme.OnIssuedChange(m.signalReport)
	return m
}

// Setup initializes the ingress manager.
// It is a no-op when the node opts out of public ingress.
func (m *IngressManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.IngressOptedOut() {
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

// Teardown cancels every route, which closes every connection, closes every
// listener, and forgets the secret inventory and every certificate. Errors are
// aggregated; cleanup continues past a failed close. Idempotent: calling
// Teardown when inactive returns nil.
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
	m.inventory = nil
	m.certs = make(map[string]*certEntry)
	m.coverage = nil
	m.signalReport()
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

// Apply makes the manager serve exactly the rules of block.
//
// It checks the block's acme member against bridge.acme_directory_urls,
// plans the block, and forgets the certificates of Secrets no held rule names
// any more. It then opens a listener for each port in the plan that has none,
// swaps the routing table of every other port in place, and closes the
// listeners of ports the plan no longer names. A route whose rule is unchanged
// keeps its context and its connections; every other route of the last Apply
// is cancelled, which closes its connections. A failed bind marks the port's
// rules listen_failed and is retried by the next Apply; the other ports are
// served. After the binds it configures the ACME account with the hosts of
// the acme rules that have no reason, which retires it when there are none,
// so an acme rule whose port failed to bind asks the CA for nothing. Last, it
// loads the certificates of the held terminate rules. The result joins the
// bind errors and is nil when there are none.
func (m *IngressManager) Apply(ctx context.Context, block api.IngressConfig) error {
	m.mu.Lock()

	if !m.active {
		m.mu.Unlock()
		return errors.New("bridge: ingress: manager is not active")
	}

	plan := planIngress(block.Rules, m.cfg.MaxIngressRules, checkACMEDirectory(block.ACME, m.cfg.ACMEDirectoryURLs))

	named := make(map[string]struct{})
	for _, st := range plan.states {
		if st.held && st.Rule.Mode == api.IngressModeTerminate {
			named[st.Rule.CertificateSecretName] = struct{}{}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.certs)) {
		if _, ok := named[name]; ok {
			continue
		}
		if e := m.certs[name]; e.cert != nil {
			m.logger.Info("ingress certificate dropped",
				"component", "bridge",
				"secret", name,
				"version", e.version,
				"reason", certDroppedRuleRemoved,
			)
		}
		delete(m.certs, name)
	}

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

	// Configured after the binds: a rule that reads listen_failed now has a
	// reason, so its host is not asked for.
	var acmeHosts []string
	for _, st := range plan.states {
		if st.held && st.Rule.Mode == api.IngressModeACME && st.Reason == "" {
			acmeHosts = append(acmeHosts, strings.ToLower(st.Rule.SNIHost))
		}
	}
	m.acme.Configure(block.ACME, acmeHosts)

	m.logRuleChanges(plan.states)
	m.states = plan.states
	m.signalReport()
	m.mu.Unlock()

	// Wait for the accept loops of closed listeners outside the lock.
	for _, l := range closed {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port)
	}

	m.loadCertificates(ctx)

	return errors.Join(errs...)
}

// logRuleChanges logs the held rules that were added, updated or removed
// since the last Apply, and each rule not served whose value or reason
// changed since then. The certificate state of a terminate rule is logged by
// loadCertificates. The caller holds mu.
func (m *IngressManager) logRuleChanges(states []IngressRuleState) {
	held := make(map[string]api.IngressRule)
	var order []string
	notServed := make(map[notServedKey]struct{})

	for _, st := range states {
		r := st.Rule
		if st.held {
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

// RuleStates returns the outcome of the last Apply, one entry per rule. A held
// terminate rule reads Served exactly when its Secret's certificate is loaded.
func (m *IngressManager) RuleStates() []IngressRuleState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.overlayCertificatesLocked()
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
// plain rule without reading, or by the server name of its ClientHello. On
// port 443 a TLS-ALPN-01 challenge for the host of a served acme rule is
// answered in place, unless a rule of another mode routes the host. A
// passthrough rule's connection is forwarded with its ClientHello; a terminate
// or acme rule's connection completes a TLS handshake at the bridge, and its
// plaintext goes to the target.
func (m *IngressManager) serveConn(ctx context.Context, l *ingressListener, conn net.Conn) {
	defer m.connCount.Add(-1)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	table := l.table.Load()
	if table.plain != nil {
		m.proxy(table.plain, conn, nil)
		return
	}

	hello, peeked, err := peekClientHello(conn, m.peekTimeout)
	var route *ingressRoute
	var reason string
	switch {
	case err != nil:
		reason = connReasonNoClientHello
	case hello.ServerName == "":
		reason = connReasonNoServerName
	default:
		route = table.match(hello.ServerName)
		if l.port == acmeChallengePort && slices.Equal(hello.ALPN, []string{acme.ALPNProto}) &&
			(route == nil || route.rule.Mode == api.IngressModeACME) && m.acme.HasHost(hello.ServerName) {
			m.answerChallenge(ctx, conn, hello, peeked)
			return
		}
		switch {
		case route == nil:
			reason = connReasonNoMatch
		case !route.served:
			reason = connReasonNotServed
		}
	}
	if reason != "" {
		m.logClosed(l, conn, hello.ServerName, reason)
		return
	}

	var cfg *tls.Config
	switch route.rule.Mode {
	case api.IngressModePassthrough:
		m.proxy(route, conn, peeked)
		return
	case api.IngressModeTerminate:
		cert := m.certificateFor(route.rule.CertificateSecretName)
		if cert == nil {
			m.logClosed(l, conn, hello.ServerName, connReasonNoCertificate)
			return
		}
		// No NextProtos: the target gets plaintext, and a negotiated h2 would
		// hand it HTTP/2 frames it did not ask for.
		cfg = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	default: // api.IngressModeACME
		// No NextProtos either, for the same reason.
		cfg = &tls.Config{GetCertificate: boundedGetCertificate(m.acme.GetCertificate), MinVersion: tls.VersionTLS12}
	}
	tlsConn, err := m.handshake(ctx, conn, peeked, cfg)
	if err != nil {
		m.logClosed(l, conn, hello.ServerName, connReasonTLSHandshakeFailed)
		return
	}
	m.proxy(route, tlsConn, nil)
}

// answerChallenge completes the TLS-ALPN-01 handshake of a CA with the
// challenge certificate of the ACME account and closes the connection. It has
// its own tls.Config: a server that offers only acme-tls/1 fails the handshake
// of any other client. autocert answers a challenge hello from memory or its
// cache; the certificate wait is bounded like an acme rule's all the same.
func (m *IngressManager) answerChallenge(ctx context.Context, conn net.Conn, hello clientHello, peeked []byte) {
	tlsConn, err := m.handshake(ctx, conn, peeked, &tls.Config{
		GetCertificate: boundedGetCertificate(m.acme.GetCertificate),
		NextProtos:     []string{acme.ALPNProto},
		MinVersion:     tls.VersionTLS12,
	})
	m.logger.Debug("ingress acme challenge answered",
		"component", "bridge",
		"server_name", hello.ServerName,
		"remote", conn.RemoteAddr().String(),
		"error", err,
	)
	_ = tlsConn.Close()
}

// handshake completes a TLS handshake as the server over conn, replaying the
// peeked ClientHello, within the handshake timeout. The connection deadline
// bounds the handshake's reads and writes. The handshake runs under a context
// that ends at the same timeout, or with ctx: crypto/tls then closes conn and
// hands the context to GetCertificate as the hello's context, which
// boundedGetCertificate stops waiting at. A handshake that succeeded clears
// the deadline.
func (m *IngressManager) handshake(ctx context.Context, conn net.Conn, peeked []byte, cfg *tls.Config) (*tls.Conn, error) {
	tlsConn := tls.Server(newPeekConn(conn, peeked), cfg)
	if err := conn.SetDeadline(time.Now().Add(m.handshakeTimeout)); err != nil {
		return tlsConn, err
	}
	hctx, cancel := context.WithTimeout(ctx, m.handshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hctx); err != nil {
		return tlsConn, err
	}
	return tlsConn, conn.SetDeadline(time.Time{})
}

// boundedGetCertificate wraps get, a tls.Config.GetCertificate that can block
// for a whole issuance, so that it returns when the hello's context ends,
// which is the handshake's context. get runs in a goroutine of its own and
// finishes in the background: autocert completes the issuance, so a later
// handshake gets the certificate.
func boundedGetCertificate(get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	type result struct {
		cert *tls.Certificate
		err  error
	}
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		ctx := hello.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		done := make(chan result, 1)
		go func() {
			cert, err := get(hello)
			done <- result{cert: cert, err: err}
		}()
		select {
		case r := <-done:
			return r.cert, r.err
		case <-ctx.Done():
			return nil, fmt.Errorf("bridge: ingress: certificate not ready: %w", ctx.Err())
		}
	}
}

// logClosed logs a connection closed without reaching a target.
func (m *IngressManager) logClosed(l *ingressListener, conn net.Conn, serverName, reason string) {
	m.logger.Debug("ingress connection closed",
		"component", "bridge",
		"listen_port", l.port,
		"remote", conn.RemoteAddr().String(),
		"server_name", serverName,
		"reason", reason,
	)
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
	for _, st := range m.overlayCertificatesLocked() {
		if st.Served {
			served++
		}
	}
	return &api.IngressInfo{
		Enabled:         true,
		RuleCount:       served,
		ConnectionCount: int(m.connCount.Load()),
		ACMEEnabled:     m.acme.Active(),
	}
}

// IngressCapabilities returns capability metadata for registration.
// Returns nil when the node opts out of public ingress.
func (m *IngressManager) IngressCapabilities() map[string]string {
	if m.cfg.IngressOptedOut() {
		return nil
	}
	return map[string]string{
		"ingress":           "true",
		"max_ingress_rules": strconv.Itoa(m.cfg.MaxIngressRules),
	}
}
