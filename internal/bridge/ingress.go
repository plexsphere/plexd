package bridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
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
	// http is where serveConn hands the handshaken connections of a host
	// whose rules have conditions: the queue of the manager's HTTP server.
	http *ingressConnQueue
}

// notServedKey identifies a "rule not served" line already logged. It holds
// the rule as its JSON, since a rule with header conditions is no map key.
type notServedKey struct {
	rule   string
	reason string
}

// newNotServedKey returns the key of a "rule not served" line for r.
func newNotServedKey(r api.IngressRule, reason string) notServedKey {
	data, _ := json.Marshal(r)
	return notServedKey{rule: string(data), reason: reason}
}

// IngressManager serves public ingress: one TCP listener per listen port of the
// tcp rules of the bridge.ingress block, routing each connection to the target
// of its rule, and one UDP socket per listen port of its udp rules, forwarding
// the datagrams of each client address and port on a flow of their own (see
// serveUDP). A passthrough rule's connection is forwarded unread; a terminate
// or acme rule's connection ends TLS at the bridge, and the plaintext goes to
// the target. On a host whose terminate or acme rules have request
// conditions, one HTTP server reads each request and forwards it to the
// target of the rule it matches (see serveHTTP). IngressManager is
// concurrent-safe via mu.
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
	// dial, nil in production, replaces the dial of a rule's target in tests.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// dialPolicy names a failed dial policy_denied; set before Setup, nil
	// without one.
	dialPolicy IngressDialPolicy
	// maxUDPFlows is the most flows one udp rule holds.
	maxUDPFlows int
	// udpUnansweredTimeout and udpAnsweredTimeout close a flow after that long
	// without a datagram in either direction, before and after the target
	// answered; tests shorten them.
	udpUnansweredTimeout time.Duration
	udpAnsweredTimeout   time.Duration
	// openUDP, nil in production, replaces openUDPFlowConn in tests.
	openUDP func(target netip.AddrPort) (udpFlowConn, error)
	// httpReadHeaderTimeout and httpIdleTimeout are the HTTP server's
	// ReadHeaderTimeout and IdleTimeout; tests shorten them before Setup.
	httpReadHeaderTimeout time.Duration
	httpIdleTimeout       time.Duration

	// mu protects the fields below from concurrent access by the reconcile
	// loop, the connections and status readers.
	mu sync.Mutex

	active bool
	// ctx is the parent of every route's context and is cancelled by
	// Teardown, which closes every connection, also one still in its peek.
	ctx       context.Context
	cancel    context.CancelFunc
	listeners map[int]*ingressListener
	udp       map[int]*udpIngressListener // the UDP socket of each udp listen port
	states    []IngressRuleState
	held      map[string]api.IngressRule // the held rules of the last Apply, by id
	heldOrder []string                   // their ids, in block order
	notServed map[notServedKey]struct{}  // the "rule not served" lines of the last Apply
	// inventory is the last secret inventory, version by Secret name; nil
	// until the first SyncSecretInventory.
	inventory map[string]int
	certs     map[string]*certEntry    // by the Secret name a held terminate rule names
	coverage  map[coverageKey]struct{} // the hosts checked against a loaded certificate
	dials     map[string]dialRecord    // the last dial of each held rule, by rule id
	// httpSrv reads the requests of every host whose rules have conditions,
	// from the connections serveConn pushes to httpConns; httpDone is closed
	// when its Serve returns. All three are set between Setup and Teardown.
	httpSrv   *http.Server
	httpConns *ingressConnQueue
	httpDone  chan struct{}

	// connCount counts the connections from accept to close and the udp flows
	// from open to close, across all ports.
	connCount atomic.Int64

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
		maxUDPFlows:      cfg.MaxIngressUDPFlows,
		listeners:        make(map[int]*ingressListener),
		udp:              make(map[int]*udpIngressListener),
		certs:            make(map[string]*certEntry),
		dials:            make(map[string]dialRecord),
		changed:          make(chan struct{}, 1),

		udpUnansweredTimeout: ingressUDPUnansweredTimeout,
		udpAnsweredTimeout:   ingressUDPAnsweredTimeout,

		httpReadHeaderTimeout: ingressHTTPReadHeaderTimeout,
		httpIdleTimeout:       ingressHTTPIdleTimeout,
	}
	acme.OnIssuedChange(m.signalReport)
	return m
}

// Setup initializes the ingress manager and starts the HTTP server that
// reads the requests of a host whose rules have conditions. It is a no-op
// when the node opts out of public ingress.
func (m *IngressManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.IngressOptedOut() {
		return nil
	}

	m.active = true
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.httpConns = newIngressConnQueue()
	m.httpSrv = m.newHTTPServer()
	m.httpDone = make(chan struct{})
	go func(srv *http.Server, conns *ingressConnQueue, done chan<- struct{}) {
		defer close(done)
		_ = srv.Serve(conns)
	}(m.httpSrv, m.httpConns, m.httpDone)

	m.logger.Info("ingress manager started",
		"component", "bridge",
		"max_rules", m.cfg.MaxIngressRules,
		"max_udp_flows", m.maxUDPFlows,
		"dial_timeout", m.dialTimeout.String(),
	)

	return nil
}

// Teardown cancels every route and host, which closes every connection and
// every udp flow, closes every listener and UDP socket and the HTTP server,
// and forgets the secret inventory and every certificate. It returns once
// every accept loop, read loop and reply loop has ended and the HTTP server's
// Serve has returned. Errors are aggregated; cleanup continues past a failed
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
	closedUDP := m.sortedUDPListeners()
	for _, l := range closedUDP {
		closeUDPListener(l)
	}

	m.active = false
	m.listeners = make(map[int]*ingressListener)
	m.udp = make(map[int]*udpIngressListener)
	m.states = nil
	m.held = nil
	m.heldOrder = nil
	m.notServed = nil
	m.inventory = nil
	m.certs = make(map[string]*certEntry)
	m.coverage = nil
	m.dials = make(map[string]dialRecord)
	httpSrv, httpDone := m.httpSrv, m.httpDone
	m.httpSrv, m.httpConns, m.httpDone = nil, nil, nil
	m.signalReport()
	m.mu.Unlock()

	// Close closes the queue the server accepts from and every connection it
	// tracks; an upgraded connection closes with the manager's context.
	_ = httpSrv.Close()
	<-httpDone

	// Wait for the accept loops and the read loops outside the lock: a read
	// loop takes mu to record a dial.
	for _, l := range closed {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port, "protocol", api.IngressProtocolTCP)
	}
	for _, l := range closedUDP {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port, "protocol", api.IngressProtocolUDP)
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
// any more. It then opens a listener for each TCP port in the plan that has
// none, swaps the routing table of every other port in place, and closes the
// listeners of ports the plan no longer names. It does the same for the UDP
// socket of each udp port, in ascending order, swapping the port's route in
// place. A route whose rule is unchanged keeps its context and its connections
// or flows, and a route with conditions its proxy and target connections;
// every other route of the last Apply is cancelled, which closes its
// connections, flows and requests in flight. A host whose rules have
// conditions keeps its client connections while the port's table holds the
// host under the same key with conditions, the same mode and the same
// certificate_secret_name; every other such host is cancelled, which closes
// them. A failed bind marks the rules of that port and
// protocol listen_failed and is retried by the next Apply; the other ports,
// and the other protocol on the same port number, are served. After the binds
// it configures the ACME account with the hosts of the acme rules that have
// no reason, which retires it when there are none, so an acme rule whose port
// failed to bind asks the CA for nothing. Last, it loads the certificates of
// the held terminate rules. The result joins the bind errors and is nil when
// there are none.
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
	for _, l := range m.udp {
		r := l.route.Load()
		current[r.rule.ID] = r
	}
	carried := make(map[*ingressRoute]struct{})
	carry := func(r *ingressRoute) {
		if old, ok := current[r.rule.ID]; ok && old.rule.Equal(r.rule) {
			r.ctx, r.cancel, r.proxy = old.ctx, old.cancel, old.proxy
			carried[old] = struct{}{}
			return
		}
		r.ctx, r.cancel = context.WithCancel(m.ctx)
		if !r.rule.Conditions.IsZero() {
			r.proxy = m.newRouteProxy(r)
		}
	}
	for _, t := range plan.tables {
		for _, r := range t.routes() {
			carry(r)
		}
	}
	for _, r := range plan.udp {
		carry(r)
	}
	for _, old := range current {
		if _, ok := carried[old]; !ok {
			old.cancel()
		}
	}

	// Carry the contexts of the hosts with conditions whose TLS stays the
	// same, so their client connections stay open, and cancel the others.
	takenOver := make(map[*ingressHost]struct{})
	carryHost := func(h, old *ingressHost) {
		if !h.http {
			return
		}
		if old != nil && old.http && sameTermination(old.lead().rule, h.lead().rule) {
			h.ctx, h.cancel = old.ctx, old.cancel
			takenOver[old] = struct{}{}
			return
		}
		h.ctx, h.cancel = context.WithCancel(m.ctx)
	}
	for port, t := range plan.tables {
		cur := newIngressTable()
		if l, ok := m.listeners[port]; ok {
			cur = l.table.Load()
		}
		for k, h := range t.exact {
			carryHost(h, cur.exact[k])
		}
		for k, h := range t.wildcard {
			carryHost(h, cur.wildcard[k])
		}
	}
	for _, l := range m.listeners {
		for _, old := range l.table.Load().hosts() {
			if _, ok := takenOver[old]; old.http && !ok {
				old.cancel()
			}
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
			for _, h := range t.hosts() {
				if h.http {
					h.cancel()
				}
			}
			m.logListenFailed(port, api.IngressProtocolTCP, err)
			errs = append(errs, fmt.Errorf("bridge: ingress: listen on %s: %w", addr, err))
			continue
		}
		l := &ingressListener{port: port, ln: ln, done: make(chan struct{}), http: m.httpConns}
		l.table.Store(t)
		m.listeners[port] = l
		go m.acceptLoop(m.ctx, l)
		m.logger.Info("ingress listener opened", "component", "bridge", "listen_port", port, "protocol", api.IngressProtocolTCP)
	}

	// The failed binds are kept per protocol: a tcp and a udp rule on one
	// port number bind sockets of their own.
	failedUDP := make(map[int]struct{})
	for _, port := range slices.Sorted(maps.Keys(plan.udp)) {
		route := plan.udp[port]
		if l, ok := m.udp[port]; ok {
			l.route.Store(route)
			continue
		}
		addr := ":" + strconv.Itoa(port)
		conn, err := m.ctrl.ListenUDP(addr)
		if err != nil {
			failedUDP[port] = struct{}{}
			route.cancel()
			m.logListenFailed(port, api.IngressProtocolUDP, err)
			errs = append(errs, fmt.Errorf("bridge: ingress: listen on udp %s: %w", addr, err))
			continue
		}
		l := newUDPIngressListener(port, conn)
		l.route.Store(route)
		m.udp[port] = l
		go m.serveUDP(l)
		m.logger.Info("ingress listener opened", "component", "bridge", "listen_port", port, "protocol", api.IngressProtocolUDP)
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
	var closedUDP []*udpIngressListener
	for _, l := range m.sortedUDPListeners() {
		if _, ok := plan.udp[l.port]; ok {
			continue
		}
		delete(m.udp, l.port)
		closeUDPListener(l)
		closedUDP = append(closedUDP, l)
	}

	for i := range plan.states {
		st := &plan.states[i]
		failedPorts := failed
		if st.Rule.Protocol == api.IngressProtocolUDP {
			failedPorts = failedUDP
		}
		if _, ok := failedPorts[st.Rule.ListenPort]; ok && st.Served {
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
	// Only a held rule has a route that dials, so the records stay within
	// bridge.max_ingress_rules.
	for id := range m.dials {
		if _, ok := m.held[id]; !ok {
			delete(m.dials, id)
		}
	}
	m.signalReport()
	m.mu.Unlock()

	// Wait for the accept loops of closed listeners and the read loops of
	// closed UDP sockets outside the lock: a read loop takes mu to record a
	// dial.
	for _, l := range closed {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port, "protocol", api.IngressProtocolTCP)
	}
	for _, l := range closedUDP {
		<-l.done
		m.logger.Info("ingress listener closed", "component", "bridge", "listen_port", l.port, "protocol", api.IngressProtocolUDP)
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
			} else if !old.Equal(r) {
				m.logRule("ingress rule updated", r)
			}
		}
		if st.Reason == "" {
			continue
		}
		key := newNotServedKey(r, st.Reason)
		notServed[key] = struct{}{}
		if _, ok := m.notServed[key]; ok {
			continue
		}
		m.logger.Warn("ingress rule not served",
			"component", "bridge",
			"rule_id", r.ID,
			"slug", r.Slug,
			"protocol", r.Protocol,
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

// logRule logs a held rule. Of its header conditions it logs the names, never
// a value: a value can be a routing token.
func (m *IngressManager) logRule(msg string, r api.IngressRule) {
	names := make([]string, len(r.Conditions.Headers))
	for i, h := range r.Conditions.Headers {
		names[i] = h.Name
	}
	m.logger.Info(msg,
		"component", "bridge",
		"rule_id", r.ID,
		"slug", r.Slug,
		"protocol", r.Protocol,
		"listen_port", r.ListenPort,
		"mode", r.Mode,
		"sni_host", r.SNIHost,
		"target", net.JoinHostPort(r.TargetAddress, strconv.Itoa(r.TargetPort)),
		"path_prefix", r.Conditions.PathPrefix,
		"header_names", strings.Join(names, ","),
		"strip_path_prefix", r.StripPathPrefix,
	)
}

// sameTermination reports whether two rules end TLS alike: the same mode
// and, on terminate, the same certificate_secret_name.
func sameTermination(a, b api.IngressRule) bool {
	return a.Mode == b.Mode && a.CertificateSecretName == b.CertificateSecretName
}

// logListenFailed logs a failed bind of port for protocol, tcp or udp, with
// the hint that a missing CAP_NET_BIND_SERVICE explains a permission error
// below 1024, which covers both protocols.
func (m *IngressManager) logListenFailed(port int, protocol string, err error) {
	attrs := []any{"component", "bridge", "listen_port", port, "protocol", protocol, "error", err}
	if port < 1024 && errors.Is(err, fs.ErrPermission) {
		attrs = append(attrs, "hint", lowPortHint)
	}
	m.logger.Error("bridge: ingress: listen failed", attrs...)
}

// sortedListeners returns the listeners by port. The caller holds mu.
func (m *IngressManager) sortedListeners() []*ingressListener {
	out := make([]*ingressListener, 0, len(m.listeners))
	for _, port := range slices.Sorted(maps.Keys(m.listeners)) {
		out = append(out, m.listeners[port])
	}
	return out
}

// sortedUDPListeners returns the UDP sockets by port. The caller holds mu.
func (m *IngressManager) sortedUDPListeners() []*udpIngressListener {
	out := make([]*udpIngressListener, 0, len(m.udp))
	for _, port := range slices.Sorted(maps.Keys(m.udp)) {
		out = append(out, m.udp[port])
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
// or acme rule's connection completes a TLS handshake at the bridge. Without
// conditions its plaintext goes to the target, and the handshake offers no
// ALPN protocol. On a host whose rules have conditions the handshake offers h2
// and http/1.1, and the connection goes to the HTTP server, which closes it
// and counts it out of connCount from then on.
func (m *IngressManager) serveConn(ctx context.Context, l *ingressListener, conn net.Conn) {
	owned := true // false once an ingressHTTPConn closes conn
	defer func() {
		if owned {
			_ = conn.Close()
			m.connCount.Add(-1)
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	table := l.table.Load()
	if table.plain != nil {
		m.proxy(table.plain, conn, nil)
		return
	}

	hello, peeked, err := peekClientHello(conn, m.peekTimeout)
	var host *ingressHost
	var route *ingressRoute
	var reason string
	switch {
	case err != nil:
		reason = connReasonNoClientHello
	case hello.ServerName == "":
		reason = connReasonNoServerName
	default:
		// A host's rules share their mode, Secret and served state, so its
		// lead route decides the connection.
		if host = table.match(hello.ServerName); host != nil {
			route = host.lead()
		}
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
		cfg = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	default: // api.IngressModeACME
		cfg = &tls.Config{GetCertificate: boundedGetCertificate(m.acme.GetCertificate), MinVersion: tls.VersionTLS12}
	}
	if host.http {
		cfg.NextProtos = []string{"h2", "http/1.1"}
		hc := m.newIngressHTTPConn(ctx, host.ctx, l, conn, peeked, hello.ServerName)
		owned = false
		// net/http serves HTTP/2 only on the *tls.Conn itself.
		tlsConn, err := m.handshake(ctx, hc, cfg)
		if err != nil {
			m.logClosed(l, conn, hello.ServerName, connReasonTLSHandshakeFailed)
			_ = hc.Close()
			return
		}
		l.http.push(tlsConn)
		return
	}
	// No NextProtos: the target gets plaintext, and a negotiated h2 would
	// hand it HTTP/2 frames it did not ask for.
	tlsConn, err := m.handshake(ctx, newPeekConn(conn, peeked), cfg)
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
	tlsConn, err := m.handshake(ctx, newPeekConn(conn, peeked), &tls.Config{
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

// handshake completes a TLS handshake as the server over conn, the
// connection tls.Server wraps, which replays the peeked ClientHello, within
// the handshake timeout. The connection deadline bounds the handshake's reads
// and writes. The handshake runs under a context that ends at the same
// timeout, or with ctx: crypto/tls then closes conn and hands the context to
// GetCertificate as the hello's context, which boundedGetCertificate stops
// waiting at. A handshake that succeeded clears the deadline.
func (m *IngressManager) handshake(ctx context.Context, conn net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	tlsConn := tls.Server(conn, cfg)
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

// proxy dials the route's target, records the dial's outcome, replays the
// peeked bytes to the target, and copies both ways until one side ends or the
// route is cancelled.
func (m *IngressManager) proxy(route *ingressRoute, client net.Conn, peeked []byte) {
	target, err := m.dialTarget(route)
	reason, _ := m.recordDial(route, err)
	if err != nil {
		m.logDialFailed(route, reason, err)
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

// logDialFailed logs a failed dial to route's target, with the reason
// recordDial gave it when it gave one.
func (m *IngressManager) logDialFailed(route *ingressRoute, reason string, err error) {
	attrs := []any{
		"component", "bridge",
		"rule_id", route.rule.ID,
		"slug", route.rule.Slug,
		"protocol", route.rule.Protocol,
		"target", route.target,
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	m.logger.Error("bridge: ingress: dial target failed", append(attrs, "error", err)...)
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
