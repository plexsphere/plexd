package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The limits of the HTTP server that reads the requests of a host whose rules
// have conditions, and of the connections to each rule's target. A request
// body and a response have no size or time bound, as a forwarded connection
// has none.
const (
	// ingressHTTPReadHeaderTimeout bounds the read of a request header.
	ingressHTTPReadHeaderTimeout = 10 * time.Second
	// ingressHTTPIdleTimeout closes a client connection that carries no
	// request for that long.
	ingressHTTPIdleTimeout = 120 * time.Second
	// ingressHTTPMaxHeaderBytes bounds a request header; a larger one gets
	// 431 from net/http.
	ingressHTTPMaxHeaderBytes = 64 << 10
	// ingressTargetMaxIdleConns is the most idle connections a rule keeps to
	// its target.
	ingressTargetMaxIdleConns = 32
	// ingressTargetIdleConnTimeout closes an idle target connection.
	ingressTargetIdleConnTimeout = 90 * time.Second
)

// The reasons a request is answered by the bridge and not forwarded.
const (
	requestReasonMisdirected = "misdirected"
	requestReasonBadPath     = "bad_path"
	requestReasonNoMatch     = "no_matching_rule"
	requestReasonDialFailed  = "dial_failed"
	requestReasonTargetError = "target_error"
)

// ingressConnQueue is the net.Listener the manager's HTTP server accepts
// from: Accept returns the handshaken connections serveConn pushes. A push
// after Close closes the connection.
type ingressConnQueue struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newIngressConnQueue() *ingressConnQueue {
	return &ingressConnQueue{conns: make(chan net.Conn), done: make(chan struct{})}
}

// push hands conn to the server, or closes it once the queue is closed.
func (q *ingressConnQueue) push(conn net.Conn) {
	select {
	case <-q.done:
		_ = conn.Close()
		return
	default:
	}
	select {
	case q.conns <- conn:
	case <-q.done:
		_ = conn.Close()
	}
}

// Accept returns the next pushed connection, or net.ErrClosed once the queue
// is closed.
func (q *ingressConnQueue) Accept() (net.Conn, error) {
	select {
	case conn := <-q.conns:
		return conn, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

// Close closes the queue. It is idempotent.
func (q *ingressConnQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

// Addr returns a placeholder: the queue listens on no address.
func (q *ingressConnQueue) Addr() net.Addr {
	return ingressQueueAddr{}
}

type ingressQueueAddr struct{}

func (ingressQueueAddr) Network() string { return "ingress" }
func (ingressQueueAddr) String() string  { return "ingress" }

// ingressHTTPConn is a client connection of a host whose rules have
// conditions, the connection tls.Server wraps. It replays the peeked
// ClientHello and carries the listener and the server name the requests are
// routed by. It closes when the manager's context or the host's context is
// done. Close runs once: it closes the socket and counts the connection out
// of connCount. It never takes the manager's mu.
type ingressHTTPConn struct {
	net.Conn
	m          *IngressManager
	l          *ingressListener
	serverName string

	mu       sync.Mutex // orders the AfterFunc registration before a close
	stops    []func() bool
	once     sync.Once
	closeErr error
}

// newIngressHTTPConn wraps a client connection whose ClientHello was peeked.
// It takes over the close of conn and its count in connCount.
func (m *IngressManager) newIngressHTTPConn(ctx, hostCtx context.Context, l *ingressListener, conn net.Conn, peeked []byte, serverName string) *ingressHTTPConn {
	c := &ingressHTTPConn{Conn: newPeekConn(conn, peeked), m: m, l: l, serverName: serverName}
	c.mu.Lock()
	defer c.mu.Unlock()
	closeConn := func() { _ = c.Close() }
	c.stops = []func() bool{context.AfterFunc(ctx, closeConn), context.AfterFunc(hostCtx, closeConn)}
	return c
}

// Close closes the connection once and counts it out of connCount.
func (c *ingressHTTPConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		for _, stop := range c.stops {
			stop()
		}
		c.mu.Unlock()
		c.closeErr = c.Conn.Close()
		c.m.connCount.Add(-1)
	})
	return c.closeErr
}

// ingressConnKey is the request context key of the *ingressHTTPConn a
// request arrived on.
type ingressConnKey struct{}

// ingressDialError is the error of a failed dial to a rule's target, with
// the reason recordDial gave it.
type ingressDialError struct {
	reason string
	err    error
}

func (e *ingressDialError) Error() string { return e.err.Error() }
func (e *ingressDialError) Unwrap() error { return e.err }

// newHTTPServer returns the server that reads the requests of every host
// whose rules have conditions. Its errors go to the manager's logger at
// Debug.
func (m *IngressManager) newHTTPServer() *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(m.serveHTTP),
		ReadHeaderTimeout: m.httpReadHeaderTimeout,
		IdleTimeout:       m.httpIdleTimeout,
		MaxHeaderBytes:    ingressHTTPMaxHeaderBytes,
		// An OPTIONS * request reaches serveHTTP, which refuses it like
		// any other target that does not start with "/".
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     m.debugLog(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if hc, ok := tc.NetConn().(*ingressHTTPConn); ok {
					return context.WithValue(ctx, ingressConnKey{}, hc)
				}
			}
			return ctx
		},
	}
}

// debugLog returns a log.Logger that writes to the manager's logger at Debug.
func (m *IngressManager) debugLog() *log.Logger {
	return slog.NewLogLogger(m.logger.With("component", "bridge").Handler(), slog.LevelDebug)
}

// serveHTTP routes one request of a host whose rules have conditions. It
// looks the connection's server name up in the listener's current table, so
// a request follows the rules of the last Apply, and aborts the connection
// when the name no longer routes to a served host with conditions. It answers
// 421 for a Host the host does not cover or that the port routes to another
// host, 400 for a CONNECT request, a request target that does not start with
// "/" and a path with a dot segment, and 404 when no rule matches; otherwise
// it forwards the request through the route's proxy, under a context that
// ends with the request's or the route's.
func (m *IngressManager) serveHTTP(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Context().Value(ingressConnKey{}).(*ingressHTTPConn)
	if c == nil {
		panic(http.ErrAbortHandler)
	}
	table := c.l.table.Load()
	host := table.match(c.serverName)
	if host == nil || !host.http || !host.lead().served {
		panic(http.ErrAbortHandler)
	}
	if !hostCovers(host.lead().rule.SNIHost, r.Host) || table.match(authorityName(r.Host)) != host {
		m.notForwarded(w, r, c, http.StatusMisdirectedRequest, requestReasonMisdirected, nil, nil)
		return
	}
	path := r.URL.EscapedPath()
	if r.Method == http.MethodConnect || !strings.HasPrefix(path, "/") || hasDotSegment(path) {
		m.notForwarded(w, r, c, http.StatusBadRequest, requestReasonBadPath, nil, nil)
		return
	}
	route := host.route(path, r.Header)
	if route == nil {
		m.notForwarded(w, r, c, http.StatusNotFound, requestReasonNoMatch, nil, nil)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(route.ctx, cancel)
	defer stop()
	route.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// notForwarded answers a request with status and its status text as a
// text/plain body, and logs it at Debug, since a public port draws scanners. The
// line carries no header value, path or query: a header value can be a
// routing token and a URL can hold a credential.
func (m *IngressManager) notForwarded(w http.ResponseWriter, r *http.Request, c *ingressHTTPConn, status int, reason string, route *ingressRoute, err error) {
	attrs := []any{
		"component", "bridge",
		"listen_port", c.l.port,
		"remote", r.RemoteAddr,
		"server_name", c.serverName,
		"status", status,
		"reason", reason,
	}
	if route != nil {
		attrs = append(attrs, "rule_id", route.rule.ID, "slug", route.rule.Slug)
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	m.logger.Debug("ingress request not forwarded", attrs...)
	http.Error(w, http.StatusText(status), status)
}

// newRouteProxy returns the proxy of a route with conditions. It speaks
// HTTP/1.1 in cleartext to the rule's first target, on kept-alive connections
// it pools until the route's context is done, and dials through dialTarget,
// never through a proxy of the environment. A failed dial also fails the
// rule's unit (see recordLastDial). The target receives the request's Host,
// query and fields, without the client's Forwarded and
// X-Forwarded-* fields, with X-Forwarded-For (the client's address alone),
// X-Forwarded-Host and X-Forwarded-Proto, and on a rule with
// strip_path_prefix the path without the prefix and X-Forwarded-Prefix.
func (m *IngressManager) newRouteProxy(route *ingressRoute) *httputil.ReverseProxy {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			conn, err := m.dialTarget(route, addr)
			if err != nil {
				reason, _ := m.recordLastDial(route, route.lb.index(addr), err)
				m.logDialFailed(route, addr, reason, err)
				return nil, &ingressDialError{reason: reason, err: err}
			}
			m.recordDial(route, route.lb.index(addr), nil)
			return conn, nil
		},
		DisableCompression:  true,
		MaxIdleConnsPerHost: ingressTargetMaxIdleConns,
		IdleConnTimeout:     ingressTargetIdleConnTimeout,
	}
	context.AfterFunc(route.ctx, transport.CloseIdleConnections)
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = route.lb.targets[0].addr
			pr.Out.URL.User = nil
			pr.Out.Host = pr.In.Host
			// ReverseProxy drops query parameters it cannot parse before
			// Rewrite; the target receives the query as the client sent it.
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			for name := range pr.Out.Header {
				if len(name) >= len("X-Forwarded-") && strings.EqualFold(name[:len("X-Forwarded-")], "X-Forwarded-") {
					delete(pr.Out.Header, name)
				}
			}
			pr.SetXForwarded()
			if route.rule.StripPathPrefix {
				prefix := route.rule.Conditions.PathPrefix
				rest := strings.TrimPrefix(pr.In.URL.EscapedPath(), prefix)
				if rest == "" {
					rest = "/"
				}
				pr.Out.URL.RawPath = rest
				pr.Out.URL.Path = rest
				if unescaped, err := url.PathUnescape(rest); err == nil {
					pr.Out.URL.Path = unescaped
				}
				pr.Out.Header.Set("X-Forwarded-Prefix", prefix)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if route.ctx.Err() != nil {
				// The rule changed or left the block.
				panic(http.ErrAbortHandler)
			}
			if r.Context().Err() != nil {
				// The client went away.
				return
			}
			c, _ := r.Context().Value(ingressConnKey{}).(*ingressHTTPConn)
			if c == nil {
				panic(http.ErrAbortHandler)
			}
			var dialErr *ingressDialError
			switch {
			case errors.As(err, &dialErr) && dialErr.reason == IngressDialReasonTimeout:
				m.notForwarded(w, r, c, http.StatusGatewayTimeout, requestReasonDialFailed, route, err)
			case errors.As(err, &dialErr):
				m.notForwarded(w, r, c, http.StatusBadGateway, requestReasonDialFailed, route, err)
			default:
				m.notForwarded(w, r, c, http.StatusBadGateway, requestReasonTargetError, route, err)
			}
		},
		ErrorLog: m.debugLog(),
	}
}

// authorityName returns a request's authority as a host name compares: in
// lowercase, without its port and without one trailing dot.
func authorityName(authority string) string {
	name := authority
	if host, _, err := net.SplitHostPort(authority); err == nil {
		name = host
	}
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// hostCovers reports whether a lowercase sni_host covers a request's
// authority, compared as ingressTable.match compares a server name: an exact
// host equals it, and *.example.com covers one label in place of the "*".
func hostCovers(sniHost, authority string) bool {
	name := authorityName(authority)
	if name == "" {
		return false
	}
	sniHost = strings.ToLower(sniHost)
	suffix, wildcard := strings.CutPrefix(sniHost, "*.")
	if !wildcard {
		return name == sniHost
	}
	label, rest, ok := strings.Cut(name, ".")
	return ok && label != "" && rest == suffix
}

// hasDotSegment reports whether a path as the client sent it has a "." or
// ".." segment, written literally or with %2e in either case. A prefix match
// against such a path could reach a path the rule does not publish.
func hasDotSegment(path string) bool {
	for seg := range strings.SplitSeq(path, "/") {
		switch strings.ToLower(seg) {
		case ".", "..", "%2e", "%2e%2e", ".%2e", "%2e.":
			return true
		}
	}
	return false
}
