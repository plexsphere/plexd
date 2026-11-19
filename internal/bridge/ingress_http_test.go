package bridge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/goleak"
	"golang.org/x/net/http2"

	"github.com/plexsphere/plexd/internal/api"
)

// The names the certificate of the HTTP tests covers.
var httpTestNames = []string{"shop.example.com", "only.example.com", "other.example.com", "*.apps.example.com", "exact.apps.example.com"}

// multiCertPEM returns a self-signed certificate for every name and its key
// as one PEM document, the value of a terminate rule's Secret.
func multiCertPEM(t *testing.T, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
}

// httpTarget is a target that answers each request with a text body: the line
// target=<name>, the request line as it arrived, the line Host: <host>, and
// one line per field value in name order. A request whose path contains
// "/slow" waits until release is closed or the request ends.
type httpTarget struct {
	srv     *httptest.Server
	conns   atomic.Int64 // connections accepted
	started chan string  // the path of each held request, once it arrived
	release chan struct{}
	ended   chan error // the context error of each held request, when it ends
}

func startHTTPTarget(t *testing.T, name string) *httpTarget {
	t.Helper()
	tg := &httpTarget{started: make(chan string, 8), release: make(chan struct{}), ended: make(chan error, 8)}
	tg.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/slow") {
			tg.started <- r.URL.Path
			select {
			case <-tg.release:
			case <-r.Context().Done():
				tg.ended <- r.Context().Err()
				return
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "target=%s\n%s %s %s\nHost: %s\n", name, r.Method, r.RequestURI, r.Proto, r.Host)
		for _, k := range slices.Sorted(func(yield func(string) bool) {
			for k := range r.Header {
				if !yield(k) {
					return
				}
			}
		}) {
			for _, v := range r.Header[k] {
				fmt.Fprintf(&b, "%s: %s\n", k, v)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, b.String())
	}))
	tg.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			tg.conns.Add(1)
		}
	}
	tg.srv.Start()
	t.Cleanup(tg.srv.Close)
	return tg
}

func (tg *httpTarget) port(t *testing.T) int {
	t.Helper()
	_, p, err := net.SplitHostPort(tg.srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("target address: %v", err)
	}
	port, _ := strconv.Atoi(p)
	return port
}

// httpRule returns a terminate rule of the Secret tls on port 443 for host to
// 127.0.0.1:targetPort, with the path prefix and the header conditions, given
// as name, value pairs.
func httpRule(slug, host string, targetPort int, prefix string, nameValues ...string) api.IngressRule {
	r := terminateRule(slug, 443, host, "tls", targetPort)
	withConditions(prefix, nameValues...)(&r)
	r.CertificateSecretName = "tls"
	return r
}

// httpFixture is an ingress fixture whose Secret tls holds a certificate for
// httpTestNames, with a client trust pool for it.
type httpFixture struct {
	*ingressFixture
	ctrl  *loopbackIngressController
	roots *x509.CertPool
	doc   []byte // the Secret's value
}

// newHTTPFixture builds the fixture; setup, when not nil, runs before Setup.
func newHTTPFixture(t *testing.T, setup func(*IngressManager)) *httpFixture {
	t.Helper()
	ctrl := newLoopbackIngressController(t)
	fx := buildIngressFixture(t, ctrl, ingressTestConfig(true))
	if setup != nil {
		setup(fx.mgr)
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	doc := multiCertPEM(t, httpTestNames...)
	fx.certs.set("tls", 1, doc)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	return &httpFixture{ingressFixture: fx, ctrl: ctrl, roots: certPool(t, doc), doc: doc}
}

// apply applies the rules and fails the test on an error.
func (fx *httpFixture) apply(t *testing.T, rules ...api.IngressRule) {
	t.Helper()
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rules...)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// client returns an HTTP client that dials port 443 of the bridge for every
// URL, trusts the fixture's certificate, and speaks HTTP/2 when h2 is set and
// HTTP/1.1 otherwise. Its idle connections close when the test ends.
func (fx *httpFixture) client(t *testing.T, h2 bool) *http.Client {
	t.Helper()
	addr := fx.ctrl.addr(443)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: fx.roots},
		ForceAttemptHTTP2: h2,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// get sends a GET with the fields, given as name, value pairs, and returns
// the status and the body.
func get(t *testing.T, c *http.Client, url string, nameValues ...string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request %s: %v", url, err)
	}
	for i := 0; i+1 < len(nameValues); i += 2 {
		req.Header.Add(nameValues[i], nameValues[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the body of %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

// requireLine fails unless body holds the line.
func requireLine(t *testing.T, body, line string) {
	t.Helper()
	if !slices.Contains(strings.Split(body, "\n"), line) {
		t.Errorf("body has no line %q:\n%s", line, body)
	}
}

// requireNoLinePrefix fails when a line of body starts with prefix.
func requireNoLinePrefix(t *testing.T, body, prefix string) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			t.Errorf("body has the line %q, want none that starts with %q:\n%s", line, prefix, body)
		}
	}
}

// rawConn is an HTTP/1.1 client connection to port 443 of the bridge that
// writes requests as given.
type rawConn struct {
	*tls.Conn
	br *bufio.Reader
}

func (fx *httpFixture) dialRaw(t *testing.T, serverName string) *rawConn {
	t.Helper()
	conn := dialTerminated(t, fx.ctrl.addr(443), serverName, fx.roots, "http/1.1")
	return &rawConn{Conn: conn, br: bufio.NewReader(conn)}
}

// roundTrip writes head, a request without a body, and reads the response.
func (c *rawConn) roundTrip(t *testing.T, head string) (int, string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatalf("write %q: %v", head, err)
	}
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("read the response to %q: %v", head, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// getHead returns a GET head for target with the Host host.
func getHead(target, host string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
}

// TestIngressHTTP_RoutesByPathPrefix routes by the longest matching prefix
// and forwards each request with the request line it was sent.
func TestIngressHTTP_RoutesByPathPrefix(t *testing.T) {
	apiT, webT := startHTTPTarget(t, "api"), startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	fx.apply(t,
		httpRule("api", "shop.example.com", apiT.port(t), "/api"),
		httpRule("web", "shop.example.com", webT.port(t), "/"),
	)
	c := fx.client(t, false)
	for _, tc := range []struct {
		path, target string
	}{
		{"/api/users?x=1", "api"},
		{"/api", "api"},
		{"/apix", "web"},
		{"/", "web"},
	} {
		status, body := get(t, c, "https://shop.example.com"+tc.path)
		if status != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200:\n%s", tc.path, status, body)
		}
		requireLine(t, body, "target="+tc.target)
		requireLine(t, body, "GET "+tc.path+" HTTP/1.1")
	}
}

// TestIngressHTTP_HeaderConditions sends a request with the header to the rule
// that asks for it, and the same request without it to the rule that does
// not. No log line carries the header's value.
func TestIngressHTTP_HeaderConditions(t *testing.T) {
	const token = "s3cr3t-routing-token"
	apiT, betaT := startHTTPTarget(t, "api"), startHTTPTarget(t, "beta")
	fx := newHTTPFixture(t, nil)
	fx.apply(t,
		httpRule("api", "shop.example.com", apiT.port(t), "/api"),
		httpRule("beta", "shop.example.com", betaT.port(t), "/api", "x-beta", token),
	)
	c := fx.client(t, false)

	_, body := get(t, c, "https://shop.example.com/api/users", "X-Beta", token)
	requireLine(t, body, "target=beta")
	_, body = get(t, c, "https://shop.example.com/api/users")
	requireLine(t, body, "target=api")
	_, body = get(t, c, "https://shop.example.com/api/users", "X-Beta", strings.ToUpper(token))
	requireLine(t, body, "target=api")
	_, body = get(t, c, "https://shop.example.com/nothing", "X-Beta", token)
	if body != "Not Found\n" {
		t.Errorf("a request no rule matches read %q, want Not Found", body)
	}

	if logLines(fx.logs, `msg="ingress rule added"`, "slug=beta", "path_prefix=/api", "header_names=x-beta", "strip_path_prefix=false") != 1 {
		t.Errorf("no 'ingress rule added' line for beta with its condition keys:\n%s", fx.logs.String())
	}
	if strings.Contains(fx.logs.String(), token) {
		t.Errorf("the log carries the header value %q:\n%s", token, fx.logs.String())
	}
}

// TestIngressHTTP_StripPathPrefix removes the prefix from the escaped path,
// keeps the query as sent and names the prefix in X-Forwarded-Prefix.
func TestIngressHTTP_StripPathPrefix(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, nil)
	strip := httpRule("api", "shop.example.com", apiT.port(t), "/api")
	strip.StripPathPrefix = true
	fx.apply(t, strip)
	conn := fx.dialRaw(t, "shop.example.com")

	for _, tc := range []struct{ sent, want string }{
		{"/api/users%2Fx?a=1;b=2&c", "/users%2Fx?a=1;b=2&c"},
		{"/api", "/"},
		{"/api?q=1", "/?q=1"},
		{"/api/", "/"},
	} {
		status, body := conn.roundTrip(t, getHead(tc.sent, "shop.example.com"))
		if status != http.StatusOK {
			t.Fatalf("GET %s: status %d:\n%s", tc.sent, status, body)
		}
		requireLine(t, body, "GET "+tc.want+" HTTP/1.1")
		requireLine(t, body, "X-Forwarded-Prefix: /api")
	}
}

// TestIngressHTTP_ForwardedHeaders tells the target the client's address, host
// and scheme, and drops the forwarding fields the client sent.
func TestIngressHTTP_ForwardedHeaders(t *testing.T) {
	apiT, webT := startHTTPTarget(t, "api"), startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	strip := httpRule("api", "shop.example.com", apiT.port(t), "/api")
	strip.StripPathPrefix = true
	fx.apply(t, strip, httpRule("web", "shop.example.com", webT.port(t), "/"))
	c := fx.client(t, false)

	claims := []string{
		"Forwarded", "for=6.6.6.6;proto=http",
		"X-Forwarded-For", "6.6.6.6",
		"X-Forwarded-Host", "evil.example.com",
		"X-Forwarded-Proto", "http",
		"X-Forwarded-Prefix", "/evil",
		"X-Forwarded-Port", "1",
		"X-Other", "kept",
	}
	_, body := get(t, c, "https://shop.example.com/web?q=1", claims...)
	requireLine(t, body, "target=web")
	requireLine(t, body, "X-Forwarded-For: 127.0.0.1")
	requireLine(t, body, "X-Forwarded-Host: shop.example.com")
	requireLine(t, body, "X-Forwarded-Proto: https")
	requireLine(t, body, "Host: shop.example.com")
	requireLine(t, body, "X-Other: kept")
	requireLine(t, body, "GET /web?q=1 HTTP/1.1")
	requireNoLinePrefix(t, body, "Forwarded:")
	requireNoLinePrefix(t, body, "X-Forwarded-Prefix:")
	requireNoLinePrefix(t, body, "X-Forwarded-Port:")
	if strings.Count(body, "X-Forwarded-For:") != 1 {
		t.Errorf("want one X-Forwarded-For line:\n%s", body)
	}

	_, body = get(t, c, "https://shop.example.com/api/x", claims...)
	requireLine(t, body, "target=api")
	requireLine(t, body, "X-Forwarded-Prefix: /api")
	requireLine(t, body, "X-Forwarded-For: 127.0.0.1")
	if strings.Count(body, "X-Forwarded-Prefix:") != 1 {
		t.Errorf("want one X-Forwarded-Prefix line:\n%s", body)
	}
}

// TestIngressHTTP_IgnoresProxyEnvironment reaches the target with HTTP_PROXY
// and HTTPS_PROXY naming an address nothing listens on.
func TestIngressHTTP_IgnoresProxyEnvironment(t *testing.T) {
	proxy := "http://127.0.0.1:" + strconv.Itoa(closedPort(t))
	t.Setenv("HTTP_PROXY", proxy)
	t.Setenv("HTTPS_PROXY", proxy)
	t.Setenv("http_proxy", proxy)
	t.Setenv("https_proxy", proxy)
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, nil)
	fx.apply(t, httpRule("api", "shop.example.com", apiT.port(t), "/api"))

	status, body := get(t, fx.client(t, false), "https://shop.example.com/api")
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200:\n%s", status, body)
	}
	requireLine(t, body, "target=api")
	route := fx.mgr.listeners[443].table.Load().exact["shop.example.com"].lead()
	if tr, ok := route.proxy.Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Errorf("the route's transport = %T with a Proxy func, want an *http.Transport without one", route.proxy.Transport)
	}
}

// TestIngressHTTP_NoMatchIs404 answers a request no rule matches with 404 and
// dials nothing, also on a host whose only rule does not match.
func TestIngressHTTP_NoMatchIs404(t *testing.T) {
	apiT, onlyT := startHTTPTarget(t, "api"), startHTTPTarget(t, "only")
	fx := newHTTPFixture(t, nil)
	apiRule := withID(httpRule("api", "shop.example.com", apiT.port(t), "/api"), reportID("a1"))
	onlyRule := withID(httpRule("only", "only.example.com", onlyT.port(t), "/only"), reportID("a2"))
	fx.apply(t, apiRule, onlyRule)
	c := fx.client(t, false)

	for _, url := range []string{"https://shop.example.com/other", "https://only.example.com/x"} {
		status, body := get(t, c, url)
		if status != http.StatusNotFound || body != "Not Found\n" {
			t.Errorf("GET %s: %d %q, want 404 Not Found", url, status, body)
		}
	}
	if n := apiT.conns.Load() + onlyT.conns.Load(); n != 0 {
		t.Errorf("the targets accepted %d connections, want none", n)
	}
	reports := fx.mgr.RuleReports()
	for _, id := range []string{apiRule.ID, onlyRule.ID} {
		if got := reportFor(t, reports, id); got.Dial != api.IngressDialNone {
			t.Errorf("rule %s: dial = %q, want none", id, got.Dial)
		}
	}
	if got := logLines(fx.logs, "level=DEBUG", `msg="ingress request not forwarded"`, "reason=no_matching_rule", "status=404"); got != 2 {
		t.Errorf("%d 'ingress request not forwarded' lines with no_matching_rule, want 2:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="ingress request not forwarded"`, "server_name=shop.example.com", "listen_port=443", "remote=127.0.0.1:"); got != 1 {
		t.Errorf("%d lines for shop.example.com with listen_port and remote, want 1:\n%s", got, fx.logs.String())
	}
	if strings.Contains(fx.logs.String(), "/other") {
		t.Errorf("the log carries the request path /other:\n%s", fx.logs.String())
	}
}

// TestIngressHTTP_BadPathIs400 refuses a dot segment and a request target
// that does not start with "/", and routes paths that only hold dots.
func TestIngressHTTP_BadPathIs400(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, nil)
	fx.apply(t, httpRule("api", "shop.example.com", apiT.port(t), "/"))

	for _, head := range []string{
		getHead("/api/../x", "shop.example.com"),
		getHead("/api/%2e%2e/x", "shop.example.com"),
		getHead("/api/%2E/x", "shop.example.com"),
		getHead("/./x", "shop.example.com"),
		getHead("/api/.%2E/x", "shop.example.com"),
		"OPTIONS * HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
		"CONNECT shop.example.com:443 HTTP/1.1\r\nHost: shop.example.com:443\r\n\r\n",
	} {
		conn := fx.dialRaw(t, "shop.example.com")
		if status, body := conn.roundTrip(t, head); status != http.StatusBadRequest || body != "Bad Request\n" {
			t.Errorf("%q: %d %q, want 400 Bad Request", head, status, body)
		}
	}
	conn := fx.dialRaw(t, "shop.example.com")
	for _, path := range []string{"/api/..x", "/api/x..", "/a.b/.c"} {
		status, body := conn.roundTrip(t, getHead(path, "shop.example.com"))
		if status != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", path, status)
		}
		requireLine(t, body, "GET "+path+" HTTP/1.1")
	}
	if got := logLines(fx.logs, `msg="ingress request not forwarded"`, "reason=bad_path", "status=400"); got != 7 {
		t.Errorf("%d bad_path lines, want 7:\n%s", got, fx.logs.String())
	}
}

func TestHasDotSegment(t *testing.T) {
	for path, want := range map[string]bool{
		"/":             false,
		"/api":          false,
		"/api/..x":      false,
		"/api/x..":      false,
		"/a.b/c":        false,
		"/...":          false,
		"/%2e%2e%2e":    false,
		"/api/../x":     true,
		"/api/..":       true,
		"/./x":          true,
		"/.":            true,
		"/api/%2e%2e/x": true,
		"/api/%2E%2E/x": true,
		"/api/%2E/x":    true,
		"/api/.%2e/x":   true,
		"/api/%2E./x":   true,
	} {
		if got := hasDotSegment(path); got != want {
			t.Errorf("hasDotSegment(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestIngressHTTP_MisdirectedIs421 answers 421 for a Host the connection's
// host does not cover, or that the port routes to another host.
func TestIngressHTTP_MisdirectedIs421(t *testing.T) {
	apiT, wildT, exactT := startHTTPTarget(t, "api"), startHTTPTarget(t, "wild"), startHTTPTarget(t, "exact")
	fx := newHTTPFixture(t, nil)
	fx.apply(t,
		httpRule("api", "shop.example.com", apiT.port(t), "/"),
		httpRule("only", "only.example.com", apiT.port(t), "/"),
		httpRule("wild", "*.apps.example.com", wildT.port(t), "/"),
		httpRule("exact", "exact.apps.example.com", exactT.port(t), "/"),
	)

	shop := fx.dialRaw(t, "shop.example.com")
	for _, host := range []string{"other.example.com", "only.example.com", "example.com", ""} {
		if status, body := shop.roundTrip(t, getHead("/", host)); status != http.StatusMisdirectedRequest || body != "Misdirected Request\n" {
			t.Errorf("Host %q on shop.example.com: %d %q, want 421 Misdirected Request", host, status, body)
		}
	}
	for _, host := range []string{"shop.example.com", "shop.example.com:443", "SHOP.Example.COM", "shop.example.com.", "shop.example.com.:443"} {
		status, body := shop.roundTrip(t, getHead("/", host))
		if status != http.StatusOK {
			t.Errorf("Host %q on shop.example.com: status %d, want 200", host, status)
		}
		requireLine(t, body, "target=api")
		requireLine(t, body, "Host: "+host)
	}

	wild := fx.dialRaw(t, "a.apps.example.com")
	for _, host := range []string{"a.apps.example.com", "b.apps.example.com", "B.apps.example.com:8443"} {
		status, body := wild.roundTrip(t, getHead("/", host))
		if status != http.StatusOK {
			t.Errorf("Host %q on a.apps.example.com: status %d, want 200", host, status)
		}
		requireLine(t, body, "target=wild")
	}
	// Two labels in place of the "*", and a host an exact rule of the port
	// routes to.
	for _, host := range []string{"x.y.apps.example.com", "apps.example.com", "exact.apps.example.com"} {
		if status, _ := wild.roundTrip(t, getHead("/", host)); status != http.StatusMisdirectedRequest {
			t.Errorf("Host %q on a.apps.example.com: status %d, want 421", host, status)
		}
	}
	if got := logLines(fx.logs, `msg="ingress request not forwarded"`, "reason=misdirected", "status=421"); got != 7 {
		t.Errorf("%d misdirected lines, want 7:\n%s", got, fx.logs.String())
	}
}

func TestHostCovers(t *testing.T) {
	for _, tc := range []struct {
		sni, authority string
		want           bool
	}{
		{"shop.example.com", "shop.example.com", true},
		{"shop.example.com", "shop.example.com:443", true},
		{"shop.example.com", "SHOP.example.com", true},
		{"shop.example.com", "shop.example.com.", true},
		{"shop.example.com", "shop.example.com.:8443", true},
		{"shop.example.com", "other.example.com", false},
		{"shop.example.com", "shop.example.com..", false},
		{"shop.example.com", "", false},
		{"shop.example.com", "[::1]:443", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "B.Example.Com:443", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", ".example.com", false},
	} {
		if got := hostCovers(tc.sni, tc.authority); got != tc.want {
			t.Errorf("hostCovers(%q, %q) = %v, want %v", tc.sni, tc.authority, got, tc.want)
		}
	}
}

// TestIngressHTTP_HTTP2Client serves two rules over one HTTP/2 connection and
// forwards both requests over HTTP/1.1.
func TestIngressHTTP_HTTP2Client(t *testing.T) {
	apiT, webT := startHTTPTarget(t, "api"), startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	fx.apply(t,
		httpRule("api", "shop.example.com", apiT.port(t), "/api"),
		httpRule("web", "shop.example.com", webT.port(t), "/"),
	)
	c := fx.client(t, true)

	var conns []net.Conn
	for _, tc := range []struct{ path, target string }{{"/api/x", "api"}, {"/web", "web"}} {
		var got net.Conn
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { got = info.Conn }}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, "https://shop.example.com"+tc.path, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Errorf("GET %s answered over %s, want HTTP/2", tc.path, resp.Proto)
		}
		requireLine(t, string(body), "target="+tc.target)
		requireLine(t, string(body), "GET "+tc.path+" HTTP/1.1")
		conns = append(conns, got)
	}
	if len(conns) != 2 || conns[0] == nil || conns[0] != conns[1] {
		t.Errorf("the two requests used the connections %v, want one", conns)
	}
	if n := connectionCount(t, fx.mgr); n != 1 {
		t.Errorf("connection_count = %d, want 1", n)
	}
}

// TestIngressHTTP_NoExtendedConnect reads the bridge's HTTP/2 SETTINGS frame,
// which must not offer the extended CONNECT of RFC 8441.
func TestIngressHTTP_NoExtendedConnect(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, nil)
	fx.apply(t, httpRule("api", "shop.example.com", apiT.port(t), "/"))

	conn := dialTerminated(t, fx.ctrl.addr(443), "shop.example.com", fx.roots, "h2")
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q, want h2", p)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("write the preface: %v", err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	for {
		f, err := framer.ReadFrame()
		if err != nil {
			t.Fatalf("read a frame: %v", err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		if v, ok := sf.Value(http2.SettingEnableConnectProtocol); ok {
			t.Errorf("SETTINGS carries SETTINGS_ENABLE_CONNECT_PROTOCOL = %d, want no such setting", v)
		}
		return
	}
}

// TestIngressHTTP_WebSocketUpgrade carries a WebSocket through a rule with
// conditions and closes it when the rule leaves the block.
func TestIngressHTTP_WebSocketUpgrade(t *testing.T) {
	wsT := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		for {
			typ, msg, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, msg); err != nil {
				return
			}
		}
	}))
	t.Cleanup(wsT.Close)
	_, p, _ := net.SplitHostPort(wsT.Listener.Addr().String())
	wsPort, _ := strconv.Atoi(p)
	webT := startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	wsRule := httpRule("ws", "shop.example.com", wsPort, "/ws")
	webRule := httpRule("web", "shop.example.com", webT.port(t), "/")
	fx.apply(t, wsRule, webRule)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://shop.example.com/ws/echo", &websocket.DialOptions{HTTPClient: fx.client(t, false)})
	if err != nil {
		t.Fatalf("dial the WebSocket: %v", err)
	}
	defer func() { _ = ws.CloseNow() }()
	if err := ws.Write(ctx, websocket.MessageText, []byte("hello through the bridge")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := ws.Read(ctx)
	if err != nil || string(msg) != "hello through the bridge" {
		t.Fatalf("read = %q, %v, want the echo", msg, err)
	}
	if n := connectionCount(t, fx.mgr); n != 1 {
		t.Errorf("connection_count with the upgraded connection = %d, want 1", n)
	}

	fx.apply(t, webRule)
	readCtx, readCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer readCancel()
	if _, _, err := ws.Read(readCtx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read after the rule left the block = %v, want the WebSocket closed", err)
	}
}

// TestIngressHTTP_RuleWithoutConditionsForwardsBytes keeps a terminate rule
// without conditions on byte forwarding without an ALPN protocol.
func TestIngressHTTP_RuleWithoutConditionsForwardsBytes(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	fx := newHTTPFixture(t, nil)
	fx.apply(t, terminateRule("term", 443, "shop.example.com", "tls", backend.port(t)))

	conn := dialTerminated(t, fx.ctrl.addr(443), "shop.example.com", fx.roots, "h2", "http/1.1")
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
		t.Errorf("negotiated %q, want no ALPN protocol", p)
	}
	requireEcho(t, conn, "\x00\x01 not http at all\r\n\r\n")
}

// TestIngressHTTP_ACMERuleWithConditions routes a request of an acme rule with
// conditions and still answers a TLS-ALPN-01 hello for its host on 443.
func TestIngressHTTP_ACMERuleWithConditions(t *testing.T) {
	apiT, webT := startHTTPTarget(t, "api"), startHTTPTarget(t, "web")
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	hookCertificate(t, fx.acme, "acme.example.com")
	acmeAPI := acmeRule("acme-api", 8443, "acme.example.com", apiT.port(t))
	acmeAPI.Conditions.PathPrefix = "/api"
	acmeWeb := acmeRule("acme-web", 8443, "acme.example.com", webT.port(t))
	acmeWeb.Conditions.PathPrefix = "/"
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{acmeAPI, acmeWeb}, ACME: testACME}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, slug := range []string{"acme-api", "acme-web"} {
		if st := stateOf(t, fx.mgr, slug); !st.Served || st.Reason != "" {
			t.Errorf("rule %s = %+v, want served", slug, st)
		}
	}
	if got := logLines(fx.logs, `msg="acme account configured"`, "hosts=1"); got != 1 {
		t.Errorf("%d 'acme account configured' lines with hosts=1, want 1:\n%s", got, fx.logs.String())
	}

	conn, err := dialALPN(ctrl.addr(8443), "acme.example.com", "http/1.1")
	if err != nil {
		t.Fatalf("tls dial the acme rules: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if p := conn.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Errorf("negotiated %q, want http/1.1", p)
	}
	raw := &rawConn{Conn: conn, br: bufio.NewReader(conn)}
	_, body := raw.roundTrip(t, getHead("/api/x", "acme.example.com"))
	requireLine(t, body, "target=api")
	_, body = raw.roundTrip(t, getHead("/x", "acme.example.com"))
	requireLine(t, body, "target=web")

	challenge, err := dialALPN(ctrl.addr(acmeChallengePort), "acme.example.com", "acme-tls/1")
	if err != nil {
		t.Fatalf("challenge handshake: %v", err)
	}
	if p := challenge.ConnectionState().NegotiatedProtocol; p != "acme-tls/1" {
		t.Errorf("challenge negotiated %q, want acme-tls/1", p)
	}
	_ = challenge.Close()
	fx.logs.waitFor(t, `msg="ingress acme challenge answered"`, 1)
}

// TestIngressHTTP_DialFailureIs502 answers 502 for a target nothing listens
// on, while a neighbour rule of the host answers.
func TestIngressHTTP_DialFailureIs502(t *testing.T) {
	webT := startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	down := withID(httpRule("down", "shop.example.com", closedPort(t), "/down"), reportID("a1"))
	web := withID(httpRule("web", "shop.example.com", webT.port(t), "/"), reportID("a2"))
	fx.apply(t, down, web)
	c := fx.client(t, false)

	status, body := get(t, c, "https://shop.example.com/down/x")
	if status != http.StatusBadGateway || body != "Bad Gateway\n" {
		t.Errorf("GET /down/x: %d %q, want 502 Bad Gateway", status, body)
	}
	if status, _ := get(t, c, "https://shop.example.com/x"); status != http.StatusOK {
		t.Errorf("GET /x: status %d, want 200 from the neighbour", status)
	}
	reports := fx.mgr.RuleReports()
	if got := reportFor(t, reports, down.ID); got.Dial != api.IngressDialFailed || got.DialReason != IngressDialReasonRefused {
		t.Errorf("down: report = %+v, want dial failed with refused", got)
	}
	if got := reportFor(t, reports, web.ID); got.Dial != api.IngressDialSucceeded {
		t.Errorf("web: report = %+v, want dial succeeded", got)
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id="+down.ID, "reason=refused"); got != 1 {
		t.Errorf("%d 'dial target failed' lines, want 1:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="ingress request not forwarded"`, "status=502", "reason=dial_failed", "rule_id="+down.ID, "slug=down", "error="); got != 1 {
		t.Errorf("%d 'ingress request not forwarded' lines with dial_failed, want 1:\n%s", got, fx.logs.String())
	}
}

// TestIngressHTTP_DialTimeoutIs504 answers 504 for a dial that timed out and
// 502 for one the policy blocks.
func TestIngressHTTP_DialTimeoutIs504(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		fx := newHTTPFixture(t, func(m *IngressManager) {
			m.dial = func(context.Context, string, string) (net.Conn, error) {
				return nil, fmt.Errorf("dial: %w", context.DeadlineExceeded)
			}
		})
		rule := withID(httpRule("slow", "shop.example.com", 9, "/"), reportID("a1"))
		fx.apply(t, rule)
		status, body := get(t, fx.client(t, false), "https://shop.example.com/x")
		if status != http.StatusGatewayTimeout || body != "Gateway Timeout\n" {
			t.Errorf("%d %q, want 504 Gateway Timeout", status, body)
		}
		if got := reportFor(t, fx.mgr.RuleReports(), rule.ID); got.Dial != api.IngressDialFailed || got.DialReason != IngressDialReasonTimeout {
			t.Errorf("report = %+v, want dial failed with timeout", got)
		}
		if got := logLines(fx.logs, `msg="ingress request not forwarded"`, "status=504", "reason=dial_failed"); got != 1 {
			t.Errorf("%d 504 lines, want 1:\n%s", got, fx.logs.String())
		}
	})
	t.Run("policy denied", func(t *testing.T) {
		fx := newHTTPFixture(t, func(m *IngressManager) { m.SetDialPolicy(&fakeDialPolicy{denied: true}) })
		rule := withID(httpRule("denied", "shop.example.com", closedPort(t), "/"), reportID("a1"))
		fx.apply(t, rule)
		if status, _ := get(t, fx.client(t, false), "https://shop.example.com/x"); status != http.StatusBadGateway {
			t.Errorf("status %d, want 502", status)
		}
		if got := reportFor(t, fx.mgr.RuleReports(), rule.ID); got.Dial != api.IngressDialFailed || got.DialReason != IngressDialReasonPolicyDenied {
			t.Errorf("report = %+v, want dial failed with policy_denied", got)
		}
	})
}

// TestIngressHTTP_TargetErrorIs502 answers 502 for a target that closes the
// connection without a response, after a dial that succeeded.
func TestIngressHTTP_TargetErrorIs502(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", func(conn net.Conn) {
		_, _ = conn.Read(make([]byte, 4096))
	})
	fx := newHTTPFixture(t, nil)
	rule := withID(httpRule("broken", "shop.example.com", backend.port(t), "/"), reportID("a1"))
	fx.apply(t, rule)

	status, body := get(t, fx.client(t, false), "https://shop.example.com/x")
	if status != http.StatusBadGateway || body != "Bad Gateway\n" {
		t.Errorf("%d %q, want 502 Bad Gateway", status, body)
	}
	if got := reportFor(t, fx.mgr.RuleReports(), rule.ID); got.Dial != api.IngressDialSucceeded {
		t.Errorf("report = %+v, want dial succeeded", got)
	}
	if got := logLines(fx.logs, `msg="ingress request not forwarded"`, "status=502", "reason=target_error", "rule_id="+rule.ID); got != 1 {
		t.Errorf("%d target_error lines, want 1:\n%s", got, fx.logs.String())
	}
}

// TestIngressHTTP_ClientGone leaves the dial record and the log as they were
// when the client goes away during a request.
func TestIngressHTTP_ClientGone(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, nil)
	rule := withID(httpRule("api", "shop.example.com", apiT.port(t), "/"), reportID("a1"))
	fx.apply(t, rule)
	c := fx.client(t, false)

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://shop.example.com/slow", nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errc <- err
	}()
	select {
	case <-apiT.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the target got no request")
	}
	before := reportFor(t, fx.mgr.RuleReports(), rule.ID)
	if before.Dial != api.IngressDialSucceeded {
		t.Fatalf("report while the request is held = %+v, want dial succeeded", before)
	}
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("the cancelled request succeeded")
	}
	select {
	case <-apiT.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the target's request did not end with the client")
	}
	time.Sleep(50 * time.Millisecond) // the handler returns after the target's request
	if got := reportFor(t, fx.mgr.RuleReports(), rule.ID); got != before {
		t.Errorf("report after the client went away = %+v, want %+v", got, before)
	}
	for _, needle := range []string{`msg="ingress request not forwarded"`, `msg="bridge: ingress: dial target failed"`} {
		if got := logLines(fx.logs, needle); got != 0 {
			t.Errorf("%d %s lines, want none:\n%s", got, needle, fx.logs.String())
		}
	}
}

// TestIngressHTTP_KeepAlive sends two requests on one client connection over
// one target connection, also across an Apply of the same block.
func TestIngressHTTP_KeepAlive(t *testing.T) {
	apiT, webT := startHTTPTarget(t, "api"), startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	rules := []api.IngressRule{
		httpRule("api", "shop.example.com", apiT.port(t), "/api"),
		httpRule("web", "shop.example.com", webT.port(t), "/"),
	}
	fx.apply(t, rules...)
	conn := fx.dialRaw(t, "shop.example.com")

	for range 2 {
		_, body := conn.roundTrip(t, getHead("/api/x", "shop.example.com"))
		requireLine(t, body, "target=api")
	}
	if n := apiT.conns.Load(); n != 1 {
		t.Errorf("two requests on one client connection caused %d target connections, want 1", n)
	}

	before := logLines(fx.logs, `msg="ingress rule`)
	fx.apply(t, rules...)
	if got := logLines(fx.logs, `msg="ingress rule`); got != before {
		t.Errorf("the second Apply of the same block logged %d rule lines, want none:\n%s", got-before, fx.logs.String())
	}
	_, body := conn.roundTrip(t, getHead("/api/y", "shop.example.com"))
	requireLine(t, body, "target=api")
	_, body = conn.roundTrip(t, getHead("/z", "shop.example.com"))
	requireLine(t, body, "target=web")
	_, body = conn.roundTrip(t, getHead("/z", "shop.example.com"))
	requireLine(t, body, "target=web")
	if a, w := apiT.conns.Load(), webT.conns.Load(); a != 1 || w != 1 {
		t.Errorf("target connections = %d (api), %d (web), want 1 each", a, w)
	}
	if n := connectionCount(t, fx.mgr); n != 1 {
		t.Errorf("connection_count = %d, want the one client connection", n)
	}
}

// TestIngressHTTP_RuleChange keeps the client connection across a changed
// target port, sends the next request to the new target, aborts the request
// in flight on the changed rule and completes the one on its neighbour.
func TestIngressHTTP_RuleChange(t *testing.T) {
	oldT, newT, webT := startHTTPTarget(t, "old"), startHTTPTarget(t, "new"), startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	apiRule := httpRule("api", "shop.example.com", oldT.port(t), "/api")
	webRule := httpRule("web", "shop.example.com", webT.port(t), "/")
	fx.apply(t, apiRule, webRule)

	kept := fx.dialRaw(t, "shop.example.com")
	_, body := kept.roundTrip(t, getHead("/api/x", "shop.example.com"))
	requireLine(t, body, "target=old")

	type result struct {
		status int
		err    error
	}
	inFlight := func(path string) <-chan result {
		ch := make(chan result, 1)
		c := fx.client(t, false)
		go func() {
			resp, err := c.Get("https://shop.example.com" + path)
			if err != nil {
				ch <- result{err: err}
				return
			}
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			ch <- result{status: resp.StatusCode, err: err}
		}()
		return ch
	}
	onAPI := inFlight("/api/slow")
	<-oldT.started
	onWeb := inFlight("/slow")
	<-webT.started

	changed := apiRule
	changed.TargetPort = newT.port(t)
	fx.apply(t, changed, webRule)

	select {
	case r := <-onAPI:
		if r.err == nil {
			t.Errorf("the request in flight on the changed rule got %d, want it aborted", r.status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request in flight on the changed rule was not aborted")
	}
	close(webT.release)
	if r := <-onWeb; r.err != nil || r.status != http.StatusOK {
		t.Errorf("the request in flight on the neighbour = %d, %v, want 200", r.status, r.err)
	}

	_, body = kept.roundTrip(t, getHead("/api/y", "shop.example.com"))
	requireLine(t, body, "target=new")
}

// TestIngressHTTP_HostChangeClosesConnections closes the idle client
// connections of a host whose Secret changes or that leaves the block.
func TestIngressHTTP_HostChangeClosesConnections(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	for _, tc := range []struct {
		name string
		next func(api.IngressRule) []api.IngressRule
	}{
		{name: "another Secret", next: func(r api.IngressRule) []api.IngressRule {
			r.CertificateSecretName = "tls-other"
			return []api.IngressRule{r}
		}},
		{name: "the host removed", next: func(api.IngressRule) []api.IngressRule {
			return []api.IngressRule{httpRule("other", "other.example.com", 9, "/")}
		}},
		{name: "the host's rule loses its conditions", next: func(r api.IngressRule) []api.IngressRule {
			r.Conditions = api.IngressConditions{}
			return []api.IngressRule{r}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newHTTPFixture(t, nil)
			rule := httpRule("api", "shop.example.com", apiT.port(t), "/")
			fx.apply(t, rule)
			conn := fx.dialRaw(t, "shop.example.com")
			if status, _ := conn.roundTrip(t, getHead("/", "shop.example.com")); status != http.StatusOK {
				t.Fatalf("status %d, want 200", status)
			}
			fx.apply(t, tc.next(rule)...)
			requireClosed(t, conn)
		})
	}
}

// TestIngressHTTP_Limits closes a slow header and an idle client connection,
// and answers an oversized header with 431.
func TestIngressHTTP_Limits(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, func(m *IngressManager) {
		m.httpReadHeaderTimeout = 200 * time.Millisecond
		m.httpIdleTimeout = 300 * time.Millisecond
	})
	fx.apply(t, httpRule("api", "shop.example.com", apiT.port(t), "/"))

	slow := fx.dialRaw(t, "shop.example.com")
	start := time.Now()
	if _, err := io.WriteString(slow, "GET / HTTP/1.1\r\nHost: shop.exa"); err != nil {
		t.Fatalf("write half a header: %v", err)
	}
	requireClosed(t, slow)
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("half a header closed after %v, want about httpReadHeaderTimeout", d)
	}

	idle := fx.dialRaw(t, "shop.example.com")
	if status, _ := idle.roundTrip(t, getHead("/", "shop.example.com")); status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	start = time.Now()
	requireClosed(t, idle)
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Errorf("an idle connection closed after %v, want about httpIdleTimeout", d)
	}

	big := fx.dialRaw(t, "shop.example.com")
	head := "GET / HTTP/1.1\r\nHost: shop.example.com\r\nX-Big: " + strings.Repeat("b", 80<<10) + "\r\n\r\n"
	if status, _ := big.roundTrip(t, head); status != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("a header of 80 KiB got %d, want 431", status)
	}
	if n := apiT.conns.Load(); n != 1 {
		t.Errorf("the target accepted %d connections, want only the idle one's", n)
	}
}

// TestIngressHTTP_Teardown counts HTTP client connections, an upgraded one
// included, takes a failed handshake back out, and leaves nothing running
// after Teardown.
func TestIngressHTTP_Teardown(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	wsT := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		_, _, _ = c.Read(r.Context())
	}))
	apiT := startHTTPTarget(t, "api")
	_, p, _ := net.SplitHostPort(wsT.Listener.Addr().String())
	wsPort, _ := strconv.Atoi(p)
	fx := newHTTPFixture(t, nil)
	fx.apply(t,
		httpRule("api", "shop.example.com", apiT.port(t), "/api"),
		httpRule("ws", "shop.example.com", wsPort, "/ws"),
	)

	conn := fx.dialRaw(t, "shop.example.com")
	if status, _ := conn.roundTrip(t, getHead("/api", "shop.example.com")); status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if n := connectionCount(t, fx.mgr); n != 1 {
		t.Errorf("connection_count with one HTTP client = %d, want 1", n)
	}
	wsClient := fx.client(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://shop.example.com/ws", &websocket.DialOptions{HTTPClient: wsClient})
	if err != nil {
		t.Fatalf("dial the WebSocket: %v", err)
	}
	if n := connectionCount(t, fx.mgr); n != 2 {
		t.Errorf("connection_count with an upgraded connection = %d, want 2", n)
	}

	// A client that refuses the bridge's certificate fails the handshake.
	raw := connect(t, fx.ctrl.addr(443))
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tls.Client(raw, &tls.Config{ServerName: "shop.example.com", NextProtos: []string{"h2"}}).Handshake(); err == nil {
		t.Fatal("a handshake that trusts no root succeeded")
	}
	_ = raw.Close()
	fx.logs.waitFor(t, "server_name=shop.example.com reason=tls_handshake_failed", 1)
	waitConnCount(t, fx.mgr, 2)

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	waitConnCount(t, fx.mgr, 0)
	_ = ws.CloseNow()
	_ = conn.Close()
	wsClient.Transport.(*http.Transport).CloseIdleConnections()
	wsT.Close()
	apiT.srv.Close()
	if err := fx.acme.Teardown(); err != nil {
		t.Fatalf("ACME Teardown: %v", err)
	}
	goleak.VerifyNone(t, ignore)
}

// waitConnCount waits up to 2 s for connCount to read want.
func waitConnCount(t *testing.T, m *IngressManager, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for m.connCount.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("connCount = %d, want %d", m.connCount.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
