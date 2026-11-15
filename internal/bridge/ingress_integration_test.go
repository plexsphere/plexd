package bridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// Integration tests — Ingress over real sockets
// ---------------------------------------------------------------------------

// testBackend is a TCP server the tests route to. It counts the connections
// it accepted.
type testBackend struct {
	ln       net.Listener
	accepted atomic.Int64
	wg       sync.WaitGroup
}

func (b *testBackend) port(t *testing.T) int {
	t.Helper()
	_, p, err := net.SplitHostPort(b.ln.Addr().String())
	if err != nil {
		t.Fatalf("backend address: %v", err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("backend port: %v", err)
	}
	return port
}

// startBackend serves every connection with handle on network and addr until
// the test ends.
func startBackend(t *testing.T, network, addr string, handle func(net.Conn)) *testBackend {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	b := &testBackend{ln: ln}
	conns := make(map[net.Conn]struct{})
	var mu sync.Mutex
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			b.wg.Add(1)
			go func() {
				defer b.wg.Done()
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		b.wg.Wait()
	})
	return b
}

func echo(conn net.Conn) { _, _ = io.Copy(conn, conn) }

// banner writes msg first and then echoes.
func banner(msg string) func(net.Conn) {
	return func(conn net.Conn) {
		if _, err := conn.Write([]byte(msg)); err != nil {
			return
		}
		echo(conn)
	}
}

// selfSignedCert returns a certificate for cn.
func selfSignedCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSBackend serves TLS with a certificate for cn and echoes.
func startTLSBackend(t *testing.T, cn string) *testBackend {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, cn)}, MinVersion: tls.VersionTLS12}
	return startBackend(t, "tcp", "127.0.0.1:0", func(conn net.Conn) {
		echo(tls.Server(conn, cfg))
	})
}

// dialTLS connects to addr with serverName and returns the connection and the
// common name of the certificate the far end presented.
func dialTLS(t *testing.T, addr, serverName string) (*tls.Conn, string) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial %s as %q: %v", addr, serverName, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

// requireEcho writes msg and reads it back within 2 s.
func requireEcho(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// requireClosed waits up to 2 s for the far end to close conn and fails when
// a byte arrives first.
func requireClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n > 0 {
		t.Fatalf("read %q, want the connection closed without a byte", buf[:n])
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("connection still open after 2s")
	}
}

// countingConn counts the bytes read from the connection.
type countingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func backendRule(t *testing.T, slug string, port int, host string, b *testBackend) api.IngressRule {
	t.Helper()
	return ingressRule(slug, port, host, b.port(t))
}

// TestIngressIntegration_SNIHostsShareAPort routes two server names on one
// port to two TLS backends, each presenting its own certificate.
func TestIngressIntegration_SNIHostsShareAPort(t *testing.T) {
	a := startTLSBackend(t, "a.example.com")
	b := startTLSBackend(t, "b.example.com")
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply([]api.IngressRule{
		backendRule(t, "a", 443, "a.example.com", a),
		backendRule(t, "b", 443, "b.example.com", b),
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, name := range []string{"a.example.com", "b.example.com"} {
		conn, cn := dialTLS(t, ctrl.addr(443), name)
		if cn != name {
			t.Errorf("server name %s got the certificate of %s", name, cn)
		}
		requireEcho(t, conn, "hello "+name)
	}
	if a.accepted.Load() != 1 || b.accepted.Load() != 1 {
		t.Errorf("backends accepted %d and %d connections, want 1 each", a.accepted.Load(), b.accepted.Load())
	}
}

// TestIngressIntegration_WildcardAndExactHosts sends a name under a wildcard
// to the wildcard's backend and a name both cover to the exact rule's.
func TestIngressIntegration_WildcardAndExactHosts(t *testing.T) {
	wild := startTLSBackend(t, "wild.example.com")
	api1 := startTLSBackend(t, "api.apps.example.com")
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply([]api.IngressRule{
		backendRule(t, "wild", 443, "*.apps.example.com", wild),
		backendRule(t, "api", 443, "api.apps.example.com", api1),
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, tc := range []struct{ name, wantCN string }{
		{name: "x.apps.example.com", wantCN: "wild.example.com"},
		{name: "API.apps.example.com", wantCN: "api.apps.example.com"},
	} {
		if _, cn := dialTLS(t, ctrl.addr(443), tc.name); cn != tc.wantCN {
			t.Errorf("server name %s got the certificate of %s, want %s", tc.name, cn, tc.wantCN)
		}
	}
}

// TestIngressIntegration_UnservedConnectionsAreClosed closes a connection for
// a terminate rule's host, for a name no rule matches, without SNI, and with
// bytes that are not TLS, without a byte from any backend.
func TestIngressIntegration_UnservedConnectionsAreClosed(t *testing.T) {
	a := startTLSBackend(t, "a.example.com")
	term := backendRule(t, "term", 443, "t.example.com", a)
	term.Mode = api.IngressModeTerminate
	ctrl := newLoopbackIngressController(t)
	mgr, logs := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply([]api.IngressRule{
		backendRule(t, "a", 443, "a.example.com", a),
		backendRule(t, "wild", 443, "*.apps.example.com", a),
		term,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, tc := range []struct {
		name       string
		serverName string // "" sends no SNI
		reason     string
	}{
		{name: "terminate host", serverName: "t.example.com", reason: "rule_not_served"},
		{name: "no matching rule", serverName: "none.example.com", reason: "no_matching_rule"},
		{name: "two labels under the wildcard", serverName: "x.y.apps.example.com", reason: "no_matching_rule"},
		{name: "no SNI", reason: "no_server_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.DialTimeout("tcp", ctrl.addr(443), 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer raw.Close()
			counted := &countingConn{Conn: raw}
			_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
			cfg := &tls.Config{ServerName: tc.serverName, InsecureSkipVerify: true}
			if err := tls.Client(counted, cfg).Handshake(); err == nil {
				t.Fatal("handshake succeeded, want the bridge to close the connection")
			}
			if n := counted.read.Load(); n != 0 {
				t.Errorf("client read %d bytes, want none", n)
			}
			logs.waitFor(t, "reason="+tc.reason, 1)
		})
	}

	t.Run("not TLS", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ctrl.addr(443), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer raw.Close()
		if _, err := raw.Write([]byte("GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		requireClosed(t, raw)
		logs.waitFor(t, "reason=no_client_hello", 1)
	})

	if n := a.accepted.Load(); n != 0 {
		t.Errorf("backend accepted %d connections, want none", n)
	}
	if got := logLines(logs, `level=DEBUG`, `msg="ingress connection closed"`, "listen_port=443", "remote="); got != 5 {
		t.Errorf("%d 'ingress connection closed' lines at Debug, want 5:\n%s", got, logs.String())
	}
}

// TestIngressIntegration_PlainPortServerSpeaksFirst forwards a plain port
// without reading, so a client that sends nothing reads the banner the
// backend writes first.
func TestIngressIntegration_PlainPortServerSpeaksFirst(t *testing.T) {
	b := startBackend(t, "tcp", "127.0.0.1:0", banner("SSH-2.0-plexd-e2e\r\n"))
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply([]api.IngressRule{backendRule(t, "ssh", 7022, "", b)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	conn, err := net.DialTimeout("tcp", ctrl.addr(7022), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len("SSH-2.0-plexd-e2e\r\n"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(buf) != "SSH-2.0-plexd-e2e\r\n" {
		t.Errorf("banner = %q", buf)
	}
}

// TestIngressIntegration_IPv6Target dials a target on the IPv6 loopback.
func TestIngressIntegration_IPv6Target(t *testing.T) {
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = probe.Close()

	b := startBackend(t, "tcp", "[::1]:0", echo)
	rule := backendRule(t, "v6", 7022, "", b)
	rule.TargetAddress = "::1"
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply([]api.IngressRule{rule}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	conn, err := net.DialTimeout("tcp", ctrl.addr(7022), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	requireEcho(t, conn, "over v6")
}

// TestIngressIntegration_RemoveRuleClosesItsConnections removes one of two
// rules on a port: its connection closes, the other keeps echoing, and the
// listener stays open.
func TestIngressIntegration_RemoveRuleClosesItsConnections(t *testing.T) {
	a := startTLSBackend(t, "a.example.com")
	b := startTLSBackend(t, "b.example.com")
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	ruleA := backendRule(t, "a", 443, "a.example.com", a)
	ruleB := backendRule(t, "b", 443, "b.example.com", b)
	if err := mgr.Apply([]api.IngressRule{ruleA, ruleB}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	connA, _ := dialTLS(t, ctrl.addr(443), "a.example.com")
	connB, _ := dialTLS(t, ctrl.addr(443), "b.example.com")
	requireEcho(t, connA, "a")
	requireEcho(t, connB, "b")

	if err := mgr.Apply([]api.IngressRule{ruleB}); err != nil {
		t.Fatalf("Apply without a: %v", err)
	}
	requireClosed(t, connA)
	requireEcho(t, connB, "b still")
	if got := len(ctrl.ingressCallsFor("Close")); got != 0 {
		t.Errorf("Close calls = %d, want 0", got)
	}
	if got := mgr.IngressStatus().RuleCount; got != 1 {
		t.Errorf("RuleCount = %d, want 1", got)
	}
}

// TestIngressIntegration_ChangedTargetPort closes the connection of a rule
// whose target changed and sends the next connection to the new target.
func TestIngressIntegration_ChangedTargetPort(t *testing.T) {
	one := startBackend(t, "tcp", "127.0.0.1:0", banner("one\n"))
	two := startBackend(t, "tcp", "127.0.0.1:0", banner("two\n"))
	ctrl := newLoopbackIngressController(t)
	mgr, logs := newActiveIngressManager(t, ctrl)
	rule := backendRule(t, "web", 7022, "", one)
	if err := mgr.Apply([]api.IngressRule{rule}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	readBanner := func(conn net.Conn) string {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read banner: %v", err)
		}
		return string(buf)
	}
	first, err := net.DialTimeout("tcp", ctrl.addr(7022), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	if got := readBanner(first); got != "one\n" {
		t.Fatalf("first connection banner = %q, want one", got)
	}

	rule.TargetPort = two.port(t)
	if err := mgr.Apply([]api.IngressRule{rule}); err != nil {
		t.Fatalf("Apply with the new target: %v", err)
	}
	requireClosed(t, first)
	second, err := net.DialTimeout("tcp", ctrl.addr(7022), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	if got := readBanner(second); got != "two\n" {
		t.Errorf("second connection banner = %q, want two", got)
	}
	if got := logLines(logs, `msg="ingress rule updated"`, "rule_id=id-web"); got != 1 {
		t.Errorf("%d 'ingress rule updated' lines, want 1:\n%s", got, logs.String())
	}
}

// TestIngressIntegration_DialRefusedClosesClient closes the client when the
// target refuses the connection and logs the failed dial.
func TestIngressIntegration_DialRefusedClosesClient(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p, _ := net.SplitHostPort(closed.Addr().String())
	_ = closed.Close()
	port, _ := strconv.Atoi(p)

	ctrl := newLoopbackIngressController(t)
	mgr, logs := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply([]api.IngressRule{ingressRule("web", 7022, "", port)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	conn, err := net.DialTimeout("tcp", ctrl.addr(7022), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	requireClosed(t, conn)
	logs.waitFor(t, `msg="bridge: ingress: dial target failed"`, 1)
	target := "target=127.0.0.1:" + p
	if got := logLines(logs, `level=ERROR`, `msg="bridge: ingress: dial target failed"`, "rule_id=id-web", "slug=web", target, errConnRefused.Error()); got != 1 {
		t.Errorf("no Error line with rule_id, slug, %s and %q:\n%s", target, errConnRefused.Error(), logs.String())
	}
}

// TestIngressIntegration_ReconcileAppliesTheBlock wires the manager to a real
// Reconciler: a pulled block opens its ports, a changed block moves them, and
// an absent block closes them.
func TestIngressIntegration_ReconcileAppliesTheBlock(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	block := func(rules ...api.IngressRule) *api.NodeStateSnapshot {
		return &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Rules: rules}}}
	}
	fetcher := &integrationStateFetcher{state: block(ingressRule("one", 7022, "", 9000))}

	rec := reconcile.NewReconciler(fetcher, reconcile.Config{Interval: time.Hour}, discardLogger())
	rec.RegisterHandler(IngressReconcileHandler(mgr, discardLogger()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx, "node-ingress") }()

	waitForCondition(t, 2*time.Second, func() bool { return len(ctrl.ingressCallsFor("Listen")) == 1 })

	fetcher.setState(block(ingressRule("two", 7023, "", 9000), ingressRule("three", 7024, "", 9000)))
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool {
		return len(ctrl.ingressCallsFor("Listen")) == 3 && len(ctrl.ingressCallsFor("Close")) == 1
	})

	fetcher.setState(&api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{}})
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool { return len(ctrl.ingressCallsFor("Close")) == 3 })

	cancel()
	<-done
	if got := ctrl.listenAddrs(); strings.Join(got, " ") != ":7022 :7023 :7024" {
		t.Errorf("Listen addresses = %v", got)
	}
}
