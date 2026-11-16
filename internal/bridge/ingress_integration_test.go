package bridge

import (
	"bytes"
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
	"slices"
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
	if err := mgr.Apply(t.Context(), rulesBlock(
		backendRule(t, "a", 443, "a.example.com", a),
		backendRule(t, "b", 443, "b.example.com", b),
	)); err != nil {
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
	if err := mgr.Apply(t.Context(), rulesBlock(
		backendRule(t, "wild", 443, "*.apps.example.com", wild),
		backendRule(t, "api", 443, "api.apps.example.com", api1),
	)); err != nil {
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
// the host of a terminate rule without a certificate, for the host of an acme
// rule with a reason, for a name no rule matches, without SNI, and with bytes
// that are not TLS, without a byte from any backend.
func TestIngressIntegration_UnservedConnectionsAreClosed(t *testing.T) {
	a := startTLSBackend(t, "a.example.com")
	term := terminateRule("term", 443, "t.example.com", "tls", a.port(t))
	acme := acmeRule("acme", 443, "acme.example.com", a.port(t))
	ctrl := newLoopbackIngressController(t)
	mgr, logs := newActiveIngressManager(t, ctrl)
	// The block has no acme member, so the acme rule reads
	// acme_directory_invalid.
	if err := mgr.Apply(t.Context(), rulesBlock(
		backendRule(t, "a", 443, "a.example.com", a),
		backendRule(t, "wild", 443, "*.apps.example.com", a),
		term,
		acme,
	)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, tc := range []struct {
		name       string
		serverName string // "" sends no SNI
		reason     string
	}{
		{name: "terminate host without a certificate", serverName: "t.example.com", reason: "no_certificate"},
		{name: "acme host with a reason", serverName: "acme.example.com", reason: "rule_not_served"},
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
	if got := logLines(logs, `level=DEBUG`, `msg="ingress connection closed"`, "listen_port=443", "remote="); got != 6 {
		t.Errorf("%d 'ingress connection closed' lines at Debug, want 6:\n%s", got, logs.String())
	}
}

// TestIngressIntegration_PlainPortServerSpeaksFirst forwards a plain port
// without reading, so a client that sends nothing reads the banner the
// backend writes first.
func TestIngressIntegration_PlainPortServerSpeaksFirst(t *testing.T) {
	b := startBackend(t, "tcp", "127.0.0.1:0", banner("SSH-2.0-plexd-e2e\r\n"))
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	if err := mgr.Apply(t.Context(), rulesBlock(backendRule(t, "ssh", 7022, "", b))); err != nil {
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
	if err := mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
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
	if err := mgr.Apply(t.Context(), rulesBlock(ruleA, ruleB)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	connA, _ := dialTLS(t, ctrl.addr(443), "a.example.com")
	connB, _ := dialTLS(t, ctrl.addr(443), "b.example.com")
	requireEcho(t, connA, "a")
	requireEcho(t, connB, "b")

	if err := mgr.Apply(t.Context(), rulesBlock(ruleB)); err != nil {
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
	if err := mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
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
	if err := mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
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
	if err := mgr.Apply(t.Context(), rulesBlock(ingressRule("web", 7022, "", port))); err != nil {
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
// Reconciler: a pulled block opens its ports, a changed block moves them, an
// absent block closes them, and so does the same rules' block once it no
// longer enables public ingress.
func TestIngressIntegration_ReconcileAppliesTheBlock(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)
	block := func(rules ...api.IngressRule) *api.NodeStateSnapshot {
		return &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Enabled: true, Rules: rules}}}
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

	enabled := block(ingressRule("two", 7023, "", 9000), ingressRule("three", 7024, "", 9000))
	fetcher.setState(enabled)
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool { return len(ctrl.ingressCallsFor("Listen")) == 5 })
	opened := []string{ctrl.addr(7023), ctrl.addr(7024)}

	notEnabled := *enabled.Bridge.Ingress
	notEnabled.Enabled = false
	fetcher.setState(&api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &notEnabled}})
	rec.TriggerReconcile()
	waitForCondition(t, 2*time.Second, func() bool { return len(ctrl.ingressCallsFor("Close")) == 5 })
	for _, addr := range opened {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()
		}
		if !errors.Is(err, errConnRefused) {
			t.Errorf("dial %s after the block stopped enabling ingress = %v, want it refused", addr, err)
		}
	}

	cancel()
	<-done
	if got := ctrl.listenAddrs(); strings.Join(got, " ") != ":7022 :7023 :7024 :7023 :7024" {
		t.Errorf("Listen addresses = %v", got)
	}
}

// recordingEcho echoes and sends every chunk it reads to got.
func recordingEcho(got chan<- []byte) func(net.Conn) {
	return func(conn net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				got <- bytes.Clone(buf[:n])
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
}

// clientHelloBytes returns the ClientHello a Go client sends for serverName.
func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	conn, _, stop := startTLSClient(t, &tls.Config{ServerName: serverName}, 0)
	_, peeked, err := peekClientHello(conn, 2*time.Second)
	stop()
	if err != nil {
		t.Fatalf("peek the client hello: %v", err)
	}
	return peeked
}

// TestIngressIntegration_TerminateServesTheSecretsCertificate ends TLS at the
// bridge with the certificate of the rule's Secret, negotiates no protocol,
// and forwards the plaintext to the target.
func TestIngressIntegration_TerminateServesTheSecretsCertificate(t *testing.T) {
	got := make(chan []byte, 16)
	backend := startBackend(t, "tcp", "127.0.0.1:0", recordingEcho(got))
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	doc := certPEM(t, "t.example.com", "v1")
	fx.certs.set("tls", 1, doc)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(terminateRule("term", 443, "t.example.com", "tls", backend.port(t)))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	conn := dialTerminated(t, ctrl.addr(443), "t.example.com", certPool(t, doc), "h2", "http/1.1")
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
		t.Errorf("negotiated protocol %q, want none", p)
	}
	requireEcho(t, conn, "plaintext through the session")
	select {
	case b := <-got:
		if string(b) != "plaintext through the session" {
			t.Errorf("backend read %q, want the plaintext", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend read nothing")
	}
	if n := backend.accepted.Load(); n != 1 {
		t.Errorf("backend accepted %d connections, want 1", n)
	}
}

// TestIngressIntegration_TerminateAndPassthroughShareAPort routes a terminate
// rule and a passthrough rule on one port to their own backends; the
// passthrough client gets the backend's own certificate.
func TestIngressIntegration_TerminateAndPassthroughShareAPort(t *testing.T) {
	plain := startBackend(t, "tcp", "127.0.0.1:0", echo)
	passBackend := startTLSBackend(t, "p.example.com")
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	doc := certPEM(t, "t.example.com", "term")
	fx.certs.set("tls", 1, doc)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(
		terminateRule("term", 443, "t.example.com", "tls", plain.port(t)),
		backendRule(t, "pass", 443, "p.example.com", passBackend),
	)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	term := dialTerminated(t, ctrl.addr(443), "t.example.com", certPool(t, doc))
	requireEcho(t, term, "to the plaintext backend")
	pass, cn := dialTLS(t, ctrl.addr(443), "p.example.com")
	if cn != "p.example.com" {
		t.Errorf("passthrough client got the certificate of %s, want the backend's", cn)
	}
	requireEcho(t, pass, "to the TLS backend")
	if plain.accepted.Load() != 1 || passBackend.accepted.Load() != 1 {
		t.Errorf("backends accepted %d and %d connections, want 1 each", plain.accepted.Load(), passBackend.accepted.Load())
	}
}

// TestIngressIntegration_TerminateWithoutAHandshake closes the connection of a
// terminate rule without a loaded certificate before its handshake, and one
// whose client sends a ClientHello and then stays silent after the handshake
// timeout.
func TestIngressIntegration_TerminateWithoutAHandshake(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	const handshakeTimeout = 300 * time.Millisecond
	fx.mgr.handshakeTimeout = handshakeTimeout
	fx.certs.set("tls-a", 1, certPEM(t, "a.example.com", "a"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls-a", 1))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(
		terminateRule("none", 443, "none.example.com", "tls-none", backend.port(t)),
		terminateRule("a", 443, "a.example.com", "tls-a", backend.port(t)),
	)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	t.Run("no certificate", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", ctrl.addr(443), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer raw.Close()
		counted := &countingConn{Conn: raw}
		_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
		if err := tls.Client(counted, &tls.Config{ServerName: "none.example.com", InsecureSkipVerify: true}).Handshake(); err == nil {
			t.Fatal("handshake succeeded, want the bridge to close the connection")
		}
		if n := counted.read.Load(); n != 0 {
			t.Errorf("client read %d bytes, want none", n)
		}
		fx.logs.waitFor(t, "reason=no_certificate", 1)
	})

	t.Run("silent after the ClientHello", func(t *testing.T) {
		hello := clientHelloBytes(t, "a.example.com")
		raw, err := net.DialTimeout("tcp", ctrl.addr(443), 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer raw.Close()
		start := time.Now()
		if _, err := raw.Write(hello); err != nil {
			t.Fatalf("write the client hello: %v", err)
		}
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.Copy(io.Discard, raw); err != nil {
			t.Fatalf("read until the bridge closes: %v", err)
		}
		if elapsed := time.Since(start); elapsed < handshakeTimeout {
			t.Errorf("closed after %v, want the %v handshake timeout", elapsed, handshakeTimeout)
		}
		fx.logs.waitFor(t, "reason=tls_handshake_failed", 1)
	})

	if n := backend.accepted.Load(); n != 0 {
		t.Errorf("backend accepted %d connections, want none", n)
	}
}

// TestIngressIntegration_RemoveTerminateRuleClosesItsConnection removes a
// terminate rule beside a passthrough rule on its port: its established TLS
// connection closes and the listener stays open.
func TestIngressIntegration_RemoveTerminateRuleClosesItsConnection(t *testing.T) {
	plain := startBackend(t, "tcp", "127.0.0.1:0", echo)
	passBackend := startTLSBackend(t, "p.example.com")
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	doc := certPEM(t, "t.example.com", "v1")
	fx.certs.set("tls", 1, doc)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	pass := backendRule(t, "pass", 443, "p.example.com", passBackend)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(terminateRule("term", 443, "t.example.com", "tls", plain.port(t)), pass)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	conn := dialTerminated(t, ctrl.addr(443), "t.example.com", certPool(t, doc))
	requireEcho(t, conn, "before")

	if err := fx.mgr.Apply(t.Context(), rulesBlock(pass)); err != nil {
		t.Fatalf("Apply without the terminate rule: %v", err)
	}
	requireClosed(t, conn)
	if got := len(ctrl.ingressCallsFor("Close")); got != 0 {
		t.Errorf("Close calls = %d, want 0", got)
	}
}

// hookCertificate makes the ACME manager answer every GetCertificate with a
// certificate for host, and returns the ALPN list of every hello it saw.
func hookCertificate(t *testing.T, mgr *ACMEManager, host string) (*tls.Certificate, func() [][]string) {
	t.Helper()
	cert := selfSignedCert(t, host)
	var mu sync.Mutex
	var seen [][]string
	mgr.getCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		seen = append(seen, slices.Clone(hello.SupportedProtos))
		mu.Unlock()
		return &cert, nil
	}
	return &cert, func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// dialALPN completes a TLS handshake with addr as serverName, offering protos
// and accepting any certificate, within 2 s.
func dialALPN(addr, serverName string, protos ...string) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		NextProtos:         protos,
		InsecureSkipVerify: true,
	})
}

// TestIngressIntegration_ACMEChallenge answers a TLS-ALPN-01 challenge on port
// 443 for the host of an acme rule on 8443, first on a challenge-only port and
// then beside a passthrough rule, closes the same hello for an unknown host,
// and forwards it for the host of the passthrough rule. On 8443 the same hello
// is terminated. For an acme rule on 443 itself, the challenge hello is
// answered and every other client is terminated and forwarded.
func TestIngressIntegration_ACMEChallenge(t *testing.T) {
	acmeBackend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	webBackend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	passBackend := startTLSBackend(t, "p.example.com")
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	_, seen := hookCertificate(t, fx.acme, "acme.example.com")
	acme := acmeRule("acme", 8443, "acme.example.com", acmeBackend.port(t))
	pass := backendRule(t, "pass", 443, "p.example.com", passBackend)

	challenge := func(serverName string) (*tls.Conn, error) {
		return dialALPN(ctrl.addr(acmeChallengePort), serverName, "acme-tls/1")
	}
	requireAnswered := func(serverName string, n int) {
		t.Helper()
		conn, err := challenge(serverName)
		if err != nil {
			t.Fatalf("challenge handshake for %s: %v", serverName, err)
		}
		if p := conn.ConnectionState().NegotiatedProtocol; p != "acme-tls/1" {
			t.Errorf("challenge for %s negotiated protocol %q, want acme-tls/1", serverName, p)
		}
		_ = conn.Close()
		fx.logs.waitFor(t, `msg="ingress acme challenge answered" component=bridge server_name=`+serverName, n)
		if !slices.ContainsFunc(seen(), func(protos []string) bool { return slices.Equal(protos, []string{"acme-tls/1"}) }) {
			t.Errorf("the hook saw the protocol lists %q, want one of [acme-tls/1]", seen())
		}
	}

	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{acme}, ACME: testACME}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireAnswered("acme.example.com", 1)

	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{
		Rules: []api.IngressRule{acme, pass},
		ACME:  testACME,
	}); err != nil {
		t.Fatalf("Apply with a passthrough rule on 443: %v", err)
	}
	requireAnswered("acme.example.com", 2)

	if conn, err := challenge("none.example.com"); err == nil {
		_ = conn.Close()
		t.Error("challenge for an unknown host succeeded, want the connection closed")
	}
	fx.logs.waitFor(t, "server_name=none.example.com reason=no_matching_rule", 1)

	conn, err := challenge("p.example.com")
	if err != nil {
		t.Fatalf("challenge hello for the passthrough host: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "p.example.com" {
		t.Errorf("challenge hello for the passthrough host got the certificate of %s, want the backend's", cn)
	}
	requireEcho(t, conn, "to the passthrough backend")
	if n := passBackend.accepted.Load(); n != 1 {
		t.Errorf("passthrough backend accepted %d connections, want 1", n)
	}
	if n := acmeBackend.accepted.Load(); n != 0 {
		t.Errorf("acme backend accepted %d connections, want none", n)
	}

	// A challenge is answered on port 443 only: on 8443 the same hello is an
	// ordinary client of the acme rule.
	other, err := dialALPN(ctrl.addr(8443), "acme.example.com", "acme-tls/1")
	if err != nil {
		t.Fatalf("acme-tls/1 hello to 8443: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	if p := other.ConnectionState().NegotiatedProtocol; p != "" {
		t.Errorf("acme-tls/1 hello to 8443 negotiated protocol %q, want none", p)
	}
	requireEcho(t, other, "to the acme backend")
	if n := acmeBackend.accepted.Load(); n != 1 {
		t.Errorf("acme backend accepted %d connections, want 1", n)
	}

	// An acme rule on 443 itself.
	web := acmeRule("web", 443, "web.example.com", webBackend.port(t))
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{acme, pass, web}, ACME: testACME}); err != nil {
		t.Fatalf("Apply with an acme rule on 443: %v", err)
	}
	if st := stateOf(t, fx.mgr, "web"); !st.Served {
		t.Fatalf("acme rule on 443 = %+v, want served", st)
	}
	requireAnswered("web.example.com", 1)
	if n := webBackend.accepted.Load(); n != 0 {
		t.Errorf("the backend of the acme rule on 443 accepted %d connections after a challenge, want none", n)
	}
	for _, protos := range [][]string{{"h2", "http/1.1"}, nil} {
		conn, err := dialALPN(ctrl.addr(443), "web.example.com", protos...)
		if err != nil {
			t.Fatalf("client offering %q to the acme rule on 443: %v", protos, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
			t.Errorf("client offering %q negotiated protocol %q, want none", protos, p)
		}
		requireEcho(t, conn, "to the acme rule on 443")
	}
	if n := webBackend.accepted.Load(); n != 2 {
		t.Errorf("the backend of the acme rule on 443 accepted %d connections, want 2", n)
	}
	if n := passBackend.accepted.Load(); n != 1 {
		t.Errorf("passthrough backend accepted %d connections, want still 1", n)
	}
}

// TestIngressIntegration_ACMERuleTerminates ends TLS for an acme rule with the
// account's certificate, negotiates no protocol, and forwards the plaintext,
// and closes the connection of an acme rule with a reason.
func TestIngressIntegration_ACMERuleTerminates(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	cert, _ := hookCertificate(t, fx.acme, "acme.example.com")
	rule := acmeRule("acme", 8443, "acme.example.com", backend.port(t))
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{rule}, ACME: testACME}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	conn, err := dialALPN(ctrl.addr(8443), "acme.example.com", "h2", "http/1.1")
	if err != nil {
		t.Fatalf("tls dial the acme rule offering h2 and http/1.1: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if leaf := conn.ConnectionState().PeerCertificates[0]; !bytes.Equal(leaf.Raw, cert.Certificate[0]) {
		t.Error("the client got another certificate than the account's")
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
		t.Errorf("negotiated protocol %q, want none", p)
	}
	requireEcho(t, conn, "plaintext to the acme rule's target")

	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply without the acme member: %v", err)
	}
	raw, err := net.DialTimeout("tcp", ctrl.addr(8443), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tls.Client(raw, &tls.Config{ServerName: "acme.example.com", InsecureSkipVerify: true}).Handshake(); err == nil {
		t.Fatal("handshake for an acme rule with a reason succeeded, want the connection closed")
	}
	fx.logs.waitFor(t, "server_name=acme.example.com reason=rule_not_served", 1)
	if n := backend.accepted.Load(); n != 1 {
		t.Errorf("backend accepted %d connections, want 1", n)
	}
}

// TestIngressIntegration_ACMEHandshakeWaitIsBounded closes a client of an acme
// rule whose certificate is not ready within the handshake timeout.
func TestIngressIntegration_ACMEHandshakeWaitIsBounded(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	const handshakeTimeout = 300 * time.Millisecond
	fx.mgr.handshakeTimeout = handshakeTimeout
	release := make(chan struct{})
	fx.acme.getCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		<-release
		return nil, errors.New("test: the issuance never completed")
	}
	// Registered after the fixture, so the hook is released before the
	// fixture's teardown and no goroutine waits on it.
	t.Cleanup(func() { close(release) })
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{
		Rules: []api.IngressRule{acmeRule("acme", 8443, "acme.example.com", backend.port(t))},
		ACME:  testACME,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	raw, err := net.DialTimeout("tcp", ctrl.addr(8443), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	start := time.Now()
	_ = raw.SetDeadline(start.Add(2 * time.Second))
	err = tls.Client(raw, &tls.Config{ServerName: "acme.example.com", InsecureSkipVerify: true}).Handshake()
	if err == nil {
		t.Fatal("handshake succeeded, want the bridge to close the connection")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("the connection is still open after 2s: %v", err)
	}
	if elapsed := time.Since(start); elapsed < handshakeTimeout {
		t.Errorf("closed after %v, want the %v handshake timeout", elapsed, handshakeTimeout)
	}
	fx.logs.waitFor(t, "server_name=acme.example.com reason=tls_handshake_failed", 1)
	if n := backend.accepted.Load(); n != 0 {
		t.Errorf("backend accepted %d connections, want none", n)
	}
}

// TestIngressIntegration_HandshakeDeadlineIsCleared keeps a terminated session
// of a terminate rule and of an acme rule echoing past the handshake timeout.
func TestIngressIntegration_HandshakeDeadlineIsCleared(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	const handshakeTimeout = 300 * time.Millisecond
	fx.mgr.handshakeTimeout = handshakeTimeout
	hookCertificate(t, fx.acme, "acme.example.com")
	doc := certPEM(t, "t.example.com", "v1")
	fx.certs.set("tls", 1, doc)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{
		Rules: []api.IngressRule{
			terminateRule("term", 8443, "t.example.com", "tls", backend.port(t)),
			acmeRule("acme", 8443, "acme.example.com", backend.port(t)),
		},
		ACME: testACME,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	term := dialTerminated(t, ctrl.addr(8443), "t.example.com", certPool(t, doc))
	requireEcho(t, term, "terminate rule within the handshake timeout")
	acmeConn, err := dialALPN(ctrl.addr(8443), "acme.example.com")
	if err != nil {
		t.Fatalf("tls dial the acme rule: %v", err)
	}
	t.Cleanup(func() { _ = acmeConn.Close() })
	requireEcho(t, acmeConn, "acme rule within the handshake timeout")

	time.Sleep(2 * handshakeTimeout)
	requireEcho(t, term, "terminate rule after the handshake timeout")
	requireEcho(t, acmeConn, "acme rule after the handshake timeout")
	if n := backend.accepted.Load(); n != 2 {
		t.Errorf("backend accepted %d connections, want 2", n)
	}
}
