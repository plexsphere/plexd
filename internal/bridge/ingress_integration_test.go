package bridge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
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

// testCA is a certificate authority a test signs client certificates and
// intermediates with, at run time.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// pem is the CA certificate as one PEM CERTIFICATE block, as a ca_bundle
	// holds it.
	pem string
}

// testSerial returns a random certificate serial number.
func testSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return serial
}

// signTestCertificate signs template with parent's key, or self-signs it when
// parent is nil, and returns the certificate and its key.
func signTestCertificate(t *testing.T, template *x509.Certificate, parent *testCA) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("create certificate %q: %v", template.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", template.Subject.CommonName, err)
	}
	return cert, key
}

// caTemplate returns the template of a CA certificate named cn, valid from an
// hour ago for a day.
func caTemplate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// newTestCA returns a self-signed CA named cn, valid from an hour ago for a
// day. edit, when not nil, changes the template before it is signed, to
// expire the CA for example.
func newTestCA(t *testing.T, cn string, edit func(*x509.Certificate)) *testCA {
	t.Helper()
	template := caTemplate(t, cn)
	if edit != nil {
		edit(template)
	}
	cert, key := signTestCertificate(t, template, nil)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))}
}

// intermediate returns a CA named cn that ca signs, valid from an hour ago
// for a day. edit, when not nil, changes the template before it is signed.
func (ca *testCA) intermediate(t *testing.T, cn string, edit func(*x509.Certificate)) *testCA {
	t.Helper()
	template := caTemplate(t, cn)
	if edit != nil {
		edit(template)
	}
	cert, key := signTestCertificate(t, template, ca)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))}
}

// issue returns a client certificate for cn that ca signs, with the extended
// key usage clientAuth, valid from a minute ago for an hour. Its chain holds
// the leaf alone; a test that sends intermediates appends their Raw bytes.
// edit, when not nil, changes the template before it is signed, to expire the
// leaf or drop its usage for example.
func (ca *testCA) issue(t *testing.T, cn string, edit func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: testSerial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if edit != nil {
		edit(template)
	}
	leaf, key := signTestCertificate(t, template, ca)
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

// caBundle joins the certificates of cas, in order, into one ca_bundle.
func caBundle(cas ...*testCA) string {
	var b strings.Builder
	for _, ca := range cas {
		b.WriteString(ca.pem)
	}
	return b.String()
}

// withClientAuth returns an edit that gives a rule client_auth with bundle as
// its ca_bundle.
func withClientAuth(bundle string) func(*api.IngressRule) {
	return func(r *api.IngressRule) {
		r.ClientAuth = &api.IngressClientAuth{CABundle: bundle}
	}
}

// dialTLSClient connects to addr with serverName, presenting cert as the
// client certificate, or none when cert is nil, without verifying the
// bridge's certificate. It presents cert through GetClientCertificate, so the
// client sends it also when its issuer is not among the authorities the
// bridge's certificate request names, which crypto/tls would otherwise
// answer with no certificate. edit, when not nil, changes the client's
// config, to pin a TLS version for example. It returns the connection once
// the client's side of the handshake completed, or the handshake's error. In
// TLS 1.3 a refused client completes its own side and reads the bridge's
// alert on its first read, so a test asserts on that read (requireClosed),
// never on the dial's error alone.
func dialTLSClient(t *testing.T, addr, serverName string, cert *tls.Certificate, edit func(*tls.Config)) (*tls.Conn, error) {
	t.Helper()
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
	if cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	if edit != nil {
		edit(cfg)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
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

// TestIngressIntegration_DialSucceededIsRecorded reports a dial that reached
// its target at the manager's clock and signals the change once; a second
// dial that succeeds moves the time and signals nothing.
func TestIngressIntegration_DialSucceededIsRecorded(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	clock := &relayClock{now: relayStart}
	fx.mgr.now = clock.Now
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(backendRule(t, "web", 7022, "", backend), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	changed := fx.mgr.ReportChanged()
	drain(changed)

	// The bridge records the dial before it copies, so the echo proves the
	// record is stored.
	requireEcho(t, connect(t, ctrl.addr(7022)), "one")
	requireSignal(t, changed, "the first dial")
	want := IngressRuleReport{
		RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
		Dial: api.IngressDialSucceeded, DialAt: relayStart,
	}
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("after the first dial: report = %+v, want %+v", got, want)
	}

	clock.Add(5 * time.Second)
	requireEcho(t, connect(t, ctrl.addr(7022)), "two")
	want.DialAt = relayStart.Add(5 * time.Second)
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("after the second dial: report = %+v, want %+v", got, want)
	}
	requireNoSignal(t, changed, "a second dial that succeeded")
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	port, _ := strconv.Atoi(p)
	return port
}

// TestIngressIntegration_DialRefusedIsReported reports a dial to a closed
// port as refused, without a dial policy.
func TestIngressIntegration_DialRefusedIsReported(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(ingressRule("web", 7022, "", closedPort(t)), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	requireClosed(t, connect(t, ctrl.addr(7022)))
	fx.logs.waitFor(t, `msg="bridge: ingress: dial target failed"`, 1)
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialFailed || got.DialReason != IngressDialReasonRefused {
		t.Errorf("report = %+v, want dial failed with %s", got, IngressDialReasonRefused)
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id="+id, "reason=refused"); got != 1 {
		t.Errorf("%d Error lines with rule_id=%s and reason=refused, want 1:\n%s", got, id, fx.logs.String())
	}
}

// TestIngressIntegration_DialPolicyDeniedIsReported names a failed dial
// policy_denied when the dial policy blocks the target.
func TestIngressIntegration_DialPolicyDeniedIsReported(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	fx := buildIngressFixture(t, ctrl, ingressTestConfig(true))
	policy := &fakeDialPolicy{denied: true}
	fx.mgr.SetDialPolicy(policy)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	port := closedPort(t)
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(ingressRule("web", 7022, "", port), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	requireClosed(t, connect(t, ctrl.addr(7022)))
	fx.logs.waitFor(t, `msg="bridge: ingress: dial target failed"`, 1)
	if got := reportFor(t, fx.mgr.RuleReports(), id); got.Dial != api.IngressDialFailed || got.DialReason != IngressDialReasonPolicyDenied {
		t.Errorf("report = %+v, want dial failed with %s", got, IngressDialReasonPolicyDenied)
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id="+id, "reason=policy_denied"); got != 1 {
		t.Errorf("%d Error lines with rule_id=%s and reason=policy_denied, want 1:\n%s", got, id, fx.logs.String())
	}
	if got, want := policy.asked(), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)); len(got) != 1 || got[0] != want {
		t.Errorf("the dial policy was asked about %v, want [%s]", got, want)
	}
}

// TestIngressIntegration_HeldPortReadsListenFailed reports a rule whose port
// another socket holds as not listening, with listen_failed.
func TestIngressIntegration_HeldPortReadsListenFailed(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer holder.Close()
	_, p, _ := net.SplitHostPort(holder.Addr().String())
	port, _ := strconv.Atoi(p)
	// Bind the loopback address of the port the manager asks for, which the
	// holder owns.
	ctrl := &mockIngressController{listenFn: func(addr string, _ *tls.Config) (net.Listener, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	}}
	fx := newIngressFixture(t, ctrl)
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(ingressRule("web", port, "", 9000), id))); err == nil {
		t.Fatalf("Apply on port %d, which another socket holds: nil error, want the bind error", port)
	}
	want := IngressRuleReport{RuleID: id, Listener: api.IngressListenerNotListening, ListenerReason: IngressReasonListenFailed}
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("report = %+v, want %+v", got, want)
	}
}

// dialLog dials for the manager and records the address of every dial, in
// order.
type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialLog) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

// dialled returns the address of every dial so far, in order.
func (d *dialLog) dialled() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.addrs)
}

// newDialLogFixture returns a set-up manager on a settable clock that dials
// through a dialLog.
func newDialLogFixture(t *testing.T, ctrl IngressController) (*ingressFixture, *relayClock, *dialLog) {
	t.Helper()
	fx := newIngressFixture(t, ctrl)
	clock := &relayClock{now: relayStart}
	fx.mgr.now = clock.Now
	dials := &dialLog{}
	fx.mgr.dial = dials.dial
	return fx, clock, dials
}

// targetOn returns a target on the loopback port port.
func targetOn(port int) api.IngressTarget {
	return api.IngressTarget{NodeID: "node-" + strconv.Itoa(port), Address: "127.0.0.1", Port: port}
}

// addrOf returns the address the bridge dials for target.
func addrOf(target api.IngressTarget) string {
	return net.JoinHostPort(target.Address, strconv.Itoa(target.Port))
}

// bannerOf reads the four-byte banner a backend writes first, within 2 s.
func bannerOf(t *testing.T, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	return string(buf)
}

// TestIngressIntegration_RoundRobinAcrossTargets sends the connections of a
// plain rule with two targets to them in turn, the first target first.
func TestIngressIntegration_RoundRobinAcrossTargets(t *testing.T) {
	one := startBackend(t, "tcp", "127.0.0.1:0", banner("one\n"))
	two := startBackend(t, "tcp", "127.0.0.1:0", banner("two\n"))
	ctrl := newLoopbackIngressController(t)
	mgr, logs := newActiveIngressManager(t, ctrl)
	rule := ingressRule("web", 7022, "", one.port(t))
	rule.Targets = []api.IngressTarget{targetOn(one.port(t)), targetOn(two.port(t))}
	if err := mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var got []string
	for range 4 {
		got = append(got, bannerOf(t, connect(t, ctrl.addr(7022))))
	}
	if want := []string{"one\n", "two\n", "one\n", "two\n"}; !slices.Equal(got, want) {
		t.Errorf("banners = %q, want %q", got, want)
	}
	if a, b := one.accepted.Load(), two.accepted.Load(); a != 2 || b != 2 {
		t.Errorf("the backends accepted %d and %d connections, want 2 each", a, b)
	}
	targets := "targets=" + addrOf(rule.Targets[0]) + "," + addrOf(rule.Targets[1])
	if got := logLines(logs, `msg="ingress rule added"`, "rule_id=id-web", targets); got != 1 {
		t.Errorf("%d 'ingress rule added' lines with %s, want 1:\n%s", got, targets, logs.String())
	}
	if got := logLines(logs, `msg="ingress rule added"`, " target="); got != 0 {
		t.Errorf("%d 'ingress rule added' lines with a target key, want 0:\n%s", got, logs.String())
	}
}

// TestIngressIntegration_FailoverToTheNextTarget serves a connection whose
// first target refuses on the second target and passes the first over for
// the connections after it.
func TestIngressIntegration_FailoverToTheNextTarget(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", banner("two\n"))
	ctrl := newLoopbackIngressController(t)
	fx, _, dials := newDialLogFixture(t, ctrl)
	refusing, serving := targetOn(closedPort(t)), targetOn(backend.port(t))
	rule := ingressRule("web", 7022, "", refusing.Port)
	rule.Targets = []api.IngressTarget{refusing, serving}
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for i := range 3 {
		if got := bannerOf(t, connect(t, ctrl.addr(7022))); got != "two\n" {
			t.Errorf("connection %d read %q, want the second backend's banner", i+1, got)
		}
	}
	if got, want := dials.dialled(), []string{addrOf(refusing), addrOf(serving), addrOf(serving), addrOf(serving)}; !slices.Equal(got, want) {
		t.Errorf("dials = %v, want %v", got, want)
	}
	if got := logLines(fx.logs, `msg="bridge: ingress: dial target failed"`); got != 1 {
		t.Errorf("%d 'dial target failed' lines, want 1:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id=id-web", "target="+addrOf(refusing)+" ", "reason=refused"); got != 1 {
		t.Errorf("%d 'dial target failed' lines for %s with reason=refused, want 1:\n%s", got, addrOf(refusing), fx.logs.String())
	}
}

// TestIngressIntegration_AllTargetsFail closes a connection whose two targets
// refuse, reports the rule and both targets failed, and dials both again for
// the next connection.
func TestIngressIntegration_AllTargetsFail(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	fx, _, dials := newDialLogFixture(t, ctrl)
	first, second := targetOn(closedPort(t)), targetOn(closedPort(t))
	// Node ids the report accepts, so the rule entry carries both targets.
	first.NodeID, second.NodeID = targetNodeID("b1"), targetNodeID("b2")
	id := reportID("a1")
	rule := withID(ingressRule("web", 7022, "", first.Port), id)
	rule.Targets = []api.IngressTarget{first, second}
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	requireClosed(t, connect(t, ctrl.addr(7022)))
	refused := func(target api.IngressTarget) IngressTargetReport {
		return IngressTargetReport{NodeID: target.NodeID, Port: target.Port, Dial: api.IngressDialFailed, DialReason: IngressDialReasonRefused, DialAt: relayStart}
	}
	want := IngressRuleReport{
		RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
		Dial: api.IngressDialFailed, DialReason: IngressDialReasonRefused, DialAt: relayStart,
		Targets: []IngressTargetReport{refused(first), refused(second)},
	}
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("report = %+v, want %+v", got, want)
	}
	failed := dialRecord{failed: true, reason: IngressDialReasonRefused, at: relayStart}
	if _, targets := balancerFor(t, fx.mgr, id).snapshot(); !slices.Equal(targets, []dialRecord{failed, failed}) {
		t.Errorf("targets = %+v, want both failed with refused", targets)
	}
	if got, want := dials.dialled(), []string{addrOf(first), addrOf(second)}; !slices.Equal(got, want) {
		t.Errorf("dials = %v, want %v", got, want)
	}

	requireClosed(t, connect(t, ctrl.addr(7022)))
	if got, want := dials.dialled(), []string{addrOf(first), addrOf(second), addrOf(first), addrOf(second)}; !slices.Equal(got, want) {
		t.Errorf("dials after the next connection = %v, want %v", got, want)
	}
	if got := logLines(fx.logs, "level=ERROR", `msg="bridge: ingress: dial target failed"`, "rule_id="+id, "reason=refused"); got != 4 {
		t.Errorf("%d 'dial target failed' lines, want one per dial:\n%s", got, fx.logs.String())
	}
}

// TestIngressIntegration_TargetReturnsAfterHoldOut dials a target whose dial
// failed again once the manager's clock passed the hold-out, for the first
// connection whose turn it is.
func TestIngressIntegration_TargetReturnsAfterHoldOut(t *testing.T) {
	two := startBackend(t, "tcp", "127.0.0.1:0", banner("two\n"))
	ctrl := newLoopbackIngressController(t)
	fx, clock, dials := newDialLogFixture(t, ctrl)
	returning, serving := targetOn(closedPort(t)), targetOn(two.port(t))
	rule := ingressRule("web", 7022, "", returning.Port)
	rule.Targets = []api.IngressTarget{returning, serving}
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := bannerOf(t, connect(t, ctrl.addr(7022))); got != "two\n" {
		t.Fatalf("the first connection read %q, want the second backend's banner", got)
	}
	one := startBackend(t, "tcp", addrOf(returning), banner("one\n"))

	clock.Add(ingressTargetHoldOut - time.Millisecond)
	if got := bannerOf(t, connect(t, ctrl.addr(7022))); got != "two\n" {
		t.Errorf("the connection at 29.999 s read %q, want the second backend's banner", got)
	}
	clock.Add(time.Millisecond)
	if got := bannerOf(t, connect(t, ctrl.addr(7022))); got != "one\n" {
		t.Errorf("the connection at 30 s read %q, want the returned backend's banner", got)
	}
	if got, want := dials.dialled(), []string{addrOf(returning), addrOf(serving), addrOf(serving), addrOf(returning)}; !slices.Equal(got, want) {
		t.Errorf("dials = %v, want %v", got, want)
	}
	if got := one.accepted.Load(); got != 1 {
		t.Errorf("the returned backend accepted %d connections, want 1", got)
	}
}

// TestIngressIntegration_TerminateRuleFailsOver fails a terminate rule
// without conditions and a passthrough rule with sni_host over to their
// second target, which receives the client's bytes whole.
func TestIngressIntegration_TerminateRuleFailsOver(t *testing.T) {
	t.Run("terminate", func(t *testing.T) {
		backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
		ctrl := newLoopbackIngressController(t)
		fx := newIngressFixture(t, ctrl)
		doc := certPEM(t, "t.example.com", "v1")
		fx.certs.set("tls", 1, doc)
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
		refusing := targetOn(closedPort(t))
		rule := terminateRule("term", 443, "t.example.com", "tls", refusing.Port)
		rule.Targets = []api.IngressTarget{refusing, targetOn(backend.port(t))}
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		conn := dialTerminated(t, ctrl.addr(443), "t.example.com", certPool(t, doc))
		requireEcho(t, conn, "terminated at the bridge")
		if got := backend.accepted.Load(); got != 1 {
			t.Errorf("the second target accepted %d connections, want 1", got)
		}
		if got := logLines(fx.logs, `msg="bridge: ingress: dial target failed"`, "slug=term", "target="+addrOf(refusing)+" ", "reason=refused"); got != 1 {
			t.Errorf("%d 'dial target failed' lines for the first target, want 1:\n%s", got, fx.logs.String())
		}
	})

	t.Run("passthrough with sni_host", func(t *testing.T) {
		backend := startTLSBackend(t, "p.example.com")
		ctrl := newLoopbackIngressController(t)
		fx := newIngressFixture(t, ctrl)
		refusing := targetOn(closedPort(t))
		rule := ingressRule("pass", 443, "p.example.com", refusing.Port)
		rule.Targets = []api.IngressTarget{refusing, targetOn(backend.port(t))}
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply: %v", err)
		}

		conn, cn := dialTLS(t, ctrl.addr(443), "p.example.com")
		if cn != "p.example.com" {
			t.Errorf("the far end presented %q, want the second target's p.example.com", cn)
		}
		requireEcho(t, conn, "passed through")
		if got := backend.accepted.Load(); got != 1 {
			t.Errorf("the second target accepted %d connections, want 1", got)
		}
		if got := logLines(fx.logs, `msg="bridge: ingress: dial target failed"`, "slug=pass", "target="+addrOf(refusing)+" ", "reason=refused"); got != 1 {
			t.Errorf("%d 'dial target failed' lines for the first target, want 1:\n%s", got, fx.logs.String())
		}
	})
}

// ---------------------------------------------------------------------------
// Client certificates
// ---------------------------------------------------------------------------

// integTLSVersions are the versions the client certificate tests pin a
// client to. In TLS 1.2 the bridge refuses a client within the client's
// handshake; in TLS 1.3 the client completes its side first.
var integTLSVersions = []struct {
	name    string
	version uint16
}{
	{name: "TLS 1.2", version: tls.VersionTLS12},
	{name: "TLS 1.3", version: tls.VersionTLS13},
}

// integPinVersion returns a client config edit that pins version.
func integPinVersion(version uint16) func(*tls.Config) {
	return func(cfg *tls.Config) { cfg.MinVersion, cfg.MaxVersion = version, version }
}

// integRequireRefused connects to addr as serverName at version, presenting
// cert, or no certificate when cert is nil, and fails unless the bridge
// closes the client without a byte of the session: in TLS 1.2 the client's
// handshake fails, in TLS 1.3 the client completes its side and its first
// read fails.
func integRequireRefused(t *testing.T, addr, serverName string, cert *tls.Certificate, version uint16) {
	t.Helper()
	conn, err := dialTLSClient(t, addr, serverName, cert, integPinVersion(version))
	if version < tls.VersionTLS13 {
		if err == nil {
			t.Fatal("the TLS 1.2 handshake completed, want the bridge to refuse the client")
		}
		return
	}
	if err != nil {
		t.Fatalf("the client's side of the TLS 1.3 handshake: %v, want it complete", err)
	}
	requireClosed(t, conn)
}

// integRequireAdmitted connects to addr as serverName with cert, or no
// certificate when cert is nil, and fails unless the session echoes msg.
func integRequireAdmitted(t *testing.T, addr, serverName string, cert *tls.Certificate, msg string) *tls.Conn {
	t.Helper()
	conn, err := dialTLSClient(t, addr, serverName, cert, nil)
	if err != nil {
		t.Fatalf("tls dial %s as %q: %v", addr, serverName, err)
	}
	requireEcho(t, conn, msg)
	return conn
}

// integFingerprint returns the lowercase hex SHA-256 of the leaf of cert.
func integFingerprint(cert *tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// integRefusalsOf returns the refusal record the manager holds for the rule
// id, nil when it holds none.
func integRefusalsOf(mgr *IngressManager, id string) *clientRefusals {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.refusals[id]
}

// integSameRefusals reports whether two refusal lists name the same reasons
// at the same times, in the same order.
func integSameRefusals(a, b []IngressClientRefusalReport) bool {
	return slices.EqualFunc(a, b, func(x, y IngressClientRefusalReport) bool {
		return x.Reason == y.Reason && x.At.Equal(y.At)
	})
}

// integRequireAdmitsAndRefuses checks the clients of the rule slug for
// serverName on addr, whose client_auth names ca, at version. A client with a
// leaf of ca reads the banner of the target, "tgt\n". A client without a
// certificate, with a leaf of another authority, with an expired leaf and
// with a leaf for server authentication only each fail their first read,
// cause no dial and leave one Debug line "ingress client refused" with their
// reason. The line names the issuer, the expiry and the fingerprint of a leaf
// whose chain failed, and never a leaf's subject. The fixture's clock reads
// relayStart.
func integRequireAdmitsAndRefuses(t *testing.T, fx *ingressFixture, dials *dialLog, addr, serverName, slug string, ca *testCA, version uint16) {
	t.Helper()
	good := ca.issue(t, "integ-good-leaf", nil)
	stranger := newTestCA(t, "integ-stranger-ca", nil)
	strangerLeaf := stranger.issue(t, "integ-stranger-leaf", nil)
	expired := ca.issue(t, "integ-expired-leaf", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	})
	serverOnly := ca.issue(t, "integ-server-leaf", func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})

	conn, err := dialTLSClient(t, addr, serverName, &good, integPinVersion(version))
	if err != nil {
		t.Fatalf("the client with a leaf of the rule's authority: %v", err)
	}
	if got := bannerOf(t, conn); got != "tgt\n" {
		t.Fatalf("the admitted client read %q, want the target's banner", got)
	}
	if got := len(dials.dialled()); got != 1 {
		t.Fatalf("%d dials for the admitted client, want 1", got)
	}

	for i, tc := range []struct {
		name   string
		cert   *tls.Certificate
		reason string
		issuer *testCA // nil: the line names no certificate
	}{
		{name: "no certificate", reason: IngressRefusalNoCertificate},
		{name: "a leaf of another authority", cert: &strangerLeaf, reason: IngressRefusalUnknownAuthority, issuer: stranger},
		{name: "an expired leaf", cert: &expired, reason: IngressRefusalCertificateExpired, issuer: ca},
		{name: "a leaf for server authentication only", cert: &serverOnly, reason: IngressRefusalCertificateInvalid, issuer: ca},
	} {
		integRequireRefused(t, addr, serverName, tc.cert, version)
		fx.logs.waitFor(t, `msg="ingress client refused"`, i+1)
		needles := []string{
			"level=DEBUG", `msg="ingress client refused"`, "component=bridge", "listen_port=", "remote=",
			"server_name=" + serverName, "rule_id=id-" + slug, "slug=" + slug, "reason=" + tc.reason,
		}
		if tc.issuer != nil {
			needles = append(needles, "issuer=", tc.issuer.cert.Subject.String(), "not_after=", "fingerprint_sha256="+integFingerprint(tc.cert))
		}
		if got := logLines(fx.logs, needles...); got != 1 {
			t.Errorf("%s: %d 'ingress client refused' lines with %q, want 1:\n%s", tc.name, got, needles, fx.logs.String())
		}
		if got := logLines(fx.logs, `msg="ingress client refused"`, "reason="+tc.reason); got != 1 {
			t.Errorf("%s: %d 'ingress client refused' lines with reason=%s, want 1:\n%s", tc.name, got, tc.reason, fx.logs.String())
		}
		if got := len(dials.dialled()); got != 1 {
			t.Errorf("%s: %d dials, want only the admitted client's", tc.name, got)
		}
	}

	if got := logLines(fx.logs, `msg="ingress client refused"`, " subject="); got != 0 {
		t.Errorf("%d 'ingress client refused' lines with a subject key, want none:\n%s", got, fx.logs.String())
	}
	for _, cn := range []string{"integ-good-leaf", "integ-stranger-leaf", "integ-expired-leaf", "integ-server-leaf"} {
		if strings.Contains(fx.logs.String(), cn) {
			t.Errorf("the log names the subject %s:\n%s", cn, fx.logs.String())
		}
	}
	if got := logLines(fx.logs, `msg="ingress connection closed"`); got != 0 {
		t.Errorf("%d 'ingress connection closed' lines, want every refusal on a line of its own:\n%s", got, fx.logs.String())
	}
	want := []IngressClientRefusalReport{
		{Reason: IngressRefusalNoCertificate, At: relayStart},
		{Reason: IngressRefusalUnknownAuthority, At: relayStart},
		{Reason: IngressRefusalCertificateExpired, At: relayStart},
		{Reason: IngressRefusalCertificateInvalid, At: relayStart},
	}
	if got := integRefusalsOf(fx.mgr, "id-"+slug).snapshot(); !integSameRefusals(got, want) {
		t.Errorf("refusals = %+v, want %+v", got, want)
	}
}

// TestIngressIntegration_ClientCertificateAdmitsAndRefuses serves a terminate
// rule with client_auth to a client with a leaf of the rule's authority and
// refuses a client without a certificate, with a leaf of another authority,
// with an expired leaf and with a leaf for server authentication only, in TLS
// 1.2 and TLS 1.3.
func TestIngressIntegration_ClientCertificateAdmitsAndRefuses(t *testing.T) {
	for _, v := range integTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			backend := startBackend(t, "tcp", "127.0.0.1:0", banner("tgt\n"))
			ctrl := newLoopbackIngressController(t)
			fx, _, dials := newDialLogFixture(t, ctrl)
			fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			ca := newTestCA(t, "integ-client-ca", nil)
			rule := terminateRule("term", 443, "t.example.com", "tls", backend.port(t))
			withClientAuth(ca.pem)(&rule)
			if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
				t.Fatalf("Apply: %v", err)
			}

			integRequireAdmitsAndRefuses(t, fx, dials, ctrl.addr(443), "t.example.com", "term", ca, v.version)
		})
	}
}

// TestIngressIntegration_ClientCertificateOnACMERule does the same for an
// acme rule with client_auth, whose certificate the ACME account supplies.
func TestIngressIntegration_ClientCertificateOnACMERule(t *testing.T) {
	for _, v := range integTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			backend := startBackend(t, "tcp", "127.0.0.1:0", banner("tgt\n"))
			ctrl := newLoopbackIngressController(t)
			fx, _, dials := newDialLogFixture(t, ctrl)
			hookCertificate(t, fx.acme, "acme.example.com")
			ca := newTestCA(t, "integ-client-ca", nil)
			rule := acmeRule("acme", 8443, "acme.example.com", backend.port(t))
			withClientAuth(ca.pem)(&rule)
			if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{rule}, ACME: testACME}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if st := stateOf(t, fx.mgr, "acme"); !st.Served {
				t.Fatalf("rule acme = %+v, want served", st)
			}

			integRequireAdmitsAndRefuses(t, fx, dials, ctrl.addr(8443), "acme.example.com", "acme", ca, v.version)
		})
	}
}

// TestIngressIntegration_ACMEChallengeAsksForNoClientCertificate answers a
// TLS-ALPN-01 challenge for the host of an acme rule with client_auth on port
// 443 without asking the client for a certificate, while an ordinary client
// of the same host is asked for one.
func TestIngressIntegration_ACMEChallengeAsksForNoClientCertificate(t *testing.T) {
	for _, v := range integTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			backend := startBackend(t, "tcp", "127.0.0.1:0", banner("tgt\n"))
			ctrl := newLoopbackIngressController(t)
			fx, _, dials := newDialLogFixture(t, ctrl)
			hookCertificate(t, fx.acme, "acme.example.com")
			ca := newTestCA(t, "integ-client-ca", nil)
			rule := acmeRule("acme", acmeChallengePort, "acme.example.com", backend.port(t))
			withClientAuth(ca.pem)(&rule)
			if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{rule}, ACME: testACME}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if st := stateOf(t, fx.mgr, "acme"); !st.Served {
				t.Fatalf("rule acme = %+v, want served", st)
			}
			leaf := ca.issue(t, "integ-good-leaf", nil)
			var asked atomic.Int32
			client := func(protos ...string) func(*tls.Config) {
				return func(cfg *tls.Config) {
					integPinVersion(v.version)(cfg)
					cfg.NextProtos = protos
					cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
						asked.Add(1)
						return &leaf, nil
					}
				}
			}

			conn, err := dialTLSClient(t, ctrl.addr(acmeChallengePort), "acme.example.com", nil, client("acme-tls/1"))
			if err != nil {
				t.Fatalf("challenge handshake: %v", err)
			}
			if p := conn.ConnectionState().NegotiatedProtocol; p != "acme-tls/1" {
				t.Errorf("the challenge negotiated protocol %q, want acme-tls/1", p)
			}
			fx.logs.waitFor(t, `msg="ingress acme challenge answered" component=bridge server_name=acme.example.com`, 1)
			if n := asked.Load(); n != 0 {
				t.Errorf("the challenge handshake asked the client for a certificate %d times, want never", n)
			}
			if got := dials.dialled(); len(got) != 0 {
				t.Errorf("dials = %v after the challenge, want none", got)
			}

			// The same host without acme-tls/1 is a client of the rule, which
			// asks for a certificate.
			ordinary, err := dialTLSClient(t, ctrl.addr(acmeChallengePort), "acme.example.com", nil, client())
			if err != nil {
				t.Fatalf("ordinary handshake: %v", err)
			}
			if got := bannerOf(t, ordinary); got != "tgt\n" {
				t.Errorf("the ordinary client read %q, want the target's banner", got)
			}
			if n := asked.Load(); n != 1 {
				t.Errorf("the ordinary handshake asked the client for a certificate %d times, want once", n)
			}
		})
	}
}

// TestIngressIntegration_ClientWithoutItsKeyIsRefused refuses a client that
// presents a chain of the rule's authority but signs with another key.
func TestIngressIntegration_ClientWithoutItsKeyIsRefused(t *testing.T) {
	for _, v := range integTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
			ctrl := newLoopbackIngressController(t)
			fx, _, dials := newDialLogFixture(t, ctrl)
			fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			ca := newTestCA(t, "integ-client-ca", nil)
			rule := terminateRule("term", 443, "t.example.com", "tls", backend.port(t))
			withClientAuth(ca.pem)(&rule)
			if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			good := ca.issue(t, "integ-good-leaf", nil)
			otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			thief := tls.Certificate{Certificate: good.Certificate, PrivateKey: otherKey, Leaf: good.Leaf}

			integRequireRefused(t, ctrl.addr(443), "t.example.com", &thief, v.version)
			fx.logs.waitFor(t, `msg="ingress client refused"`, 1)
			if got := logLines(fx.logs, "level=DEBUG", `msg="ingress client refused"`, "slug=term", "reason="+IngressRefusalCertificateInvalid); got != 1 {
				t.Errorf("%d 'ingress client refused' lines with reason=%s, want 1:\n%s", got, IngressRefusalCertificateInvalid, fx.logs.String())
			}
			if got := dials.dialled(); len(got) != 0 {
				t.Errorf("dials = %v, want none", got)
			}
			want := []IngressClientRefusalReport{{Reason: IngressRefusalCertificateInvalid, At: relayStart}}
			if got := integRefusalsOf(fx.mgr, rule.ID).snapshot(); !integSameRefusals(got, want) {
				t.Errorf("refusals = %+v, want %+v", got, want)
			}
		})
	}
}

// integClientHello returns the ClientHello a Go client sends for serverName
// that offers version as its highest.
func integClientHello(t *testing.T, serverName string, version uint16) []byte {
	t.Helper()
	conn, _, stop := startTLSClient(t, &tls.Config{ServerName: serverName, MaxVersion: version}, 0)
	_, peeked, err := peekClientHello(conn, 2*time.Second)
	stop()
	if err != nil {
		t.Fatalf("peek the client hello: %v", err)
	}
	return peeked
}

// TestIngressIntegration_ClientThatStallsIsNotRefused closes a client of a
// rule with client_auth that sends its ClientHello and nothing more after the
// handshake timeout, as a failed handshake, and records no refusal.
func TestIngressIntegration_ClientThatStallsIsNotRefused(t *testing.T) {
	for _, v := range integTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
			ctrl := newLoopbackIngressController(t)
			fx, _, dials := newDialLogFixture(t, ctrl)
			const handshakeTimeout = 300 * time.Millisecond
			fx.mgr.handshakeTimeout = handshakeTimeout
			fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			rule := terminateRule("term", 443, "t.example.com", "tls", backend.port(t))
			withClientAuth(newTestCA(t, "integ-client-ca", nil).pem)(&rule)
			if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			hello := integClientHello(t, "t.example.com", v.version)

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
			if got := logLines(fx.logs, "level=DEBUG", `msg="ingress connection closed"`, "server_name=t.example.com", "reason=tls_handshake_failed"); got != 1 {
				t.Errorf("%d 'ingress connection closed' lines with reason=tls_handshake_failed, want 1:\n%s", got, fx.logs.String())
			}
			if got := logLines(fx.logs, `msg="ingress client refused"`); got != 0 {
				t.Errorf("%d 'ingress client refused' lines, want none:\n%s", got, fx.logs.String())
			}
			if got := integRefusalsOf(fx.mgr, rule.ID).snapshot(); got != nil {
				t.Errorf("refusals = %+v, want none", got)
			}
			if got := dials.dialled(); len(got) != 0 {
				t.Errorf("dials = %v, want none", got)
			}
		})
	}
}

// TestIngressIntegration_ClientCAInvalidServesNobody binds the port of a rule
// whose client_auth bundle does not build, closes every client of its host
// before a handshake, and logs the defect once without a byte of the bundle.
// A one-byte bundle cannot be searched for in the log, so a second rule holds
// a bundle whose second block is truncated, whose lines the log must not hold.
func TestIngressIntegration_ClientCAInvalidServesNobody(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx, _, dials := newDialLogFixture(t, ctrl)
	fx.certs.set("tls", 1, certPEM(t, "*.example.com", "v1"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	ca := newTestCA(t, "integ-client-ca", nil)
	caLines := strings.Split(strings.TrimSpace(ca.pem), "\n")
	truncated := ca.pem + strings.Join(caLines[:3], "\n") + "\n"
	one := terminateRule("one", 443, "one.example.com", "tls", backend.port(t))
	withClientAuth("x")(&one)
	cut := terminateRule("cut", 443, "cut.example.com", "tls", backend.port(t))
	withClientAuth(truncated)(&cut)
	for range 2 {
		if err := fx.mgr.Apply(t.Context(), rulesBlock(one, cut)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}

	if got := ctrl.listenAddrs(); !slices.Equal(got, []string{":443"}) {
		t.Fatalf("Listen addresses = %v, want [:443]", got)
	}
	for _, tc := range []struct{ slug, host, detail string }{
		{slug: "one", host: "one.example.com", detail: "no PEM block"},
		{slug: "cut", host: "cut.example.com", detail: "a PEM block does not decode"},
	} {
		if st := stateOf(t, fx.mgr, tc.slug); st.Served || st.Reason != IngressReasonClientCAInvalid || st.Detail != tc.detail {
			t.Errorf("rule %s = %+v, want not served with %s and the detail %q", tc.slug, st, IngressReasonClientCAInvalid, tc.detail)
		}
		var asked atomic.Int32
		leaf := ca.issue(t, "integ-good-leaf", nil)
		conn, err := dialTLSClient(t, ctrl.addr(443), tc.host, nil, func(cfg *tls.Config) {
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				asked.Add(1)
				return &leaf, nil
			}
		})
		if err == nil {
			requireClosed(t, conn)
			t.Errorf("rule %s: the handshake completed, want the bridge to close the connection before it", tc.slug)
		}
		fx.logs.waitFor(t, "server_name="+tc.host+" reason=rule_not_served", 1)
		if n := asked.Load(); n != 0 {
			t.Errorf("rule %s: the client was asked for a certificate %d times, want never", tc.slug, n)
		}
		if got := logLines(fx.logs, "level=WARN", `msg="ingress rule not served"`, "slug="+tc.slug, "reason="+IngressReasonClientCAInvalid, `detail="`+tc.detail+`"`); got != 1 {
			t.Errorf("%d 'ingress rule not served' lines for %s with reason=%s, want 1:\n%s", got, tc.slug, IngressReasonClientCAInvalid, fx.logs.String())
		}
	}
	if got := logLines(fx.logs, `msg="ingress rule not served"`); got != 2 {
		t.Errorf("%d 'ingress rule not served' lines, want one per rule:\n%s", got, fx.logs.String())
	}
	logged := fx.logs.String()
	for _, line := range caLines[1 : len(caLines)-1] {
		if strings.Contains(logged, line) {
			t.Errorf("the log holds the bundle's line %q:\n%s", line, logged)
		}
	}
	if strings.Contains(logged, "ca_bundle") {
		t.Errorf("the log holds a ca_bundle key:\n%s", logged)
	}
	if got := logLines(fx.logs, `msg="ingress client refused"`); got != 0 {
		t.Errorf("%d 'ingress client refused' lines, want none:\n%s", got, logged)
	}
	if got := dials.dialled(); len(got) != 0 {
		t.Errorf("dials = %v, want none", got)
	}
}

// TestIngressIntegration_ChangedClientAuthClosesConnections closes the
// established connection of a terminate rule when an Apply adds a second
// authority, reorders the bundle, removes client_auth and adds it back,
// keeps the listener, and verifies the next handshake by the new member.
func TestIngressIntegration_ChangedClientAuthClosesConnections(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	caA, caB := newTestCA(t, "integ-ca-a", nil), newTestCA(t, "integ-ca-b", nil)
	leafA, leafB := caA.issue(t, "integ-leaf-a", nil), caB.issue(t, "integ-leaf-b", nil)
	rule := terminateRule("term", 443, "t.example.com", "tls", backend.port(t))
	apply := func(clientAuth *api.IngressClientAuth) {
		t.Helper()
		r := rule
		r.ClientAuth = clientAuth
		if err := fx.mgr.Apply(t.Context(), rulesBlock(r)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}
	apply(&api.IngressClientAuth{CABundle: caA.pem})
	addr := ctrl.addr(443)
	conn := integRequireAdmitted(t, addr, "t.example.com", &leafA, "leaf a under a")
	integRequireRefused(t, addr, "t.example.com", &leafB, tls.VersionTLS13)

	for _, step := range []struct {
		name       string
		clientAuth *api.IngressClientAuth
		admitted   []*tls.Certificate // nil: a client without a certificate
		refused    []*tls.Certificate
	}{
		{name: "adds a second authority", clientAuth: &api.IngressClientAuth{CABundle: caBundle(caA, caB)}, admitted: []*tls.Certificate{&leafB, &leafA}},
		{name: "reorders the bundle", clientAuth: &api.IngressClientAuth{CABundle: caBundle(caB, caA)}, admitted: []*tls.Certificate{&leafB, &leafA}},
		{name: "removes client_auth", admitted: []*tls.Certificate{nil}},
		{name: "adds client_auth back", clientAuth: &api.IngressClientAuth{CABundle: caA.pem}, admitted: []*tls.Certificate{&leafA}, refused: []*tls.Certificate{nil, &leafB}},
	} {
		apply(step.clientAuth)
		requireClosed(t, conn)
		if got := len(ctrl.ingressCallsFor("Listen")); got != 1 {
			t.Errorf("%s: Listen calls = %d, want still 1", step.name, got)
		}
		for _, cert := range step.refused {
			integRequireRefused(t, addr, "t.example.com", cert, tls.VersionTLS13)
		}
		for i, cert := range step.admitted {
			conn = integRequireAdmitted(t, addr, "t.example.com", cert, step.name+" "+strconv.Itoa(i))
		}
	}
	if got := len(ctrl.ingressCallsFor("Close")); got != 0 {
		t.Errorf("Close calls = %d, want 0", got)
	}
	if got := logLines(fx.logs, `msg="ingress rule updated"`, "slug=term"); got != 4 {
		t.Errorf("%d 'ingress rule updated' lines, want one per change:\n%s", got, fx.logs.String())
	}
	fx.logs.waitFor(t, `msg="ingress client refused"`, 3)
	for _, reason := range []string{IngressRefusalUnknownAuthority, IngressRefusalNoCertificate} {
		if got := logLines(fx.logs, `msg="ingress client refused"`, "reason="+reason); got == 0 {
			t.Errorf("no 'ingress client refused' line with reason=%s:\n%s", reason, fx.logs.String())
		}
	}
}

// TestIngressIntegration_SameClientAuthKeepsConnectionsAndRefusals applies the
// same block twice, the bundle text behind a new pointer: the established
// connections and the refusal record stay, and "ingress rule added" names
// client_auth for the rule with it and the rule without it.
func TestIngressIntegration_SameClientAuthKeepsConnectionsAndRefusals(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx, _, _ := newDialLogFixture(t, ctrl)
	fx.certs.set("tls", 1, certPEM(t, "*.example.com", "v1"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	ca := newTestCA(t, "integ-client-ca", nil)
	block := func() api.IngressConfig {
		auth := terminateRule("auth", 443, "auth.example.com", "tls", backend.port(t))
		withClientAuth(ca.pem)(&auth)
		open := terminateRule("open", 443, "open.example.com", "tls", backend.port(t))
		return rulesBlock(auth, open)
	}
	if err := fx.mgr.Apply(t.Context(), block()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	addr := ctrl.addr(443)
	leaf := ca.issue(t, "integ-good-leaf", nil)
	authConn := integRequireAdmitted(t, addr, "auth.example.com", &leaf, "auth before")
	openConn := integRequireAdmitted(t, addr, "open.example.com", nil, "open before")
	integRequireRefused(t, addr, "auth.example.com", nil, tls.VersionTLS13)
	fx.logs.waitFor(t, `msg="ingress client refused"`, 1)
	record := integRefusalsOf(fx.mgr, "id-auth")
	want := []IngressClientRefusalReport{{Reason: IngressRefusalNoCertificate, At: relayStart}}
	if got := record.snapshot(); !integSameRefusals(got, want) {
		t.Fatalf("refusals before the second Apply = %+v, want %+v", got, want)
	}

	if err := fx.mgr.Apply(t.Context(), block()); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	requireEcho(t, authConn, "auth after")
	requireEcho(t, openConn, "open after")
	if got := integRefusalsOf(fx.mgr, "id-auth"); got != record {
		t.Errorf("the second Apply gave the rule the refusal record %p, want the kept %p", got, record)
	}
	if got := record.snapshot(); !integSameRefusals(got, want) {
		t.Errorf("refusals after the second Apply = %+v, want %+v", got, want)
	}
	if got := integRefusalsOf(fx.mgr, "id-open"); got != nil {
		t.Errorf("the rule without client_auth has the refusal record %p, want none", got)
	}
	if got := len(ctrl.ingressCallsFor("Listen")); got != 1 {
		t.Errorf("Listen calls = %d, want 1", got)
	}
	if got := logLines(fx.logs, `msg="ingress rule added"`, "slug=auth", "client_auth=true"); got != 1 {
		t.Errorf("%d 'ingress rule added' lines for auth with client_auth=true, want 1:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="ingress rule added"`, "slug=open", "client_auth=false"); got != 1 {
		t.Errorf("%d 'ingress rule added' lines for open with client_auth=false, want 1:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="ingress rule updated"`); got != 0 {
		t.Errorf("%d 'ingress rule updated' lines, want none:\n%s", got, fx.logs.String())
	}
}

// integSessionCache is a client session cache that counts the sessions it was
// handed and the lookups it answered with one.
type integSessionCache struct {
	tls.ClientSessionCache
	puts atomic.Int32
	hits atomic.Int32
}

func (c *integSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	session, ok := c.ClientSessionCache.Get(key)
	if ok {
		c.hits.Add(1)
	}
	return session, ok
}

func (c *integSessionCache) Put(key string, session *tls.ClientSessionState) {
	if session != nil {
		c.puts.Add(1)
	}
	c.ClientSessionCache.Put(key, session)
}

// TestIngressIntegration_ClientSessionIsNotResumed offers the session of a
// client's first connection to a rule with client_auth on its second, which
// completes a full handshake.
func TestIngressIntegration_ClientSessionIsNotResumed(t *testing.T) {
	for _, v := range integTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
			ctrl := newLoopbackIngressController(t)
			fx := newIngressFixture(t, ctrl)
			fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			ca := newTestCA(t, "integ-client-ca", nil)
			rule := terminateRule("term", 443, "t.example.com", "tls", backend.port(t))
			withClientAuth(ca.pem)(&rule)
			if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			leaf := ca.issue(t, "integ-good-leaf", nil)
			cache := &integSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
			client := func(cfg *tls.Config) {
				integPinVersion(v.version)(cfg)
				cfg.ClientSessionCache = cache
			}

			first, err := dialTLSClient(t, ctrl.addr(443), "t.example.com", &leaf, client)
			if err != nil {
				t.Fatalf("first handshake: %v", err)
			}
			// A TLS 1.3 client reads its session ticket with the first bytes
			// after the handshake.
			requireEcho(t, first, "first")
			_ = first.Close()
			if n := cache.puts.Load(); n == 0 {
				t.Fatal("the client holds no session after its first connection, want one to offer")
			}

			second, err := dialTLSClient(t, ctrl.addr(443), "t.example.com", &leaf, client)
			if err != nil {
				t.Fatalf("second handshake: %v", err)
			}
			if n := cache.hits.Load(); n != 1 {
				t.Errorf("the second handshake found %d sessions to offer, want 1", n)
			}
			if second.ConnectionState().DidResume {
				t.Error("the second connection resumed the first's session, want a full handshake")
			}
			requireEcho(t, second, "second")
		})
	}
}
