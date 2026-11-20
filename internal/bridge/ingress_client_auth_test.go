package bridge

import (
	"bytes"
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
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// authPEM returns der as one PEM block of type typ.
func authPEM(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// authKeyOf returns the key of a bundle that builds from the certificates of
// cas: their lowercase hex SHA-256 fingerprints, sorted, repeats dropped,
// joined by a line feed.
func authKeyOf(cas ...*testCA) string {
	var sums []string
	for _, ca := range cas {
		sum := sha256.Sum256(ca.cert.Raw)
		sums = append(sums, hex.EncodeToString(sum[:]))
	}
	slices.Sort(sums)
	return strings.Join(slices.Compact(sums), "\n")
}

// authInvalidKey returns the key of a bundle that does not build.
func authInvalidKey(bundle string) string {
	sum := sha256.Sum256([]byte(bundle))
	return "invalid:" + hex.EncodeToString(sum[:])
}

// authBuilds returns the client authorities of bundle and fails the test
// unless the bundle builds.
func authBuilds(t *testing.T, bundle string) *clientAuthorities {
	t.Helper()
	ca := newClientAuthorities(&api.IngressClientAuth{CABundle: bundle})
	if ca == nil || ca.pool == nil || ca.defect != "" {
		t.Fatalf("authorities = %+v, want a pool and no defect", ca)
	}
	return ca
}

// authVerify verifies leaf for client authentication against pool, with
// intermediates as the chain the client sent.
func authVerify(pool *x509.CertPool, leaf *x509.Certificate, intermediates ...*x509.Certificate) error {
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

func TestNewClientAuthorities(t *testing.T) {
	if got := newClientAuthorities(nil); got != nil {
		t.Errorf("newClientAuthorities(nil) = %+v, want nil", got)
	}
	if got := clientAuthKey(nil); got != "" {
		t.Errorf("clientAuthKey(nil) = %q, want empty", got)
	}

	cas := make([]*testCA, 9)
	for i := range cas {
		cas[i] = newTestCA(t, fmt.Sprintf("client-ca-%d", i+1), nil)
	}

	t.Run("one CA certificate builds", func(t *testing.T) {
		ca := authBuilds(t, caBundle(cas[0]))
		if ca.key != authKeyOf(cas[0]) {
			t.Errorf("key = %q, want %q", ca.key, authKeyOf(cas[0]))
		}
		if got := clientAuthKey(ca); got != ca.key {
			t.Errorf("clientAuthKey = %q, want %q", got, ca.key)
		}
		if err := authVerify(ca.pool, cas[0].issue(t, "client", nil).Leaf); err != nil {
			t.Errorf("a leaf of the bundle's CA does not verify: %v", err)
		}
		if err := authVerify(ca.pool, cas[1].issue(t, "stranger", nil).Leaf); err == nil {
			t.Error("a leaf of another CA verifies")
		}
	})

	t.Run("eight CA certificates build", func(t *testing.T) {
		ca := authBuilds(t, caBundle(cas[:maxClientAuthorities]...))
		if ca.key != authKeyOf(cas[:maxClientAuthorities]...) {
			t.Errorf("key = %q, want %q", ca.key, authKeyOf(cas[:maxClientAuthorities]...))
		}
		if got := strings.Count(ca.key, "\n") + 1; got != maxClientAuthorities {
			t.Errorf("key holds %d fingerprints, want %d", got, maxClientAuthorities)
		}
		for i, authority := range cas[:maxClientAuthorities] {
			if err := authVerify(ca.pool, authority.issue(t, "client", nil).Leaf); err != nil {
				t.Errorf("a leaf of certificate %d does not verify: %v", i+1, err)
			}
		}
		if err := authVerify(ca.pool, cas[8].issue(t, "stranger", nil).Leaf); err == nil {
			t.Error("a leaf of a CA outside the bundle verifies")
		}
	})

	leaf := cas[0].issue(t, "client", nil)
	leafPEM := authPEM("CERTIFICATE", leaf.Leaf.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(cas[0].key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := authPEM("PRIVATE KEY", keyDER)
	// 96 bytes encode to two full lines of 64 base64 characters.
	random := make([]byte, 96)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	randomPEM := authPEM("CERTIFICATE", random)
	truncated := cas[1].pem[:len(cas[1].pem)/2]
	noCA := newTestCA(t, "no-ca", func(c *x509.Certificate) { c.IsCA = false })
	nineWithAKey := caBundle(cas[0]) + keyPEM + caBundle(cas[1:8]...)

	for _, tc := range []struct {
		name, bundle, defect string
	}{
		{name: "an empty bundle", bundle: "", defect: "empty"},
		{name: "a white-space-only bundle", bundle: " \n\t\r\n ", defect: "empty"},
		{name: "a truncated second block", bundle: cas[0].pem + truncated, defect: "a PEM block does not decode"},
		{name: "a BEGIN line alone", bundle: "-----BEGIN CERTIFICATE-----\n", defect: "a PEM block does not decode"},
		{name: "a truncated block after a private key", bundle: keyPEM + truncated, defect: "a PEM block does not decode"},
		{name: "x", bundle: "x", defect: "no PEM block"},
		{name: "not a certificate", bundle: "not a certificate", defect: "no PEM block"},
		{name: "nine certificates", bundle: caBundle(cas...), defect: "more than 8 certificates"},
		{name: "nine blocks, the second a private key", bundle: nineWithAKey, defect: "more than 8 certificates"},
		{name: "a private key beside a certificate", bundle: cas[0].pem + keyPEM, defect: "block 2 is not a CERTIFICATE"},
		{name: "a private key before random bytes", bundle: keyPEM + randomPEM, defect: "block 1 is not a CERTIFICATE"},
		{name: "a certificate block of random bytes", bundle: randomPEM, defect: "certificate 1 does not parse"},
		{name: "random bytes after a CA certificate", bundle: cas[0].pem + randomPEM, defect: "certificate 2 does not parse"},
		{name: "a leaf without the CA flag", bundle: leafPEM, defect: "certificate 1 is not a CA certificate"},
		{name: "a leaf after a CA certificate", bundle: cas[0].pem + leafPEM, defect: "certificate 2 is not a CA certificate"},
		{name: "basic constraints that deny the CA flag", bundle: noCA.pem, defect: "certificate 1 is not a CA certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newClientAuthorities(&api.IngressClientAuth{CABundle: tc.bundle})
			if ca == nil {
				t.Fatal("authorities = nil, want a defect")
			}
			if ca.defect != tc.defect {
				t.Errorf("defect = %q, want %q", ca.defect, tc.defect)
			}
			if want := authInvalidKey(tc.bundle); ca.key != want {
				t.Errorf("key = %q, want %q", ca.key, want)
			}
			// The pool is empty, so a handshake against it admits nobody,
			// a leaf of a CA the bundle holds included.
			if ca.pool == nil {
				t.Error("pool = nil, want an empty pool")
			} else if err := authVerify(ca.pool, leaf.Leaf); err == nil {
				t.Error("a leaf verifies against the pool of a bundle that does not build")
			}
			for line := range strings.Lines(tc.bundle) {
				if line = strings.TrimSpace(line); line != "" && strings.Contains(ca.defect, line) {
					t.Errorf("defect %q holds the bundle's line %q", ca.defect, line)
				}
			}
		})
	}

	now := time.Now()
	expired := newTestCA(t, "expired-ca", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	})
	future := newTestCA(t, "future-ca", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = now.Add(24*time.Hour), now.Add(48*time.Hour)
	})
	for _, tc := range []struct {
		name   string
		bundle string
		key    string
	}{
		{name: "an expired CA certificate", bundle: caBundle(expired), key: authKeyOf(expired)},
		{name: "a CA certificate whose NotBefore is in the future", bundle: caBundle(future), key: authKeyOf(future)},
		{name: "the same certificate twice", bundle: caBundle(cas[0], cas[0]), key: authKeyOf(cas[0])},
		{name: "white space around the blocks", bundle: " \n" + cas[0].pem + "\n\n" + cas[1].pem + "\n", key: authKeyOf(cas[0], cas[1])},
	} {
		t.Run(tc.name+" builds", func(t *testing.T) {
			if ca := authBuilds(t, tc.bundle); ca.key != tc.key {
				t.Errorf("key = %q, want %q", ca.key, tc.key)
			}
		})
	}

	t.Run("keys", func(t *testing.T) {
		key := func(bundle string) string {
			return clientAuthKey(newClientAuthorities(&api.IngressClientAuth{CABundle: bundle}))
		}
		ab, ba := key(caBundle(cas[0], cas[1])), key(caBundle(cas[1], cas[0]))
		if ab != ba {
			t.Errorf("the same certificates in another order have the keys %q and %q", ab, ba)
		}
		if ab != authKeyOf(cas[0], cas[1]) {
			t.Errorf("key = %q, want %q", ab, authKeyOf(cas[0], cas[1]))
		}
		if ac := key(caBundle(cas[0], cas[2])); ac == ab {
			t.Errorf("bundles that differ in one certificate share the key %q", ac)
		}
		if a := key(caBundle(cas[0])); a == ab {
			t.Errorf("a bundle and its subset share the key %q", a)
		}
		if a, a2 := key(cas[0].pem), key(cas[0].pem+"\n"); a != a2 {
			t.Errorf("the same certificate in another text has the keys %q and %q", a, a2)
		}

		if x1, x2 := key("x"), key("x"); x1 != x2 {
			t.Errorf("two equal bundles that do not build have the keys %q and %q", x1, x2)
		}
		for _, pair := range [][2]string{
			{"x", "y"},
			{"x", "x\n"},
			{"", " "},
			{cas[0].pem + keyPEM, cas[1].pem + keyPEM},
		} {
			if a, b := key(pair[0]), key(pair[1]); a == b {
				t.Errorf("bundles %q and %q, which do not build, share the key %q", pair[0], pair[1], a)
			}
		}
		if bad := key(cas[0].pem + keyPEM); bad == key(cas[0].pem) || !strings.HasPrefix(bad, "invalid:") {
			t.Errorf("key of a bundle that does not build = %q, want an invalid: key apart from the key of its certificate", bad)
		}
	})
}

// authPipeTimeout bounds every pipe end of a test handshake, so no handshake
// can hang.
const authPipeTimeout = 2 * time.Second

// authTLSVersions are the versions every handshake test runs with.
var authTLSVersions = []struct {
	name    string
	version uint16
}{
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

// authPumpedConn reads its connection ahead into a channel, so a write of the
// peer on a net.Pipe never waits for this side to read: the server's alert
// after a refusal, for example, while the client still writes its flight.
type authPumpedConn struct {
	net.Conn
	chunks chan []byte   // closed once a read of Conn fails
	done   chan struct{} // closed after chunks
	err    error         // the failed read's error; set before chunks closes
	rest   []byte
}

// authPump starts reading conn ahead until a read of it fails.
func authPump(conn net.Conn) *authPumpedConn {
	p := &authPumpedConn{Conn: conn, chunks: make(chan []byte, 64), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		defer close(p.chunks)
		for {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if n > 0 {
				p.chunks <- buf[:n]
			}
			if err != nil {
				p.err = err
				return
			}
		}
	}()
	return p
}

func (p *authPumpedConn) Read(b []byte) (int, error) {
	if len(p.rest) == 0 {
		chunk, ok := <-p.chunks
		if !ok {
			return 0, p.err
		}
		p.rest = chunk
	}
	n := copy(b, p.rest)
	p.rest = p.rest[n:]
	return n, nil
}

// authStallConn passes its first write, the client's ClientHello, and holds
// every later write until a read of the connection fails, so a client stalls
// after its ClientHello while it still reads the server's flight.
type authStallConn struct {
	*authPumpedConn
	wrote bool
}

func (c *authStallConn) Write(b []byte) (int, error) {
	if c.wrote {
		<-c.done
		return 0, net.ErrClosed
	}
	c.wrote = true
	return c.authPumpedConn.Write(b)
}

// authServer is the bridge's side of a handshake that requires a client
// certificate: a server certificate and the client authorities.
type authServer struct {
	cert tls.Certificate
	pool *x509.CertPool
}

// authResult is the outcome of one test handshake.
type authResult struct {
	presented bool                // the flag requireClientCertificate returned
	serverErr error               // the server's handshake error
	clientErr error               // what the client function returned
	state     tls.ConnectionState // the server's, after its handshake
}

// handshake runs the server's handshake, pinned to version, against client
// on the other end of a net.Pipe and returns its outcome. The server's end
// gives up after timeout, the client's after authPipeTimeout, and both ends
// close once the server's handshake returned.
func (s authServer) handshake(t *testing.T, version uint16, timeout time.Duration, client func(net.Conn) error) authResult {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	_ = serverEnd.SetDeadline(time.Now().Add(timeout))
	_ = clientEnd.SetDeadline(time.Now().Add(authPipeTimeout))
	cfg := &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: version, MaxVersion: version}
	presented := requireClientCertificate(cfg, s.pool)
	clientErr := make(chan error, 1)
	go func() { clientErr <- client(clientEnd) }()
	srv := tls.Server(serverEnd, cfg)
	var res authResult
	res.serverErr = srv.Handshake()
	res.state = srv.ConnectionState()
	res.presented = *presented
	_ = srv.Close()
	_ = clientEnd.Close()
	res.clientErr = <-clientErr
	return res
}

// authClient returns a client, pinned to version, that presents cert to a
// certificate request, or no certificate when cert is nil, and completes its
// side of the handshake. It presents cert through GetClientCertificate, so it
// sends it also when its issuer is not among the authorities the request
// names. acceptable, when not nil, receives the authorities the request names.
func authClient(version uint16, cert *tls.Certificate, acceptable *[][]byte) func(net.Conn) error {
	return func(conn net.Conn) error {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if acceptable != nil {
					*acceptable = cri.AcceptableCAs
				}
				if cert == nil {
					return &tls.Certificate{}, nil
				}
				return cert, nil
			},
		}
		return tls.Client(authPump(conn), cfg).Handshake()
	}
}

// authStallingClient returns a client, pinned to version, that sends its
// ClientHello, reads the server's flight and writes nothing more.
func authStallingClient(version uint16) func(net.Conn) error {
	return func(conn net.Conn) error {
		cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version}
		return tls.Client(&authStallConn{authPumpedConn: authPump(conn)}, cfg).Handshake()
	}
}

// TestClientRefusalReason reads the refusal reason of every row of the table
// of clientRefusalReason from the errors of real handshakes.
func TestClientRefusalReason(t *testing.T) {
	ca := newTestCA(t, "client-ca", nil)
	other := newTestCA(t, "other-ca", nil)
	inter := ca.intermediate(t, "client-intermediate", nil)
	now := time.Now()
	expiredCA := newTestCA(t, "expired-ca", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	})
	authorities := authBuilds(t, caBundle(ca, expiredCA))
	server := authServer{cert: selfSignedCert(t, "bridge.example.com"), pool: authorities.pool}

	strangerLeaf := other.issue(t, "stranger", nil)
	interLeaf := inter.issue(t, "client", nil)
	expiredLeaf := ca.issue(t, "client", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	})
	laterLeaf := ca.issue(t, "client", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour)
	})
	underExpiredLeaf := expiredCA.issue(t, "client", nil)
	serverAuthLeaf := ca.issue(t, "client", func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	withoutItsKey := ca.issue(t, "client", nil)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	withoutItsKey.PrivateKey = otherKey

	// The kinds of handshake error the rows expect.
	const (
		noCertificate = "the client presented no certificate"
		verification  = "a *tls.CertificateVerificationError"
		signature     = "an invalid signature by the client certificate"
		deadline      = "os.ErrDeadlineExceeded"
	)
	for _, v := range authTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				client    func(net.Conn) error
				timeout   time.Duration
				kind      string
				presented bool
				reason    string
			}{
				{name: "no certificate", client: authClient(v.version, nil, nil), kind: noCertificate, reason: IngressRefusalNoCertificate},
				{name: "a leaf of another CA", client: authClient(v.version, &strangerLeaf, nil), kind: verification, reason: IngressRefusalUnknownAuthority},
				{name: "a leaf whose intermediate the client did not send", client: authClient(v.version, &interLeaf, nil), kind: verification, reason: IngressRefusalUnknownAuthority},
				{name: "an expired leaf", client: authClient(v.version, &expiredLeaf, nil), kind: verification, reason: IngressRefusalCertificateExpired},
				{name: "a leaf not valid yet", client: authClient(v.version, &laterLeaf, nil), kind: verification, reason: IngressRefusalCertificateExpired},
				{name: "a leaf under an expired authority", client: authClient(v.version, &underExpiredLeaf, nil), kind: verification, reason: IngressRefusalCertificateExpired},
				{name: "a leaf with only the serverAuth usage", client: authClient(v.version, &serverAuthLeaf, nil), kind: verification, reason: IngressRefusalCertificateInvalid},
				{name: "a valid chain with another key", client: authClient(v.version, &withoutItsKey, nil), kind: signature, presented: true, reason: IngressRefusalCertificateInvalid},
				{name: "a client that stalls after its ClientHello", client: authStallingClient(v.version), timeout: 500 * time.Millisecond, kind: deadline, reason: ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					timeout := tc.timeout
					if timeout == 0 {
						timeout = authPipeTimeout
					}
					res := server.handshake(t, v.version, timeout, tc.client)
					err := res.serverErr
					if err == nil {
						t.Fatal("the server's handshake completed, want it to fail")
					}
					var verifyErr *tls.CertificateVerificationError
					var kind string
					switch {
					case errors.Is(err, errNoClientCertificate):
						kind = noCertificate
					case errors.As(err, &verifyErr):
						kind = verification
					case strings.Contains(err.Error(), "invalid signature by the client certificate"):
						kind = signature
					case errors.Is(err, os.ErrDeadlineExceeded):
						kind = deadline
					}
					if kind != tc.kind {
						t.Fatalf("server error = %v (%s), want %s", err, kind, tc.kind)
					}
					if res.presented != tc.presented {
						t.Errorf("presented = %v, want %v", res.presented, tc.presented)
					}
					if got := clientRefusalReason(err, res.presented); got != tc.reason {
						t.Errorf("clientRefusalReason(%v, %v) = %q, want %q", err, res.presented, got, tc.reason)
					}
				})
			}
		})
	}

	// A handshake error is a refusal only once the client presented a chain
	// that verified.
	if got := clientRefusalReason(os.ErrDeadlineExceeded, true); got != IngressRefusalCertificateInvalid {
		t.Errorf("clientRefusalReason(deadline, presented) = %q, want %q", got, IngressRefusalCertificateInvalid)
	}
	if got := clientRefusalReason(fmt.Errorf("handshake: %w", errNoClientCertificate), false); got != IngressRefusalNoCertificate {
		t.Errorf("clientRefusalReason(wrapped errNoClientCertificate) = %q, want %q", got, IngressRefusalNoCertificate)
	}
}

// TestRequireClientCertificate_Admits completes the handshake of clients
// whose chain verifies against the rule's authorities.
func TestRequireClientCertificate_Admits(t *testing.T) {
	ca := newTestCA(t, "client-ca", nil)
	second := newTestCA(t, "second-ca", nil)
	inter := ca.intermediate(t, "client-intermediate", nil)
	authorities := authBuilds(t, caBundle(ca, second))
	server := authServer{cert: selfSignedCert(t, "bridge.example.com"), pool: authorities.pool}

	leaf := ca.issue(t, "client", nil)
	noUsage := ca.issue(t, "client", func(c *x509.Certificate) { c.ExtKeyUsage = nil })
	interLeaf := inter.issue(t, "client", nil)
	interLeaf.Certificate = append(interLeaf.Certificate, inter.cert.Raw)
	secondLeaf := second.issue(t, "client", nil)

	for _, v := range authTLSVersions {
		t.Run(v.name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				cert *tls.Certificate
				root *testCA
			}{
				{name: "a leaf of the rule's CA", cert: &leaf, root: ca},
				{name: "a leaf without an extended key usage", cert: &noUsage, root: ca},
				{name: "a leaf whose intermediate the client sends", cert: &interLeaf, root: ca},
				{name: "a leaf of the bundle's second CA", cert: &secondLeaf, root: second},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var acceptable [][]byte
					res := server.handshake(t, v.version, authPipeTimeout, authClient(v.version, tc.cert, &acceptable))
					if res.serverErr != nil || res.clientErr != nil {
						t.Fatalf("handshake errors = %v (server), %v (client), want none", res.serverErr, res.clientErr)
					}
					if !res.presented {
						t.Error("presented = false, want true")
					}
					if got := res.state.PeerCertificates; len(got) == 0 || !got[0].Equal(tc.cert.Leaf) {
						t.Errorf("peer certificates = %d, want the client's leaf first", len(got))
					}
					if chains := res.state.VerifiedChains; len(chains) == 0 || !chains[0][len(chains[0])-1].Equal(tc.root.cert) {
						t.Errorf("verified chains = %d, want one that ends at %s", len(chains), tc.root.cert.Subject)
					}
					if !slices.ContainsFunc(acceptable, func(s []byte) bool { return bytes.Equal(s, ca.cert.RawSubject) }) ||
						!slices.ContainsFunc(acceptable, func(s []byte) bool { return bytes.Equal(s, second.cert.RawSubject) }) {
						t.Errorf("the certificate request names %d authorities, want both of the bundle", len(acceptable))
					}
				})
			}
		})
	}
}

func TestClientRefusals_RecordAndSnapshot(t *testing.T) {
	var none *clientRefusals
	if got := none.snapshot(); got != nil {
		t.Errorf("snapshot of a nil record = %+v, want nil", got)
	}

	base := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }

	rec := newClientRefusals("bundle")
	if rec.bundle != "bundle" {
		t.Errorf("bundle = %q, want %q", rec.bundle, "bundle")
	}
	if got := rec.snapshot(); got != nil {
		t.Errorf("snapshot before a refusal = %+v, want nil", got)
	}

	rec.record(IngressRefusalCertificateInvalid, at(1))
	rec.record(IngressRefusalNoCertificate, at(2))
	want := []IngressClientRefusalReport{
		{Reason: IngressRefusalNoCertificate, At: at(2)},
		{Reason: IngressRefusalCertificateInvalid, At: at(1)},
	}
	if got := rec.snapshot(); !slices.Equal(got, want) {
		t.Errorf("snapshot of two refusals = %+v, want %+v", got, want)
	}

	rec.record(IngressRefusalCertificateExpired, at(3))
	rec.record(IngressRefusalUnknownAuthority, at(4))
	rec.record(IngressRefusalNoCertificate, at(5))
	rec.record(IngressRefusalUnknownAuthority, at(6))
	// A refusal stamped before the last one of its reason leaves the time.
	rec.record(IngressRefusalCertificateInvalid, at(0))
	want = []IngressClientRefusalReport{
		{Reason: IngressRefusalNoCertificate, At: at(5)},
		{Reason: IngressRefusalUnknownAuthority, At: at(6)},
		{Reason: IngressRefusalCertificateExpired, At: at(3)},
		{Reason: IngressRefusalCertificateInvalid, At: at(1)},
	}
	if got := rec.snapshot(); !slices.Equal(got, want) {
		t.Errorf("snapshot = %+v, want %+v", got, want)
	}

	t.Run("32 goroutines record concurrently", func(t *testing.T) {
		rec := newClientRefusals("bundle")
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				rec.record(clientRefusalOrder[i%len(clientRefusalOrder)], at(i))
				_ = rec.snapshot()
			})
		}
		wg.Wait()
		// The last refusal of reason k is the one of goroutine 28+k.
		var want []IngressClientRefusalReport
		for k, reason := range clientRefusalOrder {
			want = append(want, IngressClientRefusalReport{Reason: reason, At: at(28 + k)})
		}
		if got := rec.snapshot(); !slices.Equal(got, want) {
			t.Errorf("snapshot = %+v, want %+v", got, want)
		}
	})
}

func TestForwardedClientCert(t *testing.T) {
	ca := newTestCA(t, "client-ca", nil)
	for _, tc := range []struct {
		name    string
		subject pkix.Name
		dn      string // the value of Subject, between its quotes
	}{
		{name: "a common name and an organization", subject: pkix.Name{CommonName: "client", Organization: []string{"Acme, Inc."}}, dn: `CN=client,O=Acme\, Inc.`},
		{name: "no subject", subject: pkix.Name{}, dn: ""},
		{name: "a quote", subject: pkix.Name{CommonName: `a"b`}, dn: `CN=a\"b`},
		{name: "a carriage return and a line feed", subject: pkix.Name{CommonName: "a\r\nb"}, dn: `CN=a\0D\0Ab`},
		{name: "a tab and 0x7F", subject: pkix.Name{CommonName: "a\tb\x7fc"}, dn: `CN=a\09b\7Fc`},
		{name: "a letter of two bytes", subject: pkix.Name{CommonName: "Zoë"}, dn: `CN=Zo\C3\AB`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := ca.issue(t, "client", func(c *x509.Certificate) { c.Subject = tc.subject }).Leaf
			sum := sha256.Sum256(leaf.Raw)
			want := "Hash=" + hex.EncodeToString(sum[:]) + `;Subject="` + tc.dn + `"`
			got := forwardedClientCert(leaf)
			if got != want {
				t.Errorf("forwardedClientCert = %q, want %q", got, want)
			}
			for i := range len(got) {
				if c := got[i]; c < 0x20 || c > 0x7E {
					t.Errorf("forwardedClientCert holds the byte %#x at %d", c, i)
				}
			}
		})
	}
}
