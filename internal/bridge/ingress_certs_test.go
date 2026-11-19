package bridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// certAndKeyPEM returns a self-signed certificate for host, with org as the
// organization of its subject, and its key, each as a PEM block.
func certAndKeyPEM(t *testing.T, host, org string) (certBlock, keyBlock []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{org}},
		DNSNames:     []string{host},
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// certPEM returns a certificate for host with org as its organization and
// its key as one PEM document, the value of a terminate rule's Secret.
func certPEM(t *testing.T, host, org string) []byte {
	t.Helper()
	certBlock, keyBlock := certAndKeyPEM(t, host, org)
	return append(certBlock, keyBlock...)
}

// certPool returns a pool that trusts the certificates of the PEM documents.
func certPool(t *testing.T, docs ...[]byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, doc := range docs {
		if !pool.AppendCertsFromPEM(doc) {
			t.Fatal("no certificate in the PEM document")
		}
	}
	return pool
}

// dialTerminated completes a TLS handshake with addr as serverName, trusting
// only roots and offering protos, and closes the connection when the test
// ends.
func dialTerminated(t *testing.T, addr, serverName string, roots *x509.CertPool, protos ...string) *tls.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: serverName, RootCAs: roots, NextProtos: protos})
	if err != nil {
		t.Fatalf("tls dial %s as %q: %v", addr, serverName, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// leafOrganization returns the organization of the certificate the far end
// of conn presented.
func leafOrganization(conn *tls.Conn) string {
	if org := conn.ConnectionState().PeerCertificates[0].Subject.Organization; len(org) > 0 {
		return org[0]
	}
	return ""
}

// servingOrganization returns the organization of the certificate loaded for
// a Secret, or "" when none is.
func servingOrganization(mgr *IngressManager, secret string) string {
	cert := mgr.certificateFor(secret)
	if cert == nil || len(cert.Leaf.Subject.Organization) == 0 {
		return ""
	}
	return cert.Leaf.Subject.Organization[0]
}

// inventoryOf returns an inventory that lists name at version.
func inventoryOf(name string, version int) []api.NodeStateSecret {
	return []api.NodeStateSecret{{Name: name, Version: version}}
}

// requireFetches fails unless the fetcher saw exactly want.
func requireFetches(t *testing.T, certs *fakeCertFetcher, want ...certVersion) {
	t.Helper()
	if got := certs.fetches(); !slices.Equal(got, want) {
		t.Fatalf("fetches = %v, want %v", got, want)
	}
}

// newClockedFixture returns a fixture whose manager reads a settable clock.
func newClockedFixture(t *testing.T) (*ingressFixture, *relayClock) {
	t.Helper()
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	clock := &relayClock{now: relayStart}
	fx.mgr.now = clock.Now
	return fx, clock
}

var termBlock = rulesBlock(terminateRule("term", 443, "t.example.com", "tls", 9000))

func TestIngressCertificates_LoadsTheListedVersion(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))

	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireFetches(t, fx.certs, certVersion{"tls", 1})
	if st := stateOf(t, fx.mgr, "term"); !st.Served || st.Reason != "" {
		t.Errorf("rule term = %+v, want served", st)
	}
	if got := logLines(fx.logs, `level=INFO`, `msg="ingress certificate loaded"`, "secret=tls", "version=1", "not_after="); got != 1 {
		t.Errorf("%d 'ingress certificate loaded' lines with secret, version and not_after, want 1:\n%s", got, fx.logs.String())
	}

	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	requireFetches(t, fx.certs, certVersion{"tls", 1})
}

func TestIngressCertificates_NotListed(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))

	requireNotListed := func(when string) {
		t.Helper()
		if st := stateOf(t, fx.mgr, "term"); st.Served || st.Reason != IngressReasonCertificateSecretNotListed || st.Detail != "tls" {
			t.Errorf("%s: rule term = %+v, want %q with the Secret name", when, st, IngressReasonCertificateSecretNotListed)
		}
	}
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireNotListed("before any inventory")
	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{})
	requireNotListed("for the inventory []")
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("other", 1))
	requireNotListed("for an inventory of other names")

	requireFetches(t, fx.certs)
	if got := logLines(fx.logs, `level=WARN`, `msg="ingress certificate not loaded"`, "secret=tls", "version=0",
		"reason=certificate_secret_not_listed", "serving_version=0"); got != 1 {
		t.Errorf("%d 'ingress certificate not loaded' lines, want 1:\n%s", got, fx.logs.String())
	}
}

func TestIngressSecretInventoryHandler(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	handler := IngressSecretInventoryHandler(fx.mgr)
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	inventory := inventoryOf("tls", 1)
	handler(t.Context(), &api.NodeStateSnapshot{Secrets: &inventory})
	if st := stateOf(t, fx.mgr, "term"); !st.Served {
		t.Fatalf("rule term = %+v, want served", st)
	}

	// A nil block is not the inventory []: it keeps the inventory, so the
	// certificate keeps serving.
	handler(t.Context(), &api.NodeStateSnapshot{})
	handler(t.Context(), nil)
	if st := stateOf(t, fx.mgr, "term"); !st.Served {
		t.Errorf("rule term after a pull without a secrets block = %+v, want served", st)
	}
	requireFetches(t, fx.certs, certVersion{"tls", 1})
}

func TestIngressCertificates_InventoryEntries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		inventory []api.NodeStateSecret
		want      []certVersion // nil: not listed
	}{
		{name: "a name listed twice", inventory: []api.NodeStateSecret{{Name: "tls", Version: 2}, {Name: "tls", Version: 3}}, want: []certVersion{{"tls", 2}}},
		{name: "version 0", inventory: []api.NodeStateSecret{{Name: "tls", Version: 0}}},
		{name: "version 0 ahead of version 4", inventory: []api.NodeStateSecret{{Name: "tls", Version: 0}, {Name: "tls", Version: 4}}, want: []certVersion{{"tls", 4}}},
		{name: "a name outside the grammar", inventory: []api.NodeStateSecret{{Name: "TLS", Version: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newIngressFixture(t, newLoopbackIngressController(t))
			for _, v := range []int{1, 2, 3, 4} {
				fx.certs.set("tls", v, certPEM(t, "t.example.com", fmt.Sprintf("v%d", v)))
			}
			if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			fx.mgr.SyncSecretInventory(t.Context(), tc.inventory)

			requireFetches(t, fx.certs, tc.want...)
			st := stateOf(t, fx.mgr, "term")
			if tc.want == nil {
				if st.Served || st.Reason != IngressReasonCertificateSecretNotListed {
					t.Errorf("rule term = %+v, want %q", st, IngressReasonCertificateSecretNotListed)
				}
				return
			}
			if !st.Served {
				t.Errorf("rule term = %+v, want served", st)
			}
		})
	}
}

func TestIngressCertificates_SetupAndTeardown(t *testing.T) {
	fx := buildIngressFixture(t, newLoopbackIngressController(t), ingressTestConfig(true))
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	inventory := inventoryOf("tls", 1)

	fx.mgr.SyncSecretInventory(t.Context(), inventory)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireFetches(t, fx.certs)
	if st := stateOf(t, fx.mgr, "term"); st.Reason != IngressReasonCertificateSecretNotListed {
		t.Errorf("rule term after an inventory before Setup = %+v, want %q", st, IngressReasonCertificateSecretNotListed)
	}
	fx.mgr.SyncSecretInventory(t.Context(), inventory)
	requireFetches(t, fx.certs, certVersion{"tls", 1})

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if cert := fx.mgr.certificateFor("tls"); cert != nil {
		t.Error("the certificate of tls is still held after Teardown, want it forgotten")
	}
	const dropped = `msg="ingress certificate dropped"`
	droppedBefore := logLines(fx.logs, dropped)
	fx.mgr.SyncSecretInventory(t.Context(), inventory)
	requireFetches(t, fx.certs, certVersion{"tls", 1})

	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup again: %v", err)
	}
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply again: %v", err)
	}
	// A certificate Teardown forgot is not there to drop.
	if got := logLines(fx.logs, dropped); got != droppedBefore {
		t.Errorf("%d 'ingress certificate dropped' lines since Teardown, want none:\n%s", got-droppedBefore, fx.logs.String())
	}
	requireFetches(t, fx.certs, certVersion{"tls", 1})
	fx.mgr.SyncSecretInventory(t.Context(), inventory)
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 1})
	if st := stateOf(t, fx.mgr, "term"); !st.Served {
		t.Errorf("rule term = %+v, want served", st)
	}
}

func TestIngressCertificates_RotationServesTheNextHandshake(t *testing.T) {
	backend := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	v1, v2 := certPEM(t, "t.example.com", "v1"), certPEM(t, "t.example.com", "v2")
	fx.certs.set("tls", 1, v1)
	fx.certs.set("tls", 2, v2)
	roots := certPool(t, v1, v2)

	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(terminateRule("term", 443, "t.example.com", "tls", backend.port(t)))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	first := dialTerminated(t, ctrl.addr(443), "t.example.com", roots)
	if org := leafOrganization(first); org != "v1" {
		t.Fatalf("first handshake got the certificate of %q, want v1", org)
	}
	requireEcho(t, first, "under v1")

	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 2))
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 2})
	second := dialTerminated(t, ctrl.addr(443), "t.example.com", roots)
	if org := leafOrganization(second); org != "v2" {
		t.Errorf("handshake after the rotation got the certificate of %q, want v2", org)
	}
	requireEcho(t, second, "under v2")
	requireEcho(t, first, "still under v1")
}

func TestIngressCertificates_FetchFailureKeepsTheServingVersion(t *testing.T) {
	fx, clock := newClockedFixture(t)
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	fx.certs.set("tls", 2, certPEM(t, "t.example.com", "v2"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	fx.certs.setErr(fmt.Errorf("fetch secret %q version %d: %w", "tls", 2, api.ErrForbidden))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 2))
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 2})
	if st := stateOf(t, fx.mgr, "term"); !st.Served {
		t.Errorf("rule term after a failed fetch = %+v, want served", st)
	}
	if org := servingOrganization(fx.mgr, "tls"); org != "v1" {
		t.Errorf("serving the certificate of %q, want v1", org)
	}
	if got := logLines(fx.logs, `level=WARN`, `msg="ingress certificate not loaded"`, "secret=tls", "version=2",
		"reason=certificate_fetch_failed", "serving_version=1", "403"); got != 1 {
		t.Errorf("%d 'ingress certificate not loaded' lines, want 1:\n%s", got, fx.logs.String())
	}

	clock.Add(4 * time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 2))
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 2})

	fx.certs.setErr(nil)
	clock.Add(time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 2))
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 2}, certVersion{"tls", 2})
	if org := servingOrganization(fx.mgr, "tls"); org != "v2" {
		t.Errorf("serving the certificate of %q after the retry, want v2", org)
	}
	if st := stateOf(t, fx.mgr, "term"); !st.Served {
		t.Errorf("rule term = %+v, want served", st)
	}
}

func TestIngressCertificates_RetryDelays(t *testing.T) {
	fx, clock := newClockedFixture(t)
	fx.certs.setErr(fmt.Errorf("fake: %w", api.ErrServer))
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	fetched := 1
	requireDelay := func(d time.Duration) {
		t.Helper()
		clock.Add(d - time.Second)
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
		if got := len(fx.certs.fetches()); got != fetched {
			t.Fatalf("%v after the failure: %d fetches, want %d", d-time.Second, got, fetched)
		}
		clock.Add(time.Second)
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
		fetched++
		if got := len(fx.certs.fetches()); got != fetched {
			t.Fatalf("%v after the failure: %d fetches, want %d", d, got, fetched)
		}
	}
	for _, d := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second} {
		requireDelay(d)
	}
	if got := logLines(fx.logs, `msg="ingress certificate not loaded"`, "reason=certificate_fetch_failed"); got != 1 {
		t.Errorf("%d 'ingress certificate not loaded' lines across the retries, want 1:\n%s", got, fx.logs.String())
	}

	fx.certs.setErr(fmt.Errorf("fake: %w", &api.APIError{StatusCode: 429, Message: "rate limited", RetryAfter: 120 * time.Second}))
	clock.Add(60 * time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	fetched++
	if got := len(fx.certs.fetches()); got != fetched {
		t.Fatalf("%d fetches, want %d", got, fetched)
	}
	requireDelay(120 * time.Second)
}

func TestIngressCertificates_FirstLoadIsRetried(t *testing.T) {
	fx, clock := newClockedFixture(t)
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	fx.certs.setErr(context.DeadlineExceeded)
	if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if st := stateOf(t, fx.mgr, "term"); st.Served || st.Reason != IngressReasonCertificateFetchFailed || st.Detail != "tls" {
		t.Errorf("rule term = %+v, want %q with the Secret name", st, IngressReasonCertificateFetchFailed)
	}

	fx.certs.setErr(nil)
	clock.Add(5 * time.Second)
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if st := stateOf(t, fx.mgr, "term"); !st.Served {
		t.Errorf("rule term after the retry = %+v, want served", st)
	}
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 1})
}

func TestIngressCertificates_InvalidValues(t *testing.T) {
	certBlock, _ := certAndKeyPEM(t, "t.example.com", "bad")
	_, otherKey := certAndKeyPEM(t, "t.example.com", "other")
	for name, value := range map[string][]byte{
		"empty":                              {},
		"a certificate without a key":        certBlock,
		"a key that does not match the leaf": append(append([]byte{}, certBlock...), otherKey...),
	} {
		t.Run(name, func(t *testing.T) {
			fx, clock := newClockedFixture(t)
			fx.certs.set("tls", 1, value)
			fx.certs.set("tls", 2, certPEM(t, "t.example.com", "v2"))
			fx.certs.set("tls", 3, value)
			if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
				t.Fatalf("Apply: %v", err)
			}

			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			if st := stateOf(t, fx.mgr, "term"); st.Served || st.Reason != IngressReasonCertificateInvalid || st.Detail != "tls" {
				t.Errorf("rule term on a first load = %+v, want %q", st, IngressReasonCertificateInvalid)
			}
			clock.Add(time.Hour)
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			requireFetches(t, fx.certs, certVersion{"tls", 1})

			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 2))
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 3))
			requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 2}, certVersion{"tls", 3})
			if org := servingOrganization(fx.mgr, "tls"); org != "v2" {
				t.Errorf("serving the certificate of %q, want v2 kept", org)
			}
			if st := stateOf(t, fx.mgr, "term"); !st.Served {
				t.Errorf("rule term = %+v, want served", st)
			}
			if got := logLines(fx.logs, `msg="ingress certificate not loaded"`, "version=3", "reason=certificate_invalid", "serving_version=2"); got != 1 {
				t.Errorf("%d 'ingress certificate not loaded' lines for version 3, want 1:\n%s", got, fx.logs.String())
			}
			clock.Add(time.Hour)
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 3))
			if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 2}, certVersion{"tls", 3})
		})
	}
}

func TestIngressCertificates_DroppedSecretClosesItsConnections(t *testing.T) {
	a := startBackend(t, "tcp", "127.0.0.1:0", echo)
	b := startBackend(t, "tcp", "127.0.0.1:0", echo)
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	pemA, pemB := certPEM(t, "a.example.com", "a"), certPEM(t, "b.example.com", "b")
	fx.certs.set("tls-a", 1, pemA)
	fx.certs.set("tls-b", 1, pemB)
	roots := certPool(t, pemA, pemB)

	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "tls-a", Version: 1}, {Name: "tls-b", Version: 1}})
	if err := fx.mgr.Apply(t.Context(), rulesBlock(
		terminateRule("a", 443, "a.example.com", "tls-a", a.port(t)),
		terminateRule("b", 443, "b.example.com", "tls-b", b.port(t)),
	)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	connA := dialTerminated(t, ctrl.addr(443), "a.example.com", roots)
	connB := dialTerminated(t, ctrl.addr(443), "b.example.com", roots)
	requireEcho(t, connA, "a")
	requireEcho(t, connB, "b")

	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls-b", 1))
	requireClosed(t, connA)
	requireEcho(t, connB, "b still")
	if got := logLines(fx.logs, `msg="ingress certificate dropped"`, "secret=tls-a", "version=1", "reason=certificate_secret_not_listed"); got != 1 {
		t.Errorf("%d 'ingress certificate dropped' lines, want 1:\n%s", got, fx.logs.String())
	}
	if got := len(ctrl.ingressCallsFor("Close")); got != 0 {
		t.Errorf("Close calls = %d, want 0", got)
	}
	if st := stateOf(t, fx.mgr, "a"); st.Served || st.Reason != IngressReasonCertificateSecretNotListed {
		t.Errorf("rule a = %+v, want %q", st, IngressReasonCertificateSecretNotListed)
	}

	// The fresh route of rule a carries over, so the next Apply of the same
	// block closes nothing.
	if err := fx.mgr.Apply(t.Context(), rulesBlock(
		terminateRule("a", 443, "a.example.com", "tls-a", a.port(t)),
		terminateRule("b", 443, "b.example.com", "tls-b", b.port(t)),
	)); err != nil {
		t.Fatalf("Apply again: %v", err)
	}
	requireEcho(t, connB, "b after the Apply")

	// Listed again, the Secret serves rule a on its fresh route.
	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "tls-a", Version: 1}, {Name: "tls-b", Version: 1}})
	if st := stateOf(t, fx.mgr, "a"); !st.Served {
		t.Fatalf("rule a after its Secret is listed again = %+v, want served", st)
	}
	again := dialTerminated(t, ctrl.addr(443), "a.example.com", roots)
	requireEcho(t, again, "a again")
}

// TestIngressCertificates_DroppedSecretClosesHTTPConnections closes the idle
// client connections of a host whose rules have conditions when the inventory
// stops listing its Secret, and keeps those of a host of another Secret.
func TestIngressCertificates_DroppedSecretClosesHTTPConnections(t *testing.T) {
	apiT := startHTTPTarget(t, "api")
	fx := newHTTPFixture(t, nil)
	fx.certs.set("tls-other", 1, fx.doc)
	other := httpRule("other", "other.example.com", apiT.port(t), "/")
	other.CertificateSecretName = "tls-other"
	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "tls", Version: 1}, {Name: "tls-other", Version: 1}})
	fx.apply(t, httpRule("api", "shop.example.com", apiT.port(t), "/api"), httpRule("web", "shop.example.com", apiT.port(t), "/"), other)
	shop := fx.dialRaw(t, "shop.example.com")
	kept := fx.dialRaw(t, "other.example.com")
	for _, conn := range []*rawConn{shop, kept} {
		if status, _ := conn.roundTrip(t, getHead("/api", conn.ConnectionState().ServerName)); status != http.StatusOK {
			t.Fatalf("status %d, want 200", status)
		}
	}

	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls-other", 1))
	requireClosed(t, shop)
	if status, _ := kept.roundTrip(t, getHead("/", "other.example.com")); status != http.StatusOK {
		t.Errorf("the host of another Secret answered %d, want 200 on its kept connection", status)
	}
	if got := logLines(fx.logs, `msg="ingress certificate dropped"`, "secret=tls ", "reason=certificate_secret_not_listed"); got != 1 {
		t.Errorf("%d 'ingress certificate dropped' lines, want 1:\n%s", got, fx.logs.String())
	}
}

func TestIngressCertificates_SharedSecret(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	fx.certs.set("tls", 1, certPEM(t, "*.example.com", "v1"))
	one := terminateRule("one", 443, "one.example.com", "tls", 9001)
	two := terminateRule("two", 443, "two.example.com", "tls", 9002)

	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(one, two)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireFetches(t, fx.certs, certVersion{"tls", 1})
	for _, slug := range []string{"one", "two"} {
		if st := stateOf(t, fx.mgr, slug); !st.Served {
			t.Errorf("rule %s = %+v, want served", slug, st)
		}
	}

	if err := fx.mgr.Apply(t.Context(), rulesBlock()); err != nil {
		t.Fatalf("Apply without the rules: %v", err)
	}
	if cert := fx.mgr.certificateFor("tls"); cert != nil {
		t.Error("the certificate is still held, want the entry deleted")
	}
	if got := logLines(fx.logs, `msg="ingress certificate dropped"`, "secret=tls", "version=1", "reason=rule_removed"); got != 1 {
		t.Errorf("%d 'ingress certificate dropped' lines, want 1:\n%s", got, fx.logs.String())
	}

	if err := fx.mgr.Apply(t.Context(), rulesBlock(one)); err != nil {
		t.Fatalf("Apply with one rule again: %v", err)
	}
	requireFetches(t, fx.certs, certVersion{"tls", 1}, certVersion{"tls", 1})
}

func TestIngressCertificates_HostCoverage(t *testing.T) {
	const warning = `msg="ingress certificate does not cover the rule's host"`

	t.Run("another host", func(t *testing.T) {
		fx := newIngressFixture(t, newLoopbackIngressController(t))
		fx.certs.set("tls", 1, certPEM(t, "other.example.com", "v1"))
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
		for range 2 {
			if err := fx.mgr.Apply(t.Context(), termBlock); err != nil {
				t.Fatalf("Apply: %v", err)
			}
		}
		if st := stateOf(t, fx.mgr, "term"); !st.Served {
			t.Errorf("rule term = %+v, want served", st)
		}
		if got := logLines(fx.logs, `level=WARN`, warning, "rule_id=id-term", "slug=term", "sni_host=t.example.com", "secret=tls", "version=1"); got != 1 {
			t.Errorf("%d coverage warnings, want 1:\n%s", got, fx.logs.String())
		}
	})

	t.Run("a wildcard on a wildcard rule", func(t *testing.T) {
		fx := newIngressFixture(t, newLoopbackIngressController(t))
		fx.certs.set("tls", 1, certPEM(t, "*.example.com", "v1"))
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
		if err := fx.mgr.Apply(t.Context(), rulesBlock(terminateRule("wild", 443, "*.example.com", "tls", 9000))); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if st := stateOf(t, fx.mgr, "wild"); !st.Served {
			t.Errorf("rule wild = %+v, want served", st)
		}
		if got := logLines(fx.logs, warning); got != 0 {
			t.Errorf("%d coverage warnings, want none:\n%s", got, fx.logs.String())
		}
	})
}
