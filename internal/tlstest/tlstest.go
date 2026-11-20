// Package tlstest makes certificate authorities and TLS servers whose leaf a
// given authority signed, so a test can show that a client trusts one CA and
// refuses another. httptest.NewTLSServer cannot show that: every server it
// starts presents the same built-in certificate.
//
// The package is imported only from tests.
package tlstest

import (
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
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a certificate authority that exists for the length of one test.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	file string
}

// NewCA creates a CA and writes its certificate to a PEM file under
// t.TempDir(), which File returns.
func NewCA(t testing.TB) *CA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: generate CA key: %v", err)
	}
	serial := serialNumber(t)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// Each CA gets a name of its own, as unrelated CAs have, so that a
		// pool holding one never tries it as the issuer of another's leaf.
		Subject:               pkix.Name{CommonName: fmt.Sprintf("plexd test CA %x", serial)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tlstest: create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tlstest: parse CA certificate: %v", err)
	}

	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("tlstest: write CA file: %v", err)
	}

	return &CA{cert: cert, key: key, file: file}
}

// File returns the path of a PEM file that holds the CA certificate and
// nothing else.
func (ca *CA) File() string {
	return ca.file
}

// Server starts an HTTPS server for h whose certificate the CA signed for
// 127.0.0.1, ::1 and localhost. The server sends that leaf alone, without the
// CA certificate, so a client completes the handshake only when it already
// trusts the CA. The server is closed when the test ends.
//
// The client that srv.Client() returns trusts the leaf directly, so a test
// that proves verification must use the client it is testing instead.
func (ca *CA) Server(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// leaf issues a fresh server certificate signed by the CA.
func (ca *CA) leaf(t testing.TB) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: generate leaf key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(t),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("tlstest: create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tlstest: parse leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// serialNumber returns a random 128-bit serial, so that no two certificates
// of a test run share one.
func serialNumber(t testing.TB) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("tlstest: generate serial number: %v", err)
	}
	return serial
}
