package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/tlstest"
)

// stubSystemCertPool replaces systemCertPool with fn until the test ends. The
// variable is shared by the whole package, so a test that calls this must not
// run in parallel.
func stubSystemCertPool(t *testing.T, fn func() (*x509.CertPool, error)) {
	t.Helper()
	orig := systemCertPool
	t.Cleanup(func() { systemCertPool = orig })
	systemCertPool = fn
}

// writeCAFixture writes data to a file named name under t.TempDir() and
// returns its path.
func writeCAFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// readCAFile returns the PEM bytes of ca's certificate file.
func readCAFile(t *testing.T, ca *tlstest.CA) []byte {
	t.Helper()
	data, err := os.ReadFile(ca.File())
	if err != nil {
		t.Fatalf("read CA file: %v", err)
	}
	return data
}

// ecPrivateKeyPEM returns a freshly generated key as an "EC PRIVATE KEY" PEM
// block, the kind of block a combined PEM holds beside its certificate.
func ecPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// requireVerifies fails the test unless pool verifies the leaf srv presents.
func requireVerifies(t *testing.T, pool *x509.CertPool, srv *httptest.Server) {
	t.Helper()
	if _, err := srv.Certificate().Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("leaf of %s does not verify against the pool: %v", srv.URL, err)
	}
}

func TestLoadRootCAs_EmptyPathReturnsNil(t *testing.T) {
	pool, err := LoadRootCAs("", slog.Default())
	if err != nil {
		t.Fatalf("LoadRootCAs(\"\") error = %v, want nil", err)
	}
	if pool != nil {
		t.Errorf("LoadRootCAs(\"\") pool = %v, want nil so the tls.Config uses the system roots", pool)
	}
}

func TestLoadRootCAs_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-ca.pem")

	pool, err := LoadRootCAs(path, slog.Default())
	if err == nil {
		t.Fatalf("LoadRootCAs(%q) = %v, nil; want an error", path, pool)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) = false; err = %v", err)
	}
	if !strings.HasPrefix(err.Error(), "read CA file:") {
		t.Errorf("error = %q, want it to start with %q", err, "read CA file:")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to name %s", err, path)
	}
	if pool != nil {
		t.Errorf("pool = %v, want nil with an error", pool)
	}
}

func TestLoadRootCAs_NoCertificate(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "zero-length file", data: nil},
		{name: "private key only", data: ecPrivateKeyPEM(t)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeCAFixture(t, "ca.pem", tt.data)

			pool, err := LoadRootCAs(path, slog.Default())
			if err == nil {
				t.Fatalf("LoadRootCAs(%q) = %v, nil; want an error", path, pool)
			}
			if want := "no certificate found in CA file " + path; err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
			if pool != nil {
				t.Errorf("pool = %v, want nil with an error", pool)
			}
		})
	}
}

func TestLoadRootCAs_TwoCertificates(t *testing.T) {
	caA := tlstest.NewCA(t)
	caB := tlstest.NewCA(t)
	srvA := caA.Server(t, http.NotFoundHandler())
	srvB := caB.Server(t, http.NotFoundHandler())
	path := writeCAFixture(t, "bundle.pem", bytes.Join([][]byte{readCAFile(t, caA), readCAFile(t, caB)}, nil))

	pool, err := LoadRootCAs(path, slog.Default())
	if err != nil {
		t.Fatalf("LoadRootCAs: %v", err)
	}
	requireVerifies(t, pool, srvA)
	requireVerifies(t, pool, srvB)
}

// A combined PEM often carries a key beside its certificate. Only the
// certificate matters for trust, so the other block must not make the file
// unusable.
func TestLoadRootCAs_SkipsNonCertificateBlocks(t *testing.T) {
	ca := tlstest.NewCA(t)
	srv := ca.Server(t, http.NotFoundHandler())
	path := writeCAFixture(t, "combined.pem", bytes.Join([][]byte{readCAFile(t, ca), ecPrivateKeyPEM(t)}, nil))

	pool, err := LoadRootCAs(path, slog.Default())
	if err != nil {
		t.Fatalf("LoadRootCAs: %v", err)
	}
	requireVerifies(t, pool, srv)
}

func TestLoadRootCAs_SystemPoolUnavailable(t *testing.T) {
	stubSystemCertPool(t, func() (*x509.CertPool, error) {
		return nil, errors.New("no system roots on this host")
	})
	ca := tlstest.NewCA(t)
	srv := ca.Server(t, http.NotFoundHandler())
	logs := &logCapture{}

	pool, err := LoadRootCAs(ca.File(), slog.New(logs))
	if err != nil {
		t.Fatalf("LoadRootCAs error = %v, want nil when only the system pool fails", err)
	}
	requireVerifies(t, pool, srv)

	warns := logs.find("system certificate pool unavailable, trusting only the CA file")
	if len(warns) != 1 {
		t.Fatalf("got %d lines saying the system pool is unavailable, want 1", len(warns))
	}
	if warns[0].level != slog.LevelWarn {
		t.Errorf("level = %v, want %v", warns[0].level, slog.LevelWarn)
	}
	if got := warns[0].attrs["path"]; got != ca.File() {
		t.Errorf("path = %q, want %q", got, ca.File())
	}
	if got := warns[0].attrs["error"]; got != "no system roots on this host" {
		t.Errorf("error = %q, want %q", got, "no system roots on this host")
	}
}
