package api

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
)

// systemCertPool returns the host's system roots. It is a variable so that a
// test can stand in for a host whose roots cannot be loaded, or one whose roots
// hold a CA of the test's choosing.
var systemCertPool = x509.SystemCertPool

// LoadRootCAs returns the host's system roots plus the certificates in caFile.
// An empty caFile returns nil, which a tls.Config reads as the system roots.
//
// The file is read once, when this is called, and its path is used as given,
// so a relative one resolves against the working directory. Blocks of the file
// that are not certificates are skipped, but a file without any certificate is
// an error: the operator named a CA, and trusting the system roots alone would
// fail later with an error that does not say why.
func LoadRootCAs(caFile string, logger *slog.Logger) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool, err := systemCertPool()
	if err != nil {
		// The operator named the CA they need, so a host without system roots
		// must not be refused for it.
		logger.Warn("system certificate pool unavailable, trusting only the CA file",
			"path", caFile, "error", err)
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no certificate found in CA file %s", caFile)
	}
	return pool, nil
}
