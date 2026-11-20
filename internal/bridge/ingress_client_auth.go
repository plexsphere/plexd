package bridge

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// maxClientAuthorities is the most CA certificates the ca_bundle of a rule's
// client_auth holds, as the control plane validates it.
const maxClientAuthorities = 8

// The reasons the bridge refuses a client of a rule with client_auth, as the
// ingress status report carries them in client_refusals.
const (
	// IngressRefusalNoCertificate: the client presented no certificate.
	IngressRefusalNoCertificate = "no_certificate"
	// IngressRefusalUnknownAuthority: the client's certificate chains to no
	// authority of the rule.
	IngressRefusalUnknownAuthority = "unknown_authority"
	// IngressRefusalCertificateExpired: the client's certificate, an
	// intermediate or the authority is outside its validity period.
	IngressRefusalCertificateExpired = "certificate_expired"
	// IngressRefusalCertificateInvalid: any other failed check, such as a
	// leaf whose extended key usage leaves out client authentication or a
	// client that does not hold the certificate's key.
	IngressRefusalCertificateInvalid = "certificate_invalid"
)

// clientRefusalOrder is the order in which a rule's refusals are reported.
var clientRefusalOrder = []string{
	IngressRefusalNoCertificate,
	IngressRefusalUnknownAuthority,
	IngressRefusalCertificateExpired,
	IngressRefusalCertificateInvalid,
}

// clientAuthorities is what the bridge makes of a rule's client_auth: the
// trust anchors of its handshake, a key that tells two rules' authorities
// apart, and the defect that keeps the bundle from building.
type clientAuthorities struct {
	// pool holds the bundle's certificates; empty when defect is set, so a
	// handshake against it would refuse every client.
	pool *x509.CertPool
	// key is the lowercase hex SHA-256 fingerprints of the certificates' DER,
	// sorted, repeats dropped, joined by a line feed, for a bundle that
	// builds; otherwise "invalid:" followed by the hex SHA-256 of the
	// bundle's bytes. Two rules name the same authorities exactly when their
	// keys are equal.
	key string
	// defect names the first check the bundle fails, without a byte of the
	// bundle; empty when it builds.
	defect string
}

// newClientAuthorities builds the client authorities of a rule's client_auth,
// or returns nil for a rule without one. The bundle builds when it is not
// empty after trimming white space (defect "empty"); every "-----BEGIN "
// marker opens a block encoding/pem decodes, which catches a truncated block
// pem.Decode skips ("a PEM block does not decode"); it holds a block ("no PEM
// block"), and at most maxClientAuthorities of them ("more than 8
// certificates"); and each block, counted from 1, is a CERTIFICATE ("block N
// is not a CERTIFICATE") that parses ("certificate N does not parse") as a CA
// certificate ("certificate N is not a CA certificate"). The checks run in
// that order and the first that fails is the defect. An expired authority,
// one whose validity starts later and a repeated certificate are accepted:
// the control plane keeps an authority that expires after the write on the
// rule.
func newClientAuthorities(ca *api.IngressClientAuth) *clientAuthorities {
	if ca == nil {
		return nil
	}
	pool, fingerprints, defect := parseClientAuthorities([]byte(ca.CABundle))
	if defect != "" {
		sum := sha256.Sum256([]byte(ca.CABundle))
		return &clientAuthorities{pool: x509.NewCertPool(), key: "invalid:" + hex.EncodeToString(sum[:]), defect: defect}
	}
	slices.Sort(fingerprints)
	return &clientAuthorities{pool: pool, key: strings.Join(slices.Compact(fingerprints), "\n")}
}

// parseClientAuthorities returns the pool of a bundle's certificates and their
// fingerprints, or the defect of the first check the bundle fails (see
// newClientAuthorities).
func parseClientAuthorities(bundle []byte) (*x509.CertPool, []string, string) {
	if len(bytes.TrimSpace(bundle)) == 0 {
		return nil, nil, "empty"
	}
	var blocks []*pem.Block
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	switch {
	case bytes.Count(bundle, []byte("-----BEGIN ")) != len(blocks):
		return nil, nil, "a PEM block does not decode"
	case len(blocks) == 0:
		return nil, nil, "no PEM block"
	case len(blocks) > maxClientAuthorities:
		return nil, nil, "more than " + strconv.Itoa(maxClientAuthorities) + " certificates"
	}
	pool := x509.NewCertPool()
	fingerprints := make([]string, 0, len(blocks))
	for i, block := range blocks {
		n := strconv.Itoa(i + 1)
		if block.Type != "CERTIFICATE" {
			return nil, nil, "block " + n + " is not a CERTIFICATE"
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, "certificate " + n + " does not parse"
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, nil, "certificate " + n + " is not a CA certificate"
		}
		pool.AddCert(cert)
		sum := sha256.Sum256(cert.Raw)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	return pool, fingerprints, ""
}

// clientAuthKey returns the key of a rule's client authorities, "" for a
// rule without client_auth.
func clientAuthKey(ca *clientAuthorities) string {
	if ca == nil {
		return ""
	}
	return ca.key
}

// errNoClientCertificate is the handshake error of a client that presented no
// certificate to a rule with client_auth.
var errNoClientCertificate = errors.New("bridge: ingress: the client presented no certificate")

// requireClientCertificate makes cfg ask the client for a certificate and
// complete the handshake only with one that chains to a certificate of pool.
// crypto/tls verifies a presented chain before it calls VerifyConnection,
// against pool as the roots, the certificates the client sent as
// intermediates, the current time and the usage x509.ExtKeyUsageClientAuth,
// and it names the subjects of pool in its certificate request; it checks no
// revocation. VerifyConnection refuses a client without a certificate with
// errNoClientCertificate, which tls.RequireAndVerifyClientCert would refuse
// with an error of no type. The returned flag is set once the client
// presented a chain that verified, when crypto/tls calls VerifyConnection: in
// TLS 1.3 right after the client's certificate message, in TLS 1.2 once the
// message after it arrived too. A later failure of the handshake, such as a
// client without the certificate's key, is then a refusal too.
func requireClientCertificate(cfg *tls.Config, pool *x509.CertPool) (presented *bool) {
	presented = new(bool)
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	cfg.ClientCAs = pool
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errNoClientCertificate
		}
		*presented = true
		return nil
	}
	return presented
}

// clientRefusalReason returns the refusal reason of a failed handshake of a
// rule with client_auth, presented being whether the client presented a chain
// that verified (see requireClientCertificate), or "" when the failure is no
// refusal. That is every failure with no error of its own type while presented
// is false: a client that stalled or went away before its certificate message,
// a certificate message crypto/tls refuses before the chain check (a
// certificate that does not parse, an RSA key above 8192 bits, a key type it
// does not support), and in TLS 1.2 a client that stalls between its
// certificate and the message after it. Such a connection closes with
// tls_handshake_failed. The first rule that applies decides:
//
//   - errNoClientCertificate: no_certificate;
//   - a *tls.CertificateVerificationError that wraps x509.UnknownAuthorityError:
//     unknown_authority;
//   - one that wraps x509.CertificateInvalidError with the reason x509.Expired,
//     for the leaf, an intermediate or the authority: certificate_expired;
//   - any other *tls.CertificateVerificationError, such as
//     x509.IncompatibleUsage for a leaf whose extended key usage leaves out
//     client authentication: certificate_invalid;
//   - any other error once presented is true: certificate_invalid;
//   - any other error: "".
func clientRefusalReason(err error, presented bool) string {
	if errors.Is(err, errNoClientCertificate) {
		return IngressRefusalNoCertificate
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		var unknown x509.UnknownAuthorityError
		if errors.As(verifyErr.Err, &unknown) {
			return IngressRefusalUnknownAuthority
		}
		var invalid x509.CertificateInvalidError
		if errors.As(verifyErr.Err, &invalid) && invalid.Reason == x509.Expired {
			return IngressRefusalCertificateExpired
		}
		return IngressRefusalCertificateInvalid
	}
	if presented {
		return IngressRefusalCertificateInvalid
	}
	return ""
}

// clientRefusals is the refusal record of one rule with client_auth: the time
// of the last refusal per reason, at most one entry per reason. It belongs to
// the bundle text it was made for, so a changed ca_bundle starts a new record.
// It is concurrent-safe via its own mu, since every handshake of the rule
// records on it.
type clientRefusals struct {
	bundle string

	mu   sync.Mutex
	last map[string]time.Time
}

// newClientRefusals returns an empty refusal record for bundle.
func newClientRefusals(bundle string) *clientRefusals {
	return &clientRefusals{bundle: bundle, last: make(map[string]time.Time, len(clientRefusalOrder))}
}

// record keeps at as the time of the last refusal for reason, unless a later
// one is recorded already.
func (c *clientRefusals) record(reason string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.last[reason]; !ok || at.After(prev) {
		c.last[reason] = at
	}
}

// snapshot returns the recorded refusals in the order no_certificate,
// unknown_authority, certificate_expired, certificate_invalid, each with the
// time of its last refusal, and nil without one or for a nil record.
func (c *clientRefusals) snapshot() []IngressClientRefusalReport {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []IngressClientRefusalReport
	for _, reason := range clientRefusalOrder {
		if at, ok := c.last[reason]; ok {
			out = append(out, IngressClientRefusalReport{Reason: reason, At: at})
		}
	}
	return out
}

// forwardedClientCert returns the X-Forwarded-Client-Cert value a target
// receives for a verified client, in Envoy's form with the keys Hash and
// Subject: Hash=<lowercase hex SHA-256 of the leaf's DER>;Subject="<DN>". DN
// is leaf.Subject.String(), which writes a quote as \" and passes control
// bytes through, with every byte below 0x20, the byte 0x7F and every byte
// from 0x80 up written as a backslash and two uppercase hex digits. net/http
// refuses a field value with a control byte, so the escape keeps a hostile
// subject from failing or forging a request.
func forwardedClientCert(leaf *x509.Certificate) string {
	const hexDigits = "0123456789ABCDEF"
	sum := sha256.Sum256(leaf.Raw)
	dn := leaf.Subject.String()
	var b strings.Builder
	b.WriteString("Hash=")
	b.WriteString(hex.EncodeToString(sum[:]))
	b.WriteString(`;Subject="`)
	for i := range len(dn) {
		c := dn[i]
		if c < 0x20 || c >= 0x7F {
			b.WriteByte('\\')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
			continue
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}
