package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/plexsphere/plexd/internal/api"
)

// errACMERetired fails every request of an autocert.Manager that a later
// Configure or Teardown replaced.
var errACMERetired = errors.New("bridge: acme: the account settings were replaced")

// acmeMaxRetryWait is the longest the ACME client of an account waits before
// it repeats a request the acme package retries, such as one the CA answered
// with 429 or a 5xx. A Retry-After beyond it ends the attempt instead (see
// acmeRetryBackoff).
const acmeMaxRetryWait = 10 * time.Second

// acmeTeardownWait bounds how long Teardown waits for the goroutines that
// obtain a certificate ahead of the first client.
const acmeTeardownWait = 10 * time.Second

// ACMEConfig holds the local settings of the ACME account the bridge's acme
// rules share. The directory and the contact come from the state pull.
type ACMEConfig struct {
	// CacheDir holds the account key and the certificates, as autocert.DirCache
	// lays them out. Empty keeps them in memory only.
	CacheDir string
	// HTTPTransport carries the ACME requests; nil means http.DefaultTransport.
	HTTPTransport http.RoundTripper
}

// ACMEManager obtains and renews the certificates of the bridge's acme rules
// through one autocert.Manager at a time.
//
// autocert cannot change its directory or stop a renewal, so Configure builds
// a new autocert.Manager when the account settings change or a host leaves,
// and retires the one it replaces: every request of the retired manager fails
// at its gate transport with errACMERetired, so its renewal timers, which stay
// armed, never reach the network. The certificates and the account key stay in
// CacheDir across a replacement, so a cached certificate keeps serving until
// its renewal.
//
// ACMEManager is concurrent-safe via mu. It never holds mu while it calls
// autocert.
type ACMEManager struct {
	cfg    ACMEConfig
	logger *slog.Logger

	// getCertificate, nil in production, replaces the autocert call in tests.
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// teardownWait is acmeTeardownWait; a test shortens it.
	teardownWait time.Duration

	mu      sync.Mutex
	hosts   map[string]struct{} // the lowercase sni_host of every served acme rule
	account *acmeAccount        // nil while no account is configured
	// onIssued is called, outside mu, when the issued hosts of the active
	// account change; nil calls nothing.
	onIssued func()

	// obtaining counts the goroutines that obtain a certificate ahead of the
	// first client. idle is made when the count leaves zero and closed when it
	// drops back to zero.
	obtaining int
	idle      chan struct{}
}

// acmeAccount is one autocert.Manager and the settings it was built for.
type acmeAccount struct {
	settings api.IngressACME
	hosts    map[string]struct{} // the hosts a certificate was requested for
	manager  *autocert.Manager
	client   *acme.Client
	gate     *acmeGate
	// issued holds the lowercase hosts whose last certificate request
	// succeeded; guarded by ACMEManager.mu.
	issued map[string]struct{}
}

// retire cuts the account off from the network. It is nil-safe.
func (a *acmeAccount) retire() {
	if a != nil {
		a.gate.retire()
	}
}

// NewACMEManager creates an ACMEManager without an account.
func NewACMEManager(cfg ACMEConfig, logger *slog.Logger) *ACMEManager {
	return &ACMEManager{
		cfg:          cfg,
		logger:       logger,
		teardownWait: acmeTeardownWait,
	}
}

// Configure sets the account and the hosts certificates may be requested for.
// nil settings or no hosts retire the account.
//
// It builds an autocert.Manager when none is active, when DirectoryURL or
// ContactEmail differ from the active one's, or when a host of the active one
// left the set; a host that only joins keeps the manager. For each host new to
// the active manager, a goroutine obtains the certificate ahead of the first
// client.
func (m *ACMEManager) Configure(settings *api.IngressACME, hosts []string) {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if h != "" {
			set[strings.ToLower(h)] = struct{}{}
		}
	}

	m.mu.Lock()
	if settings == nil || len(set) == 0 {
		retired := m.account
		m.account, m.hosts = nil, nil
		m.mu.Unlock()
		retired.retire()
		return
	}

	m.hosts = set
	var retired *acmeAccount
	acct := m.account
	if acct == nil || acct.settings != *settings || !hostsKept(acct.hosts, set) {
		retired = acct
		acct = m.newAccount(*settings)
		m.account = acct
		m.logger.Info("acme account configured",
			"component", "bridge",
			"directory_url", settings.DirectoryURL,
			"contact", settings.ContactEmail != "",
			"hosts", len(set),
		)
	}
	for _, h := range slices.Sorted(maps.Keys(set)) {
		if _, ok := acct.hosts[h]; ok {
			continue
		}
		acct.hosts[h] = struct{}{}
		if m.obtaining == 0 {
			m.idle = make(chan struct{})
		}
		m.obtaining++
		go m.obtain(acct, h)
	}
	m.mu.Unlock()
	retired.retire()
}

// hostsKept reports whether every host of old is in set.
func hostsKept(old, set map[string]struct{}) bool {
	for h := range old {
		if _, ok := set[h]; !ok {
			return false
		}
	}
	return true
}

// newAccount builds the autocert.Manager for settings. Its host policy reads
// the manager's current host set, so it is set once and never swapped. The
// caller holds mu.
func (m *ACMEManager) newAccount(settings api.IngressACME) *acmeAccount {
	base := m.cfg.HTTPTransport
	if base == nil {
		base = http.DefaultTransport
	}
	gate := newACMEGate(base)
	client := &acme.Client{
		DirectoryURL: settings.DirectoryURL,
		HTTPClient:   &http.Client{Transport: gate},
		RetryBackoff: acmeRetryBackoff(gate),
	}
	am := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      settings.ContactEmail,
		HostPolicy: m.hostPolicy,
		Client:     client,
	}
	if m.cfg.CacheDir != "" {
		am.Cache = autocert.DirCache(m.cfg.CacheDir)
	}
	return &acmeAccount{
		settings: settings,
		hosts:    make(map[string]struct{}),
		manager:  am,
		client:   client,
		gate:     gate,
		issued:   make(map[string]struct{}),
	}
}

// acmeRetryBackoff returns the acme.Client.RetryBackoff of the account whose
// transport is gate. The acme package sleeps for the delay it returns before
// it repeats a failed request, and retiring gate does not wake that sleep, so
// every delay is at most acmeMaxRetryWait:
//
//   - once gate is retired, it returns -1, so the request is not repeated;
//   - for a response whose Retry-After is longer than acmeMaxRetryWait, it
//     returns -1 too: the attempt fails, the next client handshake asks
//     again, and autocert waits a minute after a failed issuance before it
//     orders again, so the CA's wait is respected;
//   - for a shorter Retry-After, it returns the Retry-After;
//   - otherwise the nth retry waits 1 s, doubling per retry up to
//     acmeMaxRetryWait.
//
// Retry-After is read as integer seconds or as an HTTP date, as the acme
// package reads it. A value that is neither, or that names no wait, counts as
// absent.
func acmeRetryBackoff(gate *acmeGate) func(n int, r *http.Request, resp *http.Response) time.Duration {
	return func(n int, _ *http.Request, resp *http.Response) time.Duration {
		if gate.retired() {
			return -1
		}
		if resp != nil {
			if d := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); d > 0 {
				if d > acmeMaxRetryWait {
					return -1
				}
				return d
			}
		}
		// The acme package bounds n the same way; 1<<29 s does not overflow.
		n = min(max(n, 1), 30)
		return min(time.Second<<(n-1), acmeMaxRetryWait)
	}
}

// parseRetryAfter reads a Retry-After value as integer seconds, or as an HTTP
// date relative to now. It returns 0 for a value that is neither.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if s, err := strconv.ParseInt(v, 10, 64); err == nil {
		if s > int64(math.MaxInt64/time.Second) {
			return math.MaxInt64
		}
		return time.Duration(s) * time.Second
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0
	}
	return t.Sub(now)
}

// hostPolicy admits the sni_host of a served acme rule and refuses every
// other name, so a client cannot make the bridge order a certificate for a
// name of its choosing.
func (m *ACMEManager) hostPolicy(_ context.Context, host string) error {
	if !m.HasHost(host) {
		return fmt.Errorf("bridge: acme: %q is not the sni_host of an acme rule", host)
	}
	return nil
}

// obtain asks the account for the certificate of host with a ClientHello that
// offers ECDSA P-256, the variant autocert gives a current client, and logs
// the outcome. A result that arrives after the account was retired is dropped.
// There is no retry: the next client handshake asks autocert again.
func (m *ACMEManager) obtain(acct *acmeAccount, host string) {
	defer m.obtainDone()
	hello := &tls.ClientHelloInfo{
		ServerName:       host,
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
	}
	cert, err := m.certificate(acct, hello)
	if acct.gate.retired() {
		return
	}
	if err != nil {
		m.logger.Error("bridge: acme: obtain certificate failed",
			"component", "bridge",
			"sni_host", host,
			"error", err,
		)
		return
	}
	m.logger.Info("ingress certificate obtained",
		"component", "bridge",
		"sni_host", host,
		"not_after", certificateNotAfter(cert),
	)
}

// obtainDone counts an obtain goroutine out.
func (m *ACMEManager) obtainDone() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obtaining--
	if m.obtaining == 0 {
		close(m.idle)
	}
}

// certificateNotAfter returns the expiry of a certificate's leaf, or the zero
// time when the leaf does not parse.
func certificateNotAfter(cert *tls.Certificate) time.Time {
	if cert.Leaf != nil {
		return cert.Leaf.NotAfter
	}
	if len(cert.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// certificate asks acct's autocert.Manager, or the test hook, for a
// certificate. For a hello that is no TLS-ALPN-01 challenge it records the
// outcome: a certificate marks the lowercase server name issued, an error
// unmarks it.
func (m *ACMEManager) certificate(acct *acmeAccount, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var cert *tls.Certificate
	var err error
	if m.getCertificate != nil {
		cert, err = m.getCertificate(hello)
	} else {
		cert, err = acct.manager.GetCertificate(hello)
	}
	if !slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		m.recordIssued(acct, hello.ServerName, err == nil)
	}
	return cert, err
}

// recordIssued marks host issued or not on acct. When that changes the set
// and acct is still the active account, it calls the function OnIssuedChange
// registered, outside mu.
func (m *ACMEManager) recordIssued(acct *acmeAccount, serverName string, issued bool) {
	host := strings.ToLower(serverName)
	if host == "" {
		return
	}
	m.mu.Lock()
	_, was := acct.issued[host]
	if issued {
		acct.issued[host] = struct{}{}
	} else {
		delete(acct.issued, host)
	}
	var notify func()
	if was != issued && m.account == acct {
		notify = m.onIssued
	}
	m.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// Issued reports whether an account is configured and the last certificate
// request for host, in any case, succeeded: the obtain ahead of the first
// client or a client handshake, not a TLS-ALPN-01 challenge. A new account
// starts with no host issued.
func (m *ACMEManager) Issued(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.account == nil {
		return false
	}
	_, ok := m.account.issued[strings.ToLower(host)]
	return ok
}

// OnIssuedChange registers fn, which is called whenever a request changes
// whether a host of the active account is issued. fn runs on the goroutine
// that made the request, outside the manager's lock, and must not block.
func (m *ACMEManager) OnIssuedChange(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onIssued = fn
}

// HasHost reports whether serverName, in any case, is the sni_host of a
// served acme rule while an account is configured.
func (m *ACMEManager) HasHost(serverName string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.account == nil {
		return false
	}
	_, ok := m.hosts[strings.ToLower(serverName)]
	return ok
}

// GetCertificate returns the certificate of the active account for hello: the
// host's certificate, or for a TLS-ALPN-01 challenge hello the challenge
// certificate. It fits tls.Config.GetCertificate.
func (m *ACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	acct := m.account
	m.mu.Unlock()
	if acct == nil {
		return nil, errors.New("bridge: acme: no account is configured")
	}
	return m.certificate(acct, hello)
}

// Active reports whether an account is configured.
func (m *ACMEManager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.account != nil
}

// Teardown retires the active account and waits at most acmeTeardownWait for
// the goroutines that obtain a certificate ahead of the first client. The
// retired gate fails their next request and acmeRetryBackoff keeps every wait
// between two requests within acmeMaxRetryWait, so they normally end within
// the bound. When they do not, Teardown logs a warning and returns; they end
// on their own later. It is idempotent and returns nil.
func (m *ACMEManager) Teardown() error {
	m.mu.Lock()
	acct := m.account
	m.account, m.hosts = nil, nil
	busy, idle := m.obtaining > 0, m.idle
	m.mu.Unlock()
	acct.retire()
	if !busy {
		return nil
	}

	timer := time.NewTimer(m.teardownWait)
	defer timer.Stop()
	select {
	case <-idle:
	case <-timer.C:
		m.logger.Warn("bridge: acme: certificate requests still running after teardown",
			"component", "bridge",
		)
	}
	return nil
}

// acmeGate is the transport of one account. Once retired it fails every
// request with errACMERetired without calling the base transport, and it
// cancels the requests in flight.
type acmeGate struct {
	base   http.RoundTripper
	ctx    context.Context // cancelled on retire
	cancel context.CancelFunc
}

func newACMEGate(base http.RoundTripper) *acmeGate {
	ctx, cancel := context.WithCancel(context.Background())
	return &acmeGate{base: base, ctx: ctx, cancel: cancel}
}

func (g *acmeGate) retire()       { g.cancel() }
func (g *acmeGate) retired() bool { return g.ctx.Err() != nil }

// RoundTrip passes req to the base transport under a context that retire
// cancels. The context lives until the response body is closed, because the
// caller reads the body after RoundTrip returns.
func (g *acmeGate) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.retired() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errACMERetired
	}
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(g.ctx, cancel)
	done := func() {
		stop()
		cancel()
	}
	resp, err := g.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		done()
		if g.retired() {
			return nil, errACMERetired
		}
		return nil, err
	}
	if resp.Body == nil {
		done()
		return resp, nil
	}
	resp.Body = &gatedBody{ReadCloser: resp.Body, done: done}
	return resp, nil
}

// gatedBody ends the request context of a gated request when the body is
// closed.
type gatedBody struct {
	io.ReadCloser
	done func()
}

func (b *gatedBody) Close() error {
	err := b.ReadCloser.Close()
	b.done()
	return err
}
