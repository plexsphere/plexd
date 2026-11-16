package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The delays before the next fetch of a version whose fetch failed: the first
// after one failure, doubling per consecutive failure up to the last.
const (
	certRetryFirst = 5 * time.Second
	certRetryMax   = 60 * time.Second
)

// certDroppedRuleRemoved is the reason an "ingress certificate dropped" line
// gives when no held rule names the Secret any more.
const certDroppedRuleRemoved = "rule_removed"

// CertificateSecretFetcher reads the value of one version of a Secret the
// node may read: the PEM document of a terminate rule's certificate.
type CertificateSecretFetcher interface {
	FetchCertificateSecret(ctx context.Context, name string, version int) ([]byte, error)
}

// certEntry is the certificate of one Secret a held terminate rule names.
type certEntry struct {
	cert    *tls.Certificate // nil while none is loaded
	version int              // the version cert was loaded from

	// The last failure: the version it was for, its reason, the consecutive
	// failed fetches of that version, and when the next fetch is due.
	failVersion int
	failReason  string
	attempts    int
	nextAttempt time.Time

	// logged holds the "ingress certificate not loaded" lines logged since
	// the last load.
	logged map[notLoadedKey]struct{}
}

// notLoadedKey identifies an "ingress certificate not loaded" line.
type notLoadedKey struct {
	version int
	reason  string
}

// coverageKey identifies a rule's host checked against a loaded certificate.
type coverageKey struct {
	ruleID  string
	host    string
	secret  string
	version int
}

// secretInventory maps the pull's secret inventory onto name and version. It
// keeps the first entry of a name and drops a name outside the grammar and a
// version below 1, as the node API's secret index does, and never returns nil.
func secretInventory(inventory []api.NodeStateSecret) map[string]int {
	out := make(map[string]int, len(inventory))
	for _, entry := range inventory {
		if _, dup := out[entry.Name]; dup || !api.ValidSecretName(entry.Name) || entry.Version < 1 {
			continue
		}
		out[entry.Name] = entry.Version
	}
	return out
}

// SyncSecretInventory takes the secret inventory of a pull and loads, replaces
// or drops the certificates of the held terminate rules. It does nothing while
// the manager is not active.
func (m *IngressManager) SyncSecretInventory(ctx context.Context, inventory []api.NodeStateSecret) {
	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	m.inventory = secretInventory(inventory)
	m.mu.Unlock()

	m.loadCertificates(ctx)
}

// certificateNamesLocked returns, sorted, the Secret names the held terminate
// rules name. The caller holds mu.
func (m *IngressManager) certificateNamesLocked() []string {
	names := make(map[string]struct{})
	for _, st := range m.states {
		if st.held && st.Rule.Mode == api.IngressModeTerminate {
			names[st.Rule.CertificateSecretName] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(names))
}

// loadCertificates brings the certificate of every Secret a held terminate
// rule names in line with the inventory:
//
//   - a name the inventory does not list has no certificate; one it held is
//     dropped, and the connections of every rule naming it are closed;
//   - a listed version the entry holds is kept;
//   - any other listed version is fetched, unless it failed as invalid, or
//     failed to fetch and its next attempt is not due.
//
// A version that fails to load leaves a certificate the entry holds serving.
// The fetches run outside mu; the reconcile goroutine is the only caller, so
// two loads never overlap.
func (m *IngressManager) loadCertificates(ctx context.Context) {
	type fetch struct {
		name    string
		version int
	}

	m.mu.Lock()
	if !m.active {
		m.mu.Unlock()
		return
	}
	now := m.now()
	var fetches []fetch
	dropped := make(map[string]bool)
	for _, name := range m.certificateNamesLocked() {
		e := m.certs[name]
		if e == nil {
			e = &certEntry{}
			m.certs[name] = e
		}
		v, listed := m.inventory[name]
		switch {
		case !listed && e.cert == nil:
			m.logNotLoadedLocked(name, e, 0, IngressReasonCertificateSecretNotListed, nil)
		case !listed:
			m.logger.Info("ingress certificate dropped",
				"component", "bridge",
				"secret", name,
				"version", e.version,
				"reason", IngressReasonCertificateSecretNotListed,
			)
			e.cert, e.version = nil, 0
			// The dropped line says it; no "not loaded" line repeats it.
			e.markLogged(0, IngressReasonCertificateSecretNotListed)
			dropped[name] = true
		case e.cert != nil && e.version == v:
		case e.failVersion == v && e.failReason == IngressReasonCertificateInvalid:
		case e.failVersion == v && e.failReason == IngressReasonCertificateFetchFailed && now.Before(e.nextAttempt):
		default:
			fetches = append(fetches, fetch{name: name, version: v})
		}
	}
	if len(dropped) > 0 {
		m.renewRoutesLocked(func(r api.IngressRule) bool {
			return r.Mode == api.IngressModeTerminate && dropped[r.CertificateSecretName]
		})
	}
	m.mu.Unlock()

	for _, f := range fetches {
		value, err := m.fetcher.FetchCertificateSecret(ctx, f.name, f.version)
		if err != nil && ctx.Err() != nil {
			// The cycle is over (plexd stops); the next one fetches again.
			break
		}
		var cert *tls.Certificate
		reason := ""
		if err != nil {
			reason = IngressReasonCertificateFetchFailed
		} else {
			cert, err = parseCertificate(value)
			clear(value)
			if err != nil {
				reason = IngressReasonCertificateInvalid
			}
		}

		m.mu.Lock()
		e := m.certs[f.name]
		if !m.active || e == nil {
			m.mu.Unlock()
			continue
		}
		if reason == "" {
			e.cert, e.version = cert, f.version
			e.failVersion, e.failReason, e.attempts, e.nextAttempt = 0, "", 0, time.Time{}
			e.logged = nil
			m.logger.Info("ingress certificate loaded",
				"component", "bridge",
				"secret", f.name,
				"version", f.version,
				"not_after", cert.Leaf.NotAfter,
			)
		} else {
			if reason == IngressReasonCertificateFetchFailed && e.failVersion == f.version && e.failReason == reason {
				e.attempts++
			} else {
				e.attempts = 1
			}
			e.failVersion, e.failReason = f.version, reason
			if reason == IngressReasonCertificateFetchFailed {
				e.nextAttempt = m.now().Add(certRetryDelay(e.attempts, err))
			}
			m.logNotLoadedLocked(f.name, e, f.version, reason, err)
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	m.checkCoverageLocked()
	m.signalReport()
	m.mu.Unlock()
}

// certRetryDelay returns the delay after the given count of consecutive failed
// fetches of one version: 5 s, doubling to 60 s, or the Retry-After of an API
// error when that is longer.
func certRetryDelay(attempts int, err error) time.Duration {
	d := certRetryFirst
	for i := 1; i < attempts && d < certRetryMax; i++ {
		d *= 2
	}
	d = min(d, certRetryMax)
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > d {
		d = apiErr.RetryAfter
	}
	return d
}

// parseCertificate reads a certificate chain and its key from one PEM
// document: the CERTIFICATE blocks are the chain and the first private key
// block is the key, which must match the leaf.
func parseCertificate(value []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(value, value)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// logNotLoadedLocked logs that version of a Secret did not load, once per
// version and reason until the next load. The caller holds mu.
func (m *IngressManager) logNotLoadedLocked(name string, e *certEntry, version int, reason string, err error) {
	if !e.markLogged(version, reason) {
		return
	}
	var errText string
	if err != nil {
		errText = err.Error()
	}
	m.logger.Warn("ingress certificate not loaded",
		"component", "bridge",
		"secret", name,
		"version", version,
		"reason", reason,
		"error", errText,
		"serving_version", e.version,
	)
}

// markLogged records a "not loaded" line and reports whether it is new.
func (e *certEntry) markLogged(version int, reason string) bool {
	key := notLoadedKey{version: version, reason: reason}
	if _, ok := e.logged[key]; ok {
		return false
	}
	if e.logged == nil {
		e.logged = make(map[notLoadedKey]struct{})
	}
	e.logged[key] = struct{}{}
	return true
}

// checkCoverageLocked warns once per rule, host and certificate version about
// a held terminate rule whose host the leaf of its loaded certificate does not
// cover. The certificate serves anyway: the control plane checks no coverage,
// and the operator's client will say the same. The caller holds mu.
func (m *IngressManager) checkCoverageLocked() {
	checked := make(map[coverageKey]struct{})
	for _, st := range m.states {
		r := st.Rule
		if !st.held || r.Mode != api.IngressModeTerminate {
			continue
		}
		e := m.certs[r.CertificateSecretName]
		if e == nil || e.cert == nil {
			continue
		}
		host := strings.ToLower(r.SNIHost)
		key := coverageKey{ruleID: r.ID, host: host, secret: r.CertificateSecretName, version: e.version}
		checked[key] = struct{}{}
		if _, ok := m.coverage[key]; ok {
			continue
		}
		name := host
		if strings.HasPrefix(name, "*.") {
			name = "x" + name[1:]
		}
		if e.cert.Leaf.VerifyHostname(name) != nil {
			m.logger.Warn("ingress certificate does not cover the rule's host",
				"component", "bridge",
				"rule_id", r.ID,
				"slug", r.Slug,
				"sni_host", r.SNIHost,
				"secret", r.CertificateSecretName,
				"version", e.version,
			)
		}
	}
	m.coverage = checked
}

// certificateFor returns the loaded certificate of a Secret, or nil.
func (m *IngressManager) certificateFor(name string) *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.certs[name]; e != nil {
		return e.cert
	}
	return nil
}

// overlayCertificatesLocked returns the states of the last Apply with the
// certificate state of each held terminate rule: Served exactly when its
// Secret's certificate is loaded, and otherwise the reason it is not, with the
// Secret name as Detail. The caller holds mu.
func (m *IngressManager) overlayCertificatesLocked() []IngressRuleState {
	out := slices.Clone(m.states)
	for i := range out {
		st := &out[i]
		if !st.held || st.Rule.Mode != api.IngressModeTerminate || st.Reason != "" {
			continue
		}
		name := st.Rule.CertificateSecretName
		e := m.certs[name]
		if e != nil && e.cert != nil {
			continue
		}
		st.Served = false
		st.Detail = name
		v, listed := m.inventory[name]
		switch {
		case !listed:
			st.Reason = IngressReasonCertificateSecretNotListed
		case e != nil && e.failVersion == v && e.failReason != "":
			st.Reason = e.failReason
		default:
			// The listed version has not loaded yet.
			st.Reason = IngressReasonCertificateFetchFailed
		}
	}
	return out
}

// renewRoutesLocked closes the connections of every route whose rule affected
// selects: it stores, for each listener that routes such a rule, a copy of
// its table with a fresh route in place of each selected one, then cancels the
// old routes. proxy reads a route's context without a lock, so the table is
// replaced rather than changed. The caller holds mu.
func (m *IngressManager) renewRoutesLocked(affected func(api.IngressRule) bool) {
	var old []*ingressRoute
	renew := func(r *ingressRoute) *ingressRoute {
		if r == nil || !affected(r.rule) {
			return r
		}
		fresh := &ingressRoute{rule: r.rule, target: r.target, served: r.served}
		fresh.ctx, fresh.cancel = context.WithCancel(m.ctx)
		old = append(old, r)
		return fresh
	}
	for _, l := range m.sortedListeners() {
		t := l.table.Load()
		if !slices.ContainsFunc(t.routes(), func(r *ingressRoute) bool { return affected(r.rule) }) {
			continue
		}
		nt := &ingressTable{
			plain:    renew(t.plain),
			exact:    make(map[string]*ingressRoute, len(t.exact)),
			wildcard: make(map[string]*ingressRoute, len(t.wildcard)),
		}
		for k, r := range t.exact {
			nt.exact[k] = renew(r)
		}
		for k, r := range t.wildcard {
			nt.wildcard[k] = renew(r)
		}
		l.table.Store(nt)
	}
	for _, r := range old {
		r.cancel()
	}
}
