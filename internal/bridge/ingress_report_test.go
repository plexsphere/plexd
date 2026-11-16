package bridge

import (
	"crypto/tls"
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// reportID returns a rule id in canonical UUID form, ending in suffix, two
// hex digits.
func reportID(suffix string) string {
	return "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1" + suffix
}

// withID returns r with the id id.
func withID(r api.IngressRule, id string) api.IngressRule {
	r.ID = id
	return r
}

// reportFor returns the report of the rule id in reports.
func reportFor(t *testing.T, reports []IngressRuleReport, id string) IngressRuleReport {
	t.Helper()
	for _, r := range reports {
		if r.RuleID == id {
			return r
		}
	}
	t.Fatalf("no report for rule %s in %+v", id, reports)
	return IngressRuleReport{}
}

// drain empties ch.
func drain(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// certResult is what a hooked ACME certificate request answers.
type certResult struct {
	cert *tls.Certificate
	err  error
}

// hookACME makes every certificate request of the fixture's ACME manager wait
// for the next result on the returned channel. The channel is closed when the
// test ends, which releases a request still waiting.
func hookACME(t *testing.T, fx *ingressFixture) chan<- certResult {
	t.Helper()
	results := make(chan certResult, 4)
	fx.acme.getCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		r, ok := <-results
		if !ok {
			return nil, errors.New("test: ended")
		}
		return r.cert, r.err
	}
	t.Cleanup(func() { close(results) })
	return results
}

func TestRuleReports_InactiveAndEmpty(t *testing.T) {
	fx := buildIngressFixture(t, newLoopbackIngressController(t), ingressTestConfig(true))
	if got := fx.mgr.RuleReports(); got != nil {
		t.Errorf("RuleReports before Setup = %+v, want nil", got)
	}
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := fx.mgr.RuleReports(); got == nil || len(got) != 0 {
		t.Errorf("RuleReports after an Apply of the zero block = %#v, want an empty result", got)
	}
	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := fx.mgr.RuleReports(); got != nil {
		t.Errorf("RuleReports after Teardown = %+v, want nil", got)
	}
}

func TestRuleReports_RulesNotHeld(t *testing.T) {
	cfg := ingressTestConfig(true)
	cfg.MaxIngressRules = 2
	fx := buildIngressFixture(t, newLoopbackIngressController(t), cfg)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	invalid := withID(ingressRule("bad", 7024, "", 9000), reportID("c3"))
	invalid.Mode = "bogus"
	if err := fx.mgr.Apply(t.Context(), rulesBlock(
		withID(ingressRule("a", 7022, "", 9000), reportID("a1")),
		withID(ingressRule("conflict", 7022, "", 9000), reportID("b2")),
		invalid,
		withID(ingressRule("d", 7023, "", 9000), reportID("d4")),
		withID(ingressRule("over", 7025, "", 9000), reportID("e5")),
	)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	reports := fx.mgr.RuleReports()
	for _, tc := range []struct{ id, reason string }{
		{reportID("b2"), IngressReasonListenerConflict},
		{reportID("c3"), IngressReasonInvalid},
		{reportID("e5"), IngressReasonMaxRules},
	} {
		want := IngressRuleReport{RuleID: tc.id, Listener: api.IngressListenerNotListening, ListenerReason: tc.reason}
		if got := reportFor(t, reports, tc.id); got != want {
			t.Errorf("report = %+v, want %+v", got, want)
		}
	}
	for _, id := range []string{reportID("a1"), reportID("d4")} {
		if got := reportFor(t, reports, id); got.Listener != api.IngressListenerListening {
			t.Errorf("held rule %s reads listener %q, want listening", id, got.Listener)
		}
	}
	if len(reports) != 5 {
		t.Errorf("%d reports, want one per rule (5): %+v", len(reports), reports)
	}
}

func TestRuleReports_ListenFailed(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	ctrl.failListen(8443, syscall.EADDRINUSE)
	fx := newIngressFixture(t, ctrl)
	// The block has no acme member, so the acme rule is held with the reason
	// acme_directory_invalid before its port fails to bind.
	block := rulesBlock(
		withID(ingressRule("pass", 8443, "p.example.com", 9000), reportID("a1")),
		withID(terminateRule("term", 8443, "t.example.com", "tls", 9000), reportID("b2")),
		withID(acmeRule("acme", 8443, "a.example.com", 9000), reportID("c3")),
	)
	if err := fx.mgr.Apply(t.Context(), block); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want the bind error", err)
	}
	if st := stateOf(t, fx.mgr, "acme"); st.Reason != IngressReasonACMEDirectoryInvalid {
		t.Fatalf("acme rule state = %+v, want the reason %s", st, IngressReasonACMEDirectoryInvalid)
	}

	reports := fx.mgr.RuleReports()
	for _, id := range []string{reportID("a1"), reportID("b2"), reportID("c3")} {
		want := IngressRuleReport{RuleID: id, Listener: api.IngressListenerNotListening, ListenerReason: IngressReasonListenFailed}
		if got := reportFor(t, reports, id); got != want {
			t.Errorf("report = %+v, want %+v", got, want)
		}
	}
}

func TestRuleReports_PassthroughNobodyConnected(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(ingressRule("web", 7022, "", 9000), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := IngressRuleReport{RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired, Dial: api.IngressDialNone}
	if got := reportFor(t, fx.mgr.RuleReports(), id); got != want {
		t.Errorf("report = %+v, want %+v", got, want)
	}
}

func TestRuleReports_TerminateCertificate(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	id := reportID("a1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(terminateRule("term", 443, "t.example.com", "tls", 9000), id))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	certificate := func(step string) (string, string) {
		t.Helper()
		r := reportFor(t, fx.mgr.RuleReports(), id)
		if r.Listener != api.IngressListenerListening || r.Dial != api.IngressDialNone {
			t.Errorf("%s: report = %+v, want listening with dial none", step, r)
		}
		return r.Certificate, r.CertificateReason
	}

	if c, reason := certificate("no inventory"); c != api.IngressCertificateNotReady || reason != IngressReasonCertificateSecretNotListed {
		t.Errorf("no inventory: certificate %q %q, want not_ready %s", c, reason, IngressReasonCertificateSecretNotListed)
	}

	fx.certs.setErr(errors.New("fake: unavailable"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if c, reason := certificate("fetch fails"); c != api.IngressCertificateNotReady || reason != IngressReasonCertificateFetchFailed {
		t.Errorf("fetch fails: certificate %q %q, want not_ready %s", c, reason, IngressReasonCertificateFetchFailed)
	}

	fx.certs.setErr(nil)
	fx.certs.set("tls", 2, []byte("not a certificate"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 2))
	if c, reason := certificate("no PEM"); c != api.IngressCertificateNotReady || reason != IngressReasonCertificateInvalid {
		t.Errorf("no PEM: certificate %q %q, want not_ready %s", c, reason, IngressReasonCertificateInvalid)
	}

	fx.certs.set("tls", 3, certPEM(t, "t.example.com", "v3"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 3))
	if c, reason := certificate("loaded"); c != api.IngressCertificateReady || reason != "" {
		t.Errorf("loaded: certificate %q %q, want ready without a reason", c, reason)
	}
}

func TestRuleReports_ACMECertificate(t *testing.T) {
	cfg := ingressTestConfig(true)
	cfg.ACMEDirectoryURLs = []string{testACME.DirectoryURL}
	fx := buildIngressFixture(t, newLoopbackIngressController(t), cfg)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	results := hookACME(t, fx)
	id := reportID("a1")
	rule := withID(acmeRule("acme", 8443, "acme.example.com", 9000), id)
	certificate := func(step string) (string, string) {
		t.Helper()
		r := reportFor(t, fx.mgr.RuleReports(), id)
		if r.Listener != api.IngressListenerListening || r.Dial != api.IngressDialNone {
			t.Errorf("%s: report = %+v, want listening with dial none", step, r)
		}
		return r.Certificate, r.CertificateReason
	}

	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{
		Rules: []api.IngressRule{rule},
		ACME:  &api.IngressACME{DirectoryURL: "https://other.invalid/dir"},
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if c, reason := certificate("directory not allowed"); c != api.IngressCertificateNotReady || reason != IngressReasonACMEDirectoryNotAllowed {
		t.Errorf("directory not allowed: certificate %q %q, want not_ready %s", c, reason, IngressReasonACMEDirectoryNotAllowed)
	}

	// The obtain ahead of the first client waits on the hook.
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{rule}, ACME: testACME}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	drain(fx.mgr.ReportChanged())
	if c, reason := certificate("not answered"); c != api.IngressCertificateNotReady || reason != IngressReasonACMENotIssued {
		t.Errorf("not answered: certificate %q %q, want not_ready %s", c, reason, IngressReasonACMENotIssued)
	}

	cert := selfSignedCert(t, "acme.example.com")
	results <- certResult{cert: &cert}
	requireSignal(t, fx.mgr.ReportChanged(), "the obtain succeeded")
	if c, reason := certificate("issued"); c != api.IngressCertificateReady || reason != "" {
		t.Errorf("issued: certificate %q %q, want ready without a reason", c, reason)
	}

	results <- certResult{err: errors.New("acme: order failed")}
	if _, err := fx.acme.GetCertificate(&tls.ClientHelloInfo{ServerName: "acme.example.com"}); err == nil {
		t.Fatal("GetCertificate: nil error, want the order failure")
	}
	if c, reason := certificate("order failed"); c != api.IngressCertificateNotReady || reason != IngressReasonACMENotIssued {
		t.Errorf("order failed: certificate %q %q, want not_ready %s", c, reason, IngressReasonACMENotIssued)
	}
}

func TestRuleReports_SkipsMalformedAndRepeatedIDs(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	id := reportID("a1")
	upper := strings.ToUpper(reportID("b2"))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(
		withID(ingressRule("first", 7022, "", 9000), id),
		withID(ingressRule("again", 7023, "", 9000), id),
		ingressRule("web", 7024, "", 9000), // id-web
		withID(ingressRule("empty", 7025, "", 9000), ""),
		withID(ingressRule("lower", 7026, "", 9000), reportID("b2")),
		withID(ingressRule("upper", 7027, "", 9000), upper),
	)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	reports := fx.mgr.RuleReports()
	if len(reports) != 2 {
		t.Fatalf("reports = %+v, want one for %s and one for %s", reports, id, reportID("b2"))
	}
	// The first rule of the id is held; the second reads duplicate_id.
	if r := reports[0]; r.RuleID != id || r.Listener != api.IngressListenerListening {
		t.Errorf("first report = %+v, want the held first rule of %s", r, id)
	}
	// Two spellings of one UUID repeat each other for the control plane.
	if r := reports[1]; r.RuleID != reportID("b2") {
		t.Errorf("second report = %+v, want %s only, not its upper-case spelling", r, reportID("b2"))
	}
}

func TestReportChanged_Signals(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	changed := fx.mgr.ReportChanged()
	requireOne := func(what string) {
		t.Helper()
		requireSignal(t, changed, what)
		requireNoSignal(t, changed, what+", a second time")
	}

	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(terminateRule("term", 443, "t.example.com", "tls", 9000), reportID("a1")))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	requireOne("an Apply")

	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	if servingOrganization(fx.mgr, "tls") != "v1" {
		t.Fatal("version 1 of tls did not load")
	}
	requireOne("a SyncSecretInventory that loads a certificate")

	results := hookACME(t, fx)
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{
		Rules: []api.IngressRule{withID(acmeRule("acme", 8443, "acme.example.com", 9000), reportID("b2"))},
		ACME:  testACME,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	drain(changed)
	cert := selfSignedCert(t, "acme.example.com")
	results <- certResult{cert: &cert}
	requireOne("the first success of the ACME hook")

	if err := fx.mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	requireOne("Teardown")
}

func TestIngressReasons_AreReasonTokens(t *testing.T) {
	for _, reason := range []string{
		IngressReasonInvalid,
		IngressReasonDuplicateID,
		IngressReasonListenerConflict,
		IngressReasonMaxRules,
		IngressReasonListenFailed,
		IngressReasonACMEDirectoryInvalid,
		IngressReasonACMEDirectoryNotAllowed,
		IngressReasonACMEChallengePortTaken,
		IngressReasonCertificateSecretNotListed,
		IngressReasonCertificateFetchFailed,
		IngressReasonCertificateInvalid,
		IngressReasonACMENotIssued,
		IngressDialReasonPolicyDenied,
		IngressDialReasonTimeout,
		IngressDialReasonRefused,
		IngressDialReasonUnreachable,
		IngressDialReasonOther,
	} {
		if !api.ValidIngressReason(reason) {
			t.Errorf("api.ValidIngressReason(%q) = false, want true", reason)
		}
	}
	for _, s := range []string{"", "Policy Denied", "9lives", strings.Repeat("a", 64)} {
		if api.ValidIngressReason(s) {
			t.Errorf("api.ValidIngressReason(%q) = true, want false", s)
		}
	}
}
