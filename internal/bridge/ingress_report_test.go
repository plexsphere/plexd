package bridge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// sameReport reports whether a and b are equal in every member, their target
// entries included.
func sameReport(a, b IngressRuleReport) bool {
	return reflect.DeepEqual(a, b)
}

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
		if got := reportFor(t, reports, tc.id); !sameReport(got, want) {
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
		if got := reportFor(t, reports, id); !sameReport(got, want) {
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
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("report = %+v, want %+v", got, want)
	}
}

func TestRuleReports_UDPRule(t *testing.T) {
	udpID, tcpID := reportID("a1"), reportID("b2")
	block := rulesBlock(
		withID(udpIngressRule("dns", 7053, 9053), udpID),
		withID(ingressRule("dns-tcp", 7053, "", 9053), tcpID),
	)
	listening := func(id string) IngressRuleReport {
		return IngressRuleReport{RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired, Dial: api.IngressDialNone}
	}
	listenFailed := func(id string) IngressRuleReport {
		return IngressRuleReport{RuleID: id, Listener: api.IngressListenerNotListening, ListenerReason: IngressReasonListenFailed}
	}

	t.Run("before any datagram", func(t *testing.T) {
		fx := newIngressFixture(t, newLoopbackIngressController(t))
		if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(udpIngressRule("dns", 7053, 9053), udpID))); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got, want := reportFor(t, fx.mgr.RuleReports(), udpID), listening(udpID); !sameReport(got, want) {
			t.Errorf("report = %+v, want %+v", got, want)
		}
	})

	t.Run("the udp bind failed", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		ctrl.failListenUDP(7053, syscall.EADDRINUSE)
		fx := newIngressFixture(t, ctrl)
		if err := fx.mgr.Apply(t.Context(), block); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("Apply = %v, want the bind error", err)
		}
		reports := fx.mgr.RuleReports()
		if got, want := reportFor(t, reports, udpID), listenFailed(udpID); !sameReport(got, want) {
			t.Errorf("udp rule: report = %+v, want %+v", got, want)
		}
		if got, want := reportFor(t, reports, tcpID), listening(tcpID); !sameReport(got, want) {
			t.Errorf("tcp rule on the same port number: report = %+v, want %+v", got, want)
		}
	})

	t.Run("the tcp bind failed", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		ctrl.failListen(7053, syscall.EADDRINUSE)
		fx := newIngressFixture(t, ctrl)
		if err := fx.mgr.Apply(t.Context(), block); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("Apply = %v, want the bind error", err)
		}
		reports := fx.mgr.RuleReports()
		if got, want := reportFor(t, reports, tcpID), listenFailed(tcpID); !sameReport(got, want) {
			t.Errorf("tcp rule: report = %+v, want %+v", got, want)
		}
		if got, want := reportFor(t, reports, udpID), listening(udpID); !sameReport(got, want) {
			t.Errorf("udp rule on the same port number: report = %+v, want %+v", got, want)
		}
	})
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
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
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

	// A refused client is recorded on the rule's report without a signal:
	// its refusal rides the next tick.
	auth := withID(terminateRule("term", 443, "t.example.com", "tls", 9000), reportID("a1"))
	withClientAuth(caBundle(newTestCA(t, "client-ca", nil)))(&auth)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(auth)); err != nil {
		t.Fatalf("Apply with client_auth: %v", err)
	}
	requireOne("an Apply that adds client_auth")
	repRefuse(t, ctrl.addr(443), "t.example.com", nil)
	fx.logs.waitFor(t, repRefusedMsg, 1)
	if got := reportFor(t, fx.mgr.RuleReports(), auth.ID).ClientRefusals; len(got) != 1 || got[0].Reason != IngressRefusalNoCertificate {
		t.Fatalf("refusals after a client without a certificate = %+v, want one %s", got, IngressRefusalNoCertificate)
	}
	requireNoSignal(t, changed, "a refused client")

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
		IngressReasonClientCAInvalid,
		IngressDialReasonPolicyDenied,
		IngressDialReasonTimeout,
		IngressDialReasonRefused,
		IngressDialReasonUnreachable,
		IngressDialReasonOther,
		IngressRefusalNoCertificate,
		IngressRefusalUnknownAuthority,
		IngressRefusalCertificateExpired,
		IngressRefusalCertificateInvalid,
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

// TestRuleReports_CarryNoSecretName builds the report of a terminate rule
// whose Secret the inventory does not list: the body names the reason and
// not the Secret, which stays in the bridge's log.
func TestRuleReports_CarryNoSecretName(t *testing.T) {
	fx := newIngressFixture(t, newLoopbackIngressController(t))
	if err := fx.mgr.Apply(t.Context(), rulesBlock(withID(terminateRule("term", 443, "t.example.com", "tls-term", 9000), reportID("a1")))); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	req := buildIngressStatusRequest(api.IngressStateEnabled, fx.mgr.RuleReports(), time.Now())
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), IngressReasonCertificateSecretNotListed) || strings.Contains(string(body), "tls-term") {
		t.Errorf("body = %s, want %s and not the Secret name tls-term", body, IngressReasonCertificateSecretNotListed)
	}
}

// TestRuleReports_SharedHost reports each rule of a host shared by conditions
// with the last dial to its own target: one that nothing listens on reads
// failed while its neighbour reads succeeded, and a rule no request matched
// reads none.
func TestRuleReports_SharedHost(t *testing.T) {
	webT := startHTTPTarget(t, "web")
	fx := newHTTPFixture(t, nil)
	down := withID(httpRule("down", "shop.example.com", closedPort(t), "/down"), reportID("a1"))
	web := withID(httpRule("web", "shop.example.com", webT.port(t), "/"), reportID("a2"))
	idle := withID(httpRule("idle", "shop.example.com", webT.port(t), "/idle"), reportID("a3"))
	fx.apply(t, down, web, idle)
	c := fx.client(t, false)
	get(t, c, "https://shop.example.com/down")
	get(t, c, "https://shop.example.com/")

	reports := fx.mgr.RuleReports()
	if len(reports) != 3 {
		t.Fatalf("%d reports, want 3: %+v", len(reports), reports)
	}
	for _, tc := range []struct {
		id, dial, reason string
	}{
		{down.ID, api.IngressDialFailed, IngressDialReasonRefused},
		{web.ID, api.IngressDialSucceeded, ""},
		{idle.ID, api.IngressDialNone, ""},
	} {
		got := reportFor(t, reports, tc.id)
		if got.Listener != api.IngressListenerListening || got.Certificate != api.IngressCertificateReady || got.Dial != tc.dial || got.DialReason != tc.reason {
			t.Errorf("rule %s: report = %+v, want listening, ready and dial %s %s", tc.id, got, tc.dial, tc.reason)
		}
	}
}

// targetNodeID returns a node id in canonical UUID form, ending in suffix,
// two hex digits.
func targetNodeID(suffix string) string {
	return "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0" + suffix
}

// reportTargets returns n targets on the loopback, on 9000 and up, each on a
// node of its own whose id ends in b1, b2 and so on.
func reportTargets(n int) []api.IngressTarget {
	targets := make([]api.IngressTarget, n)
	for i := range targets {
		targets[i] = api.IngressTarget{NodeID: targetNodeID("b" + strconv.Itoa(i+1)), Address: "127.0.0.1", Port: 9000 + i}
	}
	return targets
}

// TestRuleReports_Targets reports a listening rule from a pull with targets
// with one entry per target in list order, none before a dial and the last
// dial to each target after one, and a rule that does not listen without
// entries.
func TestRuleReports_Targets(t *testing.T) {
	fx, ctrl, _, _ := newDialFixture(t, dialStep{err: refusedDial()}, dialStep{})
	ctrl.failListen(7023, syscall.EADDRINUSE)
	webID, conflictID, downID := reportID("a1"), reportID("b2"), reportID("c3")
	web := withID(ingressRule("web", 7022, "", 9000), webID)
	web.Targets = reportTargets(3)
	conflict := withID(ingressRule("conflict", 7022, "", 9000), conflictID)
	conflict.Targets = reportTargets(2)
	down := withID(ingressRule("down", 7023, "", 9000), downID)
	down.Targets = reportTargets(2)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(web, conflict, down)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want the bind error of port 7023", err)
	}
	entry := func(i int, dial, reason string, at time.Time) IngressTargetReport {
		return IngressTargetReport{NodeID: web.Targets[i].NodeID, Port: web.Targets[i].Port, Dial: dial, DialReason: reason, DialAt: at}
	}

	reports := fx.mgr.RuleReports()
	want := IngressRuleReport{
		RuleID: webID, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
		Dial: api.IngressDialNone,
		Targets: []IngressTargetReport{
			entry(0, api.IngressDialNone, "", time.Time{}),
			entry(1, api.IngressDialNone, "", time.Time{}),
			entry(2, api.IngressDialNone, "", time.Time{}),
		},
	}
	if got := reportFor(t, reports, webID); !sameReport(got, want) {
		t.Errorf("before a dial: report = %+v, want %+v", got, want)
	}
	for _, tc := range []struct{ id, reason string }{
		{conflictID, IngressReasonListenerConflict},
		{downID, IngressReasonListenFailed},
	} {
		want := IngressRuleReport{RuleID: tc.id, Listener: api.IngressListenerNotListening, ListenerReason: tc.reason}
		if got := reportFor(t, reports, tc.id); !sameReport(got, want) {
			t.Errorf("a rule that does not listen: report = %+v, want %+v without target entries", got, want)
		}
	}

	// The first target refuses and the second takes the connection; the
	// third is not dialled.
	connect(t, ctrl.addr(7022))
	waitForCondition(t, 2*time.Second, func() bool {
		return reportFor(t, fx.mgr.RuleReports(), webID).Dial != api.IngressDialNone
	})
	want.Dial, want.DialAt = api.IngressDialSucceeded, relayStart
	want.Targets = []IngressTargetReport{
		entry(0, api.IngressDialFailed, IngressDialReasonRefused, relayStart),
		entry(1, api.IngressDialSucceeded, "", relayStart),
		entry(2, api.IngressDialNone, "", time.Time{}),
	}
	if got := reportFor(t, fx.mgr.RuleReports(), webID); !sameReport(got, want) {
		t.Errorf("after a connection: report = %+v, want %+v", got, want)
	}
}

// TestRuleReports_NoTargetsWithoutThePullMember reports a rule from a pull
// without targets without target entries while its dial follows its one
// target, and with that target's entry once the pull carries targets.
func TestRuleReports_NoTargetsWithoutThePullMember(t *testing.T) {
	fx, ctrl, _, _ := newDialFixture(t, dialStep{err: refusedDial()}, dialStep{})
	id := reportID("a1")
	legacy := withID(ingressRule("web", 7022, "", 9000), id)
	legacy.TargetNodeID = targetNodeID("b1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(legacy)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	lb := balancerFor(t, fx.mgr, id)
	want := IngressRuleReport{RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired, Dial: api.IngressDialNone}
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("before a dial: report = %+v, want %+v", got, want)
	}

	for _, step := range []struct{ name, dial, reason string }{
		{"a refused dial", api.IngressDialFailed, IngressDialReasonRefused},
		{"a dial that succeeded", api.IngressDialSucceeded, ""},
	} {
		connect(t, ctrl.addr(7022))
		waitForCondition(t, 2*time.Second, func() bool {
			return reportFor(t, fx.mgr.RuleReports(), id).Dial == step.dial
		})
		want.Dial, want.DialReason, want.DialAt = step.dial, step.reason, relayStart
		if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
			t.Errorf("after %s: report = %+v, want %+v", step.name, got, want)
		}
		wantTarget := dialRecord{failed: step.dial == api.IngressDialFailed, reason: step.reason, at: relayStart}
		if _, targets := lb.snapshot(); len(targets) != 1 || targets[0] != wantTarget {
			t.Errorf("after %s: target records = %+v, want the one target %+v", step.name, targets, wantTarget)
		}
	}

	// A control plane that starts to send targets names the same target, so
	// the rule keeps its balancer and reports the entry with its last dial.
	current := legacy
	current.Targets = []api.IngressTarget{{NodeID: legacy.TargetNodeID, Address: legacy.TargetAddress, Port: legacy.TargetPort}}
	if err := fx.mgr.Apply(t.Context(), rulesBlock(current)); err != nil {
		t.Fatalf("Apply with targets: %v", err)
	}
	if got := balancerFor(t, fx.mgr, id); got != lb {
		t.Fatalf("balancer %p after the pull carried targets, want the rule's balancer %p", got, lb)
	}
	want.Targets = []IngressTargetReport{{NodeID: legacy.TargetNodeID, Port: legacy.TargetPort, Dial: api.IngressDialSucceeded, DialAt: relayStart}}
	if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want) {
		t.Errorf("after the pull carried targets: report = %+v, want %+v", got, want)
	}
}

// TestRuleReports_SkipsMalformedAndRepeatedTargets gives no entry to a
// target whose node_id the control plane refuses, or whose node_id and port
// an earlier entry carried in another case, while the rule dials every
// target; a rule none of whose targets has an entry has nil Targets.
func TestRuleReports_SkipsMalformedAndRepeatedTargets(t *testing.T) {
	n1, n2 := targetNodeID("b1"), targetNodeID("b2")
	targets := []api.IngressTarget{
		{NodeID: n1, Address: "127.0.0.1", Port: 9000},
		{NodeID: "", Address: "127.0.0.1", Port: 9001},
		{NodeID: "not-a-uuid", Address: "127.0.0.1", Port: 9002},
		{NodeID: "00000000-0000-0000-0000-000000000000", Address: "127.0.0.1", Port: 9003},
		{NodeID: strings.ToUpper(n1), Address: "127.0.0.1", Port: 9000},
		// The same node on another port is another target.
		{NodeID: n1, Address: "127.0.0.1", Port: 9005},
		{NodeID: n2, Address: "127.0.0.1", Port: 9006},
	}
	fx, ctrl, _, _ := newDialFixture(t, make([]dialStep, len(targets))...)
	id, otherID := reportID("a1"), reportID("b2")
	rule := withID(ingressRule("web", 7022, "", 9000), id)
	rule.Targets = targets
	other := withID(ingressRule("other", 7023, "", 9000), otherID)
	other.Targets = twoTargets()
	if err := fx.mgr.Apply(t.Context(), rulesBlock(rule, other)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if st := stateOf(t, fx.mgr, "web"); !st.Served || st.Reason != "" {
		t.Fatalf("rule state = %+v, want served", st)
	}
	lb := balancerFor(t, fx.mgr, id)

	// One connection per target: round robin dials each target once.
	for range targets {
		connect(t, ctrl.addr(7022))
	}
	waitForCondition(t, 2*time.Second, func() bool {
		_, records := lb.snapshot()
		for _, rec := range records {
			if rec.at.IsZero() {
				return false
			}
		}
		return true
	})
	_, records := lb.snapshot()
	for i, rec := range records {
		if want := (dialRecord{at: relayStart}); rec != want {
			t.Errorf("target %d = %+v, want succeeded at %v", i, rec, relayStart)
		}
	}

	reports := fx.mgr.RuleReports()
	succeeded := func(nodeID string, port int) IngressTargetReport {
		return IngressTargetReport{NodeID: nodeID, Port: port, Dial: api.IngressDialSucceeded, DialAt: relayStart}
	}
	want := IngressRuleReport{
		RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateNotRequired,
		Dial: api.IngressDialSucceeded, DialAt: relayStart,
		Targets: []IngressTargetReport{succeeded(n1, 9000), succeeded(n1, 9005), succeeded(n2, 9006)},
	}
	if got := reportFor(t, reports, id); !sameReport(got, want) {
		t.Errorf("report = %+v, want %+v", got, want)
	}
	if got := reportFor(t, reports, otherID); got.Targets != nil {
		t.Errorf("a rule whose node ids are no UUIDs: Targets = %#v, want nil", got.Targets)
	}
}

// repRefusedMsg is the log message of a refused client.
const repRefusedMsg = `msg="ingress client refused"`

// repRefuse connects to addr as serverName with cert as the client
// certificate, or none when cert is nil, and waits up to 2 s for the bridge to
// close the connection. In TLS 1.3 the client's side of the handshake
// completes and its first read fails; in TLS 1.2 the dial fails. The caller
// proves the refusal on the manager's log and report.
func repRefuse(t *testing.T, addr, serverName string, cert *tls.Certificate) {
	t.Helper()
	conn, err := dialTLSClient(t, addr, serverName, cert, nil)
	if err != nil {
		return
	}
	requireClosed(t, conn)
}

// TestRuleReports_ClientAuth reports ClientAuthEnforced on a listening rule
// with client_auth, without refusals before the first, and on no other rule:
// not on a listening rule without client_auth, and not on a rule with
// client_auth whose port did not bind, which carries no refusals either while
// its record keeps them.
func TestRuleReports_ClientAuth(t *testing.T) {
	ca := newTestCA(t, "client-ca", nil)
	ctrl := newLoopbackIngressController(t)
	ctrl.failListen(8443, syscall.EADDRINUSE)
	fx, _, _ := newDialLogFixture(t, ctrl)
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	authID, plainID, downID := reportID("a1"), reportID("b2"), reportID("c3")
	auth := withID(terminateRule("auth", 443, "t.example.com", "tls", 9000), authID)
	withClientAuth(caBundle(ca))(&auth)
	plain := withID(terminateRule("plain", 7443, "t.example.com", "tls", 9000), plainID)
	down := withID(terminateRule("down", 8443, "t.example.com", "tls", 9000), downID)
	withClientAuth(caBundle(ca))(&down)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(auth, plain, down)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want the bind error of port 8443", err)
	}
	listening := func(id string, enforced bool) IngressRuleReport {
		return IngressRuleReport{
			RuleID: id, Listener: api.IngressListenerListening, Certificate: api.IngressCertificateReady,
			Dial: api.IngressDialNone, ClientAuthEnforced: enforced,
		}
	}
	listenFailed := func(id string) IngressRuleReport {
		return IngressRuleReport{RuleID: id, Listener: api.IngressListenerNotListening, ListenerReason: IngressReasonListenFailed}
	}

	reports := fx.mgr.RuleReports()
	for _, want := range []IngressRuleReport{listening(authID, true), listening(plainID, false), listenFailed(downID)} {
		if got := reportFor(t, reports, want.RuleID); !sameReport(got, want) {
			t.Errorf("before a refusal: report = %+v, want %+v", got, want)
		}
	}

	repRefuse(t, ctrl.addr(443), "t.example.com", nil)
	fx.logs.waitFor(t, repRefusedMsg, 1)
	refused := listening(authID, true)
	refused.ClientRefusals = []IngressClientRefusalReport{{Reason: IngressRefusalNoCertificate, At: relayStart}}
	if got := reportFor(t, fx.mgr.RuleReports(), authID); !sameReport(got, refused) {
		t.Fatalf("after a refusal: report = %+v, want %+v", got, refused)
	}

	// The rule moves to the port that does not bind with the same bundle, so
	// its record keeps the refusal, and its report carries neither member.
	moved := auth
	moved.ListenPort = 8443
	if err := fx.mgr.Apply(t.Context(), rulesBlock(moved, plain)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want the bind error of port 8443", err)
	}
	if got, want := reportFor(t, fx.mgr.RuleReports(), authID), listenFailed(authID); !sameReport(got, want) {
		t.Errorf("on the port that did not bind: report = %+v, want %+v", got, want)
	}
	// Back on its port, the rule reports the refusal its record kept.
	if err := fx.mgr.Apply(t.Context(), rulesBlock(auth, plain)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := reportFor(t, fx.mgr.RuleReports(), authID); !sameReport(got, refused) {
		t.Errorf("back on its port: report = %+v, want %+v", got, refused)
	}
}

// TestRuleReports_ClientCAInvalid reports a listening terminate or acme rule
// whose client CA bundle does not build with the certificate not_ready for
// client_ca_invalid, ahead of a loaded certificate and of a valid ACME
// directory, and with ClientAuthEnforced, since the rule serves no client.
func TestRuleReports_ClientCAInvalid(t *testing.T) {
	bundles := []struct{ name, bundle string }{
		{"empty bundle", ""},
		{"no PEM block", "not a certificate"},
	}
	want := func(id string) IngressRuleReport {
		return IngressRuleReport{
			RuleID: id, Listener: api.IngressListenerListening,
			Certificate: api.IngressCertificateNotReady, CertificateReason: IngressReasonClientCAInvalid,
			Dial: api.IngressDialNone, ClientAuthEnforced: true,
		}
	}
	for _, b := range bundles {
		t.Run("terminate, "+b.name, func(t *testing.T) {
			fx := newIngressFixture(t, newLoopbackIngressController(t))
			fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
			fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
			id := reportID("a1")
			rule := withID(terminateRule("term", 443, "t.example.com", "tls", 9000), id)
			withClientAuth(b.bundle)(&rule)
			if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if servingOrganization(fx.mgr, "tls") != "v1" {
				t.Fatal("version 1 of tls did not load")
			}
			if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want(id)) {
				t.Errorf("report = %+v, want %+v", got, want(id))
			}
		})
		t.Run("acme, "+b.name, func(t *testing.T) {
			cfg := ingressTestConfig(true)
			cfg.ACMEDirectoryURLs = []string{testACME.DirectoryURL}
			fx := buildIngressFixture(t, newLoopbackIngressController(t), cfg)
			if err := fx.mgr.Setup(); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			id := reportID("a1")
			rule := withID(acmeRule("acme", 8443, "acme.example.com", 9000), id)
			withClientAuth(b.bundle)(&rule)
			if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{rule}, ACME: testACME}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if got := reportFor(t, fx.mgr.RuleReports(), id); !sameReport(got, want(id)) {
				t.Errorf("report = %+v, want %+v", got, want(id))
			}
		})
	}
}

// TestRuleReports_ClientRefusals reports the last refusal per reason of a rule
// with client_auth, at the manager's time of the refused handshake, in the
// order of the reasons, on every rule of a host shared by conditions, and
// clears them with an Apply that changes the bundle and with Teardown.
func TestRuleReports_ClientRefusals(t *testing.T) {
	t.Run("one rule", func(t *testing.T) {
		ca := newTestCA(t, "client-ca", nil)
		other := newTestCA(t, "other-ca", nil)
		stranger := newTestCA(t, "stranger-ca", nil).issue(t, "stranger", nil)
		ctrl := newLoopbackIngressController(t)
		fx, clock, dials := newDialLogFixture(t, ctrl)
		fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
		fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
		id := reportID("a1")
		rule := withID(terminateRule("auth", 443, "t.example.com", "tls", 9000), id)
		withClientAuth(caBundle(ca))(&rule)
		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		refusals := func() []IngressClientRefusalReport {
			t.Helper()
			r := reportFor(t, fx.mgr.RuleReports(), id)
			if !r.ClientAuthEnforced {
				t.Errorf("report = %+v, want ClientAuthEnforced", r)
			}
			return r.ClientRefusals
		}

		// A client of another authority, then one without a certificate, and
		// the other authority's client again: the reasons read in their fixed
		// order, each at its last refusal.
		repRefuse(t, ctrl.addr(443), "t.example.com", &stranger)
		fx.logs.waitFor(t, repRefusedMsg, 1)
		clock.Add(3 * time.Second)
		repRefuse(t, ctrl.addr(443), "t.example.com", nil)
		fx.logs.waitFor(t, repRefusedMsg, 2)
		clock.Add(2 * time.Second)
		repRefuse(t, ctrl.addr(443), "t.example.com", &stranger)
		fx.logs.waitFor(t, repRefusedMsg, 3)
		want := []IngressClientRefusalReport{
			{Reason: IngressRefusalNoCertificate, At: relayStart.Add(3 * time.Second)},
			{Reason: IngressRefusalUnknownAuthority, At: relayStart.Add(5 * time.Second)},
		}
		if got := refusals(); !reflect.DeepEqual(got, want) {
			t.Fatalf("refusals = %+v, want %+v", got, want)
		}
		if got := dials.dialled(); len(got) != 0 {
			t.Errorf("dials = %v, want none for refused clients", got)
		}

		if err := fx.mgr.Apply(t.Context(), rulesBlock(rule)); err != nil {
			t.Fatalf("Apply of the same block: %v", err)
		}
		if got := refusals(); !reflect.DeepEqual(got, want) {
			t.Errorf("after an Apply of the same block: refusals = %+v, want %+v", got, want)
		}

		changed := rule
		withClientAuth(caBundle(ca, other))(&changed)
		if err := fx.mgr.Apply(t.Context(), rulesBlock(changed)); err != nil {
			t.Fatalf("Apply with another bundle: %v", err)
		}
		if got := refusals(); got != nil {
			t.Errorf("after an Apply with another bundle: refusals = %+v, want nil", got)
		}

		repRefuse(t, ctrl.addr(443), "t.example.com", nil)
		fx.logs.waitFor(t, repRefusedMsg, 4)
		if got := refusals(); len(got) != 1 || got[0].Reason != IngressRefusalNoCertificate {
			t.Fatalf("refusals under the new bundle = %+v, want one %s", got, IngressRefusalNoCertificate)
		}
		if err := fx.mgr.Teardown(); err != nil {
			t.Fatalf("Teardown: %v", err)
		}
		if err := fx.mgr.Setup(); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		if err := fx.mgr.Apply(t.Context(), rulesBlock(changed)); err != nil {
			t.Fatalf("Apply after Setup: %v", err)
		}
		if got := refusals(); got != nil {
			t.Errorf("after Teardown, Setup and an Apply of the same block: refusals = %+v, want nil", got)
		}
	})

	t.Run("a shared host", func(t *testing.T) {
		ca := newTestCA(t, "client-ca", nil)
		expired := ca.issue(t, "expired", func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		})
		clock := &relayClock{now: relayStart}
		fx := newHTTPFixture(t, func(m *IngressManager) { m.now = clock.Now })
		shop := withID(httpRule("shop", "shop.example.com", 9000, "/shop"), reportID("a1"))
		cart := withID(httpRule("cart", "shop.example.com", 9001, "/cart"), reportID("a2"))
		withClientAuth(caBundle(ca))(&shop)
		withClientAuth(caBundle(ca))(&cart)
		fx.apply(t, shop, cart)
		for _, slug := range []string{"shop", "cart"} {
			if st := stateOf(t, fx.mgr, slug); !st.Served {
				t.Fatalf("rule %s: state = %+v, want served", slug, st)
			}
		}

		repRefuse(t, fx.ctrl.addr(443), "shop.example.com", nil)
		fx.logs.waitFor(t, repRefusedMsg, 1)
		clock.Add(2 * time.Second)
		repRefuse(t, fx.ctrl.addr(443), "shop.example.com", &expired)
		fx.logs.waitFor(t, repRefusedMsg, 2)

		want := []IngressClientRefusalReport{
			{Reason: IngressRefusalNoCertificate, At: relayStart},
			{Reason: IngressRefusalCertificateExpired, At: relayStart.Add(2 * time.Second)},
		}
		reports := fx.mgr.RuleReports()
		for _, id := range []string{shop.ID, cart.ID} {
			got := reportFor(t, reports, id)
			if !got.ClientAuthEnforced || !reflect.DeepEqual(got.ClientRefusals, want) {
				t.Errorf("rule %s: report = %+v, want ClientAuthEnforced and the refusals %+v", id, got, want)
			}
		}
	})
}
