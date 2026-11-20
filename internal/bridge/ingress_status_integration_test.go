package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// testIngressStatusNSK is the bearer the contract control plane accepts.
const testIngressStatusNSK = "test-nsk"

// ingressStatusControlPlane is an httptest control plane serving
// PUT /v1/nodes/{node_id}/ingress-status with the gates the contract,
// plexsphere/plexsphere docs/reference/api/plexd-agent-contract.md, puts on
// it: the NSK bearer, the node, a 2 MiB body cap, a strict decode that
// refuses unknown members of the report, of each rule entry, of each target
// entry and of each refusal entry, a member of the wrong type, and data after
// the report, and a state that is present and one of the two the contract
// names. It answers 200 with its own receive time as accepted_at and records
// the body, and counts every 400 it answers.
type ingressStatusControlPlane struct {
	srv      *httptest.Server
	client   *api.ControlPlane
	accepted chan string

	mu      sync.Mutex
	refused []string
}

// ingressStatusWire is the report as the control plane decodes it: every
// member is a pointer, so an absent or null one stays nil.
type ingressStatusWire struct {
	State *string                  `json:"state"`
	Rules *[]ingressStatusWireRule `json:"rules"`
}

// ingressStatusWireRule is one rule entry as the control plane decodes it. A
// dial_age_seconds that is not an integer, and a client_auth_enforced that is
// not a boolean, fail the decode.
type ingressStatusWireRule struct {
	ID                 *string                        `json:"id"`
	Listener           *string                        `json:"listener"`
	ListenerReason     *string                        `json:"listener_reason"`
	Certificate        *string                        `json:"certificate"`
	CertificateReason  *string                        `json:"certificate_reason"`
	Dial               *string                        `json:"dial"`
	DialReason         *string                        `json:"dial_reason"`
	DialAgeSeconds     *int64                         `json:"dial_age_seconds"`
	Targets            *[]ingressStatusWireTarget     `json:"targets"`
	ClientAuthEnforced *bool                          `json:"client_auth_enforced"`
	ClientRefusals     *[]repIngressStatusWireRefusal `json:"client_refusals"`
}

// ingressStatusWireTarget is one target entry of a rule entry as the control
// plane decodes it, every member a pointer as in a rule entry. A port or a
// dial_age_seconds that is not an integer fails the decode.
type ingressStatusWireTarget struct {
	NodeID         *string `json:"node_id"`
	Port           *int    `json:"port"`
	Dial           *string `json:"dial"`
	DialReason     *string `json:"dial_reason"`
	DialAgeSeconds *int64  `json:"dial_age_seconds"`
}

// repIngressStatusWireRefusal is one refusal entry of a rule entry's
// client_refusals as the control plane decodes it, every member a pointer as
// in a rule entry. An age_seconds that is not an integer fails the decode.
type repIngressStatusWireRefusal struct {
	Reason     *string `json:"reason"`
	AgeSeconds *int64  `json:"age_seconds"`
}

// maxIngressStatusWireBody is the contract's cap on a report body, 2 MiB.
const maxIngressStatusWireBody = 2 << 20

func newIngressStatusControlPlane(t *testing.T) *ingressStatusControlPlane {
	t.Helper()
	cp := &ingressStatusControlPlane{accepted: make(chan string, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/nodes/{node_id}/ingress-status", cp.serve)
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)

	client, err := api.NewControlPlane(api.Config{BaseURL: cp.srv.URL}, "1.0.0-test", discardLogger())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	client.SetAuthToken(testIngressStatusNSK)
	cp.client = client
	return cp
}

func (cp *ingressStatusControlPlane) problem(w http.ResponseWriter, status int, code, detail string) {
	if status == http.StatusBadRequest {
		cp.mu.Lock()
		cp.refused = append(cp.refused, code+": "+detail)
		cp.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "detail": detail})
}

func (cp *ingressStatusControlPlane) serve(w http.ResponseWriter, r *http.Request) {
	receivedAt := time.Now().UTC()
	if r.Header.Get("Authorization") != "Bearer "+testIngressStatusNSK {
		cp.problem(w, http.StatusUnauthorized, "unauthorized", "missing or wrong bearer")
		return
	}
	if r.PathValue("node_id") != testIngressNodeID {
		cp.problem(w, http.StatusForbidden, "node_id_mismatch", "the bearer belongs to another node")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIngressStatusWireBody))
	if err != nil {
		cp.problem(w, http.StatusRequestEntityTooLarge, "ingress_status_body_too_large", err.Error())
		return
	}
	if detail := ingressStatusMalformed(body); detail != "" {
		cp.problem(w, http.StatusBadRequest, "malformed_ingress_status", detail)
		return
	}

	cp.accepted <- string(body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted_at": receivedAt.Format(time.RFC3339Nano)})
}

// ingressStatusMalformed returns why the contract answers 400
// malformed_ingress_status for body, or "" when it does not: a body that is not
// one JSON object, an unknown member of the report, of a rule entry, of a
// target entry or of a refusal entry, a member of the wrong type, data after
// the report, a missing or null state, or a state that is neither enabled nor
// opted_out.
func ingressStatusMalformed(body []byte) string {
	report, err := decodeIngressStatusWire(body)
	if err != nil {
		return err.Error()
	}
	if report.State == nil {
		return "state is missing"
	}
	switch *report.State {
	case api.IngressStateEnabled, api.IngressStateOptedOut:
	default:
		return "state is not one of enabled and opted_out"
	}
	return ""
}

// decodeIngressStatusWire strict-decodes body as exactly one report: unknown
// members, of the report and of each entry, and data after it are errors.
func decodeIngressStatusWire(body []byte) (ingressStatusWire, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var report ingressStatusWire
	if err := dec.Decode(&report); err != nil {
		return ingressStatusWire{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ingressStatusWire{}, errors.New("data after the report")
	}
	return report, nil
}

// wantBody waits up to 2 s for the next accepted body and fails the test
// unless it is want.
func (cp *ingressStatusControlPlane) wantBody(t *testing.T, step, want string) {
	t.Helper()
	select {
	case got := <-cp.accepted:
		if got != want {
			t.Errorf("%s: accepted %s, want %s", step, got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: no body accepted within 2s, want %s", step, want)
	}
}

// wantNoMore fails the test if the control plane accepted another body or
// refused any.
func (cp *ingressStatusControlPlane) wantNoMore(t *testing.T) {
	t.Helper()
	select {
	case got := <-cp.accepted:
		t.Errorf("accepted %s beyond the expected reports", got)
	default:
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.refused) != 0 {
		t.Errorf("answered 400 to %d reports: %s", len(cp.refused), strings.Join(cp.refused, "; "))
	}
}

func TestIngressStatusIntegration_ReportsBothStatesOverTheWire(t *testing.T) {
	for _, tc := range []struct {
		optedOut bool
		want     string
	}{
		{optedOut: false, want: `{"state":"enabled"}`},
		{optedOut: true, want: `{"state":"opted_out"}`},
	} {
		t.Run(tc.want, func(t *testing.T) {
			cp := newIngressStatusControlPlane(t)
			reporter := NewIngressStatusReporter(time.Hour, testIngressNodeID, cp.client, tc.optedOut, nil, discardLogger())
			stop := startIngressStatusReporter(t, reporter)

			cp.wantBody(t, "start", tc.want)
			stop()
			cp.wantNoMore(t)
		})
	}

	// The control plane above proves the reports only as far as it enforces
	// the contract, so it is checked against bodies the contract refuses.
	t.Run("the control plane refuses what the contract refuses", func(t *testing.T) {
		cp := newIngressStatusControlPlane(t)
		tests := []struct {
			body       string
			wantStatus int
			wantCode   string
		}{
			{``, http.StatusBadRequest, "malformed_ingress_status"},
			{`{}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":null}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"paused"}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","up":true}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","dial_age_seconds":1.5}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","targets":[{"node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1","port":9000,"dial":"none","up":true}]}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","targets":[{"node_id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0b1","port":9000,"dial":"succeeded","dial_age_seconds":1.5}]}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","client_auth_enforced":"yes"}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","client_auth_enforced":true,"client_refusals":{"reason":"no_certificate","age_seconds":1}}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","client_auth_enforced":true,"client_refusals":[{"reason":"no_certificate","age_seconds":1,"subject":"CN=client"}]}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled","rules":[{"id":"0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a1a1","listener":"listening","dial":"none","client_auth_enforced":true,"client_refusals":[{"reason":"no_certificate","age_seconds":1.5}]}]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled"}{}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`["enabled"]`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled"}` + strings.Repeat(" ", maxIngressStatusWireBody+1-len(`{"state":"enabled"}`)), http.StatusRequestEntityTooLarge, "ingress_status_body_too_large"},
		}
		for _, tt := range tests {
			req, err := http.NewRequest(http.MethodPut, cp.srv.URL+"/v1/nodes/"+testIngressNodeID+"/ingress-status", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+testIngressStatusNSK)
			resp, err := cp.srv.Client().Do(req)
			if err != nil {
				t.Fatalf("PUT %.40q: %v", tt.body, err)
			}
			var problem struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&problem)
			resp.Body.Close()
			if resp.StatusCode != tt.wantStatus || problem.Code != tt.wantCode {
				t.Errorf("PUT %.40q = %d %q, want %d %q", tt.body, resp.StatusCode, problem.Code, tt.wantStatus, tt.wantCode)
			}
		}
	})
}

// TestIngressStatusIntegration_ReportsRuleEntriesOverTheWire sends three rule
// entries through the real client: the control plane decodes them strictly
// and reads each id, its facets and an integer dial age.
func TestIngressStatusIntegration_ReportsRuleEntriesOverTheWire(t *testing.T) {
	cp := newIngressStatusControlPlane(t)
	failed := dialledReport(reportID("a1"), api.IngressDialFailed, IngressDialReasonPolicyDenied, time.Now().Add(-12*time.Second))
	failed.Certificate = api.IngressCertificateReady
	notReady := listeningReport(reportID("b2"))
	notReady.Certificate, notReady.CertificateReason = api.IngressCertificateNotReady, IngressReasonCertificateSecretNotListed
	down := IngressRuleReport{RuleID: reportID("c3"), Listener: api.IngressListenerNotListening, ListenerReason: IngressReasonListenFailed}
	source := &fakeRuleSource{reports: []IngressRuleReport{failed, notReady, down}, changed: make(chan struct{}, 1)}

	reporter := NewIngressStatusReporter(time.Hour, testIngressNodeID, cp.client, false, source, discardLogger())
	stop := startIngressStatusReporter(t, reporter)
	var body string
	select {
	case body = <-cp.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("no report accepted within 2s")
	}
	stop()
	cp.wantNoMore(t)

	report, err := decodeIngressStatusWire([]byte(body))
	if err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if report.Rules == nil || len(*report.Rules) != 3 {
		t.Fatalf("rules of %s, want three entries", body)
	}
	str := func(p *string) string {
		if p == nil {
			return "<absent>"
		}
		return *p
	}
	type entry struct{ id, listener, listenerReason, certificate, certificateReason, dial, dialReason string }
	want := []entry{
		{reportID("a1"), "listening", "<absent>", "ready", "<absent>", "failed", "policy_denied"},
		{reportID("b2"), "listening", "<absent>", "not_ready", "certificate_secret_not_listed", "none", "<absent>"},
		{reportID("c3"), "not_listening", "listen_failed", "<absent>", "<absent>", "<absent>", "<absent>"},
	}
	for i, e := range *report.Rules {
		got := entry{str(e.ID), str(e.Listener), str(e.ListenerReason), str(e.Certificate), str(e.CertificateReason), str(e.Dial), str(e.DialReason)}
		if got != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got, want[i])
		}
	}
	rules := *report.Rules
	if age := rules[0].DialAgeSeconds; age == nil || *age < 12 || *age > 14 {
		t.Errorf("dial_age_seconds of the failed dial = %v, want an integer of about 12", age)
	}
	if rules[1].DialAgeSeconds != nil || rules[2].DialAgeSeconds != nil {
		t.Errorf("entries without a dial carry dial_age_seconds: %s", body)
	}
}

// TestIngressStatusIntegration_ReportsTargetEntriesOverTheWire sends a
// manager's report through the real client: the control plane decodes the
// two target entries of a rule from a pull with targets strictly, and finds
// no targets member on a rule from a pull without them.
func TestIngressStatusIntegration_ReportsTargetEntriesOverTheWire(t *testing.T) {
	fx, ctrl, _, _ := newDialFixture(t, dialStep{err: refusedDial()}, dialStep{})
	poolID, legacyID := reportID("a1"), reportID("b2")
	pool := withID(ingressRule("pool", 7022, "", 9000), poolID)
	pool.Targets = reportTargets(2)
	legacy := withID(ingressRule("legacy", 7023, "", 9100), legacyID)
	legacy.TargetNodeID = targetNodeID("c1")
	if err := fx.mgr.Apply(t.Context(), rulesBlock(pool, legacy)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The first target refuses and the second takes the connection.
	connect(t, ctrl.addr(7022))
	waitForCondition(t, 2*time.Second, func() bool {
		return reportFor(t, fx.mgr.RuleReports(), poolID).Dial == api.IngressDialSucceeded
	})
	drain(fx.mgr.ReportChanged())

	cp := newIngressStatusControlPlane(t)
	reporter := NewIngressStatusReporter(time.Hour, testIngressNodeID, cp.client, false, fx.mgr, discardLogger())
	// The manager dates its dials on the fixture's clock.
	reporter.now = func() time.Time { return relayStart.Add(12500 * time.Millisecond) }
	stop := startIngressStatusReporter(t, reporter)
	var body string
	select {
	case body = <-cp.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("no report accepted within 2s")
	}
	stop()
	cp.wantNoMore(t)

	report, err := decodeIngressStatusWire([]byte(body))
	if err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if report.Rules == nil || len(*report.Rules) != 2 {
		t.Fatalf("rules of %s, want two entries", body)
	}
	rules := *report.Rules
	if rules[0].Targets == nil || len(*rules[0].Targets) != 2 {
		t.Fatalf("targets of the first entry of %s, want two entries", body)
	}
	str := func(p *string) string {
		if p == nil {
			return "<absent>"
		}
		return *p
	}
	type entry struct {
		nodeID     string
		port       int
		dial       string
		dialReason string
		age        int64
	}
	want := []entry{
		{targetNodeID("b1"), 9000, "failed", "refused", 12},
		{targetNodeID("b2"), 9001, "succeeded", "<absent>", 12},
	}
	for j, e := range *rules[0].Targets {
		if e.Port == nil || e.DialAgeSeconds == nil {
			t.Errorf("target entry %d of %s misses its port or its dial_age_seconds", j, body)
			continue
		}
		got := entry{str(e.NodeID), *e.Port, str(e.Dial), str(e.DialReason), *e.DialAgeSeconds}
		if got != want[j] {
			t.Errorf("target entry %d = %+v, want %+v", j, got, want[j])
		}
	}
	if rules[1].Targets != nil || strings.Count(body, `"targets"`) != 1 {
		t.Errorf("the entry of the rule from a pull without targets carries targets: %s", body)
	}
	if got := str(rules[1].Dial); got != api.IngressDialNone {
		t.Errorf("dial of the rule from a pull without targets = %s, want none", got)
	}
}

// TestIngressStatusIntegration_ReportsClientAuthOverTheWire sends a manager's
// report through the real client after two refused handshakes: the control
// plane decodes client_auth_enforced and both refusals of the rule with
// client_auth strictly, and receives neither member for a rule without it.
func TestIngressStatusIntegration_ReportsClientAuthOverTheWire(t *testing.T) {
	ca := newTestCA(t, "client-ca", nil)
	stranger := newTestCA(t, "stranger-ca", nil).issue(t, "stranger", nil)
	ctrl := newLoopbackIngressController(t)
	fx, clock, dials := newDialLogFixture(t, ctrl)
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	fx.mgr.SyncSecretInventory(t.Context(), inventoryOf("tls", 1))
	authID, plainID := reportID("a1"), reportID("b2")
	auth := withID(terminateRule("auth", 443, "t.example.com", "tls", 9000), authID)
	withClientAuth(caBundle(ca))(&auth)
	plain := withID(terminateRule("plain", 7443, "t.example.com", "tls", 9000), plainID)
	if err := fx.mgr.Apply(t.Context(), rulesBlock(auth, plain)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A client without a certificate at the start, one of another authority
	// 2 s later.
	repRefuse(t, ctrl.addr(443), "t.example.com", nil)
	fx.logs.waitFor(t, repRefusedMsg, 1)
	clock.Add(2 * time.Second)
	repRefuse(t, ctrl.addr(443), "t.example.com", &stranger)
	fx.logs.waitFor(t, repRefusedMsg, 2)
	if got := dials.dialled(); len(got) != 0 {
		t.Errorf("dials = %v, want none for refused clients", got)
	}
	drain(fx.mgr.ReportChanged())

	cp := newIngressStatusControlPlane(t)
	reporter := NewIngressStatusReporter(time.Hour, testIngressNodeID, cp.client, false, fx.mgr, discardLogger())
	// The manager dates its refusals on the fixture's clock.
	reporter.now = func() time.Time { return relayStart.Add(12500 * time.Millisecond) }
	stop := startIngressStatusReporter(t, reporter)
	var body string
	select {
	case body = <-cp.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("no report accepted within 2s")
	}
	stop()
	cp.wantNoMore(t)

	report, err := decodeIngressStatusWire([]byte(body))
	if err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if report.Rules == nil || len(*report.Rules) != 2 {
		t.Fatalf("rules of %s, want two entries", body)
	}
	rules := *report.Rules
	if e := rules[0].ClientAuthEnforced; e == nil || !*e {
		t.Errorf("client_auth_enforced of the rule with client_auth in %s, want true", body)
	}
	if rules[0].ClientRefusals == nil || len(*rules[0].ClientRefusals) != 2 {
		t.Fatalf("client_refusals of the rule with client_auth in %s, want two entries", body)
	}
	type refusal struct {
		reason string
		age    int64
	}
	want := []refusal{{IngressRefusalNoCertificate, 12}, {IngressRefusalUnknownAuthority, 10}}
	for j, e := range *rules[0].ClientRefusals {
		if e.Reason == nil || e.AgeSeconds == nil {
			t.Errorf("refusal entry %d of %s misses its reason or its age_seconds", j, body)
			continue
		}
		if got := (refusal{*e.Reason, *e.AgeSeconds}); got != want[j] {
			t.Errorf("refusal entry %d = %+v, want %+v", j, got, want[j])
		}
	}
	if rules[1].ClientAuthEnforced != nil || rules[1].ClientRefusals != nil ||
		strings.Count(body, `"client_auth_enforced"`) != 1 || strings.Count(body, `"client_refusals"`) != 1 {
		t.Errorf("the entry of the rule without client_auth carries client_auth_enforced or client_refusals: %s", body)
	}
}
