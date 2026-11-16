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
// it: the NSK bearer, the node, a 4096-byte body cap, a strict decode that
// refuses unknown members and data after the report, and a state that is
// present and one of the two the contract names. It answers 200 with its own
// receive time as accepted_at and records the body, and counts every 400 it
// answers.
type ingressStatusControlPlane struct {
	srv      *httptest.Server
	client   *api.ControlPlane
	accepted chan string

	mu      sync.Mutex
	refused []string
}

// ingressStatusWire is the report as the control plane decodes it: state is a
// pointer, so an absent or null one stays nil.
type ingressStatusWire struct {
	State *string `json:"state"`
}

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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
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
// one JSON object, an unknown member, data after the report, a missing or null
// state, or a state that is neither enabled nor opted_out.
func ingressStatusMalformed(body []byte) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var report ingressStatusWire
	if err := dec.Decode(&report); err != nil {
		return err.Error()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "data after the report"
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
			reporter := NewIngressStatusReporter(time.Hour, testIngressNodeID, cp.client, tc.optedOut, discardLogger())
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
			{`{"state":"enabled","rules":[]}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled"}{}`, http.StatusBadRequest, "malformed_ingress_status"},
			{`["enabled"]`, http.StatusBadRequest, "malformed_ingress_status"},
			{`{"state":"enabled"}` + strings.Repeat(" ", 4097-len(`{"state":"enabled"}`)), http.StatusRequestEntityTooLarge, "ingress_status_body_too_large"},
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
