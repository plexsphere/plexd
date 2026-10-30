package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// testRelayStatusNSK is the bearer the contract control plane accepts.
const testRelayStatusNSK = "test-nsk"

// relayStatusControlPlane is an httptest control plane serving
// PUT /v1/nodes/{node_id}/relay-status with the gates plexsphere/plexsphere#968
// puts on it: the NSK bearer, the node, a 4096-byte body cap, a strict decode
// into pointer members, the enum and the ranges, and the members each state
// requires and forbids. It answers 200 with its own receive time as
// accepted_at and records the body, and counts every 400 it answers.
type relayStatusControlPlane struct {
	srv      *httptest.Server
	client   *api.ControlPlane
	accepted chan string

	mu      sync.Mutex
	refused []string
}

// relayStatusWire is the report as the control plane decodes it: every member
// a pointer, so an absent one stays nil.
type relayStatusWire struct {
	State        *string `json:"state"`
	ListenPort   *int64  `json:"listen_port"`
	BoundSeconds *int64  `json:"bound_seconds"`
}

func newRelayStatusControlPlane(t *testing.T) *relayStatusControlPlane {
	t.Helper()
	cp := &relayStatusControlPlane{accepted: make(chan string, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/nodes/{node_id}/relay-status", cp.serve)
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)

	client, err := api.NewControlPlane(api.Config{BaseURL: cp.srv.URL}, "1.0.0-test", discardLogger())
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	client.SetAuthToken(testRelayStatusNSK)
	cp.client = client
	return cp
}

func (cp *relayStatusControlPlane) problem(w http.ResponseWriter, status int, code, detail string) {
	if status == http.StatusBadRequest {
		cp.mu.Lock()
		cp.refused = append(cp.refused, code+": "+detail)
		cp.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "detail": detail})
}

func (cp *relayStatusControlPlane) serve(w http.ResponseWriter, r *http.Request) {
	receivedAt := time.Now().UTC()
	if r.Header.Get("Authorization") != "Bearer "+testRelayStatusNSK {
		cp.problem(w, http.StatusUnauthorized, "unauthorized", "missing or wrong bearer")
		return
	}
	if r.PathValue("node_id") != testRelayNodeID {
		cp.problem(w, http.StatusForbidden, "node_id_mismatch", "the bearer belongs to another node")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		cp.problem(w, http.StatusRequestEntityTooLarge, "relay_status_body_too_large", err.Error())
		return
	}
	if detail := relayStatusMalformed(body); detail != "" {
		cp.problem(w, http.StatusBadRequest, "malformed_relay_status", detail)
		return
	}
	var report relayStatusWire
	_ = json.Unmarshal(body, &report) // relayStatusMalformed decoded it already
	if detail := relayStatusInvalid(report); detail != "" {
		cp.problem(w, http.StatusBadRequest, "invalid_relay_status", detail)
		return
	}

	cp.accepted <- string(body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"accepted_at": receivedAt.Format(time.RFC3339Nano)})
}

// relayStatusMalformed returns why the contract answers 400
// malformed_relay_status for body, or "" when it does not: a body that is not
// one JSON object, an unknown member, a null member, a value of the wrong
// type, a missing state, a state outside the enum, or a value outside its
// range.
func relayStatusMalformed(body []byte) string {
	// A null member decodes into a nil pointer just as an absent one does, so
	// it is caught on the generic decode first.
	var members map[string]any
	if err := json.Unmarshal(body, &members); err != nil {
		return err.Error()
	}
	for name, v := range members {
		if v == nil {
			return name + " is null"
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var report relayStatusWire
	if err := dec.Decode(&report); err != nil {
		return err.Error()
	}
	if report.State == nil {
		return "state is missing"
	}
	switch *report.State {
	case api.RelayStateRunning, api.RelayStateStopped, api.RelayStateBindFailed, api.RelayStateNotConsented:
	default:
		return fmt.Sprintf("state %q is not one of the enum", *report.State)
	}
	if p := report.ListenPort; p != nil && (*p < 1 || *p > 65535) {
		return fmt.Sprintf("listen_port %d out of range", *p)
	}
	if b := report.BoundSeconds; b != nil && (*b < 0 || *b > api.MaxRelayStatusBoundSeconds) {
		return fmt.Sprintf("bound_seconds %d out of range", *b)
	}
	return ""
}

// relayStatusInvalid returns the member the contract answers 400
// invalid_relay_status for, because report's state requires or forbids it, or
// "" when there is none. relayStatusMalformed has already refused a report
// without a state.
func relayStatusInvalid(report relayStatusWire) string {
	needPort, needSeconds := false, false
	switch *report.State {
	case api.RelayStateRunning:
		needPort, needSeconds = true, true
	case api.RelayStateBindFailed:
		needPort = true
	}
	switch {
	case needPort && report.ListenPort == nil:
		return "listen_port is required"
	case !needPort && report.ListenPort != nil:
		return "listen_port is forbidden"
	case needSeconds && report.BoundSeconds == nil:
		return "bound_seconds is required"
	case !needSeconds && report.BoundSeconds != nil:
		return "bound_seconds is forbidden"
	}
	return ""
}

// wantBody waits up to 2 s for the next accepted body and fails the test
// unless it is want.
func (cp *relayStatusControlPlane) wantBody(t *testing.T, step, want string) {
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
func (cp *relayStatusControlPlane) wantNoMore(t *testing.T) {
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

func TestRelayStatusIntegration_ReportsEachStateOverTheWire(t *testing.T) {
	t.Run("relay states", func(t *testing.T) {
		cp := newRelayStatusControlPlane(t)
		r, _, clock := testRelay(t)
		status := NewRelayStatusTracker()
		h := RelayReconcileHandler(r, status, discardLogger())
		reporter := NewRelayStatusReporter(time.Hour, testRelayNodeID, cp.client, status, discardLogger())
		reporter.now = clock.Now
		stop := startRelayStatusReporter(t, reporter)

		enable := func(port int) error {
			return runHandler(t, h, relaySnapshot(&api.RelayConfig{Enabled: true, ListenPort: port}))
		}

		if err := enable(51821); err != nil {
			t.Fatalf("enable 51821: %v", err)
		}
		cp.wantBody(t, "enable 51821", `{"state":"running","listen_port":51821,"bound_seconds":0}`)

		clock.Add(7 * time.Second)
		if err := enable(51822); err != nil {
			t.Fatalf("enable 51822: %v", err)
		}
		cp.wantBody(t, "enable 51822", `{"state":"running","listen_port":51822,"bound_seconds":0}`)

		r.listen = func(int) (relayConn, error) {
			return nil, &net.OpError{Op: "listen", Net: "udp", Err: syscall.EADDRINUSE}
		}
		if err := enable(51823); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("enable 51823 = %v, want the listen error", err)
		}
		cp.wantBody(t, "bind failure on 51823", `{"state":"bind_failed","listen_port":51823}`)

		if err := runHandler(t, h, relaySnapshot(&api.RelayConfig{Enabled: false, ListenPort: 51823})); err != nil {
			t.Fatalf("disable: %v", err)
		}
		cp.wantBody(t, "disable", `{"state":"stopped"}`)

		stop()
		cp.wantBody(t, "shutdown", `{"state":"stopped"}`)
		cp.wantNoMore(t)
	})

	t.Run("not consented", func(t *testing.T) {
		cp := newRelayStatusControlPlane(t)
		status := NewRelayStatusTracker()
		h := RelayReconcileHandler(nil, status, discardLogger())
		reporter := NewRelayStatusReporter(time.Hour, testRelayNodeID, cp.client, status, discardLogger())
		stop := startRelayStatusReporter(t, reporter)

		if err := runHandler(t, h, relaySnapshot(&api.RelayConfig{Enabled: true, ListenPort: 51821})); err != nil {
			t.Fatalf("handler: %v", err)
		}
		cp.wantBody(t, "enable without consent", `{"state":"not_consented"}`)

		stop()
		cp.wantBody(t, "shutdown", `{"state":"stopped"}`)
		cp.wantNoMore(t)
	})

	// The control plane above proves the reports only as far as it enforces
	// the contract, so it is checked against bodies the contract refuses.
	t.Run("the control plane refuses what the contract refuses", func(t *testing.T) {
		cp := newRelayStatusControlPlane(t)
		tests := []struct {
			body     string
			wantCode string
		}{
			{`{"state":"running","listen_port":51821}`, "invalid_relay_status"},
			{`{"state":"bind_failed","listen_port":51821,"bound_seconds":0}`, "invalid_relay_status"},
			{`{"state":"stopped","listen_port":51821}`, "invalid_relay_status"},
			{`{"listen_port":51821}`, "malformed_relay_status"},
			{`{"state":"stopped","reason":"shutdown"}`, "malformed_relay_status"},
			{`{"state":"paused"}`, "malformed_relay_status"},
			{`{"state":"bind_failed","listen_port":70000}`, "malformed_relay_status"},
			{`{"state":"running","listen_port":51821,"bound_seconds":315360001}`, "malformed_relay_status"},
			{`{"state":"stopped","bound_seconds":null}`, "malformed_relay_status"},
		}
		for _, tt := range tests {
			req, err := http.NewRequest(http.MethodPut, cp.srv.URL+"/v1/nodes/"+testRelayNodeID+"/relay-status", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+testRelayStatusNSK)
			resp, err := cp.srv.Client().Do(req)
			if err != nil {
				t.Fatalf("PUT %s: %v", tt.body, err)
			}
			var problem struct {
				Code string `json:"code"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&problem)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || problem.Code != tt.wantCode {
				t.Errorf("PUT %s = %d %q, want 400 %q", tt.body, resp.StatusCode, problem.Code, tt.wantCode)
			}
		}
	})
}
