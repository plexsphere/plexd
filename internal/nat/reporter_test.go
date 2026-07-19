package nat

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter is a test double for EndpointReporter. It captures each request
// and can return per-call responses and errors indexed by call order; when no
// per-call entry exists it falls back to the single response field.
type mockReporter struct {
	mu        sync.Mutex
	calls     []mockReportCall
	response  *api.EndpointResponse
	responses []*api.EndpointResponse
	errs      []error
}

type mockReportCall struct {
	NodeID string
	Report api.EndpointRequest
}

func (m *mockReporter) ReportEndpoint(_ context.Context, nodeID string, req api.EndpointRequest) (*api.EndpointResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := len(m.calls)
	m.calls = append(m.calls, mockReportCall{NodeID: nodeID, Report: req})

	if idx < len(m.errs) && m.errs[idx] != nil {
		return nil, m.errs[idx]
	}
	if idx < len(m.responses) {
		return m.responses[idx], nil
	}
	return m.response, nil
}

func TestReport_SendsContractRequest(t *testing.T) {
	staleAfter := time.Now().UTC().Add(5 * time.Minute)
	reporter := &mockReporter{response: &api.EndpointResponse{StaleAfter: staleAfter}}

	before := time.Now().UTC()
	got, err := report(context.Background(), reporter, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATNone})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(staleAfter) {
		t.Errorf("stale_after = %v, want %v", got, staleAfter)
	}

	if len(reporter.calls) != 1 {
		t.Fatalf("expected 1 report call, got %d", len(reporter.calls))
	}
	call := reporter.calls[0]
	if call.NodeID != "node-1" {
		t.Errorf("nodeID = %q, want %q", call.NodeID, "node-1")
	}
	if call.Report.Endpoint != "9.8.7.6:51820" {
		t.Errorf("endpoint = %q, want %q", call.Report.Endpoint, "9.8.7.6:51820")
	}
	// NATNone maps through Wire() to the full_cone traversal posture.
	if call.Report.NATType != "full_cone" {
		t.Errorf("nat_type = %q, want %q", call.Report.NATType, "full_cone")
	}
	if call.Report.ReportedAt.IsZero() {
		t.Error("reported_at is zero, want a fresh timestamp")
	}
	if call.Report.ReportedAt.Before(before) {
		t.Errorf("reported_at = %v, want >= %v", call.Report.ReportedAt, before)
	}
}

// A retry would read the same clock that produced the rejected timestamp, so
// it can only resend an equally skewed reported_at — doubling the request
// volume during the very NTP incident that caused the skew.
func TestReport_ClockSkewNotRetried(t *testing.T) {
	reporter := &mockReporter{
		errs: []error{
			&api.APIError{StatusCode: 400, Code: "endpoint_clock_skew"},
		},
	}

	_, err := report(context.Background(), reporter, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nat: report endpoint: ") {
		t.Errorf("error = %q, want wrapped with %q", err.Error(), "nat: report endpoint: ")
	}
	if len(reporter.calls) != 1 {
		t.Fatalf("expected exactly 1 call, got %d", len(reporter.calls))
	}
}

func TestReport_PeerNotFoundAndGoneWrapRejection(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		statusCode int
	}{
		{"peer_not_found", "endpoint_peer_not_found", 404},
		{"peer_gone", "endpoint_peer_gone", 410},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter := &mockReporter{
				errs: []error{&api.APIError{StatusCode: tt.statusCode, Code: tt.code}},
			}

			got, err := report(context.Background(), reporter, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone})
			// The rejection must reach the caller so it can count the streak;
			// swallowing it here leaves the node silently unreachable.
			if !errors.Is(err, errEndpointRejected) {
				t.Fatalf("error = %v, want wrapped errEndpointRejected", err)
			}
			if !strings.Contains(err.Error(), tt.code) {
				t.Errorf("error = %q, want it to name the code %q", err.Error(), tt.code)
			}
			if !got.IsZero() {
				t.Errorf("stale_after = %v, want zero", got)
			}
			if len(reporter.calls) != 1 {
				t.Fatalf("expected exactly 1 call, got %d", len(reporter.calls))
			}
		})
	}
}

func TestReport_OtherErrorWrapped(t *testing.T) {
	reporter := &mockReporter{
		errs: []error{errors.New("connection refused")},
	}

	_, err := report(context.Background(), reporter, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "nat: report endpoint: ") {
		t.Errorf("error = %q, want wrapped with %q", err.Error(), "nat: report endpoint: ")
	}
	if len(reporter.calls) != 1 {
		t.Fatalf("expected exactly 1 call, got %d", len(reporter.calls))
	}
}
