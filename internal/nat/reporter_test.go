package nat

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// mockReporter is a test double for EndpointReporter.
type mockReporter struct {
	mu       sync.Mutex
	calls    []mockReportCall
	response *api.EndpointResponse
	err      error
}

type mockReportCall struct {
	NodeID string
	Report api.EndpointReport
}

func (m *mockReporter) ReportEndpoint(ctx context.Context, nodeID string, req api.EndpointReport) (*api.EndpointResponse, error) {
	m.mu.Lock()
	m.calls = append(m.calls, mockReportCall{NodeID: nodeID, Report: req})
	resp := m.response
	err := m.err
	m.mu.Unlock()
	return resp, err
}

// mockUpdater is a test double for PeerUpdater.
type mockUpdater struct {
	mu    sync.Mutex
	calls []api.Peer
	errs  map[string]error // per peer ID
}

func (m *mockUpdater) UpdatePeer(peer api.Peer) error {
	m.mu.Lock()
	m.calls = append(m.calls, peer)
	var err error
	if m.errs != nil {
		err = m.errs[peer.ID]
	}
	m.mu.Unlock()
	return err
}

func TestReportAndApply_Success(t *testing.T) {
	reporter := &mockReporter{
		response: &api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: "1.2.3.4:51820"},
				{PeerID: "peer-2", Endpoint: "5.6.7.8:51820"},
			},
		},
	}
	updater := &mockUpdater{}
	logger := discardLogger()

	err := reportAndApply(context.Background(), reporter, updater, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ReportEndpoint called with correct args.
	if len(reporter.calls) != 1 {
		t.Fatalf("expected 1 report call, got %d", len(reporter.calls))
	}
	call := reporter.calls[0]
	if call.NodeID != "node-1" {
		t.Errorf("expected nodeID %q, got %q", "node-1", call.NodeID)
	}
	if call.Report.PublicEndpoint != "9.8.7.6:51820" {
		t.Errorf("expected endpoint %q, got %q", "9.8.7.6:51820", call.Report.PublicEndpoint)
	}
	if call.Report.NATType != "full_cone" {
		t.Errorf("expected nat type %q, got %q", "full_cone", call.Report.NATType)
	}

	// Verify UpdatePeer called for each peer.
	if len(updater.calls) != 2 {
		t.Fatalf("expected 2 updater calls, got %d", len(updater.calls))
	}
	if updater.calls[0].ID != "peer-1" || updater.calls[0].Endpoint != "1.2.3.4:51820" {
		t.Errorf("unexpected first peer update: %+v", updater.calls[0])
	}
	if updater.calls[1].ID != "peer-2" || updater.calls[1].Endpoint != "5.6.7.8:51820" {
		t.Errorf("unexpected second peer update: %+v", updater.calls[1])
	}
}

func TestReportAndApply_SkipsEmptyPeerEndpoint(t *testing.T) {
	reporter := &mockReporter{
		response: &api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: ""},
				{PeerID: "peer-2", Endpoint: "5.6.7.8:51820"},
			},
		},
	}
	updater := &mockUpdater{}
	logger := discardLogger()

	err := reportAndApply(context.Background(), reporter, updater, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only peer-2 should be updated.
	if len(updater.calls) != 1 {
		t.Fatalf("expected 1 updater call, got %d", len(updater.calls))
	}
	if updater.calls[0].ID != "peer-2" {
		t.Errorf("expected peer-2, got %q", updater.calls[0].ID)
	}
}

func TestReportAndApply_ReporterError(t *testing.T) {
	reporter := &mockReporter{
		err: errors.New("connection refused"),
	}
	updater := &mockUpdater{}
	logger := discardLogger()

	err := reportAndApply(context.Background(), reporter, updater, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone}, logger)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, reporter.err) {
		t.Errorf("expected wrapped error containing %q, got %q", reporter.err, err)
	}

	// Updater should not have been called.
	if len(updater.calls) != 0 {
		t.Errorf("expected 0 updater calls, got %d", len(updater.calls))
	}
}

func TestReportAndApply_UpdaterErrorContinues(t *testing.T) {
	reporter := &mockReporter{
		response: &api.EndpointResponse{
			PeerEndpoints: []api.PeerEndpoint{
				{PeerID: "peer-1", Endpoint: "1.2.3.4:51820"},
				{PeerID: "peer-2", Endpoint: "5.6.7.8:51820"},
			},
		},
	}
	updater := &mockUpdater{
		errs: map[string]error{
			"peer-1": errors.New("wg: device busy"),
		},
	}
	logger := discardLogger()

	err := reportAndApply(context.Background(), reporter, updater, "node-1", &DiscoveryResult{Endpoint: "9.8.7.6:51820", NATType: NATFullCone}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both peers should have been attempted.
	if len(updater.calls) != 2 {
		t.Fatalf("expected 2 updater calls, got %d", len(updater.calls))
	}
	if updater.calls[0].ID != "peer-1" {
		t.Errorf("expected first call for peer-1, got %q", updater.calls[0].ID)
	}
	if updater.calls[1].ID != "peer-2" {
		t.Errorf("expected second call for peer-2, got %q", updater.calls[1].ID)
	}
}
