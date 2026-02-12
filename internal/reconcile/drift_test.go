package reconcile

import (
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func TestBuildDriftReport_PeerAdded(t *testing.T) {
	diff := StateDiff{
		PeersToAdd: []api.Peer{{ID: "peer-1", PublicKey: "key1", MeshIP: "10.0.0.1"}},
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "peer_added" {
		t.Errorf("expected type peer_added, got %s", c.Type)
	}
	if c.Detail != "peer peer-1" {
		t.Errorf("expected detail 'peer peer-1', got %s", c.Detail)
	}
}

func TestBuildDriftReport_PeerRemoved(t *testing.T) {
	diff := StateDiff{
		PeersToRemove: []string{"peer-2"},
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "peer_removed" {
		t.Errorf("expected type peer_removed, got %s", c.Type)
	}
	if c.Detail != "peer peer-2" {
		t.Errorf("expected detail 'peer peer-2', got %s", c.Detail)
	}
}

func TestBuildDriftReport_PeerUpdated(t *testing.T) {
	diff := StateDiff{
		PeersToUpdate: []api.Peer{{ID: "peer-3", PublicKey: "key3", MeshIP: "10.0.0.3"}},
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "peer_updated" {
		t.Errorf("expected type peer_updated, got %s", c.Type)
	}
	if c.Detail != "peer peer-3" {
		t.Errorf("expected detail 'peer peer-3', got %s", c.Detail)
	}
}

func TestBuildDriftReport_PolicyAdded(t *testing.T) {
	diff := StateDiff{
		PoliciesToAdd: []api.Policy{{ID: "pol-1"}},
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "policy_added" {
		t.Errorf("expected type policy_added, got %s", c.Type)
	}
	if c.Detail != "policy pol-1" {
		t.Errorf("expected detail 'policy pol-1', got %s", c.Detail)
	}
}

func TestBuildDriftReport_PolicyRemoved(t *testing.T) {
	diff := StateDiff{
		PoliciesToRemove: []string{"pol-2"},
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "policy_removed" {
		t.Errorf("expected type policy_removed, got %s", c.Type)
	}
	if c.Detail != "policy pol-2" {
		t.Errorf("expected detail 'policy pol-2', got %s", c.Detail)
	}
}

func TestBuildDriftReport_SigningKeysUpdated(t *testing.T) {
	diff := StateDiff{
		SigningKeysChanged: true,
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "signing_keys_updated" {
		t.Errorf("expected type signing_keys_updated, got %s", c.Type)
	}
	if c.Detail != "signing keys rotated" {
		t.Errorf("expected detail 'signing keys rotated', got %s", c.Detail)
	}
}

func TestBuildDriftReport_MetadataUpdated(t *testing.T) {
	diff := StateDiff{
		MetadataChanged: true,
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "metadata_updated" {
		t.Errorf("expected type metadata_updated, got %s", c.Type)
	}
	if c.Detail != "metadata updated" {
		t.Errorf("expected detail 'metadata updated', got %s", c.Detail)
	}
}

func TestBuildDriftReport_DataUpdated(t *testing.T) {
	diff := StateDiff{
		DataChanged: true,
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "data_updated" {
		t.Errorf("expected type data_updated, got %s", c.Type)
	}
	if c.Detail != "data updated" {
		t.Errorf("expected detail 'data updated', got %s", c.Detail)
	}
}

func TestBuildDriftReport_SecretRefsUpdated(t *testing.T) {
	diff := StateDiff{
		SecretRefsChanged: true,
	}
	report := BuildDriftReport(diff)
	if len(report.Corrections) != 1 {
		t.Fatalf("expected 1 correction, got %d", len(report.Corrections))
	}
	c := report.Corrections[0]
	if c.Type != "secret_refs_updated" {
		t.Errorf("expected type secret_refs_updated, got %s", c.Type)
	}
	if c.Detail != "secret refs updated" {
		t.Errorf("expected detail 'secret refs updated', got %s", c.Detail)
	}
}

func TestBuildDriftReport_MultipleDrifts(t *testing.T) {
	diff := StateDiff{
		PeersToAdd:    []api.Peer{{ID: "p1"}, {ID: "p2"}},
		PeersToRemove: []string{"p3"},
		PeersToUpdate: []api.Peer{{ID: "p4"}},
		PoliciesToAdd: []api.Policy{{ID: "pol-1"}},
		MetadataChanged: true,
		DataChanged:     true,
	}
	report := BuildDriftReport(diff)
	// 2 added + 1 removed + 1 updated + 1 policy added + metadata + data = 7
	if len(report.Corrections) != 7 {
		t.Fatalf("expected 7 corrections, got %d", len(report.Corrections))
	}

	types := make(map[string]int)
	for _, c := range report.Corrections {
		types[c.Type]++
	}
	if types["peer_added"] != 2 {
		t.Errorf("expected 2 peer_added, got %d", types["peer_added"])
	}
	if types["peer_removed"] != 1 {
		t.Errorf("expected 1 peer_removed, got %d", types["peer_removed"])
	}
	if types["peer_updated"] != 1 {
		t.Errorf("expected 1 peer_updated, got %d", types["peer_updated"])
	}
	if types["policy_added"] != 1 {
		t.Errorf("expected 1 policy_added, got %d", types["policy_added"])
	}
	if types["metadata_updated"] != 1 {
		t.Errorf("expected 1 metadata_updated, got %d", types["metadata_updated"])
	}
	if types["data_updated"] != 1 {
		t.Errorf("expected 1 data_updated, got %d", types["data_updated"])
	}
}

func TestBuildDriftReport_EmptyDiff(t *testing.T) {
	diff := StateDiff{}
	report := BuildDriftReport(diff)
	if report.Corrections == nil {
		t.Fatal("expected non-nil corrections slice")
	}
	if len(report.Corrections) != 0 {
		t.Errorf("expected 0 corrections, got %d", len(report.Corrections))
	}
}

func TestBuildDriftReport_TimestampSet(t *testing.T) {
	before := time.Now()
	report := BuildDriftReport(StateDiff{})
	after := time.Now()

	if report.Timestamp.Before(before) || report.Timestamp.After(after) {
		t.Errorf("timestamp %v not between %v and %v", report.Timestamp, before, after)
	}
}
