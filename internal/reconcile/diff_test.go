package reconcile

import (
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func TestComputeDiff_PeersAdded(t *testing.T) {
	desired := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "p1", PublicKey: "pk1", Endpoint: "1.2.3.4:51820"},
		},
	}
	current := &api.StateResponse{}

	diff := ComputeDiff(desired, current)

	if len(diff.PeersToAdd) != 1 {
		t.Fatalf("expected 1 peer to add, got %d", len(diff.PeersToAdd))
	}
	if diff.PeersToAdd[0].ID != "p1" {
		t.Errorf("expected peer ID p1, got %s", diff.PeersToAdd[0].ID)
	}
	if len(diff.PeersToRemove) != 0 {
		t.Errorf("expected 0 peers to remove, got %d", len(diff.PeersToRemove))
	}
}

func TestComputeDiff_PeersRemoved(t *testing.T) {
	desired := &api.StateResponse{}
	current := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "p1", PublicKey: "pk1", Endpoint: "1.2.3.4:51820"},
		},
	}

	diff := ComputeDiff(desired, current)

	if len(diff.PeersToRemove) != 1 {
		t.Fatalf("expected 1 peer to remove, got %d", len(diff.PeersToRemove))
	}
	if diff.PeersToRemove[0] != "p1" {
		t.Errorf("expected peer ID p1, got %s", diff.PeersToRemove[0])
	}
	if len(diff.PeersToAdd) != 0 {
		t.Errorf("expected 0 peers to add, got %d", len(diff.PeersToAdd))
	}
}

func TestComputeDiff_PeersUpdated(t *testing.T) {
	desired := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "p1", PublicKey: "pk1", Endpoint: "5.6.7.8:51820", MeshIP: "10.0.0.1"},
		},
	}
	current := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "p1", PublicKey: "pk1", Endpoint: "1.2.3.4:51820", MeshIP: "10.0.0.1"},
		},
	}

	diff := ComputeDiff(desired, current)

	if len(diff.PeersToUpdate) != 1 {
		t.Fatalf("expected 1 peer to update, got %d", len(diff.PeersToUpdate))
	}
	if diff.PeersToUpdate[0].Endpoint != "5.6.7.8:51820" {
		t.Errorf("expected updated endpoint 5.6.7.8:51820, got %s", diff.PeersToUpdate[0].Endpoint)
	}
	if len(diff.PeersToAdd) != 0 {
		t.Errorf("expected 0 peers to add, got %d", len(diff.PeersToAdd))
	}
	if len(diff.PeersToRemove) != 0 {
		t.Errorf("expected 0 peers to remove, got %d", len(diff.PeersToRemove))
	}
}

func TestComputeDiff_PeersUpdatedAllowedIPs(t *testing.T) {
	t.Run("reordered AllowedIPs should not count as update", func(t *testing.T) {
		desired := &api.StateResponse{
			Peers: []api.Peer{
				{ID: "p1", PublicKey: "pk1", AllowedIPs: []string{"10.0.0.0/24", "192.168.1.0/24"}},
			},
		}
		current := &api.StateResponse{
			Peers: []api.Peer{
				{ID: "p1", PublicKey: "pk1", AllowedIPs: []string{"192.168.1.0/24", "10.0.0.0/24"}},
			},
		}

		diff := ComputeDiff(desired, current)

		if len(diff.PeersToUpdate) != 0 {
			t.Errorf("reordered AllowedIPs should not produce update, got %d updates", len(diff.PeersToUpdate))
		}
	})

	t.Run("different AllowedIPs should count as update", func(t *testing.T) {
		desired := &api.StateResponse{
			Peers: []api.Peer{
				{ID: "p1", PublicKey: "pk1", AllowedIPs: []string{"10.0.0.0/24", "172.16.0.0/16"}},
			},
		}
		current := &api.StateResponse{
			Peers: []api.Peer{
				{ID: "p1", PublicKey: "pk1", AllowedIPs: []string{"10.0.0.0/24", "192.168.1.0/24"}},
			},
		}

		diff := ComputeDiff(desired, current)

		if len(diff.PeersToUpdate) != 1 {
			t.Fatalf("different AllowedIPs should produce update, got %d updates", len(diff.PeersToUpdate))
		}
	})
}

func TestComputeDiff_PoliciesAddedAndRemoved(t *testing.T) {
	desired := &api.StateResponse{
		Policies: []api.Policy{
			{ID: "pol-new", Rules: []api.PolicyRule{{Src: "10.0.0.1", Dst: "10.0.0.2", Action: "allow"}}},
		},
	}
	current := &api.StateResponse{
		Policies: []api.Policy{
			{ID: "pol-old", Rules: []api.PolicyRule{{Src: "10.0.0.3", Dst: "10.0.0.4", Action: "deny"}}},
		},
	}

	diff := ComputeDiff(desired, current)

	if len(diff.PoliciesToAdd) != 1 {
		t.Fatalf("expected 1 policy to add, got %d", len(diff.PoliciesToAdd))
	}
	if diff.PoliciesToAdd[0].ID != "pol-new" {
		t.Errorf("expected policy ID pol-new, got %s", diff.PoliciesToAdd[0].ID)
	}
	if len(diff.PoliciesToRemove) != 1 {
		t.Fatalf("expected 1 policy to remove, got %d", len(diff.PoliciesToRemove))
	}
	if diff.PoliciesToRemove[0] != "pol-old" {
		t.Errorf("expected policy ID pol-old, got %s", diff.PoliciesToRemove[0])
	}
}

func TestComputeDiff_SigningKeysChanged(t *testing.T) {
	desired := &api.StateResponse{
		SigningKeys: &api.SigningKeys{Current: "key-new", Previous: "key-old"},
	}
	current := &api.StateResponse{
		SigningKeys: &api.SigningKeys{Current: "key-old", Previous: ""},
	}

	diff := ComputeDiff(desired, current)

	if !diff.SigningKeysChanged {
		t.Fatal("expected SigningKeysChanged to be true")
	}
	if diff.NewSigningKeys == nil {
		t.Fatal("expected NewSigningKeys to be non-nil")
	}
	if diff.NewSigningKeys.Current != "key-new" {
		t.Errorf("expected new current key key-new, got %s", diff.NewSigningKeys.Current)
	}
}

func TestComputeDiff_SigningKeysNilToNonNil(t *testing.T) {
	desired := &api.StateResponse{
		SigningKeys: &api.SigningKeys{Current: "key-new"},
	}
	current := &api.StateResponse{
		SigningKeys: nil,
	}

	diff := ComputeDiff(desired, current)

	if !diff.SigningKeysChanged {
		t.Fatal("expected SigningKeysChanged to be true when going from nil to non-nil")
	}
	if diff.NewSigningKeys == nil || diff.NewSigningKeys.Current != "key-new" {
		t.Error("expected NewSigningKeys to reflect desired")
	}
}

func TestComputeDiff_SigningKeysNilBoth(t *testing.T) {
	desired := &api.StateResponse{SigningKeys: nil}
	current := &api.StateResponse{SigningKeys: nil}

	diff := ComputeDiff(desired, current)

	if diff.SigningKeysChanged {
		t.Error("expected no signing key change when both are nil")
	}
}

func TestComputeDiff_MetadataChanged(t *testing.T) {
	desired := &api.StateResponse{
		Metadata: map[string]string{"env": "prod", "region": "us-east"},
	}
	current := &api.StateResponse{
		Metadata: map[string]string{"env": "staging"},
	}

	diff := ComputeDiff(desired, current)

	if !diff.MetadataChanged {
		t.Fatal("expected MetadataChanged to be true")
	}
}

func TestComputeDiff_DataEntriesChanged(t *testing.T) {
	desired := &api.StateResponse{
		Data: []api.DataEntry{
			{Key: "config", Version: 3},
		},
	}
	current := &api.StateResponse{
		Data: []api.DataEntry{
			{Key: "config", Version: 2},
		},
	}

	diff := ComputeDiff(desired, current)

	if !diff.DataChanged {
		t.Fatal("expected DataChanged to be true when versions differ")
	}
}

func TestComputeDiff_SecretRefsChanged(t *testing.T) {
	desired := &api.StateResponse{
		SecretRefs: []api.SecretRef{
			{Key: "db-password", Version: 5},
		},
	}
	current := &api.StateResponse{
		SecretRefs: []api.SecretRef{
			{Key: "db-password", Version: 4},
		},
	}

	diff := ComputeDiff(desired, current)

	if !diff.SecretRefsChanged {
		t.Fatal("expected SecretRefsChanged to be true when versions differ")
	}
}

func TestComputeDiff_NoDrift(t *testing.T) {
	state := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "p1", PublicKey: "pk1", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.0.0.0/24"}},
		},
		Policies: []api.Policy{
			{ID: "pol1", Rules: []api.PolicyRule{{Src: "10.0.0.1", Dst: "10.0.0.2", Action: "allow"}}},
		},
		SigningKeys: &api.SigningKeys{Current: "key1"},
		Metadata:    map[string]string{"env": "prod"},
		Data: []api.DataEntry{
			{Key: "config", Version: 1},
		},
		SecretRefs: []api.SecretRef{
			{Key: "secret", Version: 1},
		},
	}

	diff := ComputeDiff(state, state)

	if !diff.IsEmpty() {
		t.Fatal("expected empty diff for identical states")
	}
}

func TestComputeDiff_EmptySnapshot(t *testing.T) {
	desired := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "p1", PublicKey: "pk1"},
			{ID: "p2", PublicKey: "pk2"},
		},
		Policies: []api.Policy{
			{ID: "pol1"},
		},
		SigningKeys: &api.SigningKeys{Current: "key1"},
		Metadata:    map[string]string{"env": "prod"},
		Data: []api.DataEntry{
			{Key: "config", Version: 1},
		},
		SecretRefs: []api.SecretRef{
			{Key: "secret", Version: 1},
		},
	}

	diff := ComputeDiff(desired, nil)

	if len(diff.PeersToAdd) != 2 {
		t.Errorf("expected 2 peers to add, got %d", len(diff.PeersToAdd))
	}
	if len(diff.PeersToRemove) != 0 {
		t.Errorf("expected 0 peers to remove, got %d", len(diff.PeersToRemove))
	}
	if len(diff.PoliciesToAdd) != 1 {
		t.Errorf("expected 1 policy to add, got %d", len(diff.PoliciesToAdd))
	}
	if !diff.SigningKeysChanged {
		t.Error("expected signing keys changed")
	}
	if !diff.MetadataChanged {
		t.Error("expected metadata changed")
	}
	if !diff.DataChanged {
		t.Error("expected data changed")
	}
	if !diff.SecretRefsChanged {
		t.Error("expected secret refs changed")
	}
}

func TestStateDiff_IsEmpty(t *testing.T) {
	var diff StateDiff
	if !diff.IsEmpty() {
		t.Fatal("zero-value StateDiff should be empty")
	}
}

func TestStateDiff_IsEmptyWithPeersToAdd(t *testing.T) {
	diff := StateDiff{
		PeersToAdd: []api.Peer{{ID: "p1"}},
	}
	if diff.IsEmpty() {
		t.Fatal("StateDiff with PeersToAdd should not be empty")
	}
}
