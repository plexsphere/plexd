package reconcile

import (
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func TestComputeDiff_PeersAdded(t *testing.T) {
	desired := &api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: "p1", PublicKey: "pk1", MeshIP: "10.0.0.1", FallbackEndpoint: "1.2.3.4:51820"},
		},
	}
	current := &api.NodeStateSnapshot{}

	diff := ComputeDiff(desired, current)

	if len(diff.PeersToAdd) != 1 {
		t.Fatalf("expected 1 peer to add, got %d", len(diff.PeersToAdd))
	}
	if diff.PeersToAdd[0].NodeID != "p1" {
		t.Errorf("expected peer node ID p1, got %s", diff.PeersToAdd[0].NodeID)
	}
	if len(diff.PeersToRemove) != 0 {
		t.Errorf("expected 0 peers to remove, got %d", len(diff.PeersToRemove))
	}
}

func TestComputeDiff_PeersRemoved(t *testing.T) {
	// An explicit empty desired peers list against a populated current removes
	// every peer.
	desired := &api.NodeStateSnapshot{Peers: []api.SnapshotPeer{}}
	current := &api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: "p1", PublicKey: "pk1", MeshIP: "10.0.0.1"},
			{NodeID: "p2", PublicKey: "pk2", MeshIP: "10.0.0.2"},
		},
	}

	diff := ComputeDiff(desired, current)

	if len(diff.PeersToRemove) != 2 {
		t.Fatalf("expected 2 peers to remove, got %d", len(diff.PeersToRemove))
	}
	if len(diff.PeersToAdd) != 0 {
		t.Errorf("expected 0 peers to add, got %d", len(diff.PeersToAdd))
	}
}

func TestComputeDiff_PeersUpdated(t *testing.T) {
	t.Run("public key change is an update", func(t *testing.T) {
		desired := &api.NodeStateSnapshot{
			Peers: []api.SnapshotPeer{{NodeID: "p1", PublicKey: "pk-new", MeshIP: "10.0.0.1"}},
		}
		current := &api.NodeStateSnapshot{
			Peers: []api.SnapshotPeer{{NodeID: "p1", PublicKey: "pk-old", MeshIP: "10.0.0.1"}},
		}

		diff := ComputeDiff(desired, current)

		if len(diff.PeersToUpdate) != 1 {
			t.Fatalf("expected 1 peer to update, got %d", len(diff.PeersToUpdate))
		}
		if diff.PeersToUpdate[0].PublicKey != "pk-new" {
			t.Errorf("expected updated public key pk-new, got %s", diff.PeersToUpdate[0].PublicKey)
		}
	})

	t.Run("fallback_endpoint-only change is an update", func(t *testing.T) {
		desired := &api.NodeStateSnapshot{
			Peers: []api.SnapshotPeer{{NodeID: "p1", PublicKey: "pk1", MeshIP: "10.0.0.1", FallbackEndpoint: "5.6.7.8:51820"}},
		}
		current := &api.NodeStateSnapshot{
			Peers: []api.SnapshotPeer{{NodeID: "p1", PublicKey: "pk1", MeshIP: "10.0.0.1", FallbackEndpoint: "1.2.3.4:51820"}},
		}

		diff := ComputeDiff(desired, current)

		if len(diff.PeersToUpdate) != 1 {
			t.Fatalf("expected 1 peer to update on fallback_endpoint change, got %d", len(diff.PeersToUpdate))
		}
		if diff.PeersToUpdate[0].FallbackEndpoint != "5.6.7.8:51820" {
			t.Errorf("expected updated fallback endpoint, got %s", diff.PeersToUpdate[0].FallbackEndpoint)
		}
		if len(diff.PeersToAdd) != 0 || len(diff.PeersToRemove) != 0 {
			t.Errorf("expected no adds/removes, got add=%d remove=%d", len(diff.PeersToAdd), len(diff.PeersToRemove))
		}
	})

	t.Run("identical peer is not an update", func(t *testing.T) {
		peer := api.SnapshotPeer{NodeID: "p1", PublicKey: "pk1", MeshIP: "10.0.0.1", FallbackEndpoint: "1.2.3.4:51820"}
		desired := &api.NodeStateSnapshot{Peers: []api.SnapshotPeer{peer}}
		current := &api.NodeStateSnapshot{Peers: []api.SnapshotPeer{peer}}

		diff := ComputeDiff(desired, current)

		if len(diff.PeersToUpdate) != 0 {
			t.Errorf("identical peer should not update, got %d", len(diff.PeersToUpdate))
		}
	})
}

func TestComputeDiff_PolicyFingerprintShortCircuit(t *testing.T) {
	t.Run("different rules but equal fingerprint is not a change", func(t *testing.T) {
		desired := &api.NodeStateSnapshot{
			Policy: &api.PolicySnapshot{
				RevisionID:  "rev-2",
				Fingerprint: "fp-same",
				Rules: []api.PolicyRule{
					{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0"},
				},
			},
		}
		current := &api.NodeStateSnapshot{
			Policy: &api.PolicySnapshot{
				RevisionID:  "rev-1",
				Fingerprint: "fp-same",
				Rules:       []api.PolicyRule{}, // deliberately different rule set
			},
		}

		diff := ComputeDiff(desired, current)

		if diff.PolicyChanged {
			t.Error("equal fingerprint must short-circuit: PolicyChanged should be false despite differing rules")
		}
	})

	t.Run("revision-only bump is not a change", func(t *testing.T) {
		rules := []api.PolicyRule{{Action: "deny", Protocol: "any", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "10.0.0.0/8"}}
		desired := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{RevisionID: "rev-2", Fingerprint: "fp", Rules: rules}}
		current := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: "fp", Rules: rules}}

		diff := ComputeDiff(desired, current)

		if diff.PolicyChanged {
			t.Error("revision-only bump should not change policy")
		}
	})

	t.Run("fingerprint change is a change", func(t *testing.T) {
		rules := []api.PolicyRule{{Action: "deny", Protocol: "any", SourceCIDR: "10.0.0.0/8", DestinationCIDR: "10.0.0.0/8"}}
		desired := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: "fp-new", Rules: rules}}
		current := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{RevisionID: "rev-1", Fingerprint: "fp-old", Rules: rules}}

		diff := ComputeDiff(desired, current)

		if !diff.PolicyChanged {
			t.Error("fingerprint change should set PolicyChanged")
		}
	})
}

func TestComputeDiff_PolicyNullToPopulated(t *testing.T) {
	desired := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{Fingerprint: "fp"}}
	current := &api.NodeStateSnapshot{Policy: nil}

	diff := ComputeDiff(desired, current)

	if !diff.PolicyChanged {
		t.Error("nil→populated policy should set PolicyChanged")
	}
}

// An empty desired fingerprint must not be treated as a valid comparison key:
// "" == "" would read as "no change" forever and freeze the firewall at the
// first applied revision.
func TestComputeDiff_PolicyEmptyFingerprintAlwaysChanged(t *testing.T) {
	rules := []api.PolicyRule{{Action: "allow", Protocol: "tcp"}}
	desired := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{Fingerprint: "", Rules: rules}}
	current := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{Fingerprint: "", Rules: rules}}

	diff := ComputeDiff(desired, current)

	if !diff.PolicyChanged {
		t.Error("empty desired fingerprint should set PolicyChanged, not short-circuit")
	}
}

func TestComputeDiff_PolicyPopulatedToNull(t *testing.T) {
	desired := &api.NodeStateSnapshot{Policy: nil}
	current := &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{Fingerprint: "fp"}}

	diff := ComputeDiff(desired, current)

	if !diff.PolicyChanged {
		t.Error("populated→nil policy should set PolicyChanged")
	}
}

func TestComputeDiff_BridgeTransitions(t *testing.T) {
	populated := &api.BridgeSnapshot{Relay: &api.RelayConfig{Sessions: []api.RelaySessionAssignment{{SessionID: "r1"}}}}
	changed := &api.BridgeSnapshot{Relay: &api.RelayConfig{Sessions: []api.RelaySessionAssignment{{SessionID: "r2"}}}}

	tests := []struct {
		name    string
		desired *api.BridgeSnapshot
		current *api.BridgeSnapshot
		want    bool
	}{
		{"nil to nil", nil, nil, false},
		{"nil to populated", populated, nil, true},
		{"populated to nil", nil, populated, true},
		{"populated deep change", changed, populated, true},
		{"populated no change", populated, populated, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := ComputeDiff(&api.NodeStateSnapshot{Bridge: tt.desired}, &api.NodeStateSnapshot{Bridge: tt.current})
			if diff.BridgeChanged != tt.want {
				t.Errorf("BridgeChanged = %v, want %v", diff.BridgeChanged, tt.want)
			}
		})
	}
}

func TestComputeDiff_StateTransitions(t *testing.T) {
	populated := &api.NodeStateBlock{Metadata: []api.StateEntry{{Key: "env", Value: "prod"}}}
	changed := &api.NodeStateBlock{Metadata: []api.StateEntry{{Key: "env", Value: "staging"}}}

	tests := []struct {
		name    string
		desired *api.NodeStateBlock
		current *api.NodeStateBlock
		want    bool
	}{
		{"nil to nil", nil, nil, false},
		{"nil to populated", populated, nil, true},
		{"populated to nil", nil, populated, true},
		{"populated deep change", changed, populated, true},
		{"populated no change", populated, populated, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := ComputeDiff(&api.NodeStateSnapshot{State: tt.desired}, &api.NodeStateSnapshot{State: tt.current})
			if diff.StateChanged != tt.want {
				t.Errorf("StateChanged = %v, want %v", diff.StateChanged, tt.want)
			}
		})
	}
}

func TestComputeDiff_ReportsTransitions(t *testing.T) {
	populated := &api.NodeStateBlock{Data: []api.StateEntry{{Key: "k", Value: "v1"}}}
	changed := &api.NodeStateBlock{Data: []api.StateEntry{{Key: "k", Value: "v2"}}}

	tests := []struct {
		name    string
		desired *api.NodeStateBlock
		current *api.NodeStateBlock
		want    bool
	}{
		{"nil to nil", nil, nil, false},
		{"nil to populated", populated, nil, true},
		{"populated to nil", nil, populated, true},
		{"populated deep change", changed, populated, true},
		{"populated no change", populated, populated, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := ComputeDiff(&api.NodeStateSnapshot{Reports: tt.desired}, &api.NodeStateSnapshot{Reports: tt.current})
			if diff.ReportsChanged != tt.want {
				t.Errorf("ReportsChanged = %v, want %v", diff.ReportsChanged, tt.want)
			}
		})
	}
}

func TestComputeDiff_NilDesired(t *testing.T) {
	diff := ComputeDiff(nil, &api.NodeStateSnapshot{Policy: &api.PolicySnapshot{Fingerprint: "fp"}})
	if !diff.IsEmpty() {
		t.Error("nil desired should yield an empty diff")
	}
}

func TestComputeDiff_NilCurrent(t *testing.T) {
	desired := &api.NodeStateSnapshot{
		Peers:   []api.SnapshotPeer{{NodeID: "p1", PublicKey: "pk1"}},
		Policy:  &api.PolicySnapshot{Fingerprint: "fp"},
		Bridge:  &api.BridgeSnapshot{},
		State:   &api.NodeStateBlock{},
		Reports: &api.NodeStateBlock{},
	}

	diff := ComputeDiff(desired, nil)

	if len(diff.PeersToAdd) != 1 {
		t.Errorf("expected 1 peer to add against nil current, got %d", len(diff.PeersToAdd))
	}
	if !diff.PolicyChanged || !diff.BridgeChanged || !diff.StateChanged || !diff.ReportsChanged {
		t.Errorf("all populated blocks should be changed against nil current: %+v", diff)
	}
}

func TestStateDiff_IsEmpty(t *testing.T) {
	var diff StateDiff
	if !diff.IsEmpty() {
		t.Fatal("zero-value StateDiff should be empty")
	}
	if got := diff.Summary(); got != "none" {
		t.Errorf("empty Summary = %q, want %q", got, "none")
	}
}

func TestStateDiff_Summary(t *testing.T) {
	diff := StateDiff{
		PeersToAdd:     []api.SnapshotPeer{{NodeID: "p1"}},
		PeersToUpdate:  []api.SnapshotPeer{{NodeID: "p2"}, {NodeID: "p3"}},
		PolicyChanged:  true,
		BridgeChanged:  true,
		StateChanged:   true,
		ReportsChanged: true,
	}
	if diff.IsEmpty() {
		t.Fatal("populated StateDiff should not be empty")
	}
	want := "peers+1-0~2 policy bridge state reports"
	if got := diff.Summary(); got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
}
