package reconcile

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func sampleSnapshot() *api.NodeStateSnapshot {
	return &api.NodeStateSnapshot{
		Peers: []api.SnapshotPeer{
			{NodeID: "node-1", PublicKey: "pk-1", MeshIP: "10.0.0.1", FallbackEndpoint: "1.2.3.4:51820"},
		},
		// Populated so the never-stored assertions below bite instead of holding
		// vacuously against a fixture that never carried the block.
		Reachability: json.RawMessage(`{"state":"never_reported","changed_at":"2026-01-01T00:00:00Z"}`),
		Policy: &api.PolicySnapshot{
			RevisionID:  "rev-1",
			Fingerprint: "fp-1",
			Rules: []api.PolicyRule{
				{Action: "allow", Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
			},
		},
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled: true,
				Peers: []api.UserAccessPeer{
					{PublicKey: "ua-1", AllowedIPs: []string{"10.100.0.1/32"}},
				},
			},
			SiteToSite: &api.SiteToSiteConfig{
				Enabled: true,
				Tunnels: []api.SiteToSiteTunnel{
					{TunnelID: "t1", LocalSubnets: []string{"10.0.0.0/24"}, RemoteSubnets: []string{"172.16.0.0/16"}},
				},
			},
		},
		State: &api.NodeStateBlock{
			Metadata: []api.StateEntry{{Key: "env", Value: "prod"}},
			Data:     []api.StateEntry{{Key: "app/config", Value: "x"}},
			Reports:  []api.StateEntry{},
		},
		Reports: &api.NodeStateBlock{
			Metadata: []api.StateEntry{{Key: "env", Value: "prod"}},
			Data:     []api.StateEntry{},
			Reports:  []api.StateEntry{},
		},
	}
}

func TestStateSnapshot_InitiallyEmpty(t *testing.T) {
	snap := NewStateSnapshot()
	got := snap.Get()

	if got.Peers != nil {
		t.Errorf("expected nil Peers, got %v", got.Peers)
	}
	if got.Policy != nil {
		t.Errorf("expected nil Policy, got %v", got.Policy)
	}
	if got.Bridge != nil {
		t.Errorf("expected nil Bridge, got %v", got.Bridge)
	}
	if got.State != nil {
		t.Errorf("expected nil State, got %v", got.State)
	}
	if got.Reports != nil {
		t.Errorf("expected nil Reports, got %v", got.Reports)
	}
	// Reachability is never stored.
	if got.Reachability != nil {
		t.Errorf("expected nil Reachability, got %v", got.Reachability)
	}
}

func TestStateSnapshot_Update(t *testing.T) {
	snap := NewStateSnapshot()
	snap.Update(sampleSnapshot())

	got := snap.Get()

	if len(got.Peers) != 1 || got.Peers[0].NodeID != "node-1" {
		t.Fatalf("Peers mismatch: %+v", got.Peers)
	}
	if got.Policy == nil || got.Policy.Fingerprint != "fp-1" {
		t.Fatalf("Policy mismatch: %+v", got.Policy)
	}
	if len(got.Policy.Rules) != 1 || got.Policy.Rules[0].Ports == nil || got.Policy.Rules[0].Ports.From != 443 {
		t.Fatalf("Policy rules mismatch: %+v", got.Policy.Rules)
	}
	if got.Bridge == nil || got.Bridge.UserAccess == nil || len(got.Bridge.UserAccess.Peers) != 1 {
		t.Fatalf("Bridge mismatch: %+v", got.Bridge)
	}
	if got.State == nil || len(got.State.Metadata) != 1 || got.State.Metadata[0].Value != "prod" {
		t.Fatalf("State mismatch: %+v", got.State)
	}
	if got.Reports == nil || len(got.Reports.Metadata) != 1 {
		t.Fatalf("Reports mismatch: %+v", got.Reports)
	}
	// Reachability is not desired state.
	if got.Reachability != nil {
		t.Errorf("expected nil Reachability after update, got %v", got.Reachability)
	}
}

func TestStateSnapshot_UpdateCopiesData(t *testing.T) {
	snap := NewStateSnapshot()
	desired := sampleSnapshot()
	snap.Update(desired)

	// Mutate the source after Update — snapshot must be unaffected.
	desired.Peers[0].NodeID = "mutated"
	desired.Policy.Rules[0].Action = "deny"
	desired.Policy.Rules[0].Ports.From = 8443
	desired.Bridge.UserAccess.Peers[0].AllowedIPs[0] = "mutated"
	desired.Bridge.SiteToSite.Tunnels[0].LocalSubnets[0] = "mutated"
	desired.State.Metadata[0].Value = "mutated"
	desired.Reports.Metadata[0].Value = "mutated"

	got := snap.Get()

	if got.Peers[0].NodeID == "mutated" {
		t.Error("Peers were not copied on Update")
	}
	if got.Policy.Rules[0].Action == "deny" {
		t.Error("Policy rules were not copied on Update")
	}
	if got.Policy.Rules[0].Ports.From == 8443 {
		t.Error("Policy rule port range pointer was not deep-copied on Update")
	}
	if got.Bridge.UserAccess.Peers[0].AllowedIPs[0] == "mutated" {
		t.Error("Bridge user access AllowedIPs were not copied on Update")
	}
	if got.Bridge.SiteToSite.Tunnels[0].LocalSubnets[0] == "mutated" {
		t.Error("Bridge site-to-site subnets were not copied on Update")
	}
	if got.State.Metadata[0].Value == "mutated" {
		t.Error("State block was not copied on Update")
	}
	if got.Reports.Metadata[0].Value == "mutated" {
		t.Error("Reports block was not copied on Update")
	}
}

func TestStateSnapshot_GetReturnsCopy(t *testing.T) {
	snap := NewStateSnapshot()
	snap.Update(sampleSnapshot())

	got := snap.Get()

	// Mutate the returned value — snapshot must be unaffected.
	got.Peers[0].NodeID = "mutated"
	got.Policy.Rules[0].Action = "deny"
	got.Policy.Rules[0].Ports.To = 8443
	got.Bridge.UserAccess.Peers[0].AllowedIPs[0] = "mutated"
	got.Bridge.SiteToSite.Tunnels[0].RemoteSubnets[0] = "mutated"
	got.State.Metadata[0].Value = "mutated"

	got2 := snap.Get()

	if got2.Peers[0].NodeID == "mutated" {
		t.Error("Get did not return a copy of Peers")
	}
	if got2.Policy.Rules[0].Action == "deny" {
		t.Error("Get did not return a copy of Policy rules")
	}
	if got2.Policy.Rules[0].Ports.To == 8443 {
		t.Error("Get did not deep-copy the port range pointer")
	}
	if got2.Bridge.UserAccess.Peers[0].AllowedIPs[0] == "mutated" {
		t.Error("Get did not return a copy of Bridge user access AllowedIPs")
	}
	if got2.Bridge.SiteToSite.Tunnels[0].RemoteSubnets[0] == "mutated" {
		t.Error("Get did not return a copy of Bridge site-to-site subnets")
	}
	if got2.State.Metadata[0].Value == "mutated" {
		t.Error("Get did not return a copy of the State block")
	}
}

func TestStateSnapshot_ConcurrentAccess(t *testing.T) {
	snap := NewStateSnapshot()
	desired := sampleSnapshot()
	snap.Update(desired)

	const goroutines = 20
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if id%2 == 0 {
					snap.Update(desired)
				} else {
					got := snap.Get()
					_ = got.Peers
				}
			}
		}(g)
	}

	wg.Wait()
}
