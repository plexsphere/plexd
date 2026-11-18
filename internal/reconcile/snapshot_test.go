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
			{NodeID: "node-1", PublicKey: "pk-1", MeshIP: "10.0.0.1", FallbackEndpoint: "1.2.3.4:51820", FallbackEndpoints: []string{"1.2.3.4:51820", "5.6.7.8:51820"}, EndpointCandidates: []string{"10.0.0.5:51820"}, RoutedSubnets: []string{"10.20.0.0/16"}},
		},
		// Populated so the never-stored assertions below bite instead of holding
		// vacuously against a fixture that never carried the block.
		Reachability: json.RawMessage(`{"state":"never_reported","changed_at":"2026-01-01T00:00:00Z"}`),
		Policy: &api.PolicySnapshot{
			RevisionID:  "rev-1",
			Fingerprint: "fp-1",
			Rules: []api.PolicyRule{
				{Protocol: "tcp", SourceCIDR: "10.0.0.0/24", DestinationCIDR: "0.0.0.0/0", Ports: &api.PortRange{From: 443, To: 443}},
			},
			Revisions: []api.PolicyRevisionRef{{PolicyID: "pol-1", RevisionID: "rev-1"}},
		},
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled: true,
				Providers: []api.UserAccessProvider{
					{
						ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1", Slug: "field-team", Kind: api.UserAccessKindWireGuard,
						ListenPort: 51821, AddressPool: "10.100.0.0/24", MaxDevices: 64,
						Devices: []api.UserAccessDevice{{ID: "dev-1", Slug: "alice-laptop", PublicKey: "ua-1", Address: "10.100.0.2"}},
					},
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
		Secrets: &[]api.NodeStateSecret{{Name: "db-password", Version: 2}},
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
	if got.Bridge == nil || got.Bridge.UserAccess == nil || len(got.Bridge.UserAccess.Providers) != 1 {
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
	// Neither is the secret inventory: the node API's dispatch handler
	// consumes it on every pull.
	if got.Secrets != nil {
		t.Errorf("expected nil Secrets after update, got %v", got.Secrets)
	}
}

func TestStateSnapshot_UpdateCopiesData(t *testing.T) {
	snap := NewStateSnapshot()
	desired := sampleSnapshot()
	snap.Update(desired)

	// Mutate the source after Update — snapshot must be unaffected.
	desired.Peers[0].NodeID = "mutated"
	desired.Peers[0].FallbackEndpoints[0] = "mutated"
	desired.Peers[0].EndpointCandidates[0] = "mutated"
	desired.Peers[0].RoutedSubnets[0] = "mutated"
	desired.Policy.Rules[0].SourceCIDR = "mutated"
	desired.Policy.Rules[0].Ports.From = 8443
	desired.Policy.Revisions[0].RevisionID = "mutated"
	desired.Bridge.UserAccess.Providers[0].Devices[0].Address = "mutated"
	desired.Bridge.SiteToSite.Tunnels[0].LocalSubnets[0] = "mutated"
	desired.State.Metadata[0].Value = "mutated"
	desired.Reports.Metadata[0].Value = "mutated"

	got := snap.Get()

	if got.Peers[0].NodeID == "mutated" {
		t.Error("Peers were not copied on Update")
	}
	if got.Peers[0].FallbackEndpoints[0] == "mutated" {
		t.Error("Peer fallback endpoints were not copied on Update")
	}
	if got.Peers[0].EndpointCandidates[0] == "mutated" {
		t.Error("Peer endpoint candidates were not copied on Update")
	}
	if got.Peers[0].RoutedSubnets[0] == "mutated" {
		t.Error("Peer routed subnets were not copied on Update")
	}
	if got.Policy.Rules[0].SourceCIDR == "mutated" {
		t.Error("Policy rules were not copied on Update")
	}
	if got.Policy.Rules[0].Ports.From == 8443 {
		t.Error("Policy rule port range pointer was not deep-copied on Update")
	}
	if len(got.Policy.Revisions) != 1 || got.Policy.Revisions[0].RevisionID != "rev-1" {
		t.Errorf("Policy revisions = %+v, want the stored [{pol-1 rev-1}] unaffected by the source", got.Policy.Revisions)
	}
	if got.Bridge.UserAccess.Providers[0].Devices[0].Address == "mutated" {
		t.Error("Bridge user access devices were not copied on Update")
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
	got.Peers[0].FallbackEndpoints[0] = "mutated"
	got.Peers[0].EndpointCandidates[0] = "mutated"
	got.Peers[0].RoutedSubnets[0] = "mutated"
	got.Policy.Rules[0].SourceCIDR = "mutated"
	got.Policy.Rules[0].Ports.To = 8443
	got.Bridge.UserAccess.Providers[0].Devices[0].Address = "mutated"
	got.Bridge.SiteToSite.Tunnels[0].RemoteSubnets[0] = "mutated"
	got.State.Metadata[0].Value = "mutated"

	got2 := snap.Get()

	if got2.Peers[0].NodeID == "mutated" {
		t.Error("Get did not return a copy of Peers")
	}
	if got2.Peers[0].FallbackEndpoints[0] == "mutated" {
		t.Error("Get did not return a copy of the peer fallback endpoints")
	}
	if got2.Peers[0].EndpointCandidates[0] == "mutated" {
		t.Error("Get did not return a copy of the peer endpoint candidates")
	}
	if got2.Peers[0].RoutedSubnets[0] == "mutated" {
		t.Error("Get did not return a copy of the peer routed subnets")
	}
	if got2.Policy.Rules[0].SourceCIDR == "mutated" {
		t.Error("Get did not return a copy of Policy rules")
	}
	if got2.Policy.Rules[0].Ports.To == 8443 {
		t.Error("Get did not deep-copy the port range pointer")
	}
	if got2.Bridge.UserAccess.Providers[0].Devices[0].Address == "mutated" {
		t.Error("Get did not return a copy of Bridge user access devices")
	}
	if got2.Bridge.SiteToSite.Tunnels[0].RemoteSubnets[0] == "mutated" {
		t.Error("Get did not return a copy of Bridge site-to-site subnets")
	}
	if got2.State.Metadata[0].Value == "mutated" {
		t.Error("Get did not return a copy of the State block")
	}
}

// TestStateSnapshot_CopiesIngressACME proves copyIngress clones the block's
// acme member on both Update and Get, so a stored snapshot never aliases the
// pulled one.
func TestStateSnapshot_CopiesIngressACME(t *testing.T) {
	snap := NewStateSnapshot()
	desired := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Ingress: &api.IngressConfig{
				Rules: []api.IngressRule{{ID: "r1", Slug: "api", ListenPort: 443, Mode: api.IngressModeACME, SNIHost: "api.example.com"}},
				ACME:  &api.IngressACME{DirectoryURL: "https://ca.example/dir", ContactEmail: "ops@example.com"},
			},
		},
	}
	snap.Update(desired)

	got := snap.Get()
	if diff := ComputeDiff(desired, &got); diff.BridgeChanged {
		t.Fatalf("stored ingress = %+v, want %+v", got.Bridge.Ingress, desired.Bridge.Ingress)
	}

	// Mutate the source after Update — snapshot must be unaffected.
	desired.Bridge.Ingress.ACME.DirectoryURL = "https://mutated.example/dir"
	if got2 := snap.Get(); got2.Bridge.Ingress.ACME.DirectoryURL != "https://ca.example/dir" {
		t.Error("the ingress acme member was not copied on Update")
	}

	// Mutate the returned value — snapshot must be unaffected.
	got.Bridge.Ingress.ACME.ContactEmail = "mutated@example.com"
	if got3 := snap.Get(); got3.Bridge.Ingress.ACME.ContactEmail != "ops@example.com" {
		t.Error("Get did not return a copy of the ingress acme member")
	}
}

// TestStateSnapshot_CopiesRelayAssignments proves copyRelay clones the relay
// assignments on both Update and Get, and keeps an empty list empty: a nil
// copy of the [] a pull decodes would make ComputeDiff report bridge drift on
// every pull.
func TestStateSnapshot_CopiesRelayAssignments(t *testing.T) {
	snap := NewStateSnapshot()
	desired := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Relay: &api.RelayConfig{
				Enabled:    true,
				ListenPort: 51821,
				Assignments: []api.RelayAssignment{
					{PeerNodeID: "node-1", FallbackEndpoint: "203.0.113.50", FallbackEndpointPort: 51821},
				},
			},
		},
	}
	snap.Update(desired)

	got := snap.Get()
	if diff := ComputeDiff(desired, &got); diff.BridgeChanged {
		t.Fatalf("stored relay = %+v, want %+v", got.Bridge.Relay, desired.Bridge.Relay)
	}

	// Mutate the source after Update — snapshot must be unaffected.
	desired.Bridge.Relay.Assignments[0].PeerNodeID = "mutated"
	if got2 := snap.Get(); got2.Bridge.Relay.Assignments[0].PeerNodeID == "mutated" {
		t.Error("Relay assignments were not copied on Update")
	}

	// Mutate the returned value — snapshot must be unaffected.
	got.Bridge.Relay.Assignments[0].FallbackEndpoint = "mutated"
	if got3 := snap.Get(); got3.Bridge.Relay.Assignments[0].FallbackEndpoint == "mutated" {
		t.Error("Get did not return a copy of the relay assignments")
	}

	empty := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			Relay: &api.RelayConfig{ListenPort: 51821, Assignments: []api.RelayAssignment{}},
		},
	}
	snap.Update(empty)
	got = snap.Get()
	if got.Bridge.Relay.Assignments == nil {
		t.Error("empty relay assignments were copied to nil, want an empty non-nil slice")
	}
	if diff := ComputeDiff(empty, &got); diff.BridgeChanged {
		t.Error("an unchanged relay block with no assignments reads as bridge drift")
	}
}

// TestStateSnapshot_CopiesUserAccessDevices proves copyUserAccess clones each
// provider and its devices on both Update and Get, so mutating a copied
// provider's device leaves the stored snapshot unchanged, and keeps an empty
// device list empty: a nil copy of the [] a pull decodes would make
// ComputeDiff report bridge drift on every pull.
func TestStateSnapshot_CopiesUserAccessDevices(t *testing.T) {
	snap := NewStateSnapshot()
	desired := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled: true,
				Providers: []api.UserAccessProvider{
					{
						ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1", Slug: "field-team", Kind: api.UserAccessKindWireGuard,
						ListenPort: 51821, AddressPool: "10.99.0.0/24", MaxDevices: 64,
						Devices: []api.UserAccessDevice{
							{ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0d1", Slug: "alice-laptop", PublicKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", Address: "10.99.0.2"},
						},
					},
					{ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2", Slug: "tailnet", Kind: api.UserAccessKindTailscale, AuthSecretName: "ts-join"},
				},
			},
		},
	}
	snap.Update(desired)

	got := snap.Get()
	if diff := ComputeDiff(desired, &got); diff.BridgeChanged {
		t.Fatalf("stored user access = %+v, want %+v", got.Bridge.UserAccess, desired.Bridge.UserAccess)
	}

	// Mutate the source after Update: the snapshot must be unaffected.
	desired.Bridge.UserAccess.Providers[0].Devices[0].Address = "10.99.0.9"
	desired.Bridge.UserAccess.Providers[1].AuthSecretName = "mutated"
	if got2 := snap.Get(); got2.Bridge.UserAccess.Providers[0].Devices[0].Address != "10.99.0.2" {
		t.Error("user access devices were not copied on Update")
	} else if got2.Bridge.UserAccess.Providers[1].AuthSecretName != "ts-join" {
		t.Error("user access providers were not copied on Update")
	}

	// Mutate a device of the returned copy: the snapshot must be unaffected.
	got.Bridge.UserAccess.Providers[0].Devices[0].PublicKey = "mutated"
	got.Bridge.UserAccess.Providers[0].Devices = append(got.Bridge.UserAccess.Providers[0].Devices, api.UserAccessDevice{ID: "extra"})
	got3 := snap.Get()
	if devices := got3.Bridge.UserAccess.Providers[0].Devices; len(devices) != 1 || devices[0].PublicKey != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" {
		t.Errorf("stored devices = %+v after mutating a copy, want the one device unchanged", devices)
	}

	empty := &api.NodeStateSnapshot{
		Bridge: &api.BridgeSnapshot{
			UserAccess: &api.UserAccessConfig{
				Enabled:   true,
				Providers: []api.UserAccessProvider{{ID: "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e1", Kind: api.UserAccessKindWireGuard, Devices: []api.UserAccessDevice{}}},
			},
		},
	}
	snap.Update(empty)
	got = snap.Get()
	if got.Bridge.UserAccess.Providers[0].Devices == nil {
		t.Error("an empty device list was copied to nil, want an empty non-nil slice")
	}
	if diff := ComputeDiff(empty, &got); diff.BridgeChanged {
		t.Error("an unchanged user access block with no devices reads as bridge drift")
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
