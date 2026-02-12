package reconcile

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func sampleState() *api.StateResponse {
	expires := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	return &api.StateResponse{
		Peers: []api.Peer{
			{
				ID:         "node-1",
				PublicKey:  "pk-1",
				MeshIP:     "10.0.0.1",
				Endpoint:   "1.2.3.4:51820",
				AllowedIPs: []string{"10.0.0.1/32", "10.0.0.2/32"},
				PSK:        "psk-1",
			},
		},
		Policies: []api.Policy{
			{
				ID: "pol-1",
				Rules: []api.PolicyRule{
					{Src: "10.0.0.0/24", Dst: "10.0.0.0/24", Port: 443, Protocol: "tcp", Action: "allow"},
				},
			},
		},
		SigningKeys: &api.SigningKeys{
			Current:           "key-current",
			Previous:          "key-previous",
			TransitionExpires: &expires,
		},
		Metadata: map[string]string{
			"env":    "prod",
			"region": "us-east-1",
		},
		Data: []api.DataEntry{
			{
				Key:         "config.yaml",
				ContentType: "application/yaml",
				Payload:     json.RawMessage(`{"foo":"bar"}`),
				Version:     1,
				UpdatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		SecretRefs: []api.SecretRef{
			{Key: "db-password", Version: 3},
		},
	}
}

func TestStateSnapshot_InitiallyEmpty(t *testing.T) {
	snap := NewStateSnapshot()
	got := snap.Get()

	if got.Peers != nil {
		t.Errorf("expected nil Peers, got %v", got.Peers)
	}
	if got.Policies != nil {
		t.Errorf("expected nil Policies, got %v", got.Policies)
	}
	if got.SigningKeys != nil {
		t.Errorf("expected nil SigningKeys, got %v", got.SigningKeys)
	}
	if got.Metadata != nil {
		t.Errorf("expected nil Metadata, got %v", got.Metadata)
	}
	if got.Data != nil {
		t.Errorf("expected nil Data, got %v", got.Data)
	}
	if got.SecretRefs != nil {
		t.Errorf("expected nil SecretRefs, got %v", got.SecretRefs)
	}
}

func TestStateSnapshot_Update(t *testing.T) {
	snap := NewStateSnapshot()
	desired := sampleState()
	snap.Update(desired)

	got := snap.Get()

	if len(got.Peers) != 1 || got.Peers[0].ID != "node-1" {
		t.Fatalf("Peers mismatch: %+v", got.Peers)
	}
	if len(got.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs mismatch: %+v", got.Peers[0].AllowedIPs)
	}
	if len(got.Policies) != 1 || got.Policies[0].ID != "pol-1" {
		t.Fatalf("Policies mismatch: %+v", got.Policies)
	}
	if len(got.Policies[0].Rules) != 1 {
		t.Fatalf("Rules mismatch: %+v", got.Policies[0].Rules)
	}
	if got.SigningKeys == nil || got.SigningKeys.Current != "key-current" {
		t.Fatalf("SigningKeys mismatch: %+v", got.SigningKeys)
	}
	if got.SigningKeys.TransitionExpires == nil {
		t.Fatal("TransitionExpires should not be nil")
	}
	if got.Metadata["env"] != "prod" {
		t.Fatalf("Metadata mismatch: %+v", got.Metadata)
	}
	if len(got.Data) != 1 || got.Data[0].Key != "config.yaml" {
		t.Fatalf("Data mismatch: %+v", got.Data)
	}
	if string(got.Data[0].Payload) != `{"foo":"bar"}` {
		t.Fatalf("Payload mismatch: %s", got.Data[0].Payload)
	}
	if len(got.SecretRefs) != 1 || got.SecretRefs[0].Key != "db-password" {
		t.Fatalf("SecretRefs mismatch: %+v", got.SecretRefs)
	}
}

func TestStateSnapshot_UpdateCopiesData(t *testing.T) {
	snap := NewStateSnapshot()
	desired := sampleState()
	snap.Update(desired)

	// Mutate the source after Update — snapshot must be unaffected.
	desired.Peers[0].ID = "mutated"
	desired.Peers[0].AllowedIPs[0] = "mutated"
	desired.Policies[0].Rules[0].Action = "deny"
	desired.Metadata["env"] = "staging"
	desired.Data[0].Payload = json.RawMessage(`{"mutated":true}`)
	desired.SecretRefs[0].Key = "mutated"
	desired.SigningKeys.Current = "mutated"

	got := snap.Get()

	if got.Peers[0].ID == "mutated" {
		t.Error("Peers were not copied on Update")
	}
	if got.Peers[0].AllowedIPs[0] == "mutated" {
		t.Error("AllowedIPs were not copied on Update")
	}
	if got.Policies[0].Rules[0].Action == "deny" {
		t.Error("Policy rules were not copied on Update")
	}
	if got.Metadata["env"] == "staging" {
		t.Error("Metadata was not copied on Update")
	}
	if string(got.Data[0].Payload) == `{"mutated":true}` {
		t.Error("Data payload was not copied on Update")
	}
	if got.SecretRefs[0].Key == "mutated" {
		t.Error("SecretRefs were not copied on Update")
	}
	if got.SigningKeys.Current == "mutated" {
		t.Error("SigningKeys were not copied on Update")
	}
}

func TestStateSnapshot_GetReturnsCopy(t *testing.T) {
	snap := NewStateSnapshot()
	snap.Update(sampleState())

	got := snap.Get()

	// Mutate the returned value — snapshot must be unaffected.
	got.Peers[0].ID = "mutated"
	got.Peers[0].AllowedIPs[0] = "mutated"
	got.Policies[0].Rules[0].Action = "deny"
	got.Metadata["env"] = "staging"
	got.Data[0].Payload = json.RawMessage(`{"mutated":true}`)
	got.SecretRefs[0].Key = "mutated"
	got.SigningKeys.Current = "mutated"

	got2 := snap.Get()

	if got2.Peers[0].ID == "mutated" {
		t.Error("Get did not return a copy of Peers")
	}
	if got2.Peers[0].AllowedIPs[0] == "mutated" {
		t.Error("Get did not return a copy of AllowedIPs")
	}
	if got2.Policies[0].Rules[0].Action == "deny" {
		t.Error("Get did not return a copy of Policy rules")
	}
	if got2.Metadata["env"] == "staging" {
		t.Error("Get did not return a copy of Metadata")
	}
	if string(got2.Data[0].Payload) == `{"mutated":true}` {
		t.Error("Get did not return a copy of Data payload")
	}
	if got2.SecretRefs[0].Key == "mutated" {
		t.Error("Get did not return a copy of SecretRefs")
	}
	if got2.SigningKeys.Current == "mutated" {
		t.Error("Get did not return a copy of SigningKeys")
	}
}

func TestStateSnapshot_UpdatePartial(t *testing.T) {
	snap := NewStateSnapshot()
	snap.Update(sampleState())

	// Partially update only peers and metadata.
	partial := &api.StateResponse{
		Peers: []api.Peer{
			{ID: "node-2", PublicKey: "pk-2", MeshIP: "10.0.0.2"},
		},
		Metadata: map[string]string{"env": "staging"},
	}
	snap.UpdatePartial(partial, "peers", "metadata")

	got := snap.Get()

	// Peers and metadata should reflect the partial update.
	if len(got.Peers) != 1 || got.Peers[0].ID != "node-2" {
		t.Fatalf("Peers should have been updated: %+v", got.Peers)
	}
	if got.Metadata["env"] != "staging" {
		t.Fatalf("Metadata should have been updated: %+v", got.Metadata)
	}

	// Other categories should remain unchanged.
	if len(got.Policies) != 1 || got.Policies[0].ID != "pol-1" {
		t.Fatalf("Policies should be unchanged: %+v", got.Policies)
	}
	if got.SigningKeys == nil || got.SigningKeys.Current != "key-current" {
		t.Fatalf("SigningKeys should be unchanged: %+v", got.SigningKeys)
	}
	if len(got.Data) != 1 || got.Data[0].Key != "config.yaml" {
		t.Fatalf("Data should be unchanged: %+v", got.Data)
	}
	if len(got.SecretRefs) != 1 || got.SecretRefs[0].Key != "db-password" {
		t.Fatalf("SecretRefs should be unchanged: %+v", got.SecretRefs)
	}
}

func TestStateSnapshot_ConcurrentAccess(t *testing.T) {
	snap := NewStateSnapshot()
	desired := sampleState()
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
					// Writer
					snap.Update(desired)
				} else {
					// Reader
					got := snap.Get()
					_ = got.Peers
				}
			}
		}(g)
	}

	wg.Wait()
}
