package wireguard

import (
	"fmt"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

func TestPeerIndex_AddAndLookup(t *testing.T) {
	idx := NewPeerIndex()
	idx.Add("peer-1", "pubkey-abc")

	key, ok := idx.Lookup("peer-1")
	if !ok {
		t.Fatal("Lookup(peer-1) returned ok=false, want true")
	}
	if key != "pubkey-abc" {
		t.Errorf("Lookup(peer-1) = %q, want %q", key, "pubkey-abc")
	}
}

func TestPeerIndex_LookupUnknown(t *testing.T) {
	idx := NewPeerIndex()

	key, ok := idx.Lookup("no-such-peer")
	if ok {
		t.Error("Lookup(no-such-peer) returned ok=true, want false")
	}
	if key != "" {
		t.Errorf("Lookup(no-such-peer) = %q, want %q", key, "")
	}
}

func TestPeerIndex_Remove(t *testing.T) {
	idx := NewPeerIndex()
	idx.Add("peer-1", "pubkey-abc")
	idx.Remove("peer-1")

	_, ok := idx.Lookup("peer-1")
	if ok {
		t.Error("Lookup(peer-1) after Remove returned ok=true, want false")
	}
}

func TestPeerIndex_RemoveUnknown(t *testing.T) {
	idx := NewPeerIndex()
	// Must not panic.
	idx.Remove("no-such-peer")
}

func TestPeerIndex_UpdateKey(t *testing.T) {
	idx := NewPeerIndex()
	idx.Add("peer-1", "key1")
	idx.Update("peer-1", "key2")

	key, ok := idx.Lookup("peer-1")
	if !ok {
		t.Fatal("Lookup(peer-1) returned ok=false, want true")
	}
	if key != "key2" {
		t.Errorf("Lookup(peer-1) = %q, want %q", key, "key2")
	}
}

func TestPeerIndex_LoadFromPeers(t *testing.T) {
	idx := NewPeerIndex()

	// Add an entry that should be cleared by LoadFromPeers.
	idx.Add("old-peer", "old-key")

	peers := []api.Peer{
		{ID: "p1", PublicKey: "pk1"},
		{ID: "p2", PublicKey: "pk2"},
		{ID: "p3", PublicKey: "pk3"},
	}
	idx.LoadFromPeers(peers)

	// Verify old entry was cleared.
	if _, ok := idx.Lookup("old-peer"); ok {
		t.Error("Lookup(old-peer) after LoadFromPeers returned ok=true, want false")
	}

	// Verify all new entries are present.
	for _, p := range peers {
		key, ok := idx.Lookup(p.ID)
		if !ok {
			t.Errorf("Lookup(%s) returned ok=false, want true", p.ID)
			continue
		}
		if key != p.PublicKey {
			t.Errorf("Lookup(%s) = %q, want %q", p.ID, key, p.PublicKey)
		}
	}
}

func TestPeerIndex_ConcurrentAccess(t *testing.T) {
	idx := NewPeerIndex()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		id := fmt.Sprintf("peer-%d", i)
		key := fmt.Sprintf("key-%d", i)
		go func() {
			defer wg.Done()
			idx.Add(id, key)
		}()
		go func() {
			defer wg.Done()
			idx.Lookup(id)
		}()
		go func() {
			defer wg.Done()
			idx.Remove(id)
		}()
	}
	wg.Wait()
}
