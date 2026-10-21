package wireguard

import (
	"bytes"
	"encoding/base64"
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

// testKey returns a 32-byte key filled with b and its base64 form, the shape
// the control plane hands the index.
func testKey(b byte) ([32]byte, string) {
	raw := bytes.Repeat([]byte{b}, 32)
	return [32]byte(raw), base64.StdEncoding.EncodeToString(raw)
}

func TestPeerIndex_NodeIDsByPublicKey_Empty(t *testing.T) {
	idx := NewPeerIndex()

	got := idx.NodeIDsByPublicKey()
	if got == nil || len(got) != 0 {
		t.Errorf("NodeIDsByPublicKey() = %#v, want an empty map", got)
	}
}

func TestPeerIndex_NodeIDsByPublicKey_MapsDecodedKeys(t *testing.T) {
	keyA, b64A := testKey(0x0a)
	keyB, b64B := testKey(0x0b)
	idx := NewPeerIndex()
	idx.Add("peer-a", b64A)
	idx.Add("peer-b", b64B)

	got := idx.NodeIDsByPublicKey()
	if len(got) != 2 {
		t.Fatalf("NodeIDsByPublicKey() has %d entries, want 2: %v", len(got), got)
	}
	if got[keyA] != "peer-a" {
		t.Errorf("NodeIDsByPublicKey()[keyA] = %q, want %q", got[keyA], "peer-a")
	}
	if got[keyB] != "peer-b" {
		t.Errorf("NodeIDsByPublicKey()[keyB] = %q, want %q", got[keyB], "peer-b")
	}
}

func TestPeerIndex_NodeIDsByPublicKey_SkipsUndecodable(t *testing.T) {
	keyA, b64A := testKey(0x0a)
	idx := NewPeerIndex()
	idx.Add("peer-a", b64A)
	idx.Add("not-base64", "not base64!")
	idx.Add("short", base64.StdEncoding.EncodeToString(make([]byte, 31)))

	got := idx.NodeIDsByPublicKey()
	if len(got) != 1 || got[keyA] != "peer-a" {
		t.Errorf("NodeIDsByPublicKey() = %v, want only peer-a", got)
	}
}

func TestPeerIndex_NodeIDsByPublicKey_SharedKeyLeftOut(t *testing.T) {
	keyA, b64A := testKey(0x0a)
	shared, b64Shared := testKey(0x0c)
	idx := NewPeerIndex()
	idx.Add("peer-a", b64A)
	// Three holders, so a third ID cannot claim the key once the second
	// removed it.
	idx.Add("peer-x", b64Shared)
	idx.Add("peer-y", b64Shared)
	idx.Add("peer-z", b64Shared)

	got := idx.NodeIDsByPublicKey()
	if id, ok := got[shared]; ok {
		t.Errorf("NodeIDsByPublicKey()[shared] = %q, want the shared key left out", id)
	}
	if len(got) != 1 || got[keyA] != "peer-a" {
		t.Errorf("NodeIDsByPublicKey() = %v, want only peer-a", got)
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
