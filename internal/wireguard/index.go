package wireguard

import (
	"encoding/base64"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// PeerIndex maintains a thread-safe mapping from peer IDs to base64-encoded
// public keys. This bridges the gap between the control plane (which uses
// peer IDs) and WireGuard (which uses public keys).
type PeerIndex struct {
	mu    sync.RWMutex
	index map[string]string // peerID → base64 public key
}

// NewPeerIndex creates an empty PeerIndex.
func NewPeerIndex() *PeerIndex {
	return &PeerIndex{
		index: make(map[string]string),
	}
}

// Add adds or overwrites the mapping from peerID to publicKey.
func (p *PeerIndex) Add(peerID, publicKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.index[peerID] = publicKey
}

// Remove removes the mapping for peerID. It is a no-op if peerID is not present.
func (p *PeerIndex) Remove(peerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.index, peerID)
}

// Lookup returns the public key for the given peerID and whether it was found.
func (p *PeerIndex) Lookup(peerID string) (publicKey string, ok bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	publicKey, ok = p.index[peerID]
	return
}

// Update updates the mapping from peerID to newPublicKey.
// It is equivalent to Add but semantically distinct for clarity.
func (p *PeerIndex) Update(peerID, newPublicKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.index[peerID] = newPublicKey
}

// LoadFromPeers bulk-populates the index from a slice of api.Peer.
// It clears all existing entries before adding the new ones.
func (p *PeerIndex) LoadFromPeers(peers []api.Peer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.index = make(map[string]string, len(peers))
	for _, peer := range peers {
		p.index[peer.ID] = peer.PublicKey
	}
}

// NodeIDsByPublicKey returns the reverse mapping, from each stored public
// key's raw bytes to its peer ID. It is what turns a device read, which knows
// peers only by key, back into the control plane's node IDs.
//
// A stored key that is not valid base64 or does not decode to 32 bytes is
// skipped, because no device peer can carry it. A key two peer IDs share is
// left out: the device holds a single peer for it, and attributing that peer's
// state to either ID would report an edge no single node owns.
func (p *PeerIndex) NodeIDsByPublicKey() map[[32]byte]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	byKey := make(map[[32]byte]string, len(p.index))
	shared := make(map[[32]byte]bool)
	for peerID, publicKey := range p.index {
		raw, err := base64.StdEncoding.DecodeString(publicKey)
		if err != nil || len(raw) != 32 {
			continue
		}
		key := [32]byte(raw)
		if shared[key] {
			continue
		}
		if _, dup := byKey[key]; dup {
			delete(byKey, key)
			shared[key] = true
			continue
		}
		byKey[key] = peerID
	}
	return byKey
}

// Count returns the number of peers in the index.
func (p *PeerIndex) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.index)
}
