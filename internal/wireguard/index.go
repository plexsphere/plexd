package wireguard

import (
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
