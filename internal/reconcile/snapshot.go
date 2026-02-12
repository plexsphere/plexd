package reconcile

import (
	"encoding/json"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// stateSnapshot holds the last-known desired state received from the control
// plane.  All access is protected by a sync.RWMutex so concurrent goroutines
// can safely read while the reconcile loop writes.
type stateSnapshot struct {
	mu         sync.RWMutex
	peers      []api.Peer
	policies   []api.Policy
	signingKeys *api.SigningKeys
	metadata   map[string]string
	data       []api.DataEntry
	secretRefs []api.SecretRef
}

// NewStateSnapshot returns a new, empty snapshot.
func NewStateSnapshot() *stateSnapshot {
	return &stateSnapshot{}
}

// Get returns a deep copy of the current snapshot as an api.StateResponse.
func (s *stateSnapshot) Get() api.StateResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return api.StateResponse{
		Peers:       copyPeers(s.peers),
		Policies:    copyPolicies(s.policies),
		SigningKeys: copySigningKeys(s.signingKeys),
		Metadata:    copyMetadata(s.metadata),
		Data:        copyData(s.data),
		SecretRefs:  copySecretRefs(s.secretRefs),
	}
}

// Update atomically replaces the entire snapshot with the desired state.
// The snapshot stores deep copies of all fields so that later mutations of
// the source do not affect the stored state.
func (s *stateSnapshot) Update(desired *api.StateResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers = copyPeers(desired.Peers)
	s.policies = copyPolicies(desired.Policies)
	s.signingKeys = copySigningKeys(desired.SigningKeys)
	s.metadata = copyMetadata(desired.Metadata)
	s.data = copyData(desired.Data)
	s.secretRefs = copySecretRefs(desired.SecretRefs)
}

// UpdatePartial selectively updates only the categories listed.
// Recognized categories: "peers", "policies", "signing_keys", "metadata",
// "data", "secret_refs".  Unknown categories are silently ignored.
func (s *stateSnapshot) UpdatePartial(desired *api.StateResponse, categories ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, cat := range categories {
		switch cat {
		case "peers":
			s.peers = copyPeers(desired.Peers)
		case "policies":
			s.policies = copyPolicies(desired.Policies)
		case "signing_keys":
			s.signingKeys = copySigningKeys(desired.SigningKeys)
		case "metadata":
			s.metadata = copyMetadata(desired.Metadata)
		case "data":
			s.data = copyData(desired.Data)
		case "secret_refs":
			s.secretRefs = copySecretRefs(desired.SecretRefs)
		}
	}
}

// ---------------------------------------------------------------------------
// Deep-copy helpers
// ---------------------------------------------------------------------------

func copyPeers(src []api.Peer) []api.Peer {
	if src == nil {
		return nil
	}
	dst := make([]api.Peer, len(src))
	copy(dst, src)
	for i := range dst {
		if src[i].AllowedIPs != nil {
			dst[i].AllowedIPs = make([]string, len(src[i].AllowedIPs))
			copy(dst[i].AllowedIPs, src[i].AllowedIPs)
		}
	}
	return dst
}

func copyPolicies(src []api.Policy) []api.Policy {
	if src == nil {
		return nil
	}
	dst := make([]api.Policy, len(src))
	copy(dst, src)
	for i := range dst {
		if src[i].Rules != nil {
			dst[i].Rules = make([]api.PolicyRule, len(src[i].Rules))
			copy(dst[i].Rules, src[i].Rules)
		}
	}
	return dst
}

func copySigningKeys(src *api.SigningKeys) *api.SigningKeys {
	if src == nil {
		return nil
	}
	cp := *src
	if src.TransitionExpires != nil {
		t := *src.TransitionExpires
		cp.TransitionExpires = &t
	}
	return &cp
}

func copyMetadata(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyData(src []api.DataEntry) []api.DataEntry {
	if src == nil {
		return nil
	}
	dst := make([]api.DataEntry, len(src))
	copy(dst, src)
	for i := range dst {
		if src[i].Payload != nil {
			dst[i].Payload = make(json.RawMessage, len(src[i].Payload))
			copy(dst[i].Payload, src[i].Payload)
		}
	}
	return dst
}

func copySecretRefs(src []api.SecretRef) []api.SecretRef {
	if src == nil {
		return nil
	}
	dst := make([]api.SecretRef, len(src))
	copy(dst, src)
	return dst
}
