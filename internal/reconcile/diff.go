package reconcile

import (
	"maps"
	"sort"

	"github.com/plexsphere/plexd/internal/api"
)

// StateDiff describes the drift between a desired state (from the control
// plane) and the current locally-observed state.
type StateDiff struct {
	PeersToAdd    []api.Peer
	PeersToRemove []string   // peer IDs
	PeersToUpdate []api.Peer // peers with changed fields

	PoliciesToAdd    []api.Policy
	PoliciesToRemove []string // policy IDs

	SigningKeysChanged bool
	NewSigningKeys     *api.SigningKeys

	MetadataChanged   bool
	DataChanged       bool
	SecretRefsChanged bool
}

// IsEmpty reports whether there is no drift at all.
func (d StateDiff) IsEmpty() bool {
	return len(d.PeersToAdd) == 0 &&
		len(d.PeersToRemove) == 0 &&
		len(d.PeersToUpdate) == 0 &&
		len(d.PoliciesToAdd) == 0 &&
		len(d.PoliciesToRemove) == 0 &&
		!d.SigningKeysChanged &&
		!d.MetadataChanged &&
		!d.DataChanged &&
		!d.SecretRefsChanged
}

// ComputeDiff compares the desired state from the control plane against the
// current local snapshot and returns a StateDiff describing what has changed.
func ComputeDiff(desired *api.StateResponse, current *api.StateResponse) StateDiff {
	var diff StateDiff

	if desired == nil {
		return diff
	}

	cur := current
	if cur == nil {
		cur = &api.StateResponse{}
	}

	diffPeers(desired.Peers, cur.Peers, &diff)
	diffPolicies(desired.Policies, cur.Policies, &diff)
	diffSigningKeys(desired.SigningKeys, cur.SigningKeys, &diff)
	diffMetadata(desired.Metadata, cur.Metadata, &diff)
	diffData(desired.Data, cur.Data, &diff)
	diffSecretRefs(desired.SecretRefs, cur.SecretRefs, &diff)

	return diff
}

func diffPeers(desired, current []api.Peer, diff *StateDiff) {
	currentByID := make(map[string]api.Peer, len(current))
	for _, p := range current {
		currentByID[p.ID] = p
	}

	desiredByID := make(map[string]struct{}, len(desired))
	for _, dp := range desired {
		desiredByID[dp.ID] = struct{}{}
		cp, exists := currentByID[dp.ID]
		if !exists {
			diff.PeersToAdd = append(diff.PeersToAdd, dp)
			continue
		}
		if peerChanged(dp, cp) {
			diff.PeersToUpdate = append(diff.PeersToUpdate, dp)
		}
	}

	for _, cp := range current {
		if _, exists := desiredByID[cp.ID]; !exists {
			diff.PeersToRemove = append(diff.PeersToRemove, cp.ID)
		}
	}
}

func peerChanged(desired, current api.Peer) bool {
	if desired.PublicKey != current.PublicKey ||
		desired.MeshIP != current.MeshIP ||
		desired.Endpoint != current.Endpoint ||
		desired.PSK != current.PSK {
		return true
	}
	return !sortedStringsEqual(desired.AllowedIPs, current.AllowedIPs)
}

// sortedStringsEqual compares two string slices after sorting copies.
func sortedStringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := make([]string, len(a))
	copy(sa, a)
	sort.Strings(sa)

	sb := make([]string, len(b))
	copy(sb, b)
	sort.Strings(sb)

	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func diffPolicies(desired, current []api.Policy, diff *StateDiff) {
	currentByID := make(map[string]struct{}, len(current))
	for _, p := range current {
		currentByID[p.ID] = struct{}{}
	}

	desiredByID := make(map[string]struct{}, len(desired))
	for _, dp := range desired {
		desiredByID[dp.ID] = struct{}{}
		if _, exists := currentByID[dp.ID]; !exists {
			diff.PoliciesToAdd = append(diff.PoliciesToAdd, dp)
		}
	}

	for _, cp := range current {
		if _, exists := desiredByID[cp.ID]; !exists {
			diff.PoliciesToRemove = append(diff.PoliciesToRemove, cp.ID)
		}
	}
}

func diffSigningKeys(desired, current *api.SigningKeys, diff *StateDiff) {
	if desired == nil && current == nil {
		return
	}
	if desired == nil || current == nil {
		diff.SigningKeysChanged = true
		diff.NewSigningKeys = desired
		return
	}
	if desired.Current != current.Current || desired.Previous != current.Previous {
		diff.SigningKeysChanged = true
		diff.NewSigningKeys = desired
	}
}

func diffMetadata(desired, current map[string]string, diff *StateDiff) {
	if !maps.Equal(desired, current) {
		diff.MetadataChanged = true
	}
}

func diffData(desired, current []api.DataEntry, diff *StateDiff) {
	type kv struct{ version int }
	currentMap := make(map[string]kv, len(current))
	for _, e := range current {
		currentMap[e.Key] = kv{version: e.Version}
	}

	desiredMap := make(map[string]kv, len(desired))
	for _, e := range desired {
		desiredMap[e.Key] = kv{version: e.Version}
	}

	for k, dv := range desiredMap {
		cv, ok := currentMap[k]
		if !ok || dv.version != cv.version {
			diff.DataChanged = true
			return
		}
	}
	for k := range currentMap {
		if _, ok := desiredMap[k]; !ok {
			diff.DataChanged = true
			return
		}
	}
}

func diffSecretRefs(desired, current []api.SecretRef, diff *StateDiff) {
	currentMap := make(map[string]int, len(current))
	for _, s := range current {
		currentMap[s.Key] = s.Version
	}

	desiredMap := make(map[string]int, len(desired))
	for _, s := range desired {
		desiredMap[s.Key] = s.Version
	}

	for k, dv := range desiredMap {
		cv, ok := currentMap[k]
		if !ok || dv != cv {
			diff.SecretRefsChanged = true
			return
		}
	}
	for k := range currentMap {
		if _, ok := desiredMap[k]; !ok {
			diff.SecretRefsChanged = true
			return
		}
	}
}
