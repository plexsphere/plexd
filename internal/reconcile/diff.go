package reconcile

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/plexsphere/plexd/internal/api"
)

// StateDiff describes the drift between a desired NodeStateSnapshot (from the
// control plane) and the current locally-observed snapshot. The four block
// flags are presence-aware: a nil block and a populated block are distinct, so
// null on the wire ("not populated") drives convergence rather than a no-op.
type StateDiff struct {
	PeersToAdd    []api.SnapshotPeer
	PeersToRemove []string          // node IDs
	PeersToUpdate []api.SnapshotPeer // peers with changed fields

	PolicyChanged  bool
	BridgeChanged  bool
	StateChanged   bool
	ReportsChanged bool
}

// IsEmpty reports whether there is no drift at all.
func (d StateDiff) IsEmpty() bool {
	return len(d.PeersToAdd) == 0 &&
		len(d.PeersToRemove) == 0 &&
		len(d.PeersToUpdate) == 0 &&
		!d.PolicyChanged &&
		!d.BridgeChanged &&
		!d.StateChanged &&
		!d.ReportsChanged
}

// Summary returns a compact human-readable description of the diff for the
// cycle log, e.g. "peers+1-0~2 policy bridge state reports". Only changed parts
// are mentioned; an empty diff returns "none".
func (d StateDiff) Summary() string {
	if d.IsEmpty() {
		return "none"
	}
	var parts []string
	if len(d.PeersToAdd) > 0 || len(d.PeersToRemove) > 0 || len(d.PeersToUpdate) > 0 {
		parts = append(parts, fmt.Sprintf("peers+%d-%d~%d",
			len(d.PeersToAdd), len(d.PeersToRemove), len(d.PeersToUpdate)))
	}
	if d.PolicyChanged {
		parts = append(parts, "policy")
	}
	if d.BridgeChanged {
		parts = append(parts, "bridge")
	}
	if d.StateChanged {
		parts = append(parts, "state")
	}
	if d.ReportsChanged {
		parts = append(parts, "reports")
	}
	return strings.Join(parts, " ")
}

// ComputeDiff compares the desired snapshot from the control plane against the
// current local snapshot and returns a StateDiff describing what has changed.
func ComputeDiff(desired, current *api.NodeStateSnapshot) StateDiff {
	var diff StateDiff

	if desired == nil {
		return diff
	}

	cur := current
	if cur == nil {
		cur = &api.NodeStateSnapshot{}
	}

	diffPeers(desired.Peers, cur.Peers, &diff)
	diff.PolicyChanged = diffPolicy(desired.Policy, cur.Policy)
	// reflect.DeepEqual on the block pointers is already presence-aware: two
	// nils are equal, a nil and a populated block are not, and two populated
	// blocks compare by value.
	diff.BridgeChanged = !reflect.DeepEqual(desired.Bridge, cur.Bridge)
	diff.StateChanged = !reflect.DeepEqual(desired.State, cur.State)
	diff.ReportsChanged = !reflect.DeepEqual(desired.Reports, cur.Reports)

	return diff
}

func diffPeers(desired, current []api.SnapshotPeer, diff *StateDiff) {
	currentByID := make(map[string]api.SnapshotPeer, len(current))
	for _, p := range current {
		currentByID[p.NodeID] = p
	}

	desiredByID := make(map[string]struct{}, len(desired))
	for _, dp := range desired {
		desiredByID[dp.NodeID] = struct{}{}
		cp, exists := currentByID[dp.NodeID]
		if !exists {
			diff.PeersToAdd = append(diff.PeersToAdd, dp)
			continue
		}
		if peerChanged(dp, cp) {
			diff.PeersToUpdate = append(diff.PeersToUpdate, dp)
		}
	}

	for _, cp := range current {
		if _, exists := desiredByID[cp.NodeID]; !exists {
			diff.PeersToRemove = append(diff.PeersToRemove, cp.NodeID)
		}
	}
}

func peerChanged(desired, current api.SnapshotPeer) bool {
	return desired.MeshIP != current.MeshIP ||
		desired.PublicKey != current.PublicKey ||
		desired.FallbackEndpoint != current.FallbackEndpoint
}

// diffPolicy is presence-aware. When both blocks are populated it compares ONLY
// the Fingerprint byte-for-byte: revision-only bumps and rule-array differences
// with equal fingerprints are NOT changes. The fingerprint is an opaque
// comparison key and is never re-derived from the rules.
func diffPolicy(desired, current *api.PolicySnapshot) bool {
	if desired == nil && current == nil {
		return false
	}
	if desired == nil || current == nil {
		return true
	}
	// An empty fingerprint is not a usable comparison key. If the control plane
	// omits it, "" == "" would read as "no change" forever and freeze the
	// firewall at the first applied revision. Treat a missing desired
	// fingerprint as always-changed so the ruleset keeps reconciling.
	if desired.Fingerprint == "" {
		return true
	}
	return desired.Fingerprint != current.Fingerprint
}
