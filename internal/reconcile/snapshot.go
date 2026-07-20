package reconcile

import (
	"slices"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// stateSnapshot holds the last-known desired state received from the control
// plane.  All access is protected by a sync.RWMutex so concurrent goroutines
// can safely read while the reconcile loop writes. Reachability is the node's
// own health projection, not desired state, so it is never stored.
type stateSnapshot struct {
	mu      sync.RWMutex
	peers   []api.SnapshotPeer
	policy  *api.PolicySnapshot
	bridge  *api.BridgeSnapshot
	state   *api.NodeStateBlock
	reports *api.NodeStateBlock
}

// NewStateSnapshot returns a new, empty snapshot.
func NewStateSnapshot() *stateSnapshot {
	return &stateSnapshot{}
}

// Get returns a deep copy of the current snapshot as an api.NodeStateSnapshot.
// Reachability is not desired state, so it is always nil.
func (s *stateSnapshot) Get() api.NodeStateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return api.NodeStateSnapshot{
		Peers:   slices.Clone(s.peers),
		Policy:  copyPolicy(s.policy),
		Bridge:  copyBridge(s.bridge),
		State:   copyBlock(s.state),
		Reports: copyBlock(s.reports),
	}
}

// Update atomically replaces the entire snapshot with the desired state.
// The snapshot stores deep copies of all blocks so that later mutations of
// the source do not affect the stored state.
func (s *stateSnapshot) Update(desired *api.NodeStateSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers = slices.Clone(desired.Peers)
	s.policy = copyPolicy(desired.Policy)
	s.bridge = copyBridge(desired.Bridge)
	s.state = copyBlock(desired.State)
	s.reports = copyBlock(desired.Reports)
}

// ---------------------------------------------------------------------------
// Deep-copy helpers
// ---------------------------------------------------------------------------

func copyPolicy(src *api.PolicySnapshot) *api.PolicySnapshot {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Rules = copyRules(src.Rules)
	return &cp
}

func copyRules(src []api.PolicyRule) []api.PolicyRule {
	dst := slices.Clone(src)
	for i := range dst {
		if src[i].Ports != nil {
			pr := *src[i].Ports
			dst[i].Ports = &pr
		}
	}
	return dst
}

func copyBridge(src *api.BridgeSnapshot) *api.BridgeSnapshot {
	if src == nil {
		return nil
	}
	return &api.BridgeSnapshot{
		Relay:      copyRelay(src.Relay),
		UserAccess: copyUserAccess(src.UserAccess),
		Ingress:    copyIngress(src.Ingress),
		SiteToSite: copySiteToSite(src.SiteToSite),
	}
}

func copyRelay(src *api.RelayConfig) *api.RelayConfig {
	if src == nil {
		return nil
	}
	return &api.RelayConfig{Sessions: slices.Clone(src.Sessions)}
}

func copyUserAccess(src *api.UserAccessConfig) *api.UserAccessConfig {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Peers = slices.Clone(src.Peers)
	for i := range cp.Peers {
		cp.Peers[i].AllowedIPs = slices.Clone(src.Peers[i].AllowedIPs)
	}
	return &cp
}

func copyIngress(src *api.IngressConfig) *api.IngressConfig {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Rules = slices.Clone(src.Rules)
	return &cp
}

func copySiteToSite(src *api.SiteToSiteConfig) *api.SiteToSiteConfig {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Tunnels = slices.Clone(src.Tunnels)
	for i := range cp.Tunnels {
		cp.Tunnels[i].LocalSubnets = slices.Clone(src.Tunnels[i].LocalSubnets)
		cp.Tunnels[i].RemoteSubnets = slices.Clone(src.Tunnels[i].RemoteSubnets)
	}
	return &cp
}

func copyBlock(src *api.NodeStateBlock) *api.NodeStateBlock {
	if src == nil {
		return nil
	}
	return &api.NodeStateBlock{
		Metadata: slices.Clone(src.Metadata),
		Data:     slices.Clone(src.Data),
		Reports:  slices.Clone(src.Reports),
	}
}
