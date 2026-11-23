package reconcile

import (
	"slices"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// stateSnapshot holds the last-known desired state received from the control
// plane: the peers, policy, bridge, state, reports and shared_subnets blocks,
// the ones ComputeDiff compares. No other block is stored. All access is
// protected by a sync.RWMutex so concurrent goroutines can safely read while
// the reconcile loop writes. Reachability is the node's own health projection,
// not desired state, so it is never stored. Neither is the signing key: a
// dispatch handler installs it on every pull, and there is nothing for the
// differ to converge on. Nor is the secret inventory: the node API's dispatch
// handler hands it to the secret index on every pull. Nor are the mesh DNS
// names of the dns block: the mesh resolver's dispatch handler takes them on
// every pull. Nor is the failure-detection time: the WireGuard manager's
// dispatch handler takes it on every pull. Nor are the executions, sessions
// and hooks blocks: their dispatch handlers take them on every pull.
type stateSnapshot struct {
	mu            sync.RWMutex
	peers         []api.SnapshotPeer
	policy        *api.PolicySnapshot
	bridge        *api.BridgeSnapshot
	state         *api.NodeStateBlock
	reports       *api.NodeStateBlock
	sharedSubnets []api.NodeStateSharedSubnet
}

// NewStateSnapshot returns a new, empty snapshot.
func NewStateSnapshot() *stateSnapshot {
	return &stateSnapshot{}
}

// Get returns a deep copy of the current snapshot as an api.NodeStateSnapshot.
// It carries the stored Peers, Policy, Bridge, State, Reports and
// SharedSubnets; every other block is not stored, so it is always nil.
func (s *stateSnapshot) Get() api.NodeStateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return api.NodeStateSnapshot{
		Peers:         copyPeers(s.peers),
		Policy:        copyPolicy(s.policy),
		Bridge:        copyBridge(s.bridge),
		State:         copyBlock(s.state),
		Reports:       copyBlock(s.reports),
		SharedSubnets: copySharedSubnets(s.sharedSubnets),
	}
}

// Update atomically replaces the entire snapshot with the desired state.
// The snapshot stores deep copies of all blocks so that later mutations of
// the source do not affect the stored state.
func (s *stateSnapshot) Update(desired *api.NodeStateSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers = copyPeers(desired.Peers)
	s.policy = copyPolicy(desired.Policy)
	s.bridge = copyBridge(desired.Bridge)
	s.state = copyBlock(desired.State)
	s.reports = copyBlock(desired.Reports)
	s.sharedSubnets = copySharedSubnets(desired.SharedSubnets)
}

// ---------------------------------------------------------------------------
// Deep-copy helpers
// ---------------------------------------------------------------------------

func copyPeers(src []api.SnapshotPeer) []api.SnapshotPeer {
	dst := slices.Clone(src)
	for i := range dst {
		dst[i].FallbackEndpoints = slices.Clone(src[i].FallbackEndpoints)
		dst[i].EndpointCandidates = slices.Clone(src[i].EndpointCandidates)
		dst[i].RoutedSubnets = slices.Clone(src[i].RoutedSubnets)
	}
	return dst
}

func copySharedSubnets(src []api.NodeStateSharedSubnet) []api.NodeStateSharedSubnet {
	dst := slices.Clone(src)
	for i := range dst {
		dst[i].Bridges = slices.Clone(src[i].Bridges)
	}
	return dst
}

func copyPolicy(src *api.PolicySnapshot) *api.PolicySnapshot {
	return src.Clone()
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
	cp := *src
	cp.Assignments = slices.Clone(src.Assignments)
	return &cp
}

func copyUserAccess(src *api.UserAccessConfig) *api.UserAccessConfig {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Providers = slices.Clone(src.Providers)
	for i := range cp.Providers {
		cp.Providers[i].Devices = slices.Clone(src.Providers[i].Devices)
	}
	return &cp
}

func copyIngress(src *api.IngressConfig) *api.IngressConfig {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Rules = slices.Clone(src.Rules)
	for i, r := range cp.Rules {
		if r.ClientAuth != nil {
			ca := *r.ClientAuth
			cp.Rules[i].ClientAuth = &ca
		}
	}
	if src.ACME != nil {
		acme := *src.ACME
		cp.ACME = &acme
	}
	return &cp
}

func copySiteToSite(src *api.SiteToSiteConfig) *api.SiteToSiteConfig {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Tunnels = slices.Clone(src.Tunnels)
	for i := range cp.Tunnels {
		cp.Tunnels[i].AllowedSubnets = slices.Clone(src.Tunnels[i].AllowedSubnets)
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
