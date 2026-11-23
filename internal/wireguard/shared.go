package wireguard

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// routedSubnetNoBridge: the shared_subnets entry names no bridge that is the
// node_id of a peer of the same pull. Only setSharedSubnets gives it, for an
// entry whose subnet passed the rules of usableRoutedSubnets.
const routedSubnetNoBridge = "no_bridge"

// sharedSubnet is one shared subnet, a subnet an accepted entry of the pull's
// shared_subnets block names. Its bridges are the entry's node IDs that name
// a peer of the pull. The holder is the one bridge whose allowed IPs carry
// the subnet; the device gives an equal prefix to one peer only, so every
// other bridge of the entry is a standby.
type sharedSubnet struct {
	bridges []string  // node IDs in the pull's order
	holder  string    // the bridge whose allowed IPs carry the subnet
	since   time.Time // when holder last changed
}

// setSharedSubnets replaces the shared subnets m holds with the accepted
// entries of entries, the shared_subnets block of a pull whose peers are
// peers, and picks the holder of each. It writes nothing to the device: the
// reconcile handler's updates and adds, which take each peer's routed subnets
// from routedSubnets, and then syncSharedSubnets write the peers whose routed
// subnets the holders change. mesh and local are the prefixes the handler
// read for the run.
//
// The entries are taken in their order, and an entry is skipped by the first
// rule that applies, which logs wireguard: shared subnet not programmed at
// Warn with the subnet as the pull carried it and the reason:
//   - invalid, overlaps_mesh, inside_local_network or duplicate: the subnet
//     fails that rule of usableRoutedSubnets, which checks the subnets of
//     entries as one list. An entry that passes them and is then skipped for
//     no_bridge still makes a later entry of its subnet a duplicate.
//   - no_bridge: no bridge is left once the bridges that are the node_id of
//     no peer of peers, and those that repeat an earlier one, are dropped.
//
// Of the bridges left, the first MaxSharedSubnetBridges are kept. The cap
// counts after the drops, so an unknown or repeated ID does not cost a usable
// standby. A skipped entry is no shared subnet: its subnet stays on the peers
// whose routed_subnets list it.
//
// The holder of an accepted entry is, by the first rule that applies:
//  1. the holder m records for the subnet, when the entry's bridges still
//     list it;
//  2. the first of the entry's bridges whose peer, as last written, carries
//     the subnet among its routed subnets: the bridge that had it through its
//     routed_subnets;
//  3. the first bridge.
//
// A subnet m did not hold logs wireguard: shared subnet assigned at Info with
// the holder as bridge and the number of bridges kept. A recorded holder that
// rule 2 or 3 replaces logs wireguard: shared subnet moved at Info with from,
// to and reason=pull. A subnet m held that no accepted entry names any more
// logs wireguard: shared subnet released at Info with its last holder as
// bridge, after the entries and in the string order of the CIDRs. since is
// the time of the call for a new subnet and a new holder; a kept holder
// keeps it and logs nothing. A subnet m held keeps its record, which the
// call updates in place.
func (m *Manager) setSharedSubnets(entries []api.NodeStateSharedSubnet, peers []api.SnapshotPeer, mesh netip.Prefix, local []netip.Prefix) {
	known := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		known[p.NodeID] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	next := make(map[string]*sharedSubnet, len(entries))
	seen := make(map[netip.Prefix]struct{}, len(entries))
	for _, e := range entries {
		prefix, reason := checkRoutedSubnet(e.Subnet, mesh, local, seen)
		var bridges []string
		if reason == "" {
			if bridges = sharedBridges(e.Bridges, known); len(bridges) == 0 {
				reason = routedSubnetNoBridge
			}
		}
		if reason != "" {
			m.logger.Warn("wireguard: shared subnet not programmed",
				"component", "wireguard",
				"subnet", e.Subnet,
				"reason", reason,
			)
			continue
		}

		subnet := prefix.String()
		s, held := m.shared[subnet]
		holder := m.sharedHolderLocked(subnet, bridges, s)
		switch {
		case !held:
			s = &sharedSubnet{holder: holder, since: now}
			m.logger.Info("wireguard: shared subnet assigned",
				"component", "wireguard",
				"subnet", subnet,
				"bridge", holder,
				"bridges", len(bridges),
			)
		case holder != s.holder:
			m.logger.Info("wireguard: shared subnet moved",
				"component", "wireguard",
				"subnet", subnet,
				"from", s.holder,
				"to", holder,
				"reason", "pull",
			)
			s.holder, s.since = holder, now
		}
		s.bridges = bridges
		next[subnet] = s
	}

	for _, subnet := range slices.Sorted(maps.Keys(m.shared)) {
		if _, kept := next[subnet]; kept {
			continue
		}
		m.logger.Info("wireguard: shared subnet released",
			"component", "wireguard",
			"subnet", subnet,
			"bridge", m.shared[subnet].holder,
		)
	}
	m.shared = next
}

// sharedBridges returns the bridges of a shared_subnets entry that are kept:
// ids in their order without those known does not hold and without repeats,
// at most api.MaxSharedSubnetBridges, and nil when none is left.
func sharedBridges(ids []string, known map[string]struct{}) []string {
	var kept []string
	for _, id := range ids {
		if len(kept) == api.MaxSharedSubnetBridges {
			break
		}
		if _, ok := known[id]; !ok || slices.Contains(kept, id) {
			continue
		}
		kept = append(kept, id)
	}
	return kept
}

// sharedHolderLocked picks the holder of subnet, a canonical CIDR, among
// bridges, by the rules setSharedSubnets lists. s is what m records for the
// subnet, nil for a new one. Callers hold m.mu and pass at least one bridge.
func (m *Manager) sharedHolderLocked(subnet string, bridges []string, s *sharedSubnet) string {
	if s != nil && slices.Contains(bridges, s.holder) {
		return s.holder
	}
	for _, id := range bridges {
		if st, ok := m.dial[id]; ok && slices.Contains(st.peer.RoutedSubnets, subnet) {
			return id
		}
	}
	return bridges[0]
}

// sharedHeldLocked returns the shared subnets m holds per holder, each list
// sorted by address and then by prefix length (see comparePrefixes). A peer
// that holds none has no key. Callers hold m.mu.
func (m *Manager) sharedHeldLocked() map[string][]string {
	byHolder := make(map[string][]netip.Prefix)
	for subnet, s := range m.shared {
		// Every key is the String of a prefix setSharedSubnets accepted.
		byHolder[s.holder] = append(byHolder[s.holder], netip.MustParsePrefix(subnet))
	}
	held := make(map[string][]string, len(byHolder))
	for holder, prefixes := range byHolder {
		slices.SortFunc(prefixes, comparePrefixes)
		subnets := make([]string, len(prefixes))
		for i, p := range prefixes {
			subnets[i] = p.String()
		}
		held[holder] = subnets
	}
	return held
}

// routedSubnets returns the routed subnets the device carries for p, its
// effective list: the entries of p.RoutedSubnets that are no shared subnet,
// as usableRoutedSubnets accepts them and in their order, followed by the
// shared subnets whose holder p is, sorted by address and then by prefix
// length. skipped is what usableRoutedSubnets refused. An entry is compared
// with the shared subnets parsed and in canonical form; one that does not
// parse goes on to usableRoutedSubnets, which skips it as invalid. routed is
// nil when it is empty. It reads the shared subnets under m.mu.
func (m *Manager) routedSubnets(p api.SnapshotPeer, mesh netip.Prefix, local []netip.Prefix) (routed []string, skipped []skippedSubnet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routedSubnetsLocked(p, m.sharedHeldLocked(), mesh, local)
}

// routedSubnetsLocked is routedSubnets for a caller that holds m.mu, with
// held as sharedHeldLocked returns it.
func (m *Manager) routedSubnetsLocked(p api.SnapshotPeer, held map[string][]string, mesh netip.Prefix, local []netip.Prefix) (routed []string, skipped []skippedSubnet) {
	var own []string
	for _, subnet := range p.RoutedSubnets {
		if prefix, err := netip.ParsePrefix(subnet); err == nil {
			if _, shared := m.shared[prefix.String()]; shared {
				continue
			}
		}
		own = append(own, subnet)
	}
	routed, skipped = usableRoutedSubnets(own, mesh, local)
	return append(routed, held[p.NodeID]...), skipped
}

// syncSharedSubnets writes the peers whose routed subnets the shared subnets'
// holders changed, for a pull whose peers are peers. A pull can move a
// subnet without changing either peer entry, and then neither the update nor
// the add of the reconcile handler writes them.
//
// Each peer m tracks gets a target list. For a peer of peers last written
// with the pull's public key it is the effective list (see routedSubnets).
// Any other tracked peer only loses subnets: its target is the list it was
// last written with, less the shared subnets another peer holds. Such a peer
// is one the pull no longer lists and whose removal failed, one whose key
// rotation failed, so that its device peer belongs to the old key, or one
// whose update or add failed in the run, which the handler leaves out of
// peers; the next run writes its lists.
//
// The step writes in two rounds, each in node ID order, and holds mu for
// both, so no move of endpoint selection runs in between:
//  1. A peer of peers whose target holds a subnet its record lacks, or that
//     holds a shared subnet another tracked peer was last written with, is
//     written with its target and with every subnet its record lists that
//     the target drops. The second case repairs a race: snapshotPeer reads
//     the holders before UpdatePeer takes mu, so a move in between writes
//     the old holder back with the subnet, and the device gives an equal
//     prefix to the peer written last. In steady state only the holder
//     carries a shared subnet, and the second case writes nothing.
//  2. Every peer whose record differs from its target is then written with
//     its target and with each subnet the target drops that has not landed
//     yet: a shared subnet whose holder is untracked or was not written with
//     it, or another subnet the target of an other peer holds while that
//     peer's record lacks it. The device takes a subnet off a peer when
//     another peer is written with it, so a peer gives a subnet up only once
//     the one that carries it next has it, and a failed or skipped write of
//     that peer leaves the subnet where it was rather than on no peer.
//
// Each write is the one writeRoutedSubnets makes, which leaves the device
// endpoint and the endpoint selection state as they are. A failed write is
// logged as reconcile: update peer failed at Error, leaves the peer's record
// as it was, so the next run tries it again, and is returned joined; a peer
// whose first-round write failed is not written again in the second. It logs
// no skipped routed subnet: snapshotPeer logs those on the add and the
// update.
func (m *Manager) syncSharedSubnets(peers []api.SnapshotPeer, mesh netip.Prefix, local []netip.Prefix) error {
	byID := make(map[string]api.SnapshotPeer, len(peers))
	for _, p := range peers {
		byID[p.NodeID] = p
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	held := m.sharedHeldLocked()
	ids := slices.Sorted(maps.Keys(m.dial))
	target := make(map[string][]string, len(ids))
	writable := make(map[string]bool, len(ids))
	for _, id := range ids {
		st := m.dial[id]
		if p, ok := byID[id]; ok && st.peer.PublicKey == p.PublicKey {
			target[id], _ = m.routedSubnetsLocked(p, held, mesh, local)
			writable[id] = true
			continue
		}
		target[id] = slices.DeleteFunc(slices.Clone(st.peer.RoutedSubnets), func(subnet string) bool {
			s, shared := m.shared[subnet]
			return shared && s.holder != id
		})
	}

	// landed reports whether subnet, which id's target drops, is where it
	// goes next: on the record of its holder for a shared subnet, and
	// otherwise on the record of every other peer whose target holds it.
	landed := func(id, subnet string) bool {
		if s, shared := m.shared[subnet]; shared {
			hst, tracked := m.dial[s.holder]
			return s.holder != id && tracked && slices.Contains(hst.peer.RoutedSubnets, subnet)
		}
		for _, other := range ids {
			if other != id && slices.Contains(target[other], subnet) && !slices.Contains(m.dial[other].peer.RoutedSubnets, subnet) {
				return false
			}
		}
		return true
	}

	var errs []error
	failed := make(map[string]bool)
	write := func(id string, routed []string) {
		if len(routed) == 0 {
			routed = nil
		}
		if err := m.writeRoutedSubnets(m.dial[id], routed); err != nil {
			m.logger.Error("reconcile: update peer failed",
				"component", "wireguard",
				"peer_id", id,
				"error", err,
			)
			errs = append(errs, fmt.Errorf("wireguard: write routed subnets of peer %s: %w", id, err))
			failed[id] = true
		}
	}

	for _, id := range ids {
		if !writable[id] {
			continue
		}
		record := m.dial[id].peer.RoutedSubnets
		gains := slices.ContainsFunc(target[id], func(subnet string) bool { return !slices.Contains(record, subnet) })
		if !gains && !m.listedElsewhereLocked(id, held[id]) {
			continue
		}
		routed := slices.Clone(target[id])
		for _, subnet := range record {
			if !slices.Contains(routed, subnet) {
				routed = append(routed, subnet)
			}
		}
		write(id, routed)
	}

	for _, id := range ids {
		if failed[id] {
			continue
		}
		record := m.dial[id].peer.RoutedSubnets
		routed := slices.Clone(target[id])
		for _, subnet := range record {
			if !slices.Contains(routed, subnet) && !landed(id, subnet) {
				routed = append(routed, subnet)
			}
		}
		if slices.Equal(routed, record) {
			continue
		}
		write(id, routed)
	}
	return errors.Join(errs...)
}

// listedElsewhereLocked reports whether a peer m tracks other than id was
// last written with one of subnets among its routed subnets. Callers hold
// m.mu.
func (m *Manager) listedElsewhereLocked(id string, subnets []string) bool {
	for other, st := range m.dial {
		if other != id && slices.ContainsFunc(subnets, func(s string) bool {
			return slices.Contains(st.peer.RoutedSubnets, s)
		}) {
			return true
		}
	}
	return false
}

// writeRoutedSubnets writes the peer st records with routed as its routed
// subnets, and with allowed IPs to match, mesh_ip/32 followed by routed. It
// is the write SetPeerPSK makes: the recorded peer otherwise unchanged, and an
// empty endpoint, which leaves the device's endpoint, and with it the
// endpoint selection state, as they are. A successful write records the
// peer; a failed one records nothing. Callers hold m.mu.
func (m *Manager) writeRoutedSubnets(st *dialState, routed []string) error {
	addr, err := netip.ParseAddr(st.peer.MeshIP)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("invalid mesh_ip %q", st.peer.MeshIP)
	}
	peer := st.peer
	peer.RoutedSubnets = routed
	peer.AllowedIPs = peerAllowedIPs(addr, routed)
	peerCfg, err := m.peerConfig(peer, "")
	if err != nil {
		return err
	}
	if err := m.ctrl.AddPeer(m.cfg.InterfaceName, peerCfg); err != nil {
		return err
	}
	st.peer = peer
	return nil
}
