package wireguard

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// The rules of the in-process mesh source rewrite. A wrapper around the tun
// device of each of plexd's own wireguard-go devices hands every packet
// wireguard-go writes to one of them to decide. A packet the far end of a
// source interface sends into the mesh leaves through the mesh interface with
// the mesh interface's address as its source, and the reply returns to the far
// end, without the host's forwarding, NAT or firewall ever seeing either.
//
// The rules do no I/O: they read and write packets, the tables below and the
// clock through now. Every piece of state sits under one mutex. Only IPv4 is
// rewritten, as the Linux table plexd-mesh-nat and the pf rules do.

// IP protocol numbers and the ICMP types the rules tell apart.
const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	icmpEchoReply       = 0
	icmpUnreachable     = 3
	icmpEchoRequest     = 8
	icmpTimeExceeded    = 11
	icmpFragNeededCode  = 4
	icmpTTLExceededCode = 0

	ipv4HeaderLen = 20

	tcpFlagFIN = 0x01
	tcpFlagRST = 0x04
)

// The range mesh ports and mesh ids are taken from. It lies below Windows'
// default dynamic ports, 49152 to 65535, so the host's own sockets on the mesh
// address do not draw from it.
const (
	meshPortFirst = 32768
	meshPortLast  = 49151
)

// The limits of the tables. A packet that would create one more translated or
// host flow is dropped as table_full. A first fragment beyond the record limit
// translates without a record, so its later fragments are dropped as fragment;
// the limit keeps a far end from growing the records without bound.
const (
	maxTranslatedFlows = 65536
	maxHostFlows       = 65536
	maxFragmentRecords = 65536
)

// Lifetimes after an entry's last packet. The flow lifetimes are the defaults
// of netfilter's connection tracking (nf_conntrack_tcp_timeout_established,
// nf_conntrack_udp_timeout and _stream, nf_conntrack_icmp_timeout), so a flow
// lives about as long on a Windows bridge as on a Linux one.
const (
	tcpUnrepliedLifetime   = 120 * time.Second
	tcpEstablishedLifetime = 432000 * time.Second
	udpUnrepliedLifetime   = 30 * time.Second
	udpRepliedLifetime     = 120 * time.Second
	icmpEchoLifetime       = 30 * time.Second
	fragmentRecordLifetime = 30 * time.Second

	// sweepInterval is how often packet handling removes every expired
	// entry; a lookup removes the one it finds in between.
	sweepInterval = 30 * time.Second
)

// icmpErrorsPerSecond caps the ICMP errors plexd sends of its own.
const icmpErrorsPerSecond = 100

// dropReportInterval is the least time between two drop reports of one
// reason.
const dropReportInterval = 60 * time.Second

// limitedBroadcast is an address a far end's packet never translates to: it
// is the host's, as every multicast address is.
var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// dropReason says why the rewrite dropped a packet.
type dropReason int

const (
	dropQueueFull dropReason = iota
	dropFragment
	dropUnsupportedProtocol
	dropTTL
	dropOversize
	dropTableFull
	numDropReasons
)

// String returns the reason as the drop log line names it.
func (r dropReason) String() string {
	switch r {
	case dropQueueFull:
		return "queue_full"
	case dropFragment:
		return "fragment"
	case dropUnsupportedProtocol:
		return "unsupported_protocol"
	case dropTTL:
		return "ttl"
	case dropOversize:
		return "oversize"
	case dropTableFull:
		return "table_full"
	}
	return "unknown"
}

// dropReport is one drop log line that is due: the drops of reason since the
// last line of that reason.
type dropReport struct {
	reason dropReason
	count  uint64
}

// dropCounter counts the drops of one reason.
type dropCounter struct {
	total    uint64    // every drop since the rewriter was made
	pending  uint64    // the drops no report carried yet
	reported time.Time // when the last report of this reason was due
}

// natDevice is what the rules need of a device a packet leaves through: its
// MTU, the largest packet the rules let leave through it.
type natDevice interface {
	MTU() (int, error)
}

// natAction is what becomes of a packet wireguard-go wrote to a device.
type natAction uint8

const (
	// natPass hands the packet to the host unchanged.
	natPass natAction = iota
	// natQueue queues the translated copy for the device it leaves through.
	natQueue
	// natDrop drops the packet.
	natDrop
)

// natResult is the decision about one packet.
type natResult struct {
	action natAction
	// out is the translated copy of the packet, to queue for the device to.
	out []byte
	to  natDevice
	// icmp is an ICMP error plexd sends in answer, to queue for icmpTo.
	icmp   []byte
	icmpTo natDevice
	// reports are the drop reports that fell due while handling the packet.
	reports []dropReport
}

// natRewrite is one rewrite: what the far ends behind the source interface from
// send into the mesh leaves through mesh with the source meshAddr. prefixes are
// the IPv4 prefixes from carries, whose addresses are the host's.
type natRewrite struct {
	from     string
	mesh     string
	meshAddr netip.Addr
	prefixes []netip.Prefix
}

// toHost reports whether a far end's packet to dst is for the host: row A2.
func (rw *natRewrite) toHost(dst netip.Addr) bool {
	if dst == rw.meshAddr || dst == limitedBroadcast || dst.IsMulticast() {
		return true
	}
	for _, p := range rw.prefixes {
		if p.Contains(dst) {
			return true
		}
	}
	return false
}

// flowKey identifies a translated or a host flow of the source interface iface
// from the far end's side: far is the address of the device or site host
// behind iface, remote the address on the mesh side it talks to. farPort and
// remotePort are TCP or UDP ports. For an ICMP echo the id takes the place of
// the port of the side that sent the request, and the other side's is 0.
type flowKey struct {
	iface      string
	proto      uint8
	far        netip.Addr
	farPort    uint16
	remote     netip.Addr
	remotePort uint16
}

// portKey is what a mesh port is unique for: protocol, remote address and
// remote port. A mesh peer's reply finds its flow by it.
type portKey struct {
	proto      uint8
	remote     netip.Addr
	remotePort uint16
	meshPort   uint16
}

// fragKey identifies the fragments of one datagram by the addresses, protocol
// and IP identification they arrive with.
type fragKey struct {
	src, dst netip.Addr
	proto    uint8
	id       uint16
}

// natFlow is a flow a far end opened toward the mesh, translated to meshAddr
// and meshPort (an echo: its mesh id) on the mesh interface mesh.
type natFlow struct {
	key      flowKey
	mesh     string
	meshAddr netip.Addr
	meshPort uint16
	last     time.Time
	replied  bool // a packet of the mesh peer's direction was seen
	closing  bool // a TCP FIN or RST was seen
	gone     bool // removed; a fragment record that names it is stale
}

func (f *natFlow) portKey() portKey {
	return portKey{proto: f.key.proto, remote: f.key.remote, remotePort: f.key.remotePort, meshPort: f.meshPort}
}

func (f *natFlow) expired(now time.Time) bool {
	return !now.Before(f.last.Add(flowLifetime(f.key.proto, f.replied, f.closing)))
}

// hostFlow is a flow the host sent through a source interface: what a mesh
// node or the host itself opened toward a far end, which Windows forwarded or
// sent there. Its replies are the host's.
type hostFlow struct {
	key     flowKey
	last    time.Time
	replied bool
	closing bool
	gone    bool
}

func (h *hostFlow) expired(now time.Time) bool {
	return !now.Before(h.last.Add(flowLifetime(h.key.proto, h.replied, h.closing)))
}

// flowLifetime is how long a flow lives after its last packet.
func flowLifetime(proto uint8, replied, closing bool) time.Duration {
	switch proto {
	case protoTCP:
		if closing || !replied {
			return tcpUnrepliedLifetime
		}
		return tcpEstablishedLifetime
	case protoUDP:
		if replied {
			return udpRepliedLifetime
		}
		return udpUnrepliedLifetime
	}
	return icmpEchoLifetime
}

// fragRecord is what the first fragment of a datagram left for its later
// fragments, which carry no ports: the flow they belong to. A record names a
// translated flow (flow, with toMesh for the far end's direction) or a host
// flow whose reply it is (host).
type fragRecord struct {
	flow   *natFlow
	toMesh bool
	host   *hostFlow
	last   time.Time
}

func (r *fragRecord) stale(now time.Time) bool {
	if r.flow != nil && r.flow.gone || r.host != nil && r.host.gone {
		return true
	}
	return !now.Before(r.last.Add(fragmentRecordLifetime))
}

// meshNAT holds the rewrites, the devices they run between and every flow, and
// decides what becomes of each packet.
type meshNAT struct {
	mu  sync.Mutex
	now func() time.Time

	devices  map[string]natDevice   // every device a wrapper knows, by name
	rewrites map[string]*natRewrite // by source interface
	meshUse  map[string]int         // the number of rewrites into each mesh interface

	flows     map[flowKey]*natFlow
	meshPorts map[portKey]*natFlow
	hostFlows map[flowKey]*hostFlow
	frags     map[fragKey]*fragRecord

	lastSweep time.Time

	// icmpWindow starts the second icmpSent counts the ICMP errors of.
	icmpWindow time.Time
	icmpSent   int

	drops [numDropReasons]dropCounter

	// The limits and the mesh port range; the tests lower them.
	maxFlows     int
	maxHostFlows int
	portFirst    uint16
	portLast     uint16
}

func newMeshNAT(now func() time.Time) *meshNAT {
	return &meshNAT{
		now:          now,
		devices:      make(map[string]natDevice),
		rewrites:     make(map[string]*natRewrite),
		meshUse:      make(map[string]int),
		flows:        make(map[flowKey]*natFlow),
		meshPorts:    make(map[portKey]*natFlow),
		hostFlows:    make(map[flowKey]*hostFlow),
		frags:        make(map[fragKey]*fragRecord),
		maxFlows:     maxTranslatedFlows,
		maxHostFlows: maxHostFlows,
		portFirst:    meshPortFirst,
		portLast:     meshPortLast,
	}
}

// register knows dev under name. A device registered under name before is
// replaced, and the rewrites of name stay.
func (n *meshNAT) register(name string, dev natDevice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.devices[name] = dev
}

// unregister forgets dev under name, every rewrite name takes part in, as the
// source or the mesh interface, and the flows of those rewrites. A device
// registered under name since is left alone.
func (n *meshNAT) unregister(name string, dev natDevice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.devices[name] != dev {
		return
	}
	delete(n.devices, name)
	for from, rw := range n.rewrites {
		if from == name || rw.mesh == name {
			n.removeRewriteLocked(from)
		}
	}
}

// known reports whether a device is registered under name.
func (n *meshNAT) known(name string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.devices[name]
	return ok
}

// involved reports whether name takes part in a rewrite. A device that takes
// part in none passes every packet.
func (n *meshNAT) involved(name string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.rewrites[name] != nil || n.meshUse[name] > 0
}

// addOutcome is what addRewrite did, or what it would do.
type addOutcome int

const (
	addAdded addOutcome = iota
	addPresent
	addNoSource
	addNoMesh
)

// checkRewrite reports what addRewrite would do for from and mesh, without
// adding.
func (n *meshNAT) checkRewrite(from, mesh string) addOutcome {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.checkRewriteLocked(from, mesh)
}

// checkRewriteLocked checks the mesh interface first: without it no rewrite
// can exist, whatever the source interface is.
func (n *meshNAT) checkRewriteLocked(from, mesh string) addOutcome {
	if _, ok := n.devices[mesh]; !ok {
		return addNoMesh
	}
	if _, ok := n.devices[from]; !ok {
		return addNoSource
	}
	if n.rewrites[from] != nil {
		return addPresent
	}
	return addAdded
}

// addRewrite adds the rewrite from from into mesh with the source meshAddr.
// prefixes are the IPv4 prefixes from carries. A rewrite that exists for from
// is left alone.
func (n *meshNAT) addRewrite(from, mesh string, meshAddr netip.Addr, prefixes []netip.Prefix) addOutcome {
	n.mu.Lock()
	defer n.mu.Unlock()
	if o := n.checkRewriteLocked(from, mesh); o != addAdded {
		return o
	}
	n.rewrites[from] = &natRewrite{
		from:     from,
		mesh:     mesh,
		meshAddr: meshAddr,
		prefixes: slices.Clone(prefixes),
	}
	n.meshUse[mesh]++
	return addAdded
}

// removeRewrite forgets the rewrite of from and its flows. It reports the mesh
// interface the rewrite named, and false when from had none.
func (n *meshNAT) removeRewrite(from string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	rw := n.rewrites[from]
	if rw == nil {
		return "", false
	}
	n.removeRewriteLocked(from)
	return rw.mesh, true
}

// resetRewrites forgets every rewrite and every flow.
func (n *meshNAT) resetRewrites() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for from := range n.rewrites {
		n.removeRewriteLocked(from)
	}
}

// setMeshAddr gives every rewrite into mesh the source addr and removes every
// flow of mesh that was translated to another address. It reports the number
// of rewrites it moved and of flows it removed.
//
// The far end's next packet of a removed flow opens a flow on addr. Without
// the removal a running conversation would keep its old source until the flow
// idles out, up to five days for an established TCP connection.
func (n *meshNAT) setMeshAddr(mesh string, addr netip.Addr) (rewrites, flows int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, rw := range n.rewrites {
		if rw.mesh == mesh {
			rw.meshAddr = addr
			rewrites++
		}
	}
	for _, f := range n.flows {
		if f.mesh == mesh && f.meshAddr != addr {
			n.removeFlow(f)
			flows++
		}
	}
	return rewrites, flows
}

func (n *meshNAT) removeRewriteLocked(from string) {
	rw := n.rewrites[from]
	if rw == nil {
		return
	}
	delete(n.rewrites, from)
	if n.meshUse[rw.mesh]--; n.meshUse[rw.mesh] <= 0 {
		delete(n.meshUse, rw.mesh)
	}
	for k, f := range n.flows {
		if k.iface == from {
			n.removeFlow(f)
		}
	}
	for k, h := range n.hostFlows {
		if k.iface == from {
			n.removeHostFlow(h)
		}
	}
	for k, r := range n.frags {
		if r.flow != nil && r.flow.gone || r.host != nil && r.host.gone {
			delete(n.frags, k)
		}
	}
}

// decide decides a packet wireguard-go wrote to the device iface: one a far end
// sent when iface is a source interface (rows A1 to A9), one a mesh peer sent
// when it is a mesh interface (rows B1 to B4). Any other device's packet
// passes. pkt is not changed; a translated packet is a copy.
func (n *meshNAT) decide(iface string, pkt []byte) natResult {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.sweepIfDue(now)

	var res natResult
	if rw := n.rewrites[iface]; rw != nil {
		n.fromFarEnd(&res, rw, pkt, now)
	} else if n.meshUse[iface] > 0 {
		n.fromMeshPeer(&res, iface, pkt, now)
	}
	res.reports = n.dueReports(now)
	return res
}

// observe accounts for a packet the host hands the device iface, which passes
// to wireguard-go. A TCP, UDP or ICMP echo request packet of a source
// interface creates or refreshes a host flow, which is how the far end's reply
// is known as the host's (row A3). It reports false for a packet that would
// create a host flow beyond the limit, which is dropped as table_full.
func (n *meshNAT) observe(iface string, pkt []byte) (bool, []dropReport) {
	n.mu.Lock()
	defer n.mu.Unlock()
	rw := n.rewrites[iface]
	if rw == nil {
		return true, nil
	}
	now := n.now()
	n.sweepIfDue(now)

	pass := n.fromHost(rw, pkt, now)
	return pass, n.dueReports(now)
}

// dropped counts a drop a wrapper made itself, a full queue, and returns the
// reports that fell due.
func (n *meshNAT) dropped(reason dropReason) []dropReport {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	n.count(reason)
	return n.dueReports(now)
}

// dropCount returns the number of drops of reason so far.
func (n *meshNAT) dropCount(reason dropReason) uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.drops[reason].total
}

func (n *meshNAT) fromHost(rw *natRewrite, raw []byte, now time.Time) bool {
	p, ok := parseIPv4(raw)
	if !ok || p.off != 0 {
		return true
	}
	t, ok := parseTransport(p.proto, p.b[p.hl:], false)
	if !ok || !t.ports || p.proto == protoICMP && t.icmpType != icmpEchoRequest {
		return true
	}

	key := towardFarKey(rw.from, p, t)
	h := n.hostFlow(key, now)
	if h == nil {
		if len(n.hostFlows) >= n.maxHostFlows {
			n.count(dropTableFull)
			return false
		}
		h = &hostFlow{key: key}
		n.hostFlows[key] = h
	}
	h.last = now
	h.closing = h.closing || t.finOrRST()
	return true
}

// fromFarEnd applies rows A1 to A9 to a packet the far end behind rw.from sent.
// wireguard-go has checked its source against the peer's allowed IPs.
func (n *meshNAT) fromFarEnd(res *natResult, rw *natRewrite, raw []byte, now time.Time) {
	// A1: no IPv4 packet whose header length and total length fit its bytes.
	p, ok := parseIPv4(raw)
	if !ok {
		return
	}
	// A2: for the host.
	if rw.toHost(p.dst) {
		return
	}
	var t transport
	if p.off == 0 {
		// A6: a first fragment too short for its TCP, UDP or ICMP header is
		// none the rewrite carries, and rows A3 and A4 need the header it
		// cuts short. Handed to Windows, it would be forwarded with the far
		// end's own source.
		if t, ok = parseTransport(p.proto, p.b[p.hl:], false); !ok {
			n.drop(res, dropUnsupportedProtocol)
			return
		}
	}

	// A3: the reply to a host flow.
	if n.answersHostFlow(rw, p, t, now) {
		return
	}

	// A4: an ICMP error about the reply of a translated flow.
	if t.icmpError && !p.mf {
		// The quoted packet went to the far end: a reply, so an echo in it
		// is an echo reply.
		if q, qt, ok := quotedPacket(p); ok && (q.proto != protoICMP || qt.icmpType == icmpEchoReply) {
			if f := n.flow(towardFarKey(rw.from, q, qt), now); f != nil {
				e := newEdit(p, t)
				e.setSrc(f.meshAddr)
				e.editQuoted(q, qt, func(qe *edit) {
					qe.setDst(f.meshAddr)
					qe.setDstPort(f.meshPort)
				})
				n.queue(res, e.b, rw.mesh)
				return
			}
		}
	}

	// A5: a later fragment, which carries no ports.
	if p.off > 0 {
		r := n.fragment(p, now)
		if r == nil || r.flow == nil || !r.toMesh || r.flow.key.iface != rw.from {
			n.drop(res, dropFragment)
			return
		}
		r.flow.last = now
		e := newEdit(p, t)
		e.setSrc(r.flow.meshAddr)
		n.queue(res, e.b, rw.mesh)
		return
	}

	// A6: what the rewrite carries is TCP, UDP and ICMP echo.
	if !t.ports || p.proto == protoICMP && t.icmpType != icmpEchoRequest {
		n.drop(res, dropUnsupportedProtocol)
		return
	}

	// A7: the packet would leave with a TTL of 0.
	if p.ttl <= 1 {
		n.drop(res, dropTTL)
		n.sendICMPError(res, rw.from, rw.meshAddr, p, icmpTimeExceeded, icmpTTLExceededCode, 0, now)
		return
	}

	// A8: too long for the mesh device. plexd fragments nothing.
	if mtu := deviceMTU(n.devices[rw.mesh]); mtu > 0 && len(p.b) > mtu {
		if p.df {
			res.action = natDrop
			n.sendICMPError(res, rw.from, rw.meshAddr, p, icmpUnreachable, icmpFragNeededCode, mtu, now)
			return
		}
		n.drop(res, dropOversize)
		return
	}

	// A9: translate.
	key := fromFarKey(rw.from, p, t)
	f := n.flow(key, now)
	if f == nil {
		if len(n.flows) >= n.maxFlows {
			n.drop(res, dropTableFull)
			return
		}
		port, ok := n.freeMeshPort(key, now)
		if !ok {
			n.drop(res, dropTableFull)
			return
		}
		f = &natFlow{key: key, mesh: rw.mesh, meshAddr: rw.meshAddr, meshPort: port}
		n.flows[key] = f
		n.meshPorts[f.portKey()] = f
	}
	f.last = now
	f.closing = f.closing || t.finOrRST()

	e := newEdit(p, t)
	e.setSrc(f.meshAddr)
	e.setSrcPort(f.meshPort)
	e.decrementTTL()
	if p.mf {
		n.leaveRecord(p, fragRecord{flow: f, toMesh: true}, now)
	}
	n.queue(res, e.b, rw.mesh)
}

// answersHostFlow reports whether a far end's packet answers a host flow of
// rw.from: row A3. A reply refreshes the flow, and its first fragment leaves a
// record so its later fragments are the host's too.
func (n *meshNAT) answersHostFlow(rw *natRewrite, p ipv4, t transport, now time.Time) bool {
	if p.off > 0 {
		r := n.fragment(p, now)
		if r == nil || r.host == nil || r.host.key.iface != rw.from {
			return false
		}
		r.host.last = now
		return true
	}
	if t.icmpError {
		if p.mf {
			return false
		}
		// The quoted packet is one the host sent, so an echo in it is a
		// request, as every echo host flow starts with one.
		q, qt, ok := quotedPacket(p)
		if !ok || q.proto == protoICMP && qt.icmpType != icmpEchoRequest {
			return false
		}
		return n.hostFlow(towardFarKey(rw.from, q, qt), now) != nil
	}
	// A far end's echo request opens a flow of its own; only a reply answers.
	if !t.ports || p.proto == protoICMP && t.icmpType != icmpEchoReply {
		return false
	}
	h := n.hostFlow(fromFarKey(rw.from, p, t), now)
	if h == nil {
		return false
	}
	h.last = now
	h.replied = true
	h.closing = h.closing || t.finOrRST()
	if p.mf {
		n.leaveRecord(p, fragRecord{host: h}, now)
	}
	return true
}

// fromMeshPeer applies rows B1 to B4 to a packet a mesh peer sent to the mesh
// interface mesh.
func (n *meshNAT) fromMeshPeer(res *natResult, mesh string, raw []byte, now time.Time) {
	p, ok := parseIPv4(raw)
	if !ok {
		return
	}

	// B2: a later fragment of a reply.
	if p.off > 0 {
		r := n.fragment(p, now)
		if r == nil || r.flow == nil || r.toMesh || r.flow.mesh != mesh || r.flow.meshAddr != p.dst {
			return
		}
		r.flow.last = now
		e := newEdit(p, transport{})
		e.setDst(r.flow.key.far)
		n.queue(res, e.b, r.flow.key.iface)
		return
	}

	t, ok := parseTransport(p.proto, p.b[p.hl:], false)
	if !ok {
		return
	}

	// B1: the reply of a translated flow.
	if t.ports && (p.proto != protoICMP || t.icmpType == icmpEchoReply) {
		k := portKey{proto: p.proto, remote: p.src, remotePort: t.srcPort, meshPort: t.dstPort}
		if f := n.flowByMeshPort(k, now); f != nil && f.mesh == mesh && f.meshAddr == p.dst {
			n.replyToFarEnd(res, f, p, t, now)
			return
		}
	}

	// B3: an ICMP error about a packet of a translated flow.
	if t.icmpError && !p.mf {
		q, qt, ok := quotedPacket(p)
		if !ok || q.src != p.dst || q.proto == protoICMP && qt.icmpType != icmpEchoRequest {
			return
		}
		k := portKey{proto: q.proto, remote: q.dst, remotePort: qt.dstPort, meshPort: qt.srcPort}
		f := n.flowByMeshPort(k, now)
		if f == nil || f.mesh != mesh || f.meshAddr != p.dst {
			return
		}
		e := newEdit(p, t)
		e.setDst(f.key.far)
		e.editQuoted(q, qt, func(qe *edit) {
			qe.setSrc(f.key.far)
			qe.setSrcPort(f.key.farPort)
		})
		n.queue(res, e.b, f.key.iface)
	}

	// B4: anything else is the host's.
}

// replyToFarEnd translates the reply of the flow f back to the far end: row B1.
func (n *meshNAT) replyToFarEnd(res *natResult, f *natFlow, p ipv4, t transport, now time.Time) {
	if p.ttl <= 1 {
		n.drop(res, dropTTL)
		return
	}
	if mtu := deviceMTU(n.devices[f.key.iface]); mtu > 0 && len(p.b) > mtu {
		if p.df {
			res.action = natDrop
			n.sendICMPError(res, f.mesh, f.meshAddr, p, icmpUnreachable, icmpFragNeededCode, mtu, now)
			return
		}
		n.drop(res, dropOversize)
		return
	}

	f.last = now
	f.replied = true
	f.closing = f.closing || t.finOrRST()

	e := newEdit(p, t)
	e.setDst(f.key.far)
	e.setDstPort(f.key.farPort)
	e.decrementTTL()
	if p.mf {
		n.leaveRecord(p, fragRecord{flow: f}, now)
	}
	n.queue(res, e.b, f.key.iface)
}

// queue makes out the result, to leave through the device dev.
func (n *meshNAT) queue(res *natResult, out []byte, dev string) {
	res.action = natQueue
	res.out = out
	res.to = n.devices[dev]
}

// drop drops the packet and counts it under reason.
func (n *meshNAT) drop(res *natResult, reason dropReason) {
	res.action = natDrop
	n.count(reason)
}

// count counts a drop of reason. dueReports reports it.
func (n *meshNAT) count(reason dropReason) {
	n.drops[reason].total++
	n.drops[reason].pending++
}

// dueReports returns a report for every reason whose drops wait for one and
// whose last report is 60 s old. The first drop of a reason is reported at
// once, since a reason never reported has the zero time as its last report;
// later ones wait for the next report, 60 s after the last.
func (n *meshNAT) dueReports(now time.Time) []dropReport {
	var reports []dropReport
	for i := range n.drops {
		c := &n.drops[i]
		if c.pending == 0 || now.Sub(c.reported) < dropReportInterval {
			continue
		}
		reports = append(reports, dropReport{reason: dropReason(i), count: c.pending})
		c.pending = 0
		c.reported = now
	}
	return reports
}

// sendICMPError answers the packet p with an ICMP error of typ and code from
// src, queued for the device dev the packet came through. mtu is the next-hop
// MTU of a "fragmentation needed". plexd sends at most icmpErrorsPerSecond,
// and none about an ICMP error or a later fragment (RFC 1812, 4.3.2.7).
func (n *meshNAT) sendICMPError(res *natResult, dev string, src netip.Addr, p ipv4, typ, code uint8, mtu int, now time.Time) {
	if p.off > 0 || isICMPError(p) {
		return
	}
	to := n.devices[dev]
	if to == nil {
		return
	}
	if now.Before(n.icmpWindow) || now.Sub(n.icmpWindow) >= time.Second {
		n.icmpWindow = now
		n.icmpSent = 0
	}
	if n.icmpSent >= icmpErrorsPerSecond {
		return
	}
	n.icmpSent++
	res.icmp = icmpErrorPacket(src, p, typ, code, mtu)
	res.icmpTo = to
}

// flow returns the live translated flow of k, removing an expired one.
func (n *meshNAT) flow(k flowKey, now time.Time) *natFlow {
	f := n.flows[k]
	if f != nil && f.expired(now) {
		n.removeFlow(f)
		return nil
	}
	return f
}

// flowByMeshPort returns the live translated flow that holds the mesh port of
// k, removing an expired one.
func (n *meshNAT) flowByMeshPort(k portKey, now time.Time) *natFlow {
	f := n.meshPorts[k]
	if f != nil && f.expired(now) {
		n.removeFlow(f)
		return nil
	}
	return f
}

// hostFlow returns the live host flow of k, removing an expired one.
func (n *meshNAT) hostFlow(k flowKey, now time.Time) *hostFlow {
	h := n.hostFlows[k]
	if h != nil && h.expired(now) {
		n.removeHostFlow(h)
		return nil
	}
	return h
}

func (n *meshNAT) removeFlow(f *natFlow) {
	delete(n.flows, f.key)
	delete(n.meshPorts, f.portKey())
	f.gone = true
}

func (n *meshNAT) removeHostFlow(h *hostFlow) {
	delete(n.hostFlows, h.key)
	h.gone = true
}

// freeMeshPort finds a mesh port for a new flow of k that no live flow holds
// for its protocol, remote address and remote port. The search starts at a
// hash of the far end's address and port, so a far end keeps its mesh port
// across flows to different remotes where it can.
func (n *meshNAT) freeMeshPort(k flowKey, now time.Time) (uint16, bool) {
	span := uint32(n.portLast-n.portFirst) + 1
	start := farEndHash(k.far, k.farPort) % span
	for i := range span {
		port := n.portFirst + uint16((start+i)%span)
		pk := portKey{proto: k.proto, remote: k.remote, remotePort: k.remotePort, meshPort: port}
		if f := n.meshPorts[pk]; f == nil || f.expired(now) {
			if f != nil {
				n.removeFlow(f)
			}
			return port, true
		}
	}
	return 0, false
}

// farEndHash is FNV-1a over the far end's address and port.
func farEndHash(addr netip.Addr, port uint16) uint32 {
	a := addr.As4()
	h := fnv.New32a()
	_, _ = h.Write(a[:])
	_, _ = h.Write([]byte{byte(port >> 8), byte(port)})
	return h.Sum32()
}

// fragment returns the live record the first fragment of p's datagram left.
func (n *meshNAT) fragment(p ipv4, now time.Time) *fragRecord {
	k := fragKey{src: p.src, dst: p.dst, proto: p.proto, id: p.id}
	r := n.frags[k]
	if r == nil {
		return nil
	}
	if r.stale(now) {
		delete(n.frags, k)
		return nil
	}
	r.last = now
	return r
}

// leaveRecord leaves r for the later fragments of p's datagram.
func (n *meshNAT) leaveRecord(p ipv4, r fragRecord, now time.Time) {
	k := fragKey{src: p.src, dst: p.dst, proto: p.proto, id: p.id}
	if _, ok := n.frags[k]; !ok && len(n.frags) >= maxFragmentRecords {
		return
	}
	r.last = now
	n.frags[k] = &r
}

// sweepIfDue removes every expired entry, at most once per sweepInterval.
func (n *meshNAT) sweepIfDue(now time.Time) {
	if now.Sub(n.lastSweep) < sweepInterval {
		return
	}
	n.lastSweep = now
	for _, f := range n.flows {
		if f.expired(now) {
			n.removeFlow(f)
		}
	}
	for _, h := range n.hostFlows {
		if h.expired(now) {
			n.removeHostFlow(h)
		}
	}
	for k, r := range n.frags {
		if r.stale(now) {
			delete(n.frags, k)
		}
	}
}

// deviceMTU returns dev's MTU, or 0 when it has none to give.
func deviceMTU(dev natDevice) int {
	if dev == nil {
		return 0
	}
	mtu, err := dev.MTU()
	if err != nil {
		return 0
	}
	return mtu
}

// ipv4 is the part of an IPv4 header the rules read. b starts at the header:
// for a packet it is cut to the total length, for the packet an ICMP error
// quotes it holds what the error carries.
type ipv4 struct {
	b        []byte
	hl       int
	proto    uint8
	ttl      uint8
	id       uint16
	df, mf   bool
	off      uint16 // the fragment offset, in units of 8 bytes
	src, dst netip.Addr
}

// parseIPv4 reads an IPv4 packet whose header length and total length fit its
// bytes.
func parseIPv4(b []byte) (ipv4, bool) {
	if len(b) < ipv4HeaderLen || b[0]>>4 != 4 {
		return ipv4{}, false
	}
	hl := int(b[0]&0x0f) * 4
	if hl < ipv4HeaderLen || hl > len(b) {
		return ipv4{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < hl || total > len(b) {
		return ipv4{}, false
	}
	return ipv4Header(b[:total], hl), true
}

// parseQuotedIPv4 reads the packet an ICMP error quotes, which RFC 792 cuts to
// its header and the first 8 bytes after it. Its total length is not checked.
func parseQuotedIPv4(b []byte) (ipv4, bool) {
	if len(b) < ipv4HeaderLen || b[0]>>4 != 4 {
		return ipv4{}, false
	}
	hl := int(b[0]&0x0f) * 4
	if hl < ipv4HeaderLen || hl+8 > len(b) {
		return ipv4{}, false
	}
	return ipv4Header(b, hl), true
}

func ipv4Header(b []byte, hl int) ipv4 {
	frag := binary.BigEndian.Uint16(b[6:8])
	return ipv4{
		b:     b,
		hl:    hl,
		proto: b[9],
		ttl:   b[8],
		id:    binary.BigEndian.Uint16(b[4:6]),
		df:    frag&0x4000 != 0,
		mf:    frag&0x2000 != 0,
		off:   frag & 0x1fff,
		src:   netip.AddrFrom4([4]byte(b[12:16])),
		dst:   netip.AddrFrom4([4]byte(b[16:20])),
	}
}

// isICMPError reports whether p is an ICMP error message.
func isICMPError(p ipv4) bool {
	return p.proto == protoICMP && p.off == 0 && len(p.b) > p.hl && icmpErrorType(p.b[p.hl])
}

// icmpErrorType reports whether an ICMP type is an error message: destination
// unreachable, source quench, redirect, time exceeded or parameter problem.
func icmpErrorType(typ uint8) bool {
	switch typ {
	case 3, 4, 5, 11, 12:
		return true
	}
	return false
}

// transport is what the rules read of a TCP, UDP or ICMP header.
type transport struct {
	// ports is set for TCP, UDP and an ICMP echo. An echo's id is the srcPort
	// of a request and the dstPort of a reply, and the other port is 0, so
	// the keys of both directions pair up as a TCP or UDP flow's do.
	ports            bool
	srcPort, dstPort uint16
	tcpFlags         uint8
	icmpType         uint8
	icmpError        bool
}

func (t transport) finOrRST() bool {
	return t.tcpFlags&(tcpFlagFIN|tcpFlagRST) != 0
}

// parseTransport reads the transport header at the start of b, the payload of
// a packet's first fragment. quoted is set for what an ICMP error quotes, of
// which only the first 8 bytes are certain. It fails for a TCP, UDP or ICMP
// header that does not fit b; any other protocol has none to read.
func parseTransport(proto uint8, b []byte, quoted bool) (transport, bool) {
	var t transport
	switch proto {
	case protoTCP:
		if len(b) < 8 || !quoted && len(b) < 20 {
			return t, false
		}
		t.ports = true
		t.srcPort = binary.BigEndian.Uint16(b[0:2])
		t.dstPort = binary.BigEndian.Uint16(b[2:4])
		if !quoted {
			t.tcpFlags = b[13]
		}
	case protoUDP:
		if len(b) < 8 {
			return t, false
		}
		t.ports = true
		t.srcPort = binary.BigEndian.Uint16(b[0:2])
		t.dstPort = binary.BigEndian.Uint16(b[2:4])
	case protoICMP:
		if len(b) < 8 {
			return t, false
		}
		t.icmpType = b[0]
		switch t.icmpType {
		case icmpEchoRequest:
			t.ports = true
			t.srcPort = binary.BigEndian.Uint16(b[4:6])
		case icmpEchoReply:
			t.ports = true
			t.dstPort = binary.BigEndian.Uint16(b[4:6])
		default:
			t.icmpError = !quoted && icmpErrorType(t.icmpType)
		}
	}
	return t, true
}

// quotedPacket reads the packet the ICMP error p quotes, when it is a first
// fragment of TCP, UDP or an ICMP echo whose ports can be read.
func quotedPacket(p ipv4) (ipv4, transport, bool) {
	at := p.hl + 8
	if at > len(p.b) {
		return ipv4{}, transport{}, false
	}
	q, ok := parseQuotedIPv4(p.b[at:])
	if !ok || q.off != 0 {
		return ipv4{}, transport{}, false
	}
	qt, ok := parseTransport(q.proto, q.b[q.hl:], true)
	if !ok || !qt.ports {
		return ipv4{}, transport{}, false
	}
	return q, qt, true
}

// fromFarKey is the flow key of a packet the far end sent.
func fromFarKey(iface string, p ipv4, t transport) flowKey {
	return flowKey{iface: iface, proto: p.proto, far: p.src, farPort: t.srcPort, remote: p.dst, remotePort: t.dstPort}
}

// towardFarKey is the flow key of a packet sent toward the far end.
func towardFarKey(iface string, p ipv4, t transport) flowKey {
	return flowKey{iface: iface, proto: p.proto, far: p.dst, farPort: t.dstPort, remote: p.src, remotePort: t.srcPort}
}

// edit changes the addresses, ports and TTL of an IPv4 header and keeps the
// checksums that cover them right by incremental update (RFC 1624), so a
// fragment needs no reassembly. b starts at the header.
type edit struct {
	b []byte
	// tsum is the offset of the transport checksum, or -1 when the packet
	// holds none the edits reach: a later fragment, an ICMP error, or what
	// an ICMP error quotes, whose transport checksum is left alone.
	tsum int
	// pseudo is set when the transport checksum covers the addresses through
	// the pseudo header (TCP and UDP); udp when 0 in it means no checksum.
	pseudo bool
	udp    bool
	// srcPort and dstPort are the offsets of the ports (an echo: of its id),
	// or -1.
	srcPort, dstPort int
}

// newEdit returns an edit of a copy of the packet p, whose transport header t
// describes.
func newEdit(p ipv4, t transport) edit {
	return editOf(bytes.Clone(p.b), p, t, false)
}

func editOf(b []byte, p ipv4, t transport, quoted bool) edit {
	e := edit{b: b, tsum: -1, srcPort: -1, dstPort: -1}
	if p.off != 0 || !t.ports {
		return e
	}
	h := p.hl
	switch p.proto {
	case protoTCP:
		e.srcPort, e.dstPort = h, h+2
		e.tsum, e.pseudo = h+16, true
	case protoUDP:
		e.srcPort, e.dstPort = h, h+2
		e.tsum, e.pseudo, e.udp = h+6, true, true
	case protoICMP:
		e.srcPort, e.dstPort = h+4, h+4
		e.tsum = h + 2
	}
	if quoted {
		e.tsum, e.pseudo = -1, false
	}
	return e
}

func (e *edit) setSrc(a netip.Addr) { e.setAddr(12, a) }

func (e *edit) setDst(a netip.Addr) { e.setAddr(16, a) }

func (e *edit) setAddr(at int, a netip.Addr) {
	v := a.As4()
	for i := 0; i < 4; i += 2 {
		old := binary.BigEndian.Uint16(e.b[at+i:])
		nw := binary.BigEndian.Uint16(v[i:])
		updateChecksum(e.b[10:12], old, nw)
		if e.pseudo {
			e.updateTransport(old, nw)
		}
	}
	copy(e.b[at:at+4], v[:])
}

func (e *edit) setSrcPort(port uint16) { e.setPort(e.srcPort, port) }

func (e *edit) setDstPort(port uint16) { e.setPort(e.dstPort, port) }

func (e *edit) setPort(at int, port uint16) {
	if at < 0 {
		return
	}
	old := binary.BigEndian.Uint16(e.b[at:])
	binary.BigEndian.PutUint16(e.b[at:], port)
	if e.tsum >= 0 {
		e.updateTransport(old, port)
	}
}

func (e *edit) decrementTTL() {
	old := binary.BigEndian.Uint16(e.b[8:10])
	e.b[8]--
	updateChecksum(e.b[10:12], old, binary.BigEndian.Uint16(e.b[8:10]))
}

// updateTransport updates the transport checksum for a word that changed. A
// UDP checksum of 0 means none and stays 0, and one that becomes 0 is sent as
// 0xffff (RFC 768).
func (e *edit) updateTransport(old, nw uint16) {
	sum := e.b[e.tsum : e.tsum+2]
	if e.udp && binary.BigEndian.Uint16(sum) == 0 {
		return
	}
	updateChecksum(sum, old, nw)
	if e.udp && binary.BigEndian.Uint16(sum) == 0 {
		binary.BigEndian.PutUint16(sum, 0xffff)
	}
}

// editQuoted applies change to the packet the ICMP error in e quotes, q with
// the transport header qt, then recomputes the quoted header's checksum and
// the ICMP message's. The quoted transport checksum is left alone: the error
// may not carry the bytes it covers.
func (e *edit) editQuoted(q ipv4, qt transport, change func(*edit)) {
	icmp := e.b[ipv4HeaderLenOf(e.b):]
	qb := icmp[8 : 8+len(q.b)]
	qe := editOf(qb, q, qt, true)
	change(&qe)
	setChecksum(qb[:q.hl], 10)
	setChecksum(icmp, 2)
}

// ipv4HeaderLenOf returns the header length of the IPv4 packet b.
func ipv4HeaderLenOf(b []byte) int {
	return int(b[0]&0x0f) * 4
}

// updateChecksum updates the Internet checksum in sum for a 16-bit word that
// changed from old to nw: HC' = ~(~HC + ~m + m'), RFC 1624 equation 3.
func updateChecksum(sum []byte, old, nw uint16) {
	s := uint32(^binary.BigEndian.Uint16(sum)) + uint32(^old) + uint32(nw)
	s = s&0xffff + s>>16
	s = s&0xffff + s>>16
	binary.BigEndian.PutUint16(sum, ^uint16(s))
}

// setChecksum computes the Internet checksum of b with its checksum field at
// b[at:at+2] (RFC 1071) and writes it there.
func setChecksum(b []byte, at int) {
	b[at], b[at+1] = 0, 0
	binary.BigEndian.PutUint16(b[at:], ^onesSum(b))
}

// onesSum is the 16-bit one's complement sum of b.
func onesSum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

// icmpErrorPacket builds an ICMP error of typ and code from src to the source
// of p, quoting p's header and the first 8 bytes after it (RFC 792). mtu is
// the next-hop MTU of a "fragmentation needed" (RFC 1191).
func icmpErrorPacket(src netip.Addr, p ipv4, typ, code uint8, mtu int) []byte {
	quote := min(p.hl+8, len(p.b))
	b := make([]byte, ipv4HeaderLen+8+quote)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = protoICMP
	s, d := src.As4(), p.src.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	setChecksum(b[:ipv4HeaderLen], 10)

	icmp := b[ipv4HeaderLen:]
	icmp[0] = typ
	icmp[1] = code
	binary.BigEndian.PutUint16(icmp[6:8], uint16(mtu))
	copy(icmp[8:], p.b[:quote])
	setChecksum(icmp, 2)
	return b
}
