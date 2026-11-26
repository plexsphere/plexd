package bridge

import (
	"net/netip"
	"slices"
	"time"

	"github.com/plexsphere/plexd/internal/bridge/relaybpf"
)

// relayKernelRetry is how long the relay waits before it offers the kernel a
// session again that it could not take.
const relayKernelRetry = 5 * time.Second

// relayKernelFlow is what the kernel holds for one session index: transport
// datagrams from partner that name the index go to owner.
type relayKernelFlow struct{ partner, owner netip.AddrPort }

// relayKernel forwards the transport datagrams of placed sessions without
// the process. Every method is called with r.mu held.
type relayKernel interface {
	// forward installs or replaces the session of index.
	forward(index uint32, flow relayKernelFlow) error
	// forget removes the session of index. An index the kernel does not hold is no error.
	forget(index uint32) error
	// age returns how long ago the kernel last forwarded a datagram naming index.
	age(index uint32) (time.Duration, bool, error)
	// ages returns age for every index the kernel holds.
	ages() (map[uint32]time.Duration, error)
	// refresh resolves the routes again and returns the indices it forgot
	// because their route or source address changed.
	refresh() []uint32
	// counters returns the program's counters by name.
	counters() (map[string]uint64, error)
	close() error
}

// useKernel lets every later start of the relay try the kernel path, through
// meshIface, which the program asks for its routes. On a platform without a
// kernel path it only records the name: newKernel stays nil there and the
// relay forwards in the process. A run already started keeps the path it has.
//
// It takes r.life because Configure reads newKernel under it, and r.mu
// because the sweeper reads meshIface under that.
func (r *Relay) useKernel(meshIface string) {
	r.life.Lock()
	defer r.life.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.meshIface = meshIface
	newKernel := platformRelayKernel()
	if newKernel == nil {
		return
	}
	logger := r.logger
	r.newKernel = func(port int) (relayKernel, error) {
		return newKernel(port, meshIface, logger)
	}
}

// kernelOn reports whether the current run forwards through the kernel.
func (r *Relay) kernelOn() bool {
	return r.run != nil && r.run.kernel != nil
}

// kernelForward offers the kernel the session of index i, which the process
// has just forwarded a transport datagram of, so that the next datagrams of
// flow bypass the process. It does nothing while the kernel holds flow for
// the index already, because then the kernel passed this datagram up for a
// reason of its own that installing the flow again would not change, and
// nothing until relayKernelRetry has passed since the kernel refused the
// index. A refusal never stops the kernel path: the session stays in the
// process.
func (r *Relay) kernelForward(i uint32, idx *relayIndex, flow relayKernelFlow, now time.Time) {
	if !r.kernelOn() || idx.kernel == flow || now.Before(idx.kernelRetryAt) {
		return
	}
	if err := r.run.kernel.forward(i, flow); err != nil {
		idx.kernel = relayKernelFlow{}
		idx.kernelRetryAt = now.Add(relayKernelRetry)
		r.logger.Debug("relay: kernel session not installed",
			"partner_id", idx.partner.nodeID, "owner_id", idx.owner.nodeID, "error", err)
		return
	}
	idx.kernel = flow
	r.logger.Debug("relay: kernel session installed",
		"partner_id", idx.partner.nodeID, "owner_id", idx.owner.nodeID)
}

// kernelForget takes the session of index i out of the kernel when the kernel
// holds one for idx. A kernel that cannot forget would keep forwarding a
// session the table no longer has, so an error ends the kernel path.
func (r *Relay) kernelForget(i uint32, idx *relayIndex) {
	if !r.kernelOn() || idx.kernel == (relayKernelFlow{}) {
		return
	}
	idx.kernel = relayKernelFlow{}
	if err := r.run.kernel.forget(i); err != nil {
		r.kernelStop(err)
	}
}

// kernelForgetPeers takes out of the kernel every session index that names
// one of peers as owner or partner. The kernel holds the addresses a session
// had when it was installed, so after an address moved it would send to the
// old one, or drop what arrives from the new one. The next datagram of each
// such session reaches the process, which forwards it to the new address and
// installs the session again.
func (r *Relay) kernelForgetPeers(peers ...*relayPeer) {
	if !r.kernelOn() {
		return
	}
	for i, idx := range r.indices {
		if slices.Contains(peers, idx.owner) || slices.Contains(peers, idx.partner) {
			r.kernelForget(i, idx)
		}
	}
}

// kernelSync copies to the table when the kernel last forwarded a datagram of
// each session it holds, because the datagrams the kernel forwards never move
// used in the process. Every index the kernel returns that the table does not
// hold as a session index installed in the kernel is a stray and is
// forgotten. An error ends the kernel path.
func (r *Relay) kernelSync(now time.Time) {
	if !r.kernelOn() {
		return
	}
	ages, err := r.run.kernel.ages()
	if err != nil {
		r.kernelStop(err)
		return
	}
	for i, age := range ages {
		idx, ok := r.indices[i]
		if ok && idx.kernel != (relayKernelFlow{}) {
			kernelSeen(idx, now.Add(-age))
			continue
		}
		if err := r.run.kernel.forget(i); err != nil {
			r.kernelStop(err)
			return
		}
	}
}

// kernelSyncIndex is kernelSync for index i alone, for a decision that reads
// one session's used between two sweeps. An index the kernel does not hold
// keeps its used.
func (r *Relay) kernelSyncIndex(i uint32, idx *relayIndex, now time.Time) {
	if !r.kernelOn() || idx.kernel == (relayKernelFlow{}) {
		return
	}
	age, ok, err := r.run.kernel.age(i)
	if err != nil {
		r.kernelStop(err)
		return
	}
	if ok {
		kernelSeen(idx, now.Add(-age))
	}
}

// kernelSeen raises idx.used to t, when the kernel last forwarded a datagram
// of idx, and the partner's seen with it while the partner still has the
// address the kernel matched that datagram against.
func kernelSeen(idx *relayIndex, t time.Time) {
	if t.After(idx.used) {
		idx.used = t
	}
	if idx.partner.addr == idx.kernel.partner && t.After(idx.partner.seen) {
		idx.partner.seen = t
	}
}

// kernelStop ends the kernel path of the run after err, a read or write of
// the kernel's table that failed. The run goes on forwarding in the process
// until the relay starts again. A kernel the process cannot read would keep
// forwarding sessions whose used no longer moves, and the sweep would cut
// them after relayIndexTTL.
func (r *Relay) kernelStop(err error) {
	if !r.kernelOn() {
		return
	}
	k := r.run.kernel
	r.run.kernel = nil
	if cerr := k.close(); cerr != nil {
		r.logger.Debug("relay: kernel forwarding close failed", "error", cerr)
	}
	for _, idx := range r.indices {
		idx.kernel = relayKernelFlow{}
	}
	r.logger.Warn("relay: kernel forwarding stopped, forwarding in the process", "error", err)
}

// kernelRefresh has the kernel resolve its routes again and clears kernel on
// every index it forgot because a route or source address changed, so the
// next transport datagram of each installs it again with the new route.
func (r *Relay) kernelRefresh() {
	if !r.kernelOn() {
		return
	}
	for _, i := range r.run.kernel.refresh() {
		if idx, ok := r.indices[i]; ok {
			idx.kernel = relayKernelFlow{}
		}
	}
}

// kernelCounters logs the program's counters at Debug. When fib_fwd_disabled
// grew since the last sweep, the route lookups through the mesh interface
// fail because forwarding is off on it, so every transport datagram passes
// to the process; that is logged at Warn, at most once per
// relayFullWarnInterval. An error ends the kernel path.
func (r *Relay) kernelCounters(now time.Time) {
	if !r.kernelOn() {
		return
	}
	counters, err := r.run.kernel.counters()
	if err != nil {
		r.kernelStop(err)
		return
	}
	args := make([]any, 0, 2*len(relaybpf.CounterNames))
	for _, name := range relaybpf.CounterNames {
		args = append(args, name, counters[name])
	}
	r.logger.Debug("relay: kernel forwarding counters", args...)

	fwdDisabled := counters["fib_fwd_disabled"]
	grew := fwdDisabled > r.fwdDisabled
	r.fwdDisabled = fwdDisabled
	if grew && (r.fwdDisabledWarnedAt.IsZero() || now.Sub(r.fwdDisabledWarnedAt) >= relayFullWarnInterval) {
		r.fwdDisabledWarnedAt = now
		r.logger.Warn("relay: kernel forwarding passes datagrams to the process, forwarding is off on the mesh interface",
			"mesh_interface", r.meshIface)
	}
}

// setIndex records idx as index i. An entry it replaces leaves the kernel
// first: a handshake that reuses an index must not leave the kernel
// forwarding the old session's datagrams to its owner.
func (r *Relay) setIndex(i uint32, idx *relayIndex) {
	if old, ok := r.indices[i]; ok {
		r.kernelForget(i, old)
	}
	r.indices[i] = idx
}

// dropIndex deletes index i from the table and takes it out of the kernel.
func (r *Relay) dropIndex(i uint32) {
	if old, ok := r.indices[i]; ok {
		r.kernelForget(i, old)
		delete(r.indices, i)
	}
}
