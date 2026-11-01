package wireguard_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/bridge"
	"github.com/plexsphere/plexd/internal/registration"
	"github.com/plexsphere/plexd/internal/wireguard"
)

// relayLoopback is the only loopback address every CI platform has: macOS
// configures no other 127.x address.
var relayLoopback = netip.MustParseAddr("127.0.0.1")

// relayKeepalive is the nodes' persistent keepalive. It makes one trial 6 s,
// the silence after which a relayed peer is probed.
const relayKeepalive = time.Second

// logBuffer is an io.Writer safe for a manager's or a relay's goroutines to
// log into while the test reads it.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// tunController is a WGController that runs the interface as a wireguard-go
// device of a userspace backend on a channel TUN, so the test reads and writes
// the interface's packets. A channel TUN has no address, MTU or interface
// flag, so those writes do nothing. AddPeer, RemovePeer, SetPrivateKey and
// PeerStats are the backend's.
type tunController struct {
	*wireguard.UserspaceBackend
	tun *tuntest.ChannelTUN
}

var (
	_ wireguard.WGController    = (*tunController)(nil)
	_ wireguard.PeerStatsReader = (*tunController)(nil)
)

func (c *tunController) CreateInterface(name string, privateKey []byte, _ int) error {
	return c.CreateDevice(name, c.tun.TUN(), privateKey, 0)
}

func (c *tunController) DeleteInterface(name string) error { return c.DeleteDevice(name) }

func (c *tunController) ConfigureAddress(string, string) error { return nil }

func (c *tunController) SetInterfaceUp(string) error { return nil }

func (c *tunController) SetMTU(string, int) error { return nil }

// meshNode is one node of the pair: a Manager on a channel TUN, and the
// goroutine that drains the TUN's unbuffered Inbound into received, so the
// device never blocks delivering a packet while the test is not reading.
type meshNode struct {
	id   string
	ip   netip.Addr
	key  wgtypes.Key
	tun  *tuntest.ChannelTUN
	mgr  *wireguard.Manager
	logs *logBuffer

	received chan []byte
	stop     chan struct{}
	drained  chan struct{}

	cancel   context.CancelFunc
	selected chan struct{} // closed when RunEndpointSelection returns
}

// newMeshNode sets up a Manager for id with mesh IP ip in 10.99.0.0/24, a
// keepalive of relayKeepalive and its log at Debug in a buffer of its own.
// Endpoint selection is not running yet (see startSelection). The node is
// torn down on cleanup.
func newMeshNode(t *testing.T, id, ip string) *meshNode {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	n := &meshNode{
		id:       id,
		ip:       netip.MustParseAddr(ip),
		key:      key,
		tun:      tuntest.NewChannelTUN(),
		logs:     &logBuffer{},
		received: make(chan []byte, 64),
		stop:     make(chan struct{}),
		drained:  make(chan struct{}),
	}
	ctrl := &tunController{UserspaceBackend: wireguard.NewLoopbackUserspaceBackend(t), tun: n.tun}
	keepalive := relayKeepalive
	logger := slog.New(slog.NewTextHandler(n.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	n.mgr = wireguard.NewManager(ctrl, wireguard.Config{
		InterfaceName:       "wg-" + id,
		PersistentKeepalive: &keepalive,
	}, logger)

	go n.drain()
	// Registered after the backend's cleanup, so it runs first: the manager
	// stops before the backend deletes what is left.
	t.Cleanup(func() { n.close(t) })
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%s log:\n%s", n.id, n.logs)
		}
	})

	if err := n.mgr.Setup(context.Background(), &registration.NodeIdentity{
		MeshIP:         ip,
		DomainMeshCIDR: "10.99.0.0/24",
		PrivateKey:     key[:],
	}); err != nil {
		t.Fatalf("%s: Setup: %v", id, err)
	}
	return n
}

// sendProbe is the node's relay probe: it writes a ping from the node to dst
// into the TUN, as the host routes SendRelayProbe's datagram into the mesh
// interface.
func (n *meshNode) sendProbe(dst netip.Addr) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case n.tun.Outbound <- tuntest.Ping(dst, n.ip):
		return nil
	case <-timer.C:
		return errors.New("the device did not read the probe within 1s")
	}
}

// startSelection runs endpoint selection every 100 ms until cleanup. Any
// SetRelayProbe call comes before it.
func (n *meshNode) startSelection() {
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	n.selected = make(chan struct{})
	go func() {
		defer close(n.selected)
		_ = n.mgr.RunEndpointSelection(ctx, 100*time.Millisecond)
	}()
}

func (n *meshNode) drain() {
	defer close(n.drained)
	for {
		select {
		case p := <-n.tun.Inbound:
			select {
			case n.received <- p:
			default:
				// received is full of packets nobody waits for; pings are
				// re-sent, so dropping one loses nothing.
			}
		case <-n.stop:
			return
		}
	}
}

// close stops endpoint selection, deletes the device, which closes its TUN,
// then ends the drain. The test never closes the ChannelTUN itself: a second
// close panics.
func (n *meshNode) close(t *testing.T) {
	if n.cancel != nil {
		n.cancel()
		<-n.selected
	}
	if err := n.mgr.Teardown(); err != nil {
		t.Errorf("%s: Teardown: %v", n.id, err)
	}
	close(n.stop)
	<-n.drained
}

// peerOn returns n as the mesh peer of its partner, dialed through relay
// alone: relay is its only endpoint and its fallback.
func (n *meshNode) peerOn(relay string) api.Peer {
	return api.Peer{
		ID:         n.id,
		PublicKey:  n.key.PublicKey().String(),
		MeshIP:     n.ip.String(),
		AllowedIPs: []string{netip.PrefixFrom(n.ip, 32).String()},
		Endpoint:   relay,
		Endpoints:  []string{relay},
		Fallbacks:  []string{relay},
	}
}

// peerOnSet returns n as the mesh peer of its partner, dialed through relays
// alone, in order: they are its whole dial order and its relay set.
func (n *meshNode) peerOnSet(relays ...string) api.Peer {
	p := n.peerOn(relays[0])
	p.Endpoints = relays
	p.Fallbacks = relays
	return p
}

// startRelay runs a relay for a and b on a free UDP port and returns it with
// its address, 127.0.0.1 and that port. Its log goes to logs with relay=name.
// It is stopped on cleanup.
func startRelay(t *testing.T, logs *logBuffer, name string, a, b *meshNode) (*bridge.Relay, string) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: relayLoopback.AsSlice()})
	if err != nil {
		t.Fatalf("listen on %s: %v", relayLoopback, err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("close the port probe: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})).With("relay", name)
	r := bridge.NewRelay(logger)
	if err := r.Configure(port, relayPeers(a, b)); err != nil {
		t.Fatalf("relay %s: Configure(%d): %v, want nil", name, port, err)
	}
	t.Cleanup(func() { _ = r.Stop() })
	return r, netip.AddrPortFrom(relayLoopback, uint16(port)).String()
}

// relayPeers is the peer set a relay forwards among: both nodes' keys.
func relayPeers(a, b *meshNode) []api.SnapshotPeer {
	return []api.SnapshotPeer{
		{NodeID: a.id, PublicKey: a.key.PublicKey().String()},
		{NodeID: b.id, PublicKey: b.key.PublicKey().String()},
	}
}

// relayPortOf returns the port of a relay address startRelay returned.
func relayPortOf(t *testing.T, relay string) int {
	t.Helper()
	ap, err := netip.ParseAddrPort(relay)
	if err != nil {
		t.Fatalf("parse relay address %q: %v", relay, err)
	}
	return int(ap.Port())
}

// roundPing returns tuntest's ICMP echo from src to dst carrying round in its
// IPv4 identification field, with the header checksum updated. The probe's
// pings carry 0, so round 1 and up never match one.
func roundPing(dst, src netip.Addr, round uint16) []byte {
	pkt := tuntest.Ping(dst, src)
	binary.BigEndian.PutUint16(pkt[4:6], round)
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))
	return pkt
}

// pingBoth sends a ping from a to b and one from b to a about once a second
// until both have arrived, and fails the test if that takes longer than
// within. Every ping of a round carries the round number, so a late copy of an
// earlier round's ping cannot pass for this round's; any copy of this round's
// ping counts, since WireGuard may deliver one queued before its handshake.
func pingBoth(t *testing.T, a, b *meshNode, round uint16, within time.Duration) {
	t.Helper()
	toB := roundPing(b.ip, a.ip, round)
	toA := roundPing(a.ip, b.ip, round)

	start := time.Now()
	expired := time.After(within)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var atB, atA bool
	fail := func() {
		t.Helper()
		t.Fatalf("round %d: after %v the ping from %s to %s arrived = %t, the ping from %s to %s arrived = %t, want both",
			round, within, a.id, b.id, atB, b.id, a.id, atA)
	}
	send := func(from *meshNode, pkt []byte) {
		t.Helper()
		select {
		case from.tun.Outbound <- pkt:
		case <-expired:
			fail()
		}
	}

	resend := true
	for !atB || !atA {
		if resend {
			if !atB {
				send(a, toB)
			}
			if !atA {
				send(b, toA)
			}
			resend = false
		}
		select {
		case p := <-b.received:
			atB = atB || bytes.Equal(p, toB)
		case p := <-a.received:
			atA = atA || bytes.Equal(p, toA)
		case <-ticker.C:
			resend = true
		case <-expired:
			fail()
		}
	}
	t.Logf("round %d: pings crossed both ways after %v", round, time.Since(start).Round(time.Millisecond))
}

// logged reports whether one line of log has msg and every one of the
// key=value fields.
func logged(log, msg string, fields ...string) bool {
	for line := range strings.SplitSeq(log, "\n") {
		if !strings.Contains(line, `msg="`+msg+`"`) {
			continue
		}
		words := strings.Fields(line)
		if !slices.ContainsFunc(fields, func(f string) bool { return !slices.Contains(words, f) }) {
			return true
		}
	}
	return false
}

// waitFor polls cond every 50 ms until it holds and reports whether it did
// within.
func waitFor(within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		<-ticker.C
	}
	return true
}

// waitSelectedRelayed waits until n's log says its peer, partner, connected
// over the relay.
func waitSelectedRelayed(t *testing.T, n, partner *meshNode) {
	t.Helper()
	fields := []string{"peer_id=" + partner.id, "relayed=true"}
	if !waitFor(5*time.Second, func() bool { return logged(n.logs.String(), "wireguard: endpoint selected", fields...) }) {
		t.Fatalf(`%s: no "wireguard: endpoint selected" line with %v within 5s`, n.id, fields)
	}
}

// addPeers adds each of a and b as the other's peer on relay.
func addPeers(t *testing.T, a, b *meshNode, relay string) {
	t.Helper()
	if err := a.mgr.AddPeer(b.peerOn(relay)); err != nil {
		t.Fatalf("%s: AddPeer(%s): %v", a.id, b.id, err)
	}
	if err := b.mgr.AddPeer(a.peerOn(relay)); err != nil {
		t.Fatalf("%s: AddPeer(%s): %v", b.id, a.id, err)
	}
}

// dumpOnFailure logs the relays' log when the test fails.
func dumpOnFailure(t *testing.T, logs *logBuffer) {
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay log:\n%s", logs)
		}
	})
}

// relayFrontBufSize holds the largest UDP datagram.
const relayFrontBufSize = 65535

// movedBackLine is what a node logs when it moves a peer back from a relay its
// session does not run over.
const movedBackLine = "wireguard: relayed peer roamed to a relay its session does not run over, moving it back"

// frontDatagram is one datagram a node sent while a relayFront was frozen, and
// the node's address.
type frontDatagram struct {
	src netip.AddrPort
	b   []byte
}

// relayFront is a UDP socket nodes dial as the relay, which forwards their
// datagrams to the real relay and its answers back. It freezes a relay the way
// pausing a guest does: what the nodes send waits and comes out in order at the
// resume, where stopping the relay would discard it. The relay's clock keeps
// running, which does not matter under the relay's 180 s index TTL: the
// session stays as fresh to it as a clock that stood still would keep it.
//
// Every node's source is 127.0.0.1, so a source is keyed by its netip.AddrPort,
// and each one gets a back socket of its own, because the relay tells peers
// apart by the address it reads them from.
type relayFront struct {
	t     *testing.T
	conn  *net.UDPConn
	addr  netip.AddrPort
	relay netip.AddrPort

	nodesRead chan struct{}  // closed when readNodes returns
	answers   sync.WaitGroup // counts the readRelay goroutines

	// mu guards backs, frozen and queue. thaw holds it through the replay, and
	// readNodes takes it per datagram, so nothing overtakes the queue.
	mu     sync.Mutex
	backs  map[netip.AddrPort]*net.UDPConn
	frozen bool
	queue  []frontDatagram
}

// newRelayFront starts a front before the relay at address relay. It is closed
// on cleanup.
func newRelayFront(t *testing.T, relay string) *relayFront {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: relayLoopback.AsSlice()})
	if err != nil {
		t.Fatalf("listen on %s: %v", relayLoopback, err)
	}
	f := &relayFront{
		t:         t,
		conn:      conn,
		addr:      netip.AddrPortFrom(relayLoopback, uint16(conn.LocalAddr().(*net.UDPAddr).Port)),
		relay:     netip.MustParseAddrPort(relay),
		nodesRead: make(chan struct{}),
		backs:     make(map[netip.AddrPort]*net.UDPConn),
	}
	go f.readNodes()
	t.Cleanup(f.close)
	return f
}

// readNodes queues or forwards each node's datagrams until the front socket
// closes. Like the relay's dispatch loop, it ends on a closed socket alone and
// skips any other read error.
func (f *relayFront) readNodes() {
	defer close(f.nodesRead)
	buf := make([]byte, relayFrontBufSize)
	for {
		n, src, err := f.conn.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())

		f.mu.Lock()
		if f.frozen {
			f.queue = append(f.queue, frontDatagram{src: src, b: bytes.Clone(buf[:n])})
		} else if err := f.forward(src, buf[:n]); err != nil {
			f.t.Errorf("front: forward a datagram from %s: %v", src, err)
		}
		f.mu.Unlock()
	}
}

// forward writes b to the relay from src's back socket, which src's first
// datagram opens. Callers hold f.mu.
func (f *relayFront) forward(src netip.AddrPort, b []byte) error {
	back, ok := f.backs[src]
	if !ok {
		var err error
		back, err = net.ListenUDP("udp4", &net.UDPAddr{IP: relayLoopback.AsSlice()})
		if err != nil {
			return err
		}
		f.backs[src] = back
		f.answers.Add(1)
		go f.readRelay(back, src)
	}
	_, err := back.WriteToUDPAddrPort(b, f.relay)
	return err
}

// readRelay forwards the relay's datagrams on back to node from the front
// socket until back closes. A write that fails loses one datagram, as a
// network may.
func (f *relayFront) readRelay(back *net.UDPConn, node netip.AddrPort) {
	defer f.answers.Done()
	buf := make([]byte, relayFrontBufSize)
	for {
		n, _, err := back.ReadFromUDPAddrPort(buf)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		_, _ = f.conn.WriteToUDPAddrPort(buf[:n], node)
	}
}

// freeze makes the front queue what nodes send, in order, with their sources.
func (f *relayFront) freeze() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frozen = true
}

// thaw replays the queue in order at full speed, as a resumed relay drains its
// socket, and forwards what nodes send from then on. The queue stays readable
// through initiations.
func (f *relayFront) thaw() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frozen = false
	for _, d := range f.queue {
		if err := f.forward(d.src, d.b); err != nil {
			return err
		}
	}
	return nil
}

// inject writes b to the node at to from the front socket, bypassing the
// relay, so the node reads it as coming from the relay it dials.
func (f *relayFront) inject(to netip.AddrPort, b []byte) error {
	_, err := f.conn.WriteToUDPAddrPort(b, to)
	return err
}

// initiations returns the handshake initiations in the queue per source,
// oldest first, during the freeze and after the thaw alike.
func (f *relayFront) initiations() map[netip.AddrPort][][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	queued := make(map[netip.AddrPort][][]byte)
	for _, d := range f.queue {
		if len(d.b) == device.MessageInitiationSize && d.b[0] == device.MessageInitiationType {
			queued[d.src] = append(queued[d.src], d.b)
		}
	}
	return queued
}

// close ends both kinds of goroutine. readNodes goes first: it is what opens a
// back socket, so none opens after the loop that closes them.
func (f *relayFront) close() {
	_ = f.conn.Close()
	<-f.nodesRead

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, back := range f.backs {
		_ = back.Close()
	}
	f.answers.Wait()
}

// heldOn counts the initiations the relay name held back, in log.
func heldOn(log, name string) int {
	n := 0
	for line := range strings.SplitSeq(log, "\n") {
		if logged(line, "relay: dropped datagram", "relay="+name, "reason=held_for_retry") {
			n++
		}
	}
	return n
}

// deviceStat returns n's device state of its peer partner, and false when the
// device does not list it, as for a moment during a re-dial.
func deviceStat(t *testing.T, n, partner *meshNode) (wireguard.MeshPeerStat, bool) {
	t.Helper()
	stats, err := n.mgr.MeshPeerStats()
	if err != nil {
		t.Fatalf("%s: MeshPeerStats: %v", n.id, err)
	}
	i := slices.IndexFunc(stats, func(s wireguard.MeshPeerStat) bool { return s.NodeID == partner.id })
	if i < 0 {
		return wireguard.MeshPeerStat{}, false
	}
	return stats[i], true
}

// deviceEndpoint returns the endpoint of s in the form relay addresses have.
func deviceEndpoint(s wireguard.MeshPeerStat) netip.AddrPort {
	return netip.AddrPortFrom(s.Endpoint.Addr().Unmap(), s.Endpoint.Port())
}

// pingEverySecond writes a ping from each of a and b to the other into its TUN
// once a second, the first ones at once, until stop is called. Each write gives
// up on stop, so a device that no longer reads its TUN cannot keep the goroutine
// alive. stop returns once the goroutine has ended, and a second call does
// nothing.
func pingEverySecond(a, b *meshNode) (stop func()) {
	done := make(chan struct{})
	ended := make(chan struct{})
	send := func(from, to *meshNode) bool {
		select {
		case from.tun.Outbound <- tuntest.Ping(to.ip, from.ip):
			return true
		case <-done:
			return false
		}
	}
	go func() {
		defer close(ended)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for send(a, b) && send(b, a) {
			select {
			case <-ticker.C:
			case <-done:
				return
			}
		}
	}()
	return sync.OnceFunc(func() {
		close(done)
		<-ended
	})
}

// TestRelayIntegration_FallbackChangeMovesThePairAtOnce connects two Managers
// over relay E, stops E, and names relay F as both peers' fallback. Each
// Manager writes its peer anew on F, so the pair handshakes over F at once
// instead of after the relay's trial, when endpoint selection would dial F
// again, or WireGuard's 15 s data retransmit.
func TestRelayIntegration_FallbackChangeMovesThePairAtOnce(t *testing.T) {
	t.Parallel()
	relayLogs := &logBuffer{}
	dumpOnFailure(t, relayLogs)

	a := newMeshNode(t, "node-a", "10.99.0.1")
	b := newMeshNode(t, "node-b", "10.99.0.2")
	relayE, e := startRelay(t, relayLogs, "E", a, b)
	_, f := startRelay(t, relayLogs, "F", a, b)

	a.mgr.SetRelayProbe(a.sendProbe)
	b.mgr.SetRelayProbe(b.sendProbe)
	a.startSelection()
	b.startSelection()

	addPeers(t, a, b, e)
	pingBoth(t, a, b, 1, 20*time.Second)
	waitSelectedRelayed(t, a, b)
	waitSelectedRelayed(t, b, a)

	if err := relayE.Stop(); err != nil {
		t.Fatalf("relay E: Stop: %v, want nil", err)
	}
	if err := a.mgr.UpdatePeer(b.peerOn(f)); err != nil {
		t.Fatalf("%s: UpdatePeer(%s) on F: %v, want nil", a.id, b.id, err)
	}
	if err := b.mgr.UpdatePeer(a.peerOn(f)); err != nil {
		t.Fatalf("%s: UpdatePeer(%s) on F: %v, want nil", b.id, a.id, err)
	}

	// Below the relay's trial, 6 s, after which endpoint selection would dial
	// F again on its own, and below WireGuard's 15 s data retransmit: only the
	// move itself can get the pair across in time.
	pingBoth(t, a, b, 2, 5*time.Second)

	for _, n := range []struct{ node, partner *meshNode }{{a, b}, {b, a}} {
		fields := []string{"peer_id=" + n.partner.id, "from=" + e, "to=" + f}
		if !logged(n.node.logs.String(), "wireguard: relay fallback changed, moving to the new relay", fields...) {
			t.Errorf(`%s: no "wireguard: relay fallback changed, moving to the new relay" line with %v`, n.node.id, fields)
		}
	}
}

// TestRelayIntegration_ProbeRedialsARestartedRelay restarts the relay under a
// connected pair, which loses the relay's index table, and sends no traffic.
// Nothing but the relay probe sends data then, so without it the pair waits
// for the initiator's 120 s rekey. With it, each Manager probes its silent
// peer after one trial and dials the relay again when the probe goes
// unanswered.
func TestRelayIntegration_ProbeRedialsARestartedRelay(t *testing.T) {
	t.Parallel()
	relayLogs := &logBuffer{}
	dumpOnFailure(t, relayLogs)

	a := newMeshNode(t, "node-a", "10.99.0.1")
	b := newMeshNode(t, "node-b", "10.99.0.2")
	relayE, e := startRelay(t, relayLogs, "E", a, b)

	a.mgr.SetRelayProbe(a.sendProbe)
	b.mgr.SetRelayProbe(b.sendProbe)
	a.startSelection()
	b.startSelection()

	addPeers(t, a, b, e)
	pingBoth(t, a, b, 1, 20*time.Second)
	waitSelectedRelayed(t, a, b)
	waitSelectedRelayed(t, b, a)

	if err := relayE.Stop(); err != nil {
		t.Fatalf("relay E: Stop: %v, want nil", err)
	}
	// No handshake completes while nothing listens on E's port, so one later
	// than this went through the restarted relay.
	restartedAt := time.Now()
	port := relayPortOf(t, e)
	if err := relayE.Configure(port, relayPeers(a, b)); err != nil {
		t.Fatalf("relay E: Configure(%d) after Stop: %v, want nil", port, err)
	}

	handshook := func(n, partner *meshNode) bool {
		stats, err := n.mgr.MeshPeerStats()
		if err != nil {
			t.Fatalf("%s: MeshPeerStats: %v", n.id, err)
		}
		i := slices.IndexFunc(stats, func(s wireguard.MeshPeerStat) bool { return s.NodeID == partner.id })
		return i >= 0 && stats[i].LastHandshake.After(restartedAt)
	}
	if !waitFor(45*time.Second, func() bool { return handshook(a, b) && handshook(b, a) }) {
		t.Fatalf("after 45s a handshake later than the relay restart: %s = %t, %s = %t, want both",
			a.id, handshook(a, b), b.id, handshook(b, a))
	}
	t.Logf("both nodes handshook over the restarted relay after %v", time.Since(restartedAt).Round(time.Millisecond))

	pingBoth(t, a, b, 2, 10*time.Second)
}

// TestRelayIntegration_PairFailsOverToTheStandbyOnItsOwn connects two Managers
// over relay E, the first of their relay set E, F, and stops E without telling
// either Manager. Each one probes its silent peer, gets no answer and dials F,
// the next relay of the set, so the pair handshakes over F with no update in
// between.
func TestRelayIntegration_PairFailsOverToTheStandbyOnItsOwn(t *testing.T) {
	t.Parallel()
	relayLogs := &logBuffer{}
	dumpOnFailure(t, relayLogs)

	a := newMeshNode(t, "node-a", "10.99.0.1")
	b := newMeshNode(t, "node-b", "10.99.0.2")
	relayE, e := startRelay(t, relayLogs, "E", a, b)
	_, f := startRelay(t, relayLogs, "F", a, b)

	a.mgr.SetRelayProbe(a.sendProbe)
	b.mgr.SetRelayProbe(b.sendProbe)
	a.startSelection()
	b.startSelection()

	if err := a.mgr.AddPeer(b.peerOnSet(e, f)); err != nil {
		t.Fatalf("%s: AddPeer(%s): %v", a.id, b.id, err)
	}
	if err := b.mgr.AddPeer(a.peerOnSet(e, f)); err != nil {
		t.Fatalf("%s: AddPeer(%s): %v", b.id, a.id, err)
	}
	pingBoth(t, a, b, 1, 20*time.Second)
	waitSelectedRelayed(t, a, b)
	waitSelectedRelayed(t, b, a)

	if err := relayE.Stop(); err != nil {
		t.Fatalf("relay E: Stop: %v, want nil", err)
	}
	// No handshake completes over E once it stopped, so one later than this
	// that the device reports at F's address went through F.
	stoppedAt := time.Now()
	relayF := netip.MustParseAddrPort(f)

	overF := func(n, partner *meshNode) bool {
		stats, err := n.mgr.MeshPeerStats()
		if err != nil {
			t.Fatalf("%s: MeshPeerStats: %v", n.id, err)
		}
		i := slices.IndexFunc(stats, func(s wireguard.MeshPeerStat) bool { return s.NodeID == partner.id })
		if i < 0 {
			return false
		}
		endpoint := netip.AddrPortFrom(stats[i].Endpoint.Addr().Unmap(), stats[i].Endpoint.Port())
		return stats[i].LastHandshake.After(stoppedAt) && endpoint == relayF
	}
	if !waitFor(45*time.Second, func() bool { return overF(a, b) && overF(b, a) }) {
		t.Fatalf("after 45s a handshake over F later than E's stop: %s = %t, %s = %t, want both",
			a.id, overF(a, b), b.id, overF(b, a))
	}
	t.Logf("both nodes handshook over the standby relay after %v", time.Since(stoppedAt).Round(time.Millisecond))

	pingBoth(t, a, b, 2, 10*time.Second)

	for _, n := range []struct{ node, partner *meshNode }{{a, b}, {b, a}} {
		log := n.node.logs.String()
		fields := []string{"peer_id=" + n.partner.id, "from=" + e, "endpoint=" + f}
		if !logged(log, "wireguard: relayed peer did not answer the probe, dialing the relay again", fields...) {
			t.Errorf(`%s: no "wireguard: relayed peer did not answer the probe, dialing the relay again" line with %v`, n.node.id, fields)
		}
		if logged(log, "wireguard: relay fallback changed, moving to the new relay") {
			t.Errorf(`%s: logged "wireguard: relay fallback changed, moving to the new relay", want no update`, n.node.id)
		}
	}
}

// TestRelayIntegration_ResumedRelayLeavesThePairAlone freezes relay F under a
// connected pair behind a relayFront. Unanswered data makes each node's
// WireGuard send initiations, which queue on the frozen relay, and each Manager
// probes its silent peer and dials the standby E on a fresh device peer. Of the
// handshake on E, the initiator keeps no timestamp of its partner, so it would
// accept any queued initiation of the partner, and WireGuard would move its
// endpoint to F, which does not know the session.
//
// So when F resumes, it must hold the backlog back and the pair must not notice.
// The test then injects the queued initiations past the relay, the stale packet
// no relay can stop, and the node must move its peer back to E within one pass
// and keep the session.
func TestRelayIntegration_ResumedRelayLeavesThePairAlone(t *testing.T) {
	t.Parallel()
	relayLogs := &logBuffer{}
	dumpOnFailure(t, relayLogs)

	a := newMeshNode(t, "node-a", "10.99.0.1")
	b := newMeshNode(t, "node-b", "10.99.0.2")
	_, e := startRelay(t, relayLogs, "E", a, b)
	_, f := startRelay(t, relayLogs, "F", a, b)
	front := newRelayFront(t, f)

	a.mgr.SetRelayProbe(a.sendProbe)
	b.mgr.SetRelayProbe(b.sendProbe)
	a.startSelection()
	b.startSelection()

	if err := a.mgr.AddPeer(b.peerOnSet(front.addr.String(), e)); err != nil {
		t.Fatalf("%s: AddPeer(%s): %v", a.id, b.id, err)
	}
	if err := b.mgr.AddPeer(a.peerOnSet(front.addr.String(), e)); err != nil {
		t.Fatalf("%s: AddPeer(%s): %v", b.id, a.id, err)
	}
	pingBoth(t, a, b, 1, 20*time.Second)
	waitSelectedRelayed(t, a, b)
	waitSelectedRelayed(t, b, a)

	front.freeze()
	// No handshake completes over the frozen relay, so one later than this
	// that the device reports at E's address went through E.
	frozenAt := time.Now()
	relayE := netip.MustParseAddrPort(e)

	// The keepalives are not data, so they start no handshake. WireGuard's
	// 15 s timer starts with the first unanswered ping, and fires inside the
	// roughly 21 s the probe takes to condemn the relay.
	stopPings := pingEverySecond(a, b)
	defer stopPings()

	overE := func(n, partner *meshNode) bool {
		stat, ok := deviceStat(t, n, partner)
		return ok && stat.LastHandshake.After(frozenAt) && deviceEndpoint(stat) == relayE
	}
	if !waitFor(45*time.Second, func() bool { return overE(a, b) && overE(b, a) }) {
		t.Fatalf("after 45s a handshake over E later than the freeze: %s = %t, %s = %t, want both",
			a.id, overE(a, b), b.id, overE(b, a))
	}
	stopPings()
	t.Logf("both nodes handshook over the standby relay after %v", time.Since(frozenAt).Round(time.Millisecond))

	queued := front.initiations()
	counts := make(map[string]int, len(queued))
	for src, initiations := range queued {
		counts[src.String()] = len(initiations)
	}
	if len(queued) != 2 {
		t.Fatalf("queued initiations per source before the thaw = %v, want at least one from each of the two nodes", counts)
	}
	t.Logf("queued initiations per source: %v", counts)

	type side struct{ node, partner *meshNode }
	sides := []side{{a, b}, {b, a}}

	handshakes := make(map[string]time.Time, len(sides))
	for _, s := range sides {
		stat, ok := deviceStat(t, s.node, s.partner)
		if !ok {
			t.Fatalf("%s: the device does not list %s before the thaw", s.node.id, s.partner.id)
		}
		handshakes[s.node.id] = stat.LastHandshake
	}

	if err := front.thaw(); err != nil {
		t.Fatalf("thaw the front: %v", err)
	}
	thawedAt := time.Now()

	// A roamed endpoint lasts at most until the partner's next packet, 1 s at
	// this keepalive, so every sample has to look, and a pass may restore it
	// before one does, which the log line then shows.
	sample := time.NewTicker(50 * time.Millisecond)
	defer sample.Stop()
	for time.Since(thawedAt) < 3*time.Second {
		for _, s := range sides {
			stat, ok := deviceStat(t, s.node, s.partner)
			if !ok {
				t.Fatalf("%s: %v after the thaw the device does not list %s", s.node.id, time.Since(thawedAt).Round(time.Millisecond), s.partner.id)
			}
			if endpoint := deviceEndpoint(stat); endpoint == front.addr {
				t.Fatalf("%s: %v after the thaw the device endpoint of %s is the resumed relay %s, want E %s",
					s.node.id, time.Since(thawedAt).Round(time.Millisecond), s.partner.id, endpoint, relayE)
			}
			if !stat.LastHandshake.Equal(handshakes[s.node.id]) {
				t.Fatalf("%s: %v after the thaw the last handshake with %s is %v, want %v unchanged",
					s.node.id, time.Since(thawedAt).Round(time.Millisecond), s.partner.id, stat.LastHandshake, handshakes[s.node.id])
			}
			if logged(s.node.logs.String(), movedBackLine) {
				t.Fatalf("%s: %v after the thaw logged %q, want nothing to move back",
					s.node.id, time.Since(thawedAt).Round(time.Millisecond), movedBackLine)
			}
		}
		<-sample.C
	}

	// A front that lost the backlog would pass everything above too.
	if held := heldOn(relayLogs.String(), "F"); held < len(queued) {
		t.Errorf("relay F held %d initiations after the thaw, want at least one from each of the %d nodes", held, len(queued))
	}

	pingBoth(t, a, b, 2, 2*time.Second)

	// pingBoth just restarted the partner's 1 s keepalive timer, so the 100 ms
	// pass runs before the partner's next packet could heal the device. The
	// node that was the handshake's initiator accepts an injected initiation
	// and the other refuses it, so one direction of each round is a no-op.
	sources := slices.Collect(maps.Keys(queued))
	rounds := max(len(queued[sources[0]]), len(queued[sources[1]]))
	injected := 0
	var injectedAt time.Time
	movedBack := func() int {
		return slices.IndexFunc(sides, func(s side) bool { return logged(s.node.logs.String(), movedBackLine) })
	}
	if !waitFor(5*time.Second, func() bool {
		if movedBack() >= 0 {
			return true
		}
		if injected == rounds || time.Since(injectedAt) < 300*time.Millisecond {
			return false
		}
		for i, src := range sources {
			if injected >= len(queued[src]) {
				continue
			}
			if err := front.inject(sources[1-i], queued[src][injected]); err != nil {
				t.Fatalf("inject an initiation from %s at %s: %v", src, sources[1-i], err)
			}
		}
		injected++
		injectedAt = time.Now()
		return false
	}) {
		ending := "before injection ran out of initiations"
		if injected == rounds {
			ending = "and injection ran out of initiations"
		}
		t.Fatalf("after 5s neither node logged %q: %d of %d rounds injected from %v %s",
			movedBackLine, injected, rounds, counts, ending)
	}
	moved := sides[movedBack()]
	t.Logf("%s moved its peer back after %d of %d rounds of injected initiations", moved.node.id, injected, rounds)

	// The partner's next packet would heal the device too, but it is up to 1 s
	// away: only the write puts the device back on E this soon.
	if stat, ok := deviceStat(t, moved.node, moved.partner); !ok || deviceEndpoint(stat) != relayE {
		t.Fatalf("%s: right after the move back the device endpoint of %s is %v (listed = %t), want E %s",
			moved.node.id, moved.partner.id, stat.Endpoint, ok, relayE)
	}

	pingBoth(t, a, b, 3, 2*time.Second)

	// The write kept the session: a re-dial would have needed a new handshake
	// for the pings above.
	stat, ok := deviceStat(t, moved.node, moved.partner)
	if !ok {
		t.Fatalf("%s: the device does not list %s after the move back", moved.node.id, moved.partner.id)
	}
	if !stat.LastHandshake.Equal(handshakes[moved.node.id]) {
		t.Errorf("%s: the last handshake with %s after the move back is %v, want %v unchanged",
			moved.node.id, moved.partner.id, stat.LastHandshake, handshakes[moved.node.id])
	}
}
