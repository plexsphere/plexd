package wireguard_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
		Fallback:   relay,
	}
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
