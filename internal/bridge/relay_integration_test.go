package bridge

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/plexsphere/plexd/internal/api"
)

// natLoopback is the only loopback address every CI platform has: macOS
// configures no other 127.x address.
var natLoopback = netip.MustParseAddr("127.0.0.1")

// integLogBuffer is an io.Writer safe for the relay's and the devices'
// goroutines to log into while the test reads it.
type integLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *integLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *integLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// natListen binds a UDP socket on 127.0.0.1 and a port the kernel picks.
func natListen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: natLoopback.AsSlice()})
	if err != nil {
		t.Fatalf("listen on %s: %v", natLoopback, err)
	}
	return c
}

func natLocalAddr(c *net.UDPConn) netip.AddrPort {
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// natShim is a symmetric NAT in front of one device. The device sends to the
// inside socket, and the shim forwards each datagram to dst from an outside
// socket of its own, so dst sees a port the device never learns. A reply is
// admitted only when it comes from dst, and is sent to the device from the
// inside socket. The device reaches no destination but dst through the shim,
// so the shim holds one mapping.
type natShim struct {
	dst    netip.AddrPort
	inside *net.UDPConn

	mu      sync.Mutex
	device  netip.AddrPort // the last source seen on inside
	outside *net.UDPConn

	wg   sync.WaitGroup
	once sync.Once
}

// natStartShim starts a shim that forwards to dst. It is closed on cleanup.
func natStartShim(t *testing.T, dst netip.AddrPort) *natShim {
	t.Helper()
	s := &natShim{dst: dst, inside: natListen(t)}
	t.Cleanup(s.close)
	s.rebind(t)
	s.wg.Add(1)
	go s.serveInside()
	return s
}

func (s *natShim) insideAddr() netip.AddrPort { return natLocalAddr(s.inside) }

// rebind replaces the outside socket with one on a new port and closes the
// old one, as a NAT does when it drops a mapping and opens another, and
// returns the new outside address. The new socket is bound before the old one
// closes, so it cannot get the old port back.
func (s *natShim) rebind(t *testing.T) netip.AddrPort {
	t.Helper()
	out := natListen(t)
	s.mu.Lock()
	old := s.outside
	s.outside = out
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	s.wg.Add(1)
	go s.serveOutside(out)
	return natLocalAddr(out)
}

// close closes every socket and waits for the read loops. It is idempotent.
func (s *natShim) close() {
	s.once.Do(func() {
		s.mu.Lock()
		out := s.outside
		s.mu.Unlock()
		_ = s.inside.Close()
		if out != nil {
			_ = out.Close()
		}
		s.wg.Wait()
	})
}

// serveInside forwards the device's datagrams to dst through the current
// outside socket and remembers the device's address for the replies.
func (s *natShim) serveInside() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := s.inside.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Windows reports an ICMP port unreachable for an earlier send
			// as WSAECONNRESET on the next read; the socket still works.
			continue
		}
		s.mu.Lock()
		s.device = from
		out := s.outside
		s.mu.Unlock()
		// A write racing rebind's close fails: the datagram is lost, as on a
		// NAT that drops a mapping.
		_, _ = out.WriteToUDPAddrPort(buf[:n], s.dst)
	}
}

// serveOutside passes the datagrams out receives from dst to the device and
// drops every other one: the mapping filters by address and port.
func (s *natShim) serveOutside(out *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := out.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.mu.Lock()
		dev := s.device
		s.mu.Unlock()
		if from != s.dst || !dev.IsValid() {
			continue
		}
		_, _ = s.inside.WriteToUDPAddrPort(buf[:n], dev)
	}
}

// integSide is one end of the relayed pair: its node ID, mesh IP and private
// key.
type integSide struct {
	nodeID string
	ip     netip.Addr
	key    wgtypes.Key
}

func integKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	return k
}

// integNode is a wireguard-go device on a channel TUN, and the goroutine that
// drains the TUN's unbuffered Inbound into received, so the device never
// blocks delivering a packet while the test is not reading.
type integNode struct {
	ip       netip.Addr
	tun      *tuntest.ChannelTUN
	dev      *device.Device
	received chan []byte
	stop     chan struct{}
	drained  chan struct{}
	once     sync.Once
}

// integStartNode brings up a device for self with peer as its only peer at
// endpoint, keepalive every second. Its log lines go to logs. It is closed on
// cleanup.
func integStartNode(t *testing.T, logs *integLogBuffer, self, peer integSide, endpoint netip.AddrPort) *integNode {
	t.Helper()
	logf := func(format string, args ...any) {
		fmt.Fprintf(logs, "device %s: %s\n", self.nodeID, fmt.Sprintf(format, args...))
	}
	n := &integNode{
		ip:       self.ip,
		tun:      tuntest.NewChannelTUN(),
		received: make(chan []byte, 64),
		stop:     make(chan struct{}),
		drained:  make(chan struct{}),
	}
	n.dev = device.NewDevice(n.tun.TUN(), conn.NewDefaultBind(), &device.Logger{Verbosef: logf, Errorf: logf})
	go n.drain()
	t.Cleanup(n.close)

	peerKey := peer.key.PublicKey()
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(self.key[:]), hex.EncodeToString(peerKey[:]), endpoint, netip.PrefixFrom(peer.ip, 32))
	if err := n.dev.IpcSet(cfg); err != nil {
		t.Fatalf("configure device %s: %v", self.nodeID, err)
	}
	if err := n.dev.Up(); err != nil {
		t.Fatalf("bring up device %s: %v", self.nodeID, err)
	}
	return n
}

func (n *integNode) drain() {
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

// close closes the device, which closes its TUN, then ends the drain. It is
// idempotent. The test never closes the ChannelTUN itself: a second close
// panics.
func (n *integNode) close() {
	n.once.Do(func() {
		n.dev.Close()
		close(n.stop)
		<-n.drained
	})
}

// integPing returns tuntest's ICMP echo from src to dst carrying id in its
// IPv4 identification field, with the header checksum updated.
func integPing(dst, src netip.Addr, id uint16) []byte {
	pkt := tuntest.Ping(dst, src)
	binary.BigEndian.PutUint16(pkt[4:6], id)
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

// integPingBoth sends a ping from a to b and one from b to a about once a
// second until both have arrived, and fails the test if that takes longer
// than within. Every ping of a round carries the round number, so a late copy
// of an earlier round's ping cannot pass for this round's; any copy of this
// round's ping counts, since WireGuard may deliver one queued before its
// handshake.
func integPingBoth(t *testing.T, a, b *integNode, round uint16, within time.Duration) {
	t.Helper()
	toB := integPing(b.ip, a.ip, round)
	toA := integPing(a.ip, b.ip, round)

	start := time.Now()
	expired := time.After(within)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var atB, atA bool
	fail := func() {
		t.Helper()
		t.Fatalf("round %d: after %v the ping from %s to %s arrived = %t, the ping from %s to %s arrived = %t, want both",
			round, within, a.ip, b.ip, atB, b.ip, a.ip, atA)
	}
	send := func(from *integNode, pkt []byte) {
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

// integLogged reports whether one line of log has msg and every one of the
// key=value fields.
func integLogged(log, msg string, fields ...string) bool {
	for line := range strings.SplitSeq(log, "\n") {
		if !strings.Contains(line, `msg="`+msg+`"`) {
			continue
		}
		words := strings.Fields(line)
		missing := slices.ContainsFunc(fields, func(f string) bool { return !slices.Contains(words, f) })
		if !missing {
			return true
		}
	}
	return false
}

// integFreeAddr returns 127.0.0.1 and a UDP port that was free a moment ago.
func integFreeAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	c := natListen(t)
	addr := natLocalAddr(c)
	if err := c.Close(); err != nil {
		t.Fatalf("close the port probe: %v", err)
	}
	return addr
}

// TestRelayIntegration_SymmetricNATPairConnects connects two wireguard-go
// devices, each behind its own symmetric NAT, through the relay. Neither
// device can reach the other directly, and the relay learns neither address
// in advance: it has to place the first initiation by fan-out and every later
// datagram by mac1 and session index. The pair must survive a new NAT mapping
// on one side and a relay restart that loses all state.
func TestRelayIntegration_SymmetricNATPairConnects(t *testing.T) {
	logs := &integLogBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay and device log:\n%s", logs)
		}
	})

	a := integSide{nodeID: "node-a", ip: netip.MustParseAddr("10.0.0.1"), key: integKey(t)}
	b := integSide{nodeID: "node-b", ip: netip.MustParseAddr("10.0.0.2"), key: integKey(t)}
	// The third peer has no device, so the relay has to pick each
	// initiation's target by mac1 among more keys than the pair holds.
	c := integSide{nodeID: "node-c", key: integKey(t)}
	var peers []api.SnapshotPeer
	for _, s := range []integSide{a, b, c} {
		peers = append(peers, api.SnapshotPeer{NodeID: s.nodeID, PublicKey: s.key.PublicKey().String()})
	}

	relayAddr := integFreeAddr(t)
	relayPort := int(relayAddr.Port())
	r := NewRelay(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	r.listen = func(port int) (relayConn, error) {
		sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: natLoopback.AsSlice(), Port: port})
		if err != nil {
			return nil, err
		}
		return sock, nil
	}
	if err := r.Configure(relayPort, peers); err != nil {
		t.Fatalf("Configure(%d): %v, want nil", relayPort, err)
	}
	t.Cleanup(func() { _ = r.Stop() })

	shimA := natStartShim(t, relayAddr)
	shimB := natStartShim(t, relayAddr)
	nodeA := integStartNode(t, logs, a, b, shimA.insideAddr())
	nodeB := integStartNode(t, logs, b, a, shimB.insideAddr())

	integPingBoth(t, nodeA, nodeB, 1, 20*time.Second)

	newA := shimA.rebind(t)
	integPingBoth(t, nodeA, nodeB, 2, 20*time.Second)
	if !integLogged(logs.String(), "relay: peer address learned", "peer_id="+a.nodeID, "address="+newA.String()) {
		t.Fatalf(`no "relay: peer address learned" line with peer_id=%s address=%s after A's NAT rebound`, a.nodeID, newA)
	}

	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v, want nil", err)
	}
	if err := r.Configure(relayPort, peers); err != nil {
		t.Fatalf("Configure(%d) after Stop: %v, want nil", relayPort, err)
	}
	// WireGuard starts a new handshake only after the data it sent has gone
	// unanswered for about 15 s, so this round keeps pinging until then.
	integPingBoth(t, nodeA, nodeB, 3, 30*time.Second)
}
