package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Compile-time check that the backend the macOS and Windows controllers
// delegate to can read peer state on every platform.
var _ PeerStatsReader = (*UserspaceBackend)(nil)

// trackedTUN wraps a tun.Device and records whether Close has been called, so
// a test can assert the backend closed the tun it was handed. It also stays
// down: its Events channel never emits EventUp, unlike tuntest.ChannelTUN,
// which emits it at construction. A real utun or Wintun device is down until
// the per-OS controller raises the interface flag, so the port bind happens at
// the backend's explicit dev.Up(); keeping the fixture down reproduces that,
// which is what lets the port-in-use case surface at up: rather than racing the
// premature EventUp into the listen_port line. Embedding the tun.Device
// forwards every method except the overridden Events and Close.
type trackedTUN struct {
	tun.Device
	events chan tun.Event
	closed atomic.Bool
}

func newTrackedTUN() *trackedTUN {
	return &trackedTUN{
		Device: tuntest.NewChannelTUN().TUN(),
		events: make(chan tun.Event),
	}
}

func (t *trackedTUN) Events() <-chan tun.Event { return t.events }

func (t *trackedTUN) Close() error {
	t.closed.Store(true)
	close(t.events)
	return t.Device.Close()
}

// slogTextLogger returns a debug-level text logger writing to w, for asserting
// the levels and attributes deviceLogger emits.
func slogTextLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newTestBackend returns a backend whose UDP bind is bind and whose UAPI
// endpoint is a loopback TCP listener. The UAPI protocol is transport-agnostic
// (device.IpcHandle takes any net.Conn), so a TCP listener stands in for the
// Unix socket and named pipe the tests cannot create unprivileged. Every
// device the test creates is deleted on cleanup.
func newTestBackend(t *testing.T, bind conn.Bind) *UserspaceBackend {
	t.Helper()
	b := NewUserspaceBackend(discardLogger())
	b.newBind = func() conn.Bind { return bind }
	b.uapiListen = func(string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}
	t.Cleanup(func() {
		b.mu.Lock()
		names := make([]string, 0, len(b.devices))
		for name := range b.devices {
			names = append(names, name)
		}
		b.mu.Unlock()
		for _, name := range names {
			_ = b.DeleteDevice(name)
		}
	})
	return b
}

// ipcGet reads the device's UAPI dump for a device the test created.
func ipcGet(t *testing.T, b *UserspaceBackend, name string) string {
	t.Helper()
	dev, err := b.device(name)
	if err != nil {
		t.Fatalf("device(%q): %v", name, err)
	}
	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet(%q): %v", name, err)
	}
	return dump
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return key
}

// pubBytes returns the raw bytes of a key's public key. PublicKey returns an
// array value, which is not addressable to slice directly.
func pubBytes(k wgtypes.Key) []byte {
	pub := k.PublicKey()
	return pub[:]
}

func TestUserspaceBackend_HandshakeOverChannelBind(t *testing.T) {
	binds := bindtest.NewChannelBinds()
	ba := newTestBackend(t, binds[0])
	bb := newTestBackend(t, binds[1])

	keyA := mustKey(t)
	keyB := mustKey(t)

	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()

	if err := ba.CreateDevice("wg-a", tunA.TUN(), keyA[:], 0); err != nil {
		t.Fatalf("CreateDevice wg-a: %v", err)
	}
	if err := bb.CreateDevice("wg-b", tunB.TUN(), keyB[:], 0); err != nil {
		t.Fatalf("CreateDevice wg-b: %v", err)
	}

	// Each ChannelBind sends to a fixed endpoint the other side listens on.
	if err := ba.AddPeer("wg-a", PeerConfig{
		PublicKey:  pubBytes(keyB),
		Endpoint:   "127.0.0.1:1",
		AllowedIPs: []string{"10.0.0.2/32"},
	}); err != nil {
		t.Fatalf("AddPeer wg-a: %v", err)
	}
	if err := bb.AddPeer("wg-b", PeerConfig{
		PublicKey:  pubBytes(keyA),
		Endpoint:   "127.0.0.1:2",
		AllowedIPs: []string{"10.0.0.1/32"},
	}); err != nil {
		t.Fatalf("AddPeer wg-b: %v", err)
	}

	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("10.0.0.2")

	// wg-a -> wg-b
	sendPing(t, tunA, tunB, ipB, ipA)
	// wg-b -> wg-a
	sendPing(t, tunB, tunA, ipA, ipB)

	for _, tc := range []struct {
		b    *UserspaceBackend
		name string
	}{{ba, "wg-a"}, {bb, "wg-b"}} {
		if secs := handshakeSeconds(ipcGet(t, tc.b, tc.name)); secs <= 0 {
			t.Errorf("%s last_handshake_time_sec = %d, want > 0", tc.name, secs)
		}
	}

	stats, err := ba.PeerStats("wg-a")
	if err != nil {
		t.Fatalf("PeerStats(wg-a): %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("PeerStats(wg-a) returned %d peers, want 1: %+v", len(stats), stats)
	}
	st := stats[0]
	if st.PublicKey != keyB.PublicKey() {
		t.Errorf("PublicKey = %x, want B's %x", st.PublicKey, keyB.PublicKey())
	}
	// wireguard-go roams a peer's endpoint to the source of its latest
	// authenticated packet, and bindtest labels every packet bind 0 receives
	// as coming from its target6, ChannelEndpoint(3). B's handshake response
	// therefore replaces the configured 127.0.0.1:1 with 127.0.0.1:3 before A
	// sends its first ping. The roamed value is what proves PeerStats reports
	// the endpoint WireGuard uses rather than the one plexd configured.
	if want := netip.MustParseAddrPort("127.0.0.1:3"); st.Endpoint != want {
		t.Errorf("Endpoint = %v, want the roamed %v", st.Endpoint, want)
	}
	if st.LastHandshake.IsZero() {
		t.Error("LastHandshake is zero after the pings")
	} else if age := time.Since(st.LastHandshake); age < 0 || age > time.Minute {
		t.Errorf("LastHandshake = %v (age %v), want within the last minute", st.LastHandshake, age)
	}
	if st.RxBytes == 0 || st.TxBytes == 0 {
		t.Errorf("RxBytes = %d, TxBytes = %d, want both non-zero", st.RxBytes, st.TxBytes)
	}
}

func TestUserspaceBackend_HandshakeOverLoopbackUDP(t *testing.T) {
	b := newTestBackend(t, conn.NewDefaultBind())
	// Restore the real bind: newTestBackend forced a single shared instance,
	// but two UDP devices each need their own.
	b.newBind = conn.NewDefaultBind

	keyA := mustKey(t)
	keyB := mustKey(t)

	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()

	if err := b.CreateDevice("wg-a", tunA.TUN(), keyA[:], 0); err != nil {
		t.Fatalf("CreateDevice wg-a: %v", err)
	}
	if err := b.CreateDevice("wg-b", tunB.TUN(), keyB[:], 0); err != nil {
		t.Fatalf("CreateDevice wg-b: %v", err)
	}

	portA := listenPort(t, ipcGet(t, b, "wg-a"))
	portB := listenPort(t, ipcGet(t, b, "wg-b"))

	if err := b.AddPeer("wg-a", PeerConfig{
		PublicKey:  pubBytes(keyB),
		Endpoint:   fmt.Sprintf("127.0.0.1:%d", portB),
		AllowedIPs: []string{"10.0.0.2/32"},
	}); err != nil {
		t.Fatalf("AddPeer wg-a: %v", err)
	}
	if err := b.AddPeer("wg-b", PeerConfig{
		PublicKey:  pubBytes(keyA),
		Endpoint:   fmt.Sprintf("127.0.0.1:%d", portA),
		AllowedIPs: []string{"10.0.0.1/32"},
	}); err != nil {
		t.Fatalf("AddPeer wg-b: %v", err)
	}

	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("10.0.0.2")

	sendPing(t, tunA, tunB, ipB, ipA)
	sendPing(t, tunB, tunA, ipA, ipB)
}

func TestUserspaceBackend_UAPIEndpointServesGet(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	tunA := tuntest.NewChannelTUN()
	if err := b.CreateDevice("wg-a", tunA.TUN(), key[:], 0); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	b.mu.Lock()
	addr := b.devices["wg-a"].listener.Addr().String()
	b.mu.Unlock()

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial uapi: %v", err)
	}
	defer c.Close()

	if _, err := c.Write([]byte("get=1\n\n")); err != nil {
		t.Fatalf("write get: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read uapi: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "listen_port=") {
		t.Errorf("uapi get = %q, want a listen_port= line", got)
	}
	if !strings.Contains(got, "errno=0") {
		t.Errorf("uapi get = %q, want it to end with errno=0", got)
	}
}

func TestUserspaceBackend_CreateDevice_NilTUN(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	err := b.CreateDevice("wg-a", nil, key[:], 0)
	if err == nil || err.Error() != "wireguard: create interface: nil tun device" {
		t.Fatalf("err = %v, want nil tun device error", err)
	}
	if _, ok := b.devices["wg-a"]; ok {
		t.Error("device stored despite nil tun")
	}
}

func TestUserspaceBackend_CreateDevice_DuplicateName(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	if err := b.CreateDevice("wg-a", tuntest.NewChannelTUN().TUN(), key[:], 0); err != nil {
		t.Fatalf("first CreateDevice: %v", err)
	}
	dup := newTrackedTUN()
	err := b.CreateDevice("wg-a", dup, key[:], 0)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want os.ErrExist", err)
	}
	if !dup.closed.Load() {
		t.Error("duplicate CreateDevice did not close the tun it was handed")
	}
}

func TestUserspaceBackend_CreateDevice_InvalidKey(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	tdev := newTrackedTUN()
	err := b.CreateDevice("wg-a", tdev, make([]byte, 31), 0)
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: create interface: parse private key:") {
		t.Fatalf("err = %v, want parse private key prefix", err)
	}
	if _, ok := b.devices["wg-a"]; ok {
		t.Error("device stored despite invalid key")
	}
	if !tdev.closed.Load() {
		t.Error("tun not closed after invalid key")
	}
}

func TestUserspaceBackend_CreateDevice_PortInUse(t *testing.T) {
	held, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("hold port: %v", err)
	}
	defer held.Close()
	port := held.LocalAddr().(*net.UDPAddr).Port

	b := newTestBackend(t, nil)
	b.newBind = conn.NewDefaultBind

	tdev := newTrackedTUN()
	key := mustKey(t)
	err = b.CreateDevice("wg-a", tdev, key[:], port)
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: create interface: up:") {
		t.Fatalf("err = %v, want up: prefix", err)
	}
	if _, ok := b.devices["wg-a"]; ok {
		t.Error("device stored despite port in use")
	}
	if !tdev.closed.Load() {
		t.Error("tun not closed after port-in-use failure")
	}
}

func TestUserspaceBackend_CreateDevice_UAPIListenError(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	b.uapiListen = func(string) (net.Listener, error) {
		return nil, errors.New("boom")
	}
	tdev := newTrackedTUN()
	key := mustKey(t)
	err := b.CreateDevice("wg-a", tdev, key[:], 0)
	if err == nil || err.Error() != "wireguard: create interface: uapi listen: boom" {
		t.Fatalf("err = %v, want uapi listen: boom", err)
	}
	if _, ok := b.devices["wg-a"]; ok {
		t.Error("device stored despite uapi listen failure")
	}
	if !tdev.closed.Load() {
		t.Error("tun not closed after uapi listen failure")
	}
}

func TestUserspaceBackend_DeleteDevice_Unknown(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	if err := b.DeleteDevice("nope"); err != nil {
		t.Fatalf("DeleteDevice(unknown) = %v, want nil", err)
	}
}

func TestUserspaceBackend_DeleteDevice_ClosesEverything(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	tdev := newTrackedTUN()
	if err := b.CreateDevice("wg-a", tdev, key[:], 0); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	b.mu.Lock()
	addr := b.devices["wg-a"].listener.Addr().String()
	b.mu.Unlock()

	if err := b.DeleteDevice("wg-a"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if !tdev.closed.Load() {
		t.Error("tun not closed after delete")
	}
	if _, ok := b.devices["wg-a"]; ok {
		t.Error("device still present after delete")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Error("uapi listener still accepting after delete")
	}
}

func TestUserspaceBackend_SetPrivateKey_KeepsPeersAndPort(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	tdev := tuntest.NewChannelTUN()
	if err := b.CreateDevice("wg-a", tdev.TUN(), key[:], 0); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	peer := mustKey(t)
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), AllowedIPs: []string{"10.0.0.2/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	beforePort := listenPort(t, ipcGet(t, b, "wg-a"))

	newKey := mustKey(t)
	if err := b.SetPrivateKey("wg-a", newKey[:]); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	dump := ipcGet(t, b, "wg-a")
	if got := privateKeyHex(dump); got != hexKey(newKey) {
		t.Errorf("private_key = %s, want %s", got, hexKey(newKey))
	}
	if afterPort := listenPort(t, dump); afterPort != beforePort {
		t.Errorf("listen_port changed from %d to %d", beforePort, afterPort)
	}
	if !strings.Contains(dump, "public_key="+hexKey(peer.PublicKey())) {
		t.Error("peer dropped by SetPrivateKey")
	}
}

func TestUserspaceBackend_SetPrivateKey_Unknown(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	if err := b.SetPrivateKey("nope", key[:]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}

func TestUserspaceBackend_SetPrivateKey_InvalidKey(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	if err := b.CreateDevice("wg-a", tuntest.NewChannelTUN().TUN(), key[:], 0); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	err := b.SetPrivateKey("wg-a", make([]byte, 31))
	if err == nil || !strings.HasPrefix(err.Error(), "wireguard: set private key: parse private key:") {
		t.Fatalf("err = %v, want parse private key prefix", err)
	}
}

// createOnePeerDevice creates wg-a and returns the backend, ready for AddPeer /
// RemovePeer tests.
func createOnePeerDevice(t *testing.T) *UserspaceBackend {
	t.Helper()
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	key := mustKey(t)
	if err := b.CreateDevice("wg-a", tuntest.NewChannelTUN().TUN(), key[:], 0); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	return b
}

func TestUserspaceBackend_AddPeer_Unknown(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	peer := mustKey(t)
	if err := b.AddPeer("nope", PeerConfig{PublicKey: pubBytes(peer)}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}

func TestUserspaceBackend_AddPeer_InvalidPublicKey(t *testing.T) {
	b := createOnePeerDevice(t)
	err := b.AddPeer("wg-a", PeerConfig{PublicKey: make([]byte, 31)})
	assertPrefix(t, err, "wireguard: add peer: parse public key:")
}

func TestUserspaceBackend_AddPeer_InvalidAllowedIP(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), AllowedIPs: []string{"10.0.0.0/33"}})
	assertPrefix(t, err, `wireguard: add peer: parse allowed IP "10.0.0.0/33":`)
}

func TestUserspaceBackend_AddPeer_InvalidPSK(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), PSK: make([]byte, 5)})
	assertPrefix(t, err, "wireguard: add peer: parse psk:")
}

func TestUserspaceBackend_AddPeer_InvalidEndpoint(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), Endpoint: "not-an-endpoint"})
	assertPrefix(t, err, "wireguard: add peer: resolve endpoint:")
}

func TestUserspaceBackend_AddPeer_NoEndpointNoPSK(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), AllowedIPs: []string{"10.0.0.2/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	dump := ipcGet(t, b, "wg-a")
	if strings.Contains(dump, "endpoint=") {
		t.Errorf("dump has endpoint= for a peer without one: %q", dump)
	}
	// IpcGet always emits preshared_key=; with no PSK it is all zero.
	if !strings.Contains(dump, "preshared_key="+strings.Repeat("00", 32)) {
		t.Errorf("dump preshared_key not all-zero: %q", dump)
	}
}

func TestUserspaceBackend_AddPeer_EmptyAllowedIPs(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer)}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	dump := ipcGet(t, b, "wg-a")
	if strings.Contains(dump, "allowed_ip=") {
		t.Errorf("dump has allowed_ip= for a peer with none: %q", dump)
	}
}

func TestUserspaceBackend_AddPeer_ReplacesAllowedIPs(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	pub := pubBytes(peer)
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pub, AllowedIPs: []string{"10.0.0.2/32"}}); err != nil {
		t.Fatalf("first AddPeer: %v", err)
	}
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pub, AllowedIPs: []string{"10.0.9.0/24"}}); err != nil {
		t.Fatalf("second AddPeer: %v", err)
	}
	dump := ipcGet(t, b, "wg-a")
	if strings.Contains(dump, "allowed_ip=10.0.0.2/32") {
		t.Error("old allowed_ip survived the replace")
	}
	if !strings.Contains(dump, "allowed_ip=10.0.9.0/24") {
		t.Error("new allowed_ip missing after replace")
	}
}

func TestUserspaceBackend_AddPeer_Keepalive(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), AllowedIPs: []string{"10.0.0.2/32"}, PersistentKeepalive: 25}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if dump := ipcGet(t, b, "wg-a"); !strings.Contains(dump, "persistent_keepalive_interval=25") {
		t.Errorf("dump missing keepalive: %q", dump)
	}
}

func TestUserspaceBackend_RemovePeer_Unknown(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	peer := mustKey(t)
	if err := b.RemovePeer("nope", pubBytes(peer)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}

func TestUserspaceBackend_RemovePeer_InvalidKey(t *testing.T) {
	b := createOnePeerDevice(t)
	err := b.RemovePeer("wg-a", make([]byte, 31))
	assertPrefix(t, err, "wireguard: remove peer: parse public key:")
}

func TestUserspaceBackend_RemovePeer_UnknownPeer(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	if err := b.RemovePeer("wg-a", pubBytes(peer)); err != nil {
		t.Fatalf("RemovePeer(unknown peer) = %v, want nil", err)
	}
	if dump := ipcGet(t, b, "wg-a"); strings.Contains(dump, "public_key=") {
		t.Errorf("dump unexpectedly has a peer: %q", dump)
	}
}

func TestUserspaceBackend_RemovePeer_RemovesPeer(t *testing.T) {
	b := createOnePeerDevice(t)
	peer := mustKey(t)
	pub := peer.PublicKey()
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pub[:], AllowedIPs: []string{"10.0.0.2/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if dump := ipcGet(t, b, "wg-a"); !strings.Contains(dump, "public_key="+hexKey(pub)) {
		t.Fatalf("peer not present before remove: %q", dump)
	}
	if err := b.RemovePeer("wg-a", pub[:]); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if dump := ipcGet(t, b, "wg-a"); strings.Contains(dump, "public_key="+hexKey(pub)) {
		t.Errorf("peer survived remove: %q", dump)
	}
}

func TestUserspaceBackend_PeerStats_NoHandshake(t *testing.T) {
	b := createOnePeerDevice(t)

	stats, err := b.PeerStats("wg-a")
	if err != nil {
		t.Fatalf("PeerStats on a device without peers: %v", err)
	}
	if stats == nil || len(stats) != 0 {
		t.Fatalf("PeerStats on a device without peers = %#v, want an empty non-nil slice", stats)
	}

	peer := mustKey(t)
	if err := b.AddPeer("wg-a", PeerConfig{PublicKey: pubBytes(peer), AllowedIPs: []string{"10.0.0.2/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	stats, err = b.PeerStats("wg-a")
	if err != nil {
		t.Fatalf("PeerStats: %v", err)
	}
	// No endpoint and no traffic: the peer is there with nothing but its key.
	want := []PeerStat{{PublicKey: peer.PublicKey()}}
	assertPeerStats(t, stats, want)
}

func TestUserspaceBackend_PeerStats_Unknown(t *testing.T) {
	b := newTestBackend(t, bindtest.NewChannelBinds()[0])
	_, err := b.PeerStats("nope")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
	assertPrefix(t, err, "wireguard: peer stats:")
}

func TestParseUAPIPeerStats(t *testing.T) {
	var (
		privHex = strings.Repeat("deadbeef", 8)
		pskHex  = strings.Repeat("feedface", 8)
		pubAHex = strings.Repeat("0a", 32)
		pubBHex = strings.Repeat("0b", 32)
		pubA    = [32]byte(bytes.Repeat([]byte{0x0a}, 32))
		pubB    = [32]byte(bytes.Repeat([]byte{0x0b}, 32))
	)
	device := "private_key=" + privHex + "\nlisten_port=51820\nfwmark=42\n"

	tests := []struct {
		name string
		dump string
		want []PeerStat
	}{
		{
			name: "empty dump",
			dump: "",
			want: []PeerStat{},
		},
		{
			name: "device keys only",
			dump: device,
			want: []PeerStat{},
		},
		{
			name: "every field",
			dump: device +
				"public_key=" + pubAHex + "\n" +
				"preshared_key=" + pskHex + "\n" +
				"protocol_version=1\n" +
				"endpoint=198.51.100.7:51820\n" +
				"last_handshake_time_sec=1700000005\n" +
				"last_handshake_time_nsec=250\n" +
				"tx_bytes=1024\n" +
				"rx_bytes=2048\n" +
				"persistent_keepalive_interval=0\n" +
				"allowed_ip=10.0.0.2/32\n" +
				"allowed_ip=fd00::2/128\n",
			want: []PeerStat{{
				PublicKey:     pubA,
				Endpoint:      netip.MustParseAddrPort("198.51.100.7:51820"),
				LastHandshake: time.Unix(1700000005, 250),
				RxBytes:       2048,
				TxBytes:       1024,
			}},
		},
		{
			name: "no handshake is the zero time",
			dump: "public_key=" + pubAHex + "\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n",
			want: []PeerStat{{PublicKey: pubA}},
		},
		{
			// wgctrl's parser needs both values positive and would drop this one.
			name: "handshake on a whole second",
			dump: "public_key=" + pubAHex + "\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=0\n",
			want: []PeerStat{{PublicKey: pubA, LastHandshake: time.Unix(1700000000, 0)}},
		},
		{
			name: "no endpoint line leaves the endpoint invalid",
			dump: "public_key=" + pubAHex + "\ntx_bytes=7\nrx_bytes=9\n",
			want: []PeerStat{{PublicKey: pubA, RxBytes: 9, TxBytes: 7}},
		},
		{
			// The zone survives here; the handshake reporter strips it.
			name: "zoned endpoint kept",
			dump: "public_key=" + pubAHex + "\nendpoint=[fe80::1%eth0]:51820\n",
			want: []PeerStat{{PublicKey: pubA, Endpoint: netip.MustParseAddrPort("[fe80::1%eth0]:51820")}},
		},
		{
			// The second peer has no handshake lines and must not inherit the
			// first peer's time.
			name: "two peers in dump order",
			dump: device +
				"public_key=" + pubBHex + "\nendpoint=[2001:db8::7]:51820\n" +
				"last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n" +
				"public_key=" + pubAHex + "\nendpoint=198.51.100.7:51820\n",
			want: []PeerStat{
				{PublicKey: pubB, Endpoint: netip.MustParseAddrPort("[2001:db8::7]:51820"), LastHandshake: time.Unix(1700000000, 5)},
				{PublicKey: pubA, Endpoint: netip.MustParseAddrPort("198.51.100.7:51820")},
			},
		},
		{
			name: "empty lines and errno skipped",
			dump: "\n\npublic_key=" + pubAHex + "\n\nerrno=0\n\n",
			want: []PeerStat{{PublicKey: pubA}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUAPIPeerStats(tc.dump)
			if err != nil {
				t.Fatalf("parseUAPIPeerStats: %v", err)
			}
			if got == nil {
				t.Fatal("parseUAPIPeerStats returned a nil slice, want non-nil")
			}
			assertPeerStats(t, got, tc.want)
		})
	}
}

func TestParseUAPIPeerStats_Errors(t *testing.T) {
	// Distinctive key material in every dump, so the test can tell whether an
	// error text leaked it.
	var (
		privHex = strings.Repeat("deadbeef", 8)
		pskHex  = strings.Repeat("feedface", 8)
		pubHex  = strings.Repeat("0a", 32)
	)
	device := "private_key=" + privHex + "\nlisten_port=51820\n"
	peer := "public_key=" + pubHex + "\npreshared_key=" + pskHex + "\nprotocol_version=1\n"

	tests := []struct {
		name string
		dump string
		want string // exact text when wantPrefix is false
		// wantPrefix makes want a prefix: the wrapped parse error's own text
		// comes from the standard library.
		wantPrefix bool
	}{
		{
			name:       "63 hex char public_key",
			dump:       device + "public_key=" + pubHex[:63] + "\npreshared_key=" + pskHex + "\n",
			want:       "wireguard: peer stats: parse public_key:",
			wantPrefix: true,
		},
		{
			name:       "non-hex public_key",
			dump:       device + "public_key=" + strings.Repeat("zz", 32) + "\npreshared_key=" + pskHex + "\n",
			want:       "wireguard: peer stats: parse public_key:",
			wantPrefix: true,
		},
		{
			name:       "unparseable endpoint",
			dump:       device + peer + "endpoint=not-an-endpoint\n",
			want:       "wireguard: peer stats: parse endpoint:",
			wantPrefix: true,
		},
		{
			name:       "non-numeric rx_bytes",
			dump:       device + peer + "rx_bytes=lots\n",
			want:       "wireguard: peer stats: parse rx_bytes:",
			wantPrefix: true,
		},
		{
			name:       "non-numeric last_handshake_time_sec",
			dump:       device + peer + "last_handshake_time_sec=yesterday\n",
			want:       "wireguard: peer stats: parse last_handshake_time_sec:",
			wantPrefix: true,
		},
		{
			// A private_key line that lost its '=' is the worst case: the
			// whole line is the secret.
			name: "line without =",
			dump: "listen_port=51820\n" + privHex + "\n" + peer,
			want: "wireguard: peer stats: line 2 has no '='",
		},
		{
			name: "endpoint before public_key",
			dump: device + "preshared_key=" + pskHex + "\nendpoint=198.51.100.7:51820\n" + peer,
			want: "wireguard: peer stats: endpoint before public_key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUAPIPeerStats(tc.dump)
			if err == nil {
				t.Fatalf("parseUAPIPeerStats = %+v, want an error", got)
			}
			if tc.wantPrefix {
				assertPrefix(t, err, tc.want)
			} else if err.Error() != tc.want {
				t.Errorf("err = %q, want %q", err, tc.want)
			}
			for _, secret := range []string{privHex, pskHex} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("err = %q quotes key material %s", err, secret)
				}
			}
		})
	}
}

func TestDeviceLogger_MapsLevels(t *testing.T) {
	var buf strings.Builder
	logger := slogTextLogger(&buf)
	dl := deviceLogger(logger, "wg-a")

	dl.Verbosef("x %d", 1)
	dl.Errorf("y %d", 2)

	out := buf.String()
	for _, want := range []string{
		`level=DEBUG msg="x 1" component=wireguard interface=wg-a`,
		`level=ERROR msg="y 2" component=wireguard interface=wg-a`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log output %q missing %q", out, want)
		}
	}
}

// --- helpers ---

func assertPrefix(t *testing.T, err error, prefix string) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("err = %v, want prefix %q", err, prefix)
	}
}

// assertPeerStats compares peer stats field by field, the handshake time with
// time.Time.Equal so a location difference cannot fail an equal instant.
func assertPeerStats(t *testing.T, got, want []PeerStat) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d peer stats, want %d:\ngot  %+v\nwant %+v", len(got), len(want), got, want)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.PublicKey != w.PublicKey || g.Endpoint != w.Endpoint ||
			!g.LastHandshake.Equal(w.LastHandshake) || g.RxBytes != w.RxBytes || g.TxBytes != w.TxBytes {
			t.Errorf("peer stat %d:\ngot  %+v\nwant %+v", i, g, w)
		}
	}
}

// sendPing writes an ICMP echo from src to dst into the sender's tun and waits
// for the identical bytes to arrive on the receiver's tun.
func sendPing(t *testing.T, sender, receiver *tuntest.ChannelTUN, dst, src netip.Addr) {
	t.Helper()
	msg := tuntest.Ping(dst, src)
	select {
	case sender.Outbound <- msg:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout writing ping to sender tun")
	}
	select {
	case got := <-receiver.Inbound:
		if string(got) != string(msg) {
			t.Errorf("received %x, want %x", got, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ping on receiver tun")
	}
}

func uapiValue(dump, key string) (string, bool) {
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

func listenPort(t *testing.T, dump string) int {
	t.Helper()
	v, ok := uapiValue(dump, "listen_port")
	if !ok {
		t.Fatalf("no listen_port in dump: %q", dump)
	}
	var port int
	if _, err := fmt.Sscanf(v, "%d", &port); err != nil {
		t.Fatalf("parse listen_port %q: %v", v, err)
	}
	return port
}

func privateKeyHex(dump string) string {
	v, _ := uapiValue(dump, "private_key")
	return v
}

func handshakeSeconds(dump string) int64 {
	v, ok := uapiValue(dump, "last_handshake_time_sec")
	if !ok {
		return 0
	}
	var secs int64
	if _, err := fmt.Sscanf(v, "%d", &secs); err != nil {
		return 0
	}
	return secs
}
