package wireguard

import (
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
