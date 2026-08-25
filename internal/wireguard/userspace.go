package wireguard

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// UserspaceBackend runs wireguard-go devices inside the plexd process. The
// per-OS controllers create the tun device, hand it to CreateDevice, and
// program addresses, MTU and the interface flag themselves; this backend owns
// the wireguard-go device lifecycle, the private key, the listen port, the
// peers, and the UAPI endpoint that lets wg(8) read the device.
//
// It is the base of the macOS (utun) and Windows (Wintun) WGController
// implementations and of the bridge access and site-to-site controllers. On
// Linux plexd stays on the kernel path (NetlinkController); this backend
// merely compiles and is tested there.
//
// Configuration is applied in process through the device's UAPI text protocol
// (device.Device.IpcSet), not through wgctrl's userspace transport: wgctrl
// finds a userspace device only under a root-owned socket directory on Unix
// and a LocalSystem-owned named pipe on Windows, so its configure path cannot
// run unprivileged. The served UAPI endpoint still lets wgctrl and wg(8) read
// the device.
type UserspaceBackend struct {
	mu      sync.Mutex
	devices map[string]*userspaceDevice
	logger  *slog.Logger

	// newBind and uapiListen are seams: production wires them to
	// conn.NewDefaultBind and the per-platform uapiListen, and tests swap in a
	// channel bind and a loopback listener.
	newBind    func() conn.Bind
	uapiListen func(name string) (net.Listener, error)
}

// userspaceDevice is one running wireguard-go device and the UAPI listener
// that serves it.
type userspaceDevice struct {
	dev      *device.Device
	listener net.Listener
}

// NewUserspaceBackend returns a backend wired to the production UDP bind and
// the per-platform UAPI endpoint.
func NewUserspaceBackend(logger *slog.Logger) *UserspaceBackend {
	return &UserspaceBackend{
		devices:    make(map[string]*userspaceDevice),
		logger:     logger,
		newBind:    conn.NewDefaultBind,
		uapiListen: uapiListen,
	}
}

// CreateDevice starts a wireguard-go device named name over tdev, configured
// with privateKey and listenPort, and serves its UAPI endpoint.
//
// Ownership of tdev passes to the backend: on any error CreateDevice closes it
// (directly before the device exists, through device.Close afterwards), and a
// caller never closes the tun it handed in. A listenPort of 0 lets wireguard-go
// pick an ephemeral port. The device is brought up here, so a port already in
// use surfaces as an error from this call.
func (b *UserspaceBackend) CreateDevice(name string, tdev tun.Device, privateKey []byte, listenPort int) error {
	if tdev == nil {
		return errors.New("wireguard: create interface: nil tun device")
	}

	b.mu.Lock()
	if _, ok := b.devices[name]; ok {
		b.mu.Unlock()
		tdev.Close()
		return fmt.Errorf("wireguard: create interface: %w", os.ErrExist)
	}
	b.mu.Unlock()

	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		tdev.Close()
		return fmt.Errorf("wireguard: create interface: parse private key: %w", err)
	}

	dev := device.NewDevice(tdev, b.newBind(), deviceLogger(b.logger, name))

	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hexKey(key), listenPort)); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: create interface: configure device: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: create interface: up: %w", err)
	}

	l, err := b.uapiListen(name)
	if err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: create interface: uapi listen: %w", err)
	}

	go b.serveUAPI(name, dev, l)

	b.mu.Lock()
	b.devices[name] = &userspaceDevice{dev: dev, listener: l}
	b.mu.Unlock()

	b.logger.Info("wireguard interface created",
		"component", "wireguard",
		"interface", name,
		"listen_port", listenPort,
	)

	return nil
}

// serveUAPI accepts UAPI connections and hands each to the device until the
// listener is closed.
func (b *UserspaceBackend) serveUAPI(name string, dev *device.Device, l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			b.logger.Warn("uapi listener stopped",
				"component", "wireguard",
				"interface", name,
				"error", err,
			)
			return
		}
		go dev.IpcHandle(c)
	}
}

// DeleteDevice closes the named device and its UAPI listener. It is
// idempotent: deleting a device that does not exist returns nil.
func (b *UserspaceBackend) DeleteDevice(name string) error {
	b.mu.Lock()
	ud, ok := b.devices[name]
	delete(b.devices, name)
	b.mu.Unlock()

	if !ok {
		return nil
	}

	// Close the listener first so serveUAPI returns, then the device, which
	// closes the tun and waits for the device's own goroutines.
	if err := ud.listener.Close(); err != nil {
		b.logger.Warn("uapi listener close failed",
			"component", "wireguard",
			"interface", name,
			"error", err,
		)
	}
	ud.dev.Close()

	b.logger.Info("wireguard interface deleted",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// SetPrivateKey replaces the named device's private key without touching its
// listen port or peers.
func (b *UserspaceBackend) SetPrivateKey(name string, privateKey []byte) error {
	dev, err := b.device(name)
	if err != nil {
		return fmt.Errorf("wireguard: set private key: %w", err)
	}

	key, err := wgtypes.NewKey(privateKey)
	if err != nil {
		return fmt.Errorf("wireguard: set private key: parse private key: %w", err)
	}

	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", hexKey(key))); err != nil {
		return fmt.Errorf("wireguard: set private key: configure device: %w", err)
	}

	b.logger.Info("wireguard private key rotated",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// AddPeer adds or updates a peer on the named device. A public key that
// already exists updates that peer in place.
func (b *UserspaceBackend) AddPeer(name string, cfg PeerConfig) error {
	dev, err := b.device(name)
	if err != nil {
		return fmt.Errorf("wireguard: add peer: %w", err)
	}

	uapi, err := peerUAPI(cfg)
	if err != nil {
		return err
	}

	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("wireguard: add peer: configure device: %w", err)
	}

	b.logger.Debug("peer added",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// RemovePeer removes a peer from the named device by public key. A key with no
// matching peer is not an error.
func (b *UserspaceBackend) RemovePeer(name string, publicKey []byte) error {
	dev, err := b.device(name)
	if err != nil {
		return fmt.Errorf("wireguard: remove peer: %w", err)
	}

	pubKey, err := wgtypes.NewKey(publicKey)
	if err != nil {
		return fmt.Errorf("wireguard: remove peer: parse public key: %w", err)
	}

	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hexKey(pubKey))); err != nil {
		return fmt.Errorf("wireguard: remove peer: configure device: %w", err)
	}

	b.logger.Debug("peer removed",
		"component", "wireguard",
		"interface", name,
	)

	return nil
}

// device returns the running device for name, or os.ErrNotExist. The returned
// error is unwrapped so callers add their own operation prefix.
func (b *UserspaceBackend) device(name string) (*device.Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ud, ok := b.devices[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return ud.dev, nil
}

// peerUAPI builds the UAPI text for one AddPeer call. The validation order and
// error texts match NetlinkController.AddPeer so both controllers reject the
// same input the same way.
func peerUAPI(cfg PeerConfig) (string, error) {
	pubKey, err := wgtypes.NewKey(cfg.PublicKey)
	if err != nil {
		return "", fmt.Errorf("wireguard: add peer: parse public key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hexKey(pubKey))

	if cfg.Endpoint != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
		if err != nil {
			return "", fmt.Errorf("wireguard: add peer: resolve endpoint: %w", err)
		}
		fmt.Fprintf(&b, "endpoint=%s\n", udpAddr.String())
	}

	b.WriteString("replace_allowed_ips=true\n")
	for _, cidr := range cfg.AllowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return "", fmt.Errorf("wireguard: add peer: parse allowed IP %q: %w", cidr, err)
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}

	if len(cfg.PSK) > 0 {
		psk, err := wgtypes.NewKey(cfg.PSK)
		if err != nil {
			return "", fmt.Errorf("wireguard: add peer: parse psk: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", hexKey(psk))
	}

	if cfg.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.PersistentKeepalive)
	}

	return b.String(), nil
}

// hexKey renders a wgtypes.Key as the lowercase hex the UAPI protocol expects.
func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}

// deviceLogger adapts an *slog.Logger to the *device.Logger wireguard-go logs
// through, tagging every line with component=wireguard and the interface name.
// wireguard-go never logs key material; peers appear as a truncated public
// key.
func deviceLogger(logger *slog.Logger, name string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...),
				"component", "wireguard",
				"interface", name,
			)
		},
		Errorf: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...),
				"component", "wireguard",
				"interface", name,
			)
		},
	}
}
