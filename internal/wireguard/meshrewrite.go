package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// meshQueueLen is how many translated packets wait for a device to read them.
// A packet that finds the queue full is dropped as queue_full, so a slow
// device never blocks the device the packet came from.
const meshQueueLen = 512

// maxPacketSize is the largest packet a wrapper reads from the device it
// wraps, the largest an IPv4 total length allows.
const maxPacketSize = 65535

// MeshRewriter rewrites, inside the process, the source of what the far end
// of a registered interface sends into the mesh to the mesh interface's
// address.
//
// Windows has no kernel mechanism that fits: WinNAT translates nothing into
// the mesh beside the NetNat object the bridge NAT keeps for the mesh prefix,
// and what it translates passes no WFP forward filter. Every packet between a provider's
// or a tunnel's device and the mesh device already passes through plexd,
// because all of them are wireguard-go devices of this process. Wrap puts the
// rewriter between each such device and its tun, so a far end's packet is
// translated and handed to the mesh device's wireguard-go before Windows sees
// it, and a mesh peer's reply goes back the same way. The rules are in
// meshrewrite_nat.go.
//
// The three rewrite methods have the signatures of bridge.MeshSourceRewriter;
// this package does not import internal/bridge, so the assertion sits with
// the wiring in cmd/plexd/cmd. All of them are idempotent. Nothing of a
// rewrite outlives the process.
type MeshRewriter struct {
	logger *slog.Logger
	nat    *meshNAT

	// addrs reads the IPv4 prefixes an interface carries. It is a seam:
	// production reads the host's interface through net.InterfaceByName, and
	// tests supply the prefixes of channel tuns, which are no interfaces of
	// the host.
	addrs func(iface string) ([]netip.Prefix, error)
}

// NewMeshRewriter returns a rewriter that knows no device and holds no
// rewrite.
func NewMeshRewriter(logger *slog.Logger) *MeshRewriter {
	return &MeshRewriter{
		logger: logger,
		nat:    newMeshNAT(time.Now),
		addrs:  interfacePrefixes,
	}
}

// Wrap returns the tun.Device to hand wireguard-go in place of dev and
// knows it under name until it is closed.
//
// A nil dev returns nil, so UserspaceBackend.CreateDevice still refuses it.
// The wrapper owns dev: closing the wrapper closes dev.
func (r *MeshRewriter) Wrap(name string, dev tun.Device) tun.Device {
	if dev == nil {
		return nil
	}
	w := &meshTUN{
		r:          r,
		name:       name,
		dev:        dev,
		queue:      make(chan []byte, meshQueueLen),
		fromDev:    make(chan devPacket),
		closed:     make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	r.nat.register(name, w)
	go w.readDevice()
	return w
}

// AddMeshSourceRewrite rewrites the source of what the far ends behind
// fromIface send into the mesh to the address of meshIface, the first IPv4
// address it carries. Both must be devices Wrap knows; a fromIface that is
// none, such as a vendor client's adapter, needs no rewrite, because its
// client already sends with the host's address. A rewrite that exists for
// fromIface is left alone.
func (r *MeshRewriter) AddMeshSourceRewrite(fromIface, meshIface string) error {
	if done, err := r.added(r.nat.checkRewrite(fromIface, meshIface), fromIface, meshIface); done {
		return err
	}

	meshAddr, err := r.meshAddress(meshIface)
	if err != nil {
		return fmt.Errorf("bridge: add mesh source rewrite from %q to %q: address of the mesh interface: %w", fromIface, meshIface, err)
	}
	// What a far end sends to an address of its own interface is for the
	// host (row A2), so the rules need those prefixes, and a failed read
	// fails the add as a failed read of the mesh interface does. A tunnel's
	// interface may carry none.
	prefixes, err := r.ipv4Prefixes(fromIface)
	if err != nil {
		return fmt.Errorf("bridge: add mesh source rewrite from %q to %q: address of the mesh interface: %w", fromIface, meshIface, err)
	}

	// The devices may have closed, or another call added the rewrite, while
	// the addresses were read.
	if done, err := r.added(r.nat.addRewrite(fromIface, meshIface, meshAddr, prefixes), fromIface, meshIface); done {
		return err
	}

	r.logger.Debug("mesh source rewrite added",
		"component", "bridge",
		"from_iface", fromIface,
		"mesh_iface", meshIface,
		"mesh_addr", meshAddr.String(),
	)
	return nil
}

// added reports whether o settles AddMeshSourceRewrite, and with what.
func (r *MeshRewriter) added(o addOutcome, fromIface, meshIface string) (bool, error) {
	switch o {
	case addNoMesh:
		return true, fmt.Errorf("bridge: add mesh source rewrite from %q to %q: the mesh interface is no device of this process", fromIface, meshIface)
	case addNoSource:
		r.logger.Info("mesh source rewrite not needed, the interface is no device of this process",
			"component", "bridge",
			"from_iface", fromIface,
			"mesh_iface", meshIface,
		)
		return true, nil
	case addPresent:
		r.logger.Debug("mesh source rewrite already present, idempotent success",
			"component", "bridge",
			"from_iface", fromIface,
			"mesh_iface", meshIface,
		)
		return true, nil
	}
	return false, nil
}

// RemoveMeshSourceRewrite forgets the rewrite of fromIface and its flows.
// meshIface is not needed to find it and is only logged.
// Idempotent: an interface without a rewrite returns nil.
func (r *MeshRewriter) RemoveMeshSourceRewrite(fromIface, meshIface string) error {
	if _, ok := r.nat.removeRewrite(fromIface); !ok {
		r.logger.Debug("mesh source rewrite not found, idempotent success",
			"component", "bridge",
			"from_iface", fromIface,
			"mesh_iface", meshIface,
		)
		return nil
	}
	r.logger.Debug("mesh source rewrite removed",
		"component", "bridge",
		"from_iface", fromIface,
		"mesh_iface", meshIface,
	)
	return nil
}

// ResetMeshSourceRewrite forgets every rewrite and its flows. Nothing of a
// rewrite outlives the process, so a start has nothing to remove.
func (r *MeshRewriter) ResetMeshSourceRewrite() error {
	r.nat.resetRewrites()
	r.logger.Debug("mesh source rewrites reset", "component", "bridge")
	return nil
}

// SetMeshAddress moves every rewrite into meshIface to addr, the address the
// mesh interface carries since the node was moved, and forgets the flows that
// were translated to another address. A rewrite reads the address once, when
// it is added, so without this call it would keep the address the interface
// no longer holds. An addr that is no IPv4 address changes nothing, since the
// rules rewrite IPv4 alone.
func (r *MeshRewriter) SetMeshAddress(meshIface string, addr netip.Addr) {
	addr = addr.Unmap()
	if !addr.Is4() {
		r.logger.Warn("mesh source rewrite kept its address, the new one is no IPv4 address",
			"component", "bridge",
			"mesh_iface", meshIface,
			"mesh_addr", addr.String(),
		)
		return
	}
	rewrites, flows := r.nat.setMeshAddr(meshIface, addr)
	r.logger.Debug("mesh source rewrite moved to a new mesh address",
		"component", "bridge",
		"mesh_iface", meshIface,
		"mesh_addr", addr.String(),
		"rewrites", rewrites,
		"flows_removed", flows,
	)
}

// meshAddress returns the first IPv4 address of the mesh interface.
func (r *MeshRewriter) meshAddress(iface string) (netip.Addr, error) {
	prefixes, err := r.ipv4Prefixes(iface)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(prefixes) == 0 {
		return netip.Addr{}, errors.New("no IPv4 address")
	}
	return prefixes[0].Addr(), nil
}

// ipv4Prefixes returns the IPv4 prefixes iface carries, in the seam's order.
func (r *MeshRewriter) ipv4Prefixes(iface string) ([]netip.Prefix, error) {
	all, err := r.addrs(iface)
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, p := range all {
		if p.Addr().Is4() {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes, nil
}

// interfacePrefixes is the production addrs seam: the IPv4 addresses of the
// host's interface name with their prefix lengths.
func interfacePrefixes(name string) ([]netip.Prefix, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok || !ip.Unmap().Is4() {
			continue
		}
		ones, bits := ipn.Mask.Size()
		if bits == 8*net.IPv6len {
			ones -= 8 * (net.IPv6len - net.IPv4len)
		}
		if ones < 0 || ones > 8*net.IPv4len {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return prefixes, nil
}

// logDrops logs the drop reports the rules made due. No line carries a
// packet's content.
func (r *MeshRewriter) logDrops(reports []dropReport) {
	for _, rep := range reports {
		r.logger.Warn("mesh source rewrite dropped packets",
			"component", "bridge",
			"reason", rep.reason.String(),
			"count", rep.count,
		)
	}
}

// enqueue queues pkt for the device to reads it from, or drops it as
// queue_full.
func (r *MeshRewriter) enqueue(to natDevice, pkt []byte) {
	w, ok := to.(*meshTUN)
	if !ok {
		return
	}
	select {
	case w.queue <- pkt:
	default:
		r.logDrops(r.nat.dropped(dropQueueFull))
	}
}

// meshTUN is the tun.Device Wrap returns. Write hands what wireguard-go
// decrypted to the rules and passes what they leave the host to the wrapped
// device; Read returns what the host sends through the wrapped device and the
// packets the rules translated for this device. MTU, Name, File, Events and
// BatchSize are the wrapped device's.
type meshTUN struct {
	r    *MeshRewriter
	name string
	dev  tun.Device

	// queue holds the translated packets for this device. It is never
	// closed, so a rule that picked this device just before Close can still
	// queue to it without a panic.
	queue chan []byte
	// fromDev carries what readDevice read from dev, one packet or one
	// error at a time.
	fromDev chan devPacket

	closed     chan struct{}
	readerDone chan struct{}
	closeOnce  sync.Once
	closeErr   error

	readMu sync.Mutex
	// readErr is an error of dev that arrived while Read filled a batch; the
	// next Read returns it.
	readErr error
}

var (
	_ tun.Device = (*meshTUN)(nil)
	_ natDevice  = (*meshTUN)(nil)
)

// devPacket is one packet, or the error, readDevice read from the device.
type devPacket struct {
	pkt []byte
	err error
}

// readDevice reads what the host sends through the wrapped device until the
// wrapper is closed or the device fails. Each packet is a copy of its own,
// accounted for by the rules (host flows) before Read hands it on.
func (w *meshTUN) readDevice() {
	defer close(w.readerDone)

	batch := max(w.dev.BatchSize(), 1)
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, maxPacketSize)
	}
	sizes := make([]int, batch)

	for {
		n, err := w.dev.Read(bufs, sizes, 0)
		for i := range n {
			if sizes[i] < 1 {
				continue
			}
			pkt := bytes.Clone(bufs[i][:sizes[i]])
			pass, reports := w.r.nat.observe(w.name, pkt)
			w.r.logDrops(reports)
			if pass && !w.deliver(devPacket{pkt: pkt}) {
				return
			}
		}
		if err != nil {
			if !w.deliver(devPacket{err: err}) {
				return
			}
			// wireguard-go keeps reading after too many segments and
			// closes the device after any other error.
			if !errors.Is(err, tun.ErrTooManySegments) {
				return
			}
		}
	}
}

// deliver hands p to Read, and reports false once the wrapper is closed.
func (w *meshTUN) deliver(p devPacket) bool {
	select {
	case w.fromDev <- p:
		return true
	case <-w.closed:
		return false
	}
}

// Read blocks until a packet arrives from the wrapped device or the queue of
// translated packets, then fills up to len(bufs) packets without blocking
// again. Once the wrapper is closed it returns an error wrapping os.ErrClosed,
// which wireguard-go takes as the end of the device.
func (w *meshTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	if err := w.readErr; err != nil {
		w.readErr = nil
		return 0, err
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	select {
	case <-w.closed:
		return 0, w.errClosed()
	default:
	}

	select {
	case <-w.closed:
		return 0, w.errClosed()
	case pkt := <-w.queue:
		sizes[0] = copy(bufs[0][offset:], pkt)
	case p := <-w.fromDev:
		if p.err != nil {
			return 0, p.err
		}
		sizes[0] = copy(bufs[0][offset:], p.pkt)
	}

	n := 1
	for n < len(bufs) {
		select {
		case pkt := <-w.queue:
			sizes[n] = copy(bufs[n][offset:], pkt)
		case p := <-w.fromDev:
			if p.err != nil {
				w.readErr = p.err
				return n, nil
			}
			sizes[n] = copy(bufs[n][offset:], p.pkt)
		default:
			return n, nil
		}
		n++
	}
	return n, nil
}

func (w *meshTUN) errClosed() error {
	return fmt.Errorf("wireguard: mesh source rewrite: read %s: %w", w.name, os.ErrClosed)
}

// Write decides each packet by the rules. What they leave the host goes to
// the wrapped device's Write in one call, in its order; a translated packet is
// a copy, queued for the device it leaves through, since wireguard-go reuses
// bufs once Write returns. It returns len(bufs) and the wrapped device's
// error.
func (w *meshTUN) Write(bufs [][]byte, offset int) (int, error) {
	// A device that takes part in no rewrite passes every packet.
	if !w.r.nat.involved(w.name) {
		_, err := w.dev.Write(bufs, offset)
		return len(bufs), err
	}

	pass := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		if len(buf) < offset {
			pass = append(pass, buf)
			continue
		}
		res := w.r.nat.decide(w.name, buf[offset:])
		switch res.action {
		case natPass:
			pass = append(pass, buf)
		case natQueue:
			w.r.enqueue(res.to, res.out)
		}
		if res.icmp != nil {
			w.r.enqueue(res.icmpTo, res.icmp)
		}
		w.r.logDrops(res.reports)
	}

	if len(pass) == 0 {
		return len(bufs), nil
	}
	_, err := w.dev.Write(pass, offset)
	return len(bufs), err
}

// Close closes the wrapped device, ends the goroutine that reads it, and
// forgets the name, every rewrite the interface took part in and that
// rewrite's flows.
func (w *meshTUN) Close() error {
	w.closeOnce.Do(func() {
		w.r.nat.unregister(w.name, w)
		close(w.closed)
		w.closeErr = w.dev.Close()
		<-w.readerDone
	})
	return w.closeErr
}

func (w *meshTUN) File() *os.File { return w.dev.File() }

// MTU is the wrapped device's. The rules call it with their lock held, which
// costs nothing for a Wintun device: its MTU is a field.
func (w *meshTUN) MTU() (int, error) { return w.dev.MTU() }

func (w *meshTUN) Name() (string, error) { return w.dev.Name() }

func (w *meshTUN) Events() <-chan tun.Event { return w.dev.Events() }

func (w *meshTUN) BatchSize() int { return w.dev.BatchSize() }
