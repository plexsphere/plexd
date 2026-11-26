package wireguard

import (
	"context"
	"time"
)

// DefaultMTU is the MTU Linux and wireguard-go give a WireGuard link: 1500
// minus 80. Every controller creates the device at it, so Setup writes no MTU
// when it chooses this one.
const DefaultMTU = 1420

// MinMTU is the smallest MTU detection programs, IPv6's minimum link MTU. It
// bounds how far an uplink that drops probes, or an on-path attacker who drops
// them, can push the mesh MTU down.
const MinMTU = 1280

// encapsulationOverhead is IPv6 (40) + UDP (8) + WireGuard (32); it covers
// IPv4's 60. The probe measures the IPv4 path, but peers can dial IPv6
// candidates, so the mesh MTU leaves room for the larger header.
const encapsulationOverhead = 80

// MTUProbeInterval is how often RunMTUProbe measures the uplink again in plexd up.
const MTUProbeInterval = 10 * time.Minute

// The mtu_source values Setup logs: where the MTU it programmed came from.
const (
	mtuSourceConfig  = "config"
	mtuSourceProbe   = "probe"
	mtuSourceDefault = "default"
)

// MeshMTU returns the mesh MTU for an uplink that carries IPv4 packets of
// pathMTU bytes: pathMTU minus the encapsulation overhead, capped at
// DefaultMTU and floored at MinMTU. A 1500-byte uplink gives DefaultMTU, so a
// healthy node keeps the MTU it always had.
func MeshMTU(pathMTU int) int {
	return min(DefaultMTU, max(MinMTU, pathMTU-encapsulationOverhead))
}

// tcpIPv4Overhead is the IPv4 header (20) plus the TCP header (20).
const tcpIPv4Overhead = 40

// minForwardMSS is the MSS a host assumes when a SYN carries none (RFC 9293, 3.7.1).
const minForwardMSS = 536

// ForwardMSS returns the largest MSS a TCP connection may announce across a
// mesh interface of mtu bytes: mtu minus tcpIPv4Overhead, floored at
// minForwardMSS. Only IPv4 counts, because the mesh carries no IPv6.
func ForwardMSS(mtu int) int {
	return max(minForwardMSS, mtu-tcpIPv4Overhead)
}

// clampMSS clamps the MSS of the TCP connections the node forwards across the
// mesh interface to ForwardMSS(mtu), through the controller's MSSClamper. It
// does nothing for a controller without one, or when that MSS is the one
// programmed already, so a round that changed no MTU costs no call while the
// clamp is current, and retries one that failed before.
//
// A failed call leaves the recorded MSS as it was and is logged at Warn: the
// mesh then carries TCP as it would without a clamp, which is no reason to
// fail Setup or a probe round.
func (m *Manager) clampMSS(mtu int) {
	clamper, ok := m.ctrl.(MSSClamper)
	if !ok {
		return
	}
	mss := ForwardMSS(mtu)
	old := m.mss.Load()
	if int32(mss) == old {
		return
	}
	if err := clamper.ClampMSS(m.cfg.InterfaceName, mss); err != nil {
		m.logger.Warn("wireguard: forwarded tcp mss clamp failed",
			"component", "wireguard",
			"interface", m.cfg.InterfaceName,
			"mss", mss,
			"mtu", mtu,
			"error", err,
		)
		return
	}
	m.mss.Store(int32(mss))

	attrs := []any{
		"component", "wireguard",
		"interface", m.cfg.InterfaceName,
		"mss", mss,
		"mtu", mtu,
	}
	if old != 0 {
		attrs = append(attrs, "old_mss", old)
	}
	m.logger.Info("wireguard: forwarded tcp mss clamped", attrs...)
}

// SetPathMTUProbe sets the function Setup and RunMTUProbe measure the uplink
// with. It returns the largest IPv4 packet size, in bytes, that reached a STUN
// server. Call it before Setup, like SetLocalPrefixes; without it the
// interface keeps DefaultMTU unless Config.MTU pins another.
func (m *Manager) SetPathMTUProbe(probe func(context.Context) (int, error)) {
	m.probe = probe
}

// chooseMTU returns the MTU Setup programs, where it came from, and, for an
// MTU the probe sized, the path MTU the probe measured. A positive Config.MTU
// wins and the probe is not called. A probe error falls back to DefaultMTU,
// the MTU the interface had before detection existed, because a round that
// reached no STUN server says nothing about the uplink.
func (m *Manager) chooseMTU(ctx context.Context) (mtu int, source string, pathMTU int) {
	if m.cfg.MTU > 0 {
		return m.cfg.MTU, mtuSourceConfig, 0
	}
	if m.probe == nil {
		return DefaultMTU, mtuSourceDefault, 0
	}
	pathMTU, err := m.probe(ctx)
	if err != nil {
		m.logger.Warn("wireguard: mtu probe inconclusive, using the default mtu",
			"component", "wireguard",
			"mtu", DefaultMTU,
			"error", err,
		)
		return DefaultMTU, mtuSourceDefault, 0
	}
	return MeshMTU(pathMTU), mtuSourceProbe, pathMTU
}

// warnBelowMinimum logs that the uplink carries less than the mesh needs, when
// MeshMTU held the MTU for pathMTU up at MinMTU. Full-size mesh packets are
// then still lost on that uplink, and only a pinned wireguard.mtu or a better
// uplink fixes that.
func (m *Manager) warnBelowMinimum(pathMTU int) {
	if pathMTU-encapsulationOverhead >= MinMTU {
		return
	}
	m.logger.Warn("wireguard: uplink carries less than the mesh minimum mtu",
		"component", "wireguard",
		"path_mtu", pathMTU,
		"mtu", MinMTU,
	)
}

// RunMTUProbe measures the uplink every interval until ctx is done, then
// returns nil, and fits the mesh MTU, and the forwarded TCP MSS clamp with
// it, to each round (see adjustMTU). The probe in Setup counts as the first
// round, so the first one here comes an interval after the call.
//
// It returns nil at once when no probe is set or Config.MTU pins the MTU. A
// clamp that failed in Setup is then not tried again until the next start.
func (m *Manager) RunMTUProbe(ctx context.Context, interval time.Duration) error {
	if m.probe == nil || m.cfg.MTU > 0 {
		return nil
	}

	m.logger.Info("wireguard: mtu probe started",
		"component", "wireguard",
		"interval", interval,
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		m.adjustMTU(ctx)
	}
}

// adjustMTU runs one probe round and fits the mesh MTU to it. A lower MTU is
// programmed at once, because the uplink loses every mesh packet above it
// without an error. A higher one is programmed only when the round before
// asked for the same raise, so a single round that happened to get its
// probes through does not flap the MTU up and back down. A round that agrees
// with the current MTU, or whose probe failed, drops a pending raise.
//
// A failed SetMTU leaves the MTU recorded as it was and drops a pending raise.
// The next round that measures the same uplink tries a lowering again, while a
// raise waits for two agreeing rounds again.
//
// Every round whose probe measured, and that ended before ctx was done, ends
// by clamping the forwarded TCP MSS to the MTU it leaves recorded (see
// clampMSS): after SetMTU on a change, and also when the MTU stays, a raise
// is pending or SetMTU failed. Such a round programs nothing while the clamp
// is current, and tries a clamp that failed before again.
func (m *Manager) adjustMTU(ctx context.Context) {
	pathMTU, err := m.probe(ctx)
	if err != nil {
		// A round cut short by shutdown says nothing about the uplink.
		if ctx.Err() != nil {
			return
		}
		m.raiseTo = 0
		m.logger.Warn("wireguard: mtu probe inconclusive, keeping the current mtu",
			"component", "wireguard",
			"mtu", m.mtu,
			"error", err,
		)
		return
	}
	// Shutdown deletes the interface while this goroutine may still be
	// running, so a round that ended after ctx was done leaves the device
	// alone.
	if ctx.Err() != nil {
		return
	}
	// Deferred so that it follows SetMTU on every path below, and reads the
	// MTU the round leaves rather than the one it found.
	defer func() { m.clampMSS(m.mtu) }()

	target := MeshMTU(pathMTU)
	switch {
	case target == m.mtu:
		m.raiseTo = 0
		return
	case target > m.mtu && m.raiseTo != target:
		m.raiseTo = target
		m.logger.Debug("wireguard: higher mesh mtu seen, raising when the next probe agrees",
			"component", "wireguard",
			"mtu", m.mtu,
			"raise_to", target,
			"path_mtu", pathMTU,
		)
		return
	}

	old := m.mtu
	m.raiseTo = 0
	if err := m.ctrl.SetMTU(m.cfg.InterfaceName, target); err != nil {
		m.logger.Warn("wireguard: mesh mtu change failed",
			"component", "wireguard",
			"old_mtu", old,
			"mtu", target,
			"error", err,
		)
		return
	}
	m.mtu = target

	msg := "wireguard: mesh mtu lowered"
	if target > old {
		msg = "wireguard: mesh mtu raised"
	}
	m.logger.Info(msg,
		"component", "wireguard",
		"old_mtu", old,
		"mtu", target,
		"path_mtu", pathMTU,
	)
	m.warnBelowMinimum(pathMTU)
}
