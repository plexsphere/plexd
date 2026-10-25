package nat

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// MTUProbeSizes are the IPv4 packet sizes ProbePathMTU tries, in bytes.
//
// They cover the common uplinks, Ethernet (1500), PPPoE (1492), DS-Lite (1460)
// and DS-Lite over PPPoE (1452), with steps in between, down to 1360. A path
// smaller than 1360 leaves the mesh at its 1280 minimum anyway, so nothing
// below it is worth a datagram. Every entry minus the 28 bytes of IPv4 and UDP
// header is a valid size for buildPaddedBindingRequest.
var MTUProbeSizes = []int{1500, 1492, 1480, 1472, 1460, 1452, 1440, 1428, 1420, 1400, 1380, 1360}

// MTUProbeTimeout bounds one probe round.
const MTUProbeTimeout = 2 * time.Second

// mtuProbeBaseline is the IPv4 size of the unpadded request: 20 STUN + 8 UDP + 20 IPv4.
const mtuProbeBaseline = 48

// ipv4UDPHeaderSize is what IPv4 (20) and UDP (8) add to a STUN message. A
// ladder entry's request is the entry minus this, so the datagram leaves the
// host as an IPv4 packet of exactly the entry's size.
const ipv4UDPHeaderSize = 28

// ErrMTUProbeInconclusive is returned by ProbePathMTU when no STUN server
// answered any probe, so the round says nothing about the path.
var ErrMTUProbeInconclusive = errors.New("nat: mtu probe: no STUN server answered")

// ProbePathMTU returns the largest IPv4 packet size, in bytes, that reached a
// STUN server.
//
// Every server gets an unpadded baseline request and one request per
// MTUProbeSizes entry, padded to that packet size and sent with the
// don't-fragment bit set, all at once. Each request goes out on its own
// socket: Linux reports a router's "fragmentation needed" as EMSGSIZE on the
// next read of the socket that sent the packet, and on a shared socket that
// error could not be pinned to a probe. A request that draws an error, or no
// answer before the round ends, was not carried. The errors are not
// classified, because they all mean the same thing here.
//
// The result is the maximum over servers, not the minimum: an answer proves
// the uplink carried that size, and one lost probe at one server must not
// lower the mesh MTU. The baseline counts as 48 bytes, so a server that
// answers only the unpadded request still yields a result.
//
// The round lasts at most timeout, or until ctx is done, and ends as soon as
// every probe has: on a healthy uplink after one round trip. When nothing was
// answered, the error wraps ErrMTUProbeInconclusive and each server's reason.
// With no servers it is the bare sentinel, and no socket is opened. When ctx
// is done at the end of the round, the error is ctx's, whatever was answered.
// The probe logs nothing; its callers do.
func ProbePathMTU(ctx context.Context, servers []string, timeout time.Duration) (int, error) {
	if len(servers) == 0 {
		return 0, ErrMTUProbeInconclusive
	}

	roundCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sizes := make([]int, len(servers))
	errs := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Go(func() {
			sizes[i], errs[i] = probeServer(roundCtx, server)
		})
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("nat: mtu probe: %w", err)
	}

	best := 0
	var perServer []error
	for i, server := range servers {
		best = max(best, sizes[i])
		if errs[i] != nil {
			perServer = append(perServer, fmt.Errorf("%s: %w", server, errs[i]))
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("%w: %w", ErrMTUProbeInconclusive, errors.Join(perServer...))
	}
	return best, nil
}

// probeServer runs the baseline and every ladder probe against server at once
// and returns the largest size it answered. When it answered none, the error
// says why: the resolve error, or the baseline probe's error. The baseline is
// the request every reachable server answers, so its failure is the one that
// explains the silence; a ladder probe's failure is the measurement itself.
func probeServer(ctx context.Context, server string) (int, error) {
	addr, err := resolveProbeServer(ctx, server)
	if err != nil {
		return 0, err
	}

	var (
		wg          sync.WaitGroup
		baselineErr error
		answered    = make([]bool, len(MTUProbeSizes))
	)
	wg.Go(func() {
		baselineErr = probeOnce(ctx, addr, buildBindingRequest)
	})
	for i, size := range MTUProbeSizes {
		wg.Go(func() {
			err := probeOnce(ctx, addr, func(transactionID [12]byte) []byte {
				return buildPaddedBindingRequest(transactionID, size-ipv4UDPHeaderSize)
			})
			answered[i] = err == nil
		})
	}
	wg.Wait()

	best := 0
	if baselineErr == nil {
		best = mtuProbeBaseline
	}
	for i, size := range MTUProbeSizes {
		if answered[i] {
			best = max(best, size)
		}
	}
	if best == 0 {
		return 0, baselineErr
	}
	return best, nil
}

// lookupNetIP is the lookup resolveProbeServer resolves a host name with.
// Tests replace it to resolve a name without a nameserver, and to stand in
// for a nameserver that never answers.
var lookupNetIP = net.DefaultResolver.LookupNetIP

// resolveProbeServer resolves a host:port server to one IPv4 address and port
// under ctx, once per round, so every probe of the round dials a literal.
// net.ResolveUDPAddr, which UDPSTUNClient uses, takes no context: a
// nameserver that never answers would hold the round, and with it plexd up's
// startup, past its timeout. The port is resolved first, as ResolveUDPAddr
// does it, so a malformed server is rejected without a nameserver being asked
// anything.
func resolveProbeServer(ctx context.Context, server string) (string, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return "", err
	}

	number, err := net.DefaultResolver.LookupPort(ctx, "udp", port)
	if err != nil {
		return "", err
	}

	addrs, err := lookupNetIP(ctx, "ip4", host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no IPv4 address for host %q", host)
	}

	// LookupNetIP returns an IP literal, and a hosts-file entry, in its
	// IPv4-mapped IPv6 form; Unmap dials the plain IPv4 address instead.
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(number)).String(), nil
}

// probeControl is the Control function of every probe socket's dialer.
// Tests replace it to see each probe socket get the don't-fragment bit, which
// a round's result over loopback cannot show: loopback carries every ladder
// size with the bit or without it.
var probeControl = setDontFragment

// probeOnce sends the request build makes, with a fresh random transaction
// ID, from its own don't-fragment socket and waits for the answer. It returns
// nil when the server answered, and otherwise the first dial, write or read
// error, the round's end among them. A datagram that is not the answer is
// skipped and the read goes on.
func probeOnce(ctx context.Context, addr string, build func(transactionID [12]byte) []byte) error {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return fmt.Errorf("random tx id: %w", err)
	}

	dialer := net.Dialer{Control: probeControl}
	conn, err := dialer.DialContext(ctx, "udp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// The socket's deadline is the round's: its start plus the timeout, or
	// ctx's own deadline when that comes first. A cancel comes without a
	// deadline, so the AfterFunc pulls the deadline to now and a blocked read
	// returns at once. The probe waits for an AfterFunc that already started,
	// so nothing it began outlives it.
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	unblocked := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(unblocked)
		_ = conn.SetDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-unblocked
		}
	}()

	if _, err := conn.Write(build(txID)); err != nil {
		return err
	}

	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if isResponseTo(buf[:n], txID) {
			return nil
		}
	}
}
