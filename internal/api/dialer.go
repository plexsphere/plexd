package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
)

// dialFunc dials a network address, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// fallbackDialer dials the control plane and remembers, for each host name,
// the IP address its last successful dial reached. When a later dial fails
// because the name does not resolve, it dials that address with the port of
// the request instead.
//
// The fallback keeps plexd reaching its control plane while the Node's own
// resolver cannot answer the name, as with a mesh DNS catch-all whose
// resolvers are down. The pull that corrects the setting then still arrives.
// The transport takes the TLS server name from the request URL, not from the
// dialed address, so the certificate is still verified against the name.
//
// The stored addresses live in memory only and one address is kept per host.
// An address with an IP literal as its host stores nothing.
type fallbackDialer struct {
	// dial makes every connection, the ordinary one and the fallback. A test
	// in the package replaces it before the first request.
	dial   dialFunc
	logger *slog.Logger

	mu sync.Mutex
	// last maps a host name to the remote IP of its last successful ordinary
	// dial.
	last map[string]netip.Addr
	// fallingBack holds the hosts whose fallback was logged and whose name
	// has not resolved since.
	fallingBack map[string]bool
}

// newFallbackDialer returns a fallbackDialer that dials through dial and logs
// to logger.
func newFallbackDialer(dial dialFunc, logger *slog.Logger) *fallbackDialer {
	return &fallbackDialer{
		dial:        dial,
		logger:      logger,
		last:        make(map[string]netip.Addr),
		fallingBack: make(map[string]bool),
	}
}

// DialContext dials address on network. After a successful dial of an
// address whose host is a name, it stores the connection's remote IP under
// that host. When the dial fails with an error that holds a *net.DNSError and
// an address is stored for the host, it dials the stored address with the
// same port and returns that connection or that dial's error. Any other error,
// a *net.DNSError for a host without a stored address, and any error after ctx
// has ended are returned unchanged.
func (d *fallbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dial(ctx, network, address)

	host, port, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return conn, err
	}
	if _, parseErr := netip.ParseAddr(host); parseErr == nil {
		return conn, err
	}

	if err == nil {
		d.remember(host, conn)
		return conn, nil
	}

	// A lookup that ctx cuts short fails with a *net.DNSError too. The name
	// may well resolve then, and a second dial with the ended ctx would fail
	// at once, so that error is returned as it is.
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || ctx.Err() != nil {
		return conn, err
	}
	stored, first, ok := d.fallback(host)
	if !ok {
		return conn, err
	}
	target := net.JoinHostPort(stored.String(), port)
	if first {
		d.logger.Warn("control plane name does not resolve, dialing its last address",
			"host", host, "address", target, "error", err)
	}
	return d.dial(ctx, network, target)
}

// remember stores the remote IP of conn under host and logs the first
// ordinary dial that succeeds after a fallback.
func (d *fallbackDialer) remember(host string, conn net.Conn) {
	ip, ok := remoteIP(conn)

	d.mu.Lock()
	if ok {
		d.last[host] = ip
	}
	resolvesAgain := d.fallingBack[host]
	delete(d.fallingBack, host)
	d.mu.Unlock()

	if resolvesAgain {
		d.logger.Info("control plane name resolves again", "host", host)
	}
}

// fallback returns the address stored for host and whether this is the first
// fallback of host since its name last resolved. ok is false when no address
// is stored.
func (d *fallbackDialer) fallback(host string) (addr netip.Addr, first, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	addr, ok = d.last[host]
	if !ok {
		return netip.Addr{}, false, false
	}
	first = !d.fallingBack[host]
	d.fallingBack[host] = true
	return addr, first, true
}

// remoteIP returns the IP of the remote end of conn with an IPv4-mapped IPv6
// address unmapped. ok is false when the remote address carries no IP.
func remoteIP(conn net.Conn) (ip netip.Addr, ok bool) {
	if conn == nil {
		return netip.Addr{}, false
	}
	ra := conn.RemoteAddr()
	if ra == nil {
		return netip.Addr{}, false
	}
	ap, err := netip.ParseAddrPort(ra.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}
