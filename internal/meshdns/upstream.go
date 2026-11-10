package meshdns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// forwardTimeout bounds one forwarded query, every resolver it asks included.
// It stays below the 5 seconds systemd-resolved and glibc wait for a server,
// so the client gets SERVFAIL from plexd rather than count plexd as a server
// that does not answer, which would cost it the mesh names as well.
const forwardTimeout = 4 * time.Second

// resolverRetry is how long a resolver that did not answer is asked after
// the others, so a dead first resolver does not delay every query of its
// zone.
const resolverRetry = 30 * time.Second

// resolverPort is the port every resolver is asked on: the contract fixes
// plain DNS on port 53.
const resolverPort = 53

// errNoResolver reports an exchange without a resolver to ask. Route never
// returns an empty list, so the server never sees it.
var errNoResolver = errors.New("no resolver")

// upstream asks the forward resolvers for the server and relays their reply.
// It keeps no cache, because the client caches by the reply's TTL. It does
// keep which resolvers did not answer, shared by every query, so a resolver
// that is down is asked after the others until resolverRetry has passed.
type upstream struct {
	logger *slog.Logger
	// target returns the address and port a query to resolver goes to,
	// resolverAddr by default. Tests point it at fake resolvers on ports the
	// kernel picked; the marks stay keyed by resolver.
	target func(resolver netip.Addr) netip.AddrPort
	// timeout bounds one exchange, defaulted from forwardTimeout.
	timeout time.Duration
	// now returns the time the marks are set and compared with, defaulted
	// from time.Now. Tests move it on rather than wait for resolverRetry.
	now func() time.Time

	mu sync.Mutex
	// down maps each resolver that did not answer to the time until which it
	// is asked after the others. The mark outlives that time and goes only
	// with a matching reply or a prune, so a resolver that is still down
	// when it is asked first again is not reported a second time.
	down map[netip.Addr]time.Time
}

// newUpstream returns an upstream that asks each resolver on port 53, gives
// one exchange forwardTimeout, and logs to logger.
func newUpstream(logger *slog.Logger) *upstream {
	return &upstream{
		logger:  logger,
		target:  resolverAddr,
		timeout: forwardTimeout,
		now:     time.Now,
		down:    make(map[netip.Addr]time.Time),
	}
}

// resolverAddr returns where a query to resolver goes: port 53 of the
// resolver itself.
func resolverAddr(resolver netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(resolver, resolverPort)
}

// exchange asks resolvers, on behalf of zone, for the answer to query, the
// client's message as it arrived, and returns the reply as the resolver sent
// it but for the message ID, which is the client's again. It asks over TCP
// when tcp is set and over UDP otherwise, and relays a reply with TC set as
// it is, so the client asks again over TCP.
//
// The resolvers that are not marked down are asked first, then the marked
// ones, each group in list order, all within the upstream's timeout. Each
// attempt gets the time left divided by the resolvers not yet asked. A reply
// with any response code but SERVFAIL or REFUSED ends the exchange. A
// SERVFAIL or REFUSED is kept while the next resolver is asked, and the last
// one kept is returned when no resolver gives another, so the client sees the
// resolver's own code. An attempt without a matching reply marks its
// resolver down for resolverRetry, and a matching reply of any code clears
// the mark.
//
// When no resolver answered, the error wraps the last attempt's error:
// context.DeadlineExceeded for one that ran out of time, otherwise the socket
// error. When ctx ends, the error wraps ctx.Err(), and no resolver is marked
// for it. Without resolvers it sends nothing and wraps errNoResolver.
func (u *upstream) exchange(ctx context.Context, resolvers []netip.Addr, zone string, query []byte, tcp bool) ([]byte, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("meshdns: forward to %s: %w", zone, errNoResolver)
	}
	var p dnsmessage.Parser
	qh, err := p.Start(query)
	if err != nil {
		return nil, fmt.Errorf("meshdns: forward to %s: %w", zone, err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("meshdns: forward to %s: %w", zone, err)
	}

	deadline := time.Now().Add(u.timeout)
	order := u.order(resolvers)
	var kept []byte
	// lastErr stays context.DeadlineExceeded only when the time ran out
	// before the first attempt.
	var lastErr error = context.DeadlineExceeded
	for i, resolver := range order {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("meshdns: forward to %s: %w", zone, err)
		}
		left := time.Until(deadline)
		if left <= 0 {
			// The attempts before used up the time, so this resolver was
			// not asked and is not marked.
			break
		}
		reply, rcode, err := u.attempt(ctx, resolver, query, qh.ID, q, tcp, time.Now().Add(left/time.Duration(len(order)-i)))
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, fmt.Errorf("meshdns: forward to %s: %w", zone, ctxErr)
			}
			u.markDown(resolver, zone, err)
			lastErr = err
			continue
		}
		u.markUp(resolver)
		binary.BigEndian.PutUint16(reply, qh.ID)
		if rcode != dnsmessage.RCodeServerFailure && rcode != dnsmessage.RCodeRefused {
			return reply, nil
		}
		kept = reply
	}
	if kept != nil {
		return kept, nil
	}
	return nil, fmt.Errorf("meshdns: forward to %s: %w", zone, lastErr)
}

// attempt sends query to resolver from a socket of its own, a connected UDP
// socket or, with tcp set, a TCP connection with the two-byte length frame,
// under a random ID other than clientID. It returns the first reply that
// matches the query, with the reply's response code, and drops every other
// message it reads. It gives up at deadline, or as soon as ctx ends, which
// pulls the socket's deadline to now so a blocked read returns at once. Time
// running out is reported as context.DeadlineExceeded, and any other failure
// as the socket's error.
func (u *upstream) attempt(ctx context.Context, resolver netip.Addr, query []byte, clientID uint16, q dnsmessage.Question, tcp bool, deadline time.Time) ([]byte, dnsmessage.RCode, error) {
	id, err := randomID(clientID)
	if err != nil {
		return nil, 0, err
	}
	msg := slices.Clone(query)
	binary.BigEndian.PutUint16(msg, id)

	network := "udp"
	if tcp {
		network = "tcp"
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, network, u.target(resolver).String())
	if err != nil {
		return nil, 0, deadlineErr(err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, err
	}
	// A cancel comes without a deadline, so the AfterFunc pulls the
	// deadline to now. The attempt waits for an AfterFunc that already
	// started, so nothing it began outlives it.
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

	var reply []byte
	var rcode dnsmessage.RCode
	if tcp {
		reply, rcode, err = readTCPReply(conn, msg, id, q)
	} else {
		reply, rcode, err = readUDPReply(conn, msg, id, q)
	}
	if err != nil {
		return nil, 0, deadlineErr(err)
	}
	return reply, rcode, nil
}

// readUDPReply sends msg on the connected UDP socket conn and reads
// datagrams until one matches id and q.
func readUDPReply(conn net.Conn, msg []byte, id uint16, q dnsmessage.Question) ([]byte, dnsmessage.RCode, error) {
	if _, err := conn.Write(msg); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, maxMessageSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, 0, err
		}
		if rcode, ok := matchReply(buf[:n], id, q); ok {
			return slices.Clone(buf[:n]), rcode, nil
		}
	}
}

// readTCPReply sends msg on the TCP connection conn behind its two-byte
// length and reads framed messages until one matches id and q.
func readTCPReply(conn net.Conn, msg []byte, id uint16, q dnsmessage.Question) ([]byte, dnsmessage.RCode, error) {
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(msg)), uint16(len(msg)))
	if _, err := conn.Write(append(frame, msg...)); err != nil {
		return nil, 0, err
	}
	var size [2]byte
	for {
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, 0, err
		}
		reply := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return nil, 0, err
		}
		if rcode, ok := matchReply(reply, id, q); ok {
			return reply, rcode, nil
		}
	}
}

// matchReply reports whether reply answers the query sent with id for the
// question q, and returns its response code. A reply matches when it holds
// at least a header, carries id, has QR set, and its first question has q's
// name, compared in ASCII lower case, q's type and q's class. Anything else,
// such as a late reply to an earlier attempt, is no answer to this one.
func matchReply(reply []byte, id uint16, q dnsmessage.Question) (dnsmessage.RCode, bool) {
	if len(reply) < headerLen {
		return 0, false
	}
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil || h.ID != id || !h.Response {
		return 0, false
	}
	rq, err := p.Question()
	if err != nil || rq.Type != q.Type || rq.Class != q.Class || foldName(rq.Name.String()) != foldName(q.Name.String()) {
		return 0, false
	}
	return h.RCode, true
}

// randomID returns two bytes from crypto/rand as a message ID, drawn again
// while they equal not, so the query that leaves the host carries an ID of
// plexd's own rather than the client's.
func randomID(not uint16) (uint16, error) {
	var b [2]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("random message id: %w", err)
		}
		if id := binary.BigEndian.Uint16(b[:]); id != not {
			return id, nil
		}
	}
}

// deadlineErr returns context.DeadlineExceeded for a dial or a read that ran
// out of time, however package net wraps that, and err otherwise.
func deadlineErr(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

// order returns resolvers that are not marked down, then those that are,
// each group in list order. A mark whose time has passed counts as none
// here, so its resolver is asked in its turn again.
func (u *upstream) order(resolvers []netip.Addr) []netip.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	ordered := make([]netip.Addr, 0, len(resolvers))
	var later []netip.Addr
	for _, r := range resolvers {
		if until, ok := u.down[r]; ok && now.Before(until) {
			later = append(later, r)
		} else {
			ordered = append(ordered, r)
		}
	}
	return append(ordered, later...)
}

// markDown marks resolver down until resolverRetry from now. It warns when
// the resolver had no mark, and stays quiet while it stays down.
func (u *upstream) markDown(resolver netip.Addr, zone string, err error) {
	u.mu.Lock()
	_, marked := u.down[resolver]
	u.down[resolver] = u.now().Add(resolverRetry)
	u.mu.Unlock()
	if !marked {
		u.logger.Warn("mesh dns resolver does not answer", "resolver", resolver.String(), "zone", zone, "error", err)
	}
}

// markUp clears the mark of resolver, which gave a matching reply, and says
// so when it had one.
func (u *upstream) markUp(resolver netip.Addr) {
	u.mu.Lock()
	_, marked := u.down[resolver]
	delete(u.down, resolver)
	u.mu.Unlock()
	if marked {
		u.logger.Info("mesh dns resolver answers again", "resolver", resolver.String())
	}
}

// prune drops the marks of the resolvers keep names nowhere, as a forward
// zone's or the catch-all's, so the marks never outgrow the table and a
// resolver that comes back to it later starts without one. A nil keep names
// none.
func (u *upstream) prune(keep *Forwarding) {
	named := make(map[netip.Addr]struct{})
	if keep != nil {
		for _, rs := range keep.resolvers {
			for _, r := range rs {
				named[r] = struct{}{}
			}
		}
		for _, r := range keep.catchAll {
			named[r] = struct{}{}
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	maps.DeleteFunc(u.down, func(r netip.Addr, _ time.Time) bool {
		_, ok := named[r]
		return !ok
	})
}
