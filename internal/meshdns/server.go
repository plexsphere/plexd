package meshdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// recordTTL is the TTL of every record the server sends, the synthesized SOA
// included. systemd-resolved caches an answer for its TTL, so a name a pull
// changed is served stale for at most this long, and no cache flush is needed.
const recordTTL = 10

// The fields of the SOA the server synthesizes for a zone. Nothing transfers
// these zones, so only the minimum matters: RFC 2308 makes a resolver cache a
// negative answer for the lower of it and the SOA's TTL, which keeps a name
// that a pull adds from staying denied longer than a changed one stays stale.
const (
	soaMName   = "ns.plexd.invalid."
	soaRName   = "hostmaster.plexd.invalid."
	soaSerial  = 1
	soaRefresh = 3600
	soaRetry   = 600
	soaExpire  = 86400
	soaMinimum = 10
)

// ednsPayloadSize is the UDP payload size the server advertises when a query
// carries an OPT record, and the most it sends over UDP whatever the client
// offers. 1232 bytes is the size the DNS flag day 2020 settled on, which fits
// an IPv6 packet into the minimum MTU without fragmentation.
const ednsPayloadSize = 1232

// udpLimit is the most a response over UDP to a query without an OPT record
// may carry, RFC 1035's limit. A client that offers less with its OPT record
// gets this much too, as RFC 6891 has it.
const udpLimit = 512

// headerLen is the length of a DNS message header. A packet shorter than it
// cannot even name the query it belongs to, so it gets no reply.
const headerLen = 12

// opcodeQuery is the standard query, the only opcode the server implements.
const opcodeQuery dnsmessage.OpCode = 0

// typeIXFR is the incremental zone transfer, which package dnsmessage has no
// name for. Neither zone transfer is forwarded: the resolver relays queries
// for names, not zones.
const typeIXFR dnsmessage.Type = 251

// maxMessageSize is the largest DNS message UDP or the two-byte TCP length can
// carry, so a read never cuts a message short.
const maxMessageSize = 65535

// tcpIdleTimeout bounds how long a TCP connection is read after the accept,
// the latest reply or the latest forwarded query, and how long one reply may
// take to write, so a client that opens a connection and stalls, or stops
// reading its replies, holds its slot for no longer than this, plus the time
// its forwards in flight still take. A forwarded query ends within
// forwardTimeout, which is shorter, so the read does not run out while one
// waits for its resolvers.
const tcpIdleTimeout = 10 * time.Second

// maxTCPConns caps the open TCP connections. The idle timeout bounds how long
// one connection lasts; the cap bounds how many a local program can hold
// open at once, each with a goroutine and a buffer.
const maxTCPConns = 32

// maxForwards caps the forwarded queries in flight, over UDP and TCP
// together. Each waits for its resolvers off the loop that read it, for up to
// forwardTimeout, with a goroutine and a socket, so the cap bounds what a
// burst of queries to a resolver that does not answer can hold. A forward
// gives its slot back once its resolvers answered or failed, before its reply
// goes out. A query over the cap gets SERVFAIL at once.
const maxForwards = 256

// maxConnForwards caps the forwarded queries of one TCP connection, each from
// the time the read loop hands it on until its reply is written. A forward
// gives its slot of maxForwards back before that write, which may wait for
// the client, so without this cap a client that sends queries and stops
// reading the replies would keep a goroutine and a reply waiting for each
// query it sent. A forwarded query over the cap gets SERVFAIL from the
// connection's read loop, whose write waits behind the others, so the loop
// reads nothing more from such a client until it reads again.
const maxConnForwards = 16

// listenAttempts is how often Listen tries a fresh kernel-chosen port when the
// TCP side finds the port that UDP got already taken.
const listenAttempts = 10

// Server answers DNS queries for the mesh names over UDP and TCP on one
// address, and forwards a query for any other name that its forwarding table
// routes to the resolvers the table names. It answers the node itself only: a
// query from any source other than the listen address or a loopback address
// is dropped, because plexd's firewall filters forwarded traffic only and
// nothing else keeps other hosts from using the resolver.
type Server struct {
	addr   netip.AddrPort
	logger *slog.Logger

	// records holds the names the server answers from. A pull swaps it
	// whole, so a query never waits for a pull and never sees half a block.
	records atomic.Pointer[Records]
	// forwarding holds the table the server forwards with, swapped whole
	// like records. Nil forwards nothing.
	forwarding atomic.Pointer[Forwarding]
	// upstream asks the resolvers of a forwarded query and keeps which of
	// them do not answer.
	upstream *upstream
	// forwardLimit is the number of forwarded queries in flight at once, over
	// UDP and TCP together, defaulted from maxForwards. Tests shorten it.
	forwardLimit int

	// tcpIdle is how long a TCP connection is read after the accept, the
	// latest reply or the latest forwarded query, and how long one reply may
	// take to write, defaulted from tcpIdleTimeout. Tests shorten it.
	tcpIdle time.Duration

	mu    sync.Mutex
	udp   *net.UDPConn
	tcp   *net.TCPListener
	bound netip.AddrPort
	// listened is set by the Listen that succeeds and never cleared. Serve
	// takes the sockets out of udp and tcp, so a guard on those would let a
	// Listen during Serve bind a pair nothing serves and move Addr to it.
	listened bool
}

// NewServer returns a server for addr. It binds nothing until Listen, so the
// caller learns about an occupied port from Listen's error and decides what
// to do about it before serving starts. The server logs at Debug, except for
// a forward resolver that stops or starts answering, and adds no attributes
// of its own to logger.
func NewServer(addr netip.AddrPort, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		addr:         addr,
		logger:       logger,
		upstream:     newUpstream(logger),
		forwardLimit: maxForwards,
		tcpIdle:      tcpIdleTimeout,
		bound:        addr,
	}
}

// SetRecords replaces the names the server answers from. The swap is atomic,
// so a pull never blocks a query: a query in flight finishes with the records
// it started with, and the next one sees r. A nil r answers no name, as the
// server does before the first call: a name the forwarding table routes is
// forwarded, and every other name gets REFUSED.
func (s *Server) SetRecords(r *Records) {
	s.records.Store(r)
}

// SetForwarding replaces the table the server forwards with, as SetRecords
// replaces the names, and drops the marks of the resolvers f no longer names.
// A nil f forwards nothing, as the server does before the first call, so a
// name outside the mesh zones gets REFUSED.
func (s *Server) SetForwarding(f *Forwarding) {
	s.forwarding.Store(f)
	s.upstream.prune(f)
}

// Addr returns the address the server is bound to. Before Listen, and when
// addr named a port other than 0, it is addr itself; after Listen on port 0
// it carries the port the kernel chose, which is the same for UDP and TCP.
func (s *Server) Addr() netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bound
}

// Listen binds UDP and TCP on the server's address and port. A resolver that
// answers on one of them only would fail systemd-resolved as soon as it moves
// to TCP after repeated UDP losses, so a failure of either bind fails Listen
// and closes the socket that did bind. With port 0, UDP binds first and TCP
// takes the port UDP got; when that port is taken for TCP, Listen tries a
// fresh one, up to listenAttempts times. A server listens once: after a
// Listen that succeeded, Listen fails, before, during and after Serve.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listened {
		return fmt.Errorf("meshdns: listen %s: %w", s.addr, errors.New("already listening"))
	}
	if a := s.addr.Addr(); !a.IsValid() || a.Unmap().IsUnspecified() {
		// The zero address would bind every interface of the host, and so
		// would an unspecified one, 0.0.0.0 or ::. An IPv4-mapped 0.0.0.0
		// binds as 0.0.0.0, so it is unmapped first.
		return fmt.Errorf("meshdns: listen %s: %w", s.addr, errors.New("no address to listen on"))
	}

	attempts := 1
	if s.addr.Port() == 0 {
		attempts = listenAttempts
	}
	var err error
	for range attempts {
		var udp *net.UDPConn
		udp, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(s.addr))
		if err != nil {
			return fmt.Errorf("meshdns: listen %s: %w", s.addr, err)
		}
		bound := netip.AddrPortFrom(s.addr.Addr(), udp.LocalAddr().(*net.UDPAddr).AddrPort().Port())
		var tcp *net.TCPListener
		tcp, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(bound))
		if err != nil {
			// The UDP bind of the same address worked, so on a port the
			// kernel chose the TCP bind can only fail because that port is
			// taken. The errno for that differs between operating systems,
			// so any error is retried rather than one errno matched.
			_ = udp.Close()
			continue
		}
		s.udp, s.tcp, s.bound, s.listened = udp, tcp, bound, true
		return nil
	}
	return fmt.Errorf("meshdns: listen %s: %w", s.addr, err)
}

// Serve answers queries on the sockets Listen bound until ctx ends, then
// ends the forwarded queries in flight, over UDP and TCP, closes both sockets
// and every open TCP connection, waits for the goroutine of each connection
// and each forward to finish, and returns nil. A forwarded query that Serve
// ends gets no reply, as one that arrives after the close does. A failed UDP
// read, or a TCP listener closed by anything but Serve, while ctx is live
// stops serving the same way and is returned, so the caller can log that the
// resolver stopped. Any other failed accept, such as EMFILE while the process
// is out of file descriptors, is retried after a wait, so a passing shortage
// stops neither TCP nor UDP. Serve without a successful Listen returns an
// error.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	udp, tcp := s.udp, s.tcp
	s.udp, s.tcp = nil, nil
	s.mu.Unlock()
	if udp == nil {
		return errors.New("meshdns: serve: not listening")
	}

	// stop is closed before the sockets are, so a loop whose read fails
	// tells the close that Serve caused from a failure of the socket.
	stop := make(chan struct{})
	// The forwards' context ends with Serve, so a query waiting for a
	// resolver does not hold up the return.
	fctx, cancelForwards := context.WithCancel(ctx)
	defer cancelForwards()
	fw := newForwards(fctx, s.forwardLimit)
	var conns connSet
	var loops sync.WaitGroup
	errs := make(chan error, 2)
	loops.Add(2)
	go func() {
		defer loops.Done()
		errs <- s.serveUDP(udp, stop, fw)
	}()
	go func() {
		defer loops.Done()
		errs <- s.serveTCP(fw, tcp, &conns, stop)
	}()

	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	close(stop)
	cancelForwards()
	_ = udp.Close()
	_ = tcp.Close()
	// The accept loop has returned once loops.Wait does, so no connection
	// joins the set while closeAll closes it, and the UDP read loop has
	// returned. closeAll waits for the goroutine of every connection, which
	// waits for the forwards it started, so no forward joins fw while Serve
	// waits for them.
	loops.Wait()
	conns.closeAll()
	fw.wg.Wait()
	return err
}

// forwards holds the forwarded queries of one Serve call, over UDP and TCP:
// the context that ends them when Serve stops, a slot for each one in flight,
// which both transports share, so maxForwards caps them together, and their
// goroutines, which Serve waits for.
type forwards struct {
	ctx   context.Context
	slots chan struct{}
	wg    sync.WaitGroup
}

// newForwards returns the forwards of a Serve call that ends with ctx, with
// limit slots.
func newForwards(ctx context.Context, limit int) *forwards {
	return &forwards{ctx: ctx, slots: make(chan struct{}, limit)}
}

// takeSlot takes one of slots for a forwarded query and reports true: one of
// the slots of forwards, or one of the places of a TCP connection. When
// every one is taken, it logs the drop with the cap it hit and reports
// false, and the caller answers SERVFAIL at once rather than wait for one.
func (s *Server) takeSlot(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		s.logger.Debug("mesh dns dropped a forwarded query, too many are in flight", "limit", cap(slots))
		return false
	}
}

// allowedSource reports whether the server answers a query from src: the
// node itself, which reaches the listen address from that address or from
// loopback. A mesh peer cannot send from the node's own address, because
// WireGuard drops a packet whose source is outside the sending peer's allowed
// IPs.
func (s *Server) allowedSource(src netip.Addr) bool {
	src = src.Unmap()
	return src == s.addr.Addr().Unmap() || src.IsLoopback()
}

// serveUDP answers the datagrams of conn one after the other until a read
// fails, and hands the forwarded queries to fw. It returns nil when the
// failure is the close Serve caused.
func (s *Server) serveUDP(conn *net.UDPConn, stop <-chan struct{}, fw *forwards) error {
	buf := make([]byte, maxMessageSize)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			return fmt.Errorf("meshdns: serve udp: %w", err)
		}
		s.handlePacket(conn, buf[:n], src, fw)
	}
}

// packetWriter is the part of *net.UDPConn that handlePacket sends a reply
// with, so a test can watch what it sends to a source no socket can have.
type packetWriter interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// handlePacket answers the datagram msg from src through w, or drops it
// without a reply when src is not allowed or msg gets none. A query for the
// resolvers is relayed by a goroutine of fw, so a resolver that is slow to
// answer never holds up the read loop and the mesh names behind it.
func (s *Server) handlePacket(w packetWriter, msg []byte, src netip.AddrPort, fw *forwards) {
	if !s.allowedSource(src.Addr()) {
		s.logger.Debug("mesh dns dropped a packet from a source it does not answer", "source", src)
		return
	}
	resp, fwd := s.respond(nil, msg, true)
	if fwd != nil {
		s.forwardPacket(w, msg, src, fwd, fw)
		return
	}
	if resp == nil {
		s.logger.Debug("mesh dns dropped a packet that gets no reply", "source", src, "bytes", len(msg))
		return
	}
	s.sendPacket(w, resp, src)
}

// forwardPacket relays the query msg from src in a goroutine of fw and sends
// the response through w. When every slot of fw is taken, the query gets
// SERVFAIL at once rather than wait for one.
func (s *Server) forwardPacket(w packetWriter, msg []byte, src netip.AddrPort, fwd *forward, fw *forwards) {
	if !s.takeSlot(fw.slots) {
		if resp := s.serverFailure(nil, fwd); resp != nil {
			s.sendPacket(w, resp, src)
		}
		return
	}
	// The read loop reads the next datagram into msg's buffer.
	query := slices.Clone(msg)
	fw.wg.Go(func() {
		resp := s.relay(fw.ctx, nil, query, fwd, false)
		// The slot frees before the response goes out, so a client that has
		// its response finds the slot free for its next query.
		<-fw.slots
		if resp != nil {
			s.sendPacket(w, resp, src)
		}
	})
}

// sendPacket sends resp to src through w.
func (s *Server) sendPacket(w packetWriter, resp []byte, src netip.AddrPort) {
	if _, err := w.WriteToUDPAddrPort(resp, src); err != nil {
		s.logger.Debug("mesh dns could not send a reply", "source", src, "error", err)
	}
}

// acceptor is the part of *net.TCPListener that serveTCP accepts with, so a
// test can hand the loop an accept error no real listener returns on cue.
type acceptor interface {
	Accept() (net.Conn, error)
}

// The wait after a failed accept starts at minAcceptDelay and doubles with
// each further failure up to maxAcceptDelay, as net/http's Server.Serve
// waits, so a process out of file descriptors is not spun on.
const (
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second
)

// serveTCP accepts the connections of ln until ln is closed, and serves them
// with their forwarded queries in fw. It returns nil when that is the close
// Serve caused, and the accept error when it is not. Any other accept error
// is taken to pass, as EMFILE does once the process has a file descriptor
// free again, so serveTCP logs it at Debug, waits and accepts again rather
// than stop the resolver for the rest of the run.
func (s *Server) serveTCP(fw *forwards, ln acceptor, conns *connSet, stop <-chan struct{}) error {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("meshdns: serve tcp: %w", err)
			}
			delay = acceptDelay(delay)
			s.logger.Debug("mesh dns could not accept a connection", "error", err, "delay", delay)
			if !waitAccept(delay, stop) {
				return nil
			}
			continue
		}
		delay = 0
		var src netip.Addr
		if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			src = a.AddrPort().Addr()
		}
		s.accept(fw, conns, conn, src)
	}
}

// acceptDelay returns the wait after a failed accept, given the wait before
// it, which is 0 when the accept before succeeded.
func acceptDelay(last time.Duration) time.Duration {
	return min(max(2*last, minAcceptDelay), maxAcceptDelay)
}

// waitAccept waits d and reports true, or reports false as soon as stop is
// closed, so a wait between failed accepts does not hold up Serve's return.
func waitAccept(d time.Duration, stop <-chan struct{}) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-stop:
		return false
	case <-timer.C:
		return true
	}
}

// accept closes conn from src before reading anything when src is not
// allowed or conns is full, and otherwise serves it in a goroutine of its
// own that conns tracks, with its forwarded queries in fw.
func (s *Server) accept(fw *forwards, conns *connSet, conn net.Conn, src netip.Addr) {
	if !s.allowedSource(src) {
		_ = conn.Close()
		s.logger.Debug("mesh dns closed a connection from a source it does not answer", "source", src)
		return
	}
	if !conns.add(conn) {
		_ = conn.Close()
		s.logger.Debug("mesh dns closed a connection, too many are open", "source", src, "limit", maxTCPConns)
		return
	}
	go func() {
		defer conns.remove(conn)
		s.serveConn(fw, conn)
	}()
}

// serveConn answers the queries of one TCP connection, each framed by its
// two-byte length. Its loop reads the messages in turn until the client
// closes the connection, a read or write fails, or s.tcpIdle passes after the
// accept, the latest reply or the latest forwarded query while the loop waits
// for a message. A message that gets no reply does not restart the deadline:
// it asks nothing, and a client that sent one now and then would otherwise
// hold its slot for as long as it liked.
//
// A mesh answer, and any other reply that is no forward, is written from the
// loop. A forwarded query takes a place of the connection and a slot of fw
// and is relayed by a goroutine of its own, which writes the reply once the
// resolvers answered or failed, so a query sent behind it on the same
// connection, such as one for a mesh name, is answered meanwhile. The replies
// go out in the order they are ready, as RFC 7766 section 7 allows, and the
// client matches them by ID. A forwarded query that finds every place of the
// connection or every slot of fw taken gets SERVFAIL from the loop at once.
// That write waits behind the replies the client has not read, so a client
// that stops reading stops the loop with maxConnForwards forwards held.
//
// Once the loop ends, serveConn waits for the forwards the connection still
// has in flight before it closes the connection, so their replies still go
// out. When Serve stops, fw's context ends them, and they write nothing.
func (s *Server) serveConn(fw *forwards, conn net.Conn) {
	c := &tcpConn{conn: conn, idle: s.tcpIdle, forwards: make(chan struct{}, maxConnForwards)}
	defer func() {
		c.inflight.Wait()
		_ = conn.Close()
	}()
	// The write deadline set here passes as the read deadline does, so a
	// reply goes out only under the deadline its own write sets.
	if err := conn.SetDeadline(time.Now().Add(s.tcpIdle)); err != nil {
		return
	}
	var size [2]byte
	var msg []byte
	for {
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if cap(msg) < n {
			msg = make([]byte, n)
		}
		msg = msg[:n]
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		resp, fwd := s.respond(make([]byte, 2, 2+udpLimit), msg, false)
		if fwd != nil {
			if s.forwardTCP(fw, c, msg, fwd) {
				// The forward gets a reply, so it restarts the deadline as
				// a reply does, and does so now: the loop reads on while the
				// forward waits for its resolvers, which end within
				// forwardTimeout, before this deadline passes.
				if err := conn.SetReadDeadline(time.Now().Add(s.tcpIdle)); err != nil {
					return
				}
				continue
			}
			resp = s.serverFailure(make([]byte, 2, 2+udpLimit), fwd)
		}
		if resp == nil {
			s.logger.Debug("mesh dns dropped a message that gets no reply", "bytes", n)
			continue
		}
		if !c.write(resp) {
			return
		}
	}
}

// forwardTCP takes a place of the connection c and a slot of fw for the
// forwarded query msg, relays it in a goroutine of fw that writes the reply
// to c, and reports true. When c already holds maxConnForwards forwards, or
// every slot of fw is taken, it takes neither and reports false, and the
// read loop answers SERVFAIL itself.
func (s *Server) forwardTCP(fw *forwards, c *tcpConn, msg []byte, fwd *forward) bool {
	if !s.takeSlot(c.forwards) {
		return false
	}
	if !s.takeSlot(fw.slots) {
		<-c.forwards
		return false
	}
	// The loop reads the next message into msg's buffer.
	query := slices.Clone(msg)
	c.inflight.Add(1)
	fw.wg.Go(func() { s.relayTCP(fw, c, query, fwd) })
	return true
}

// relayTCP is the goroutine of one forwarded query of the connection c. It
// gives the slot of fw back once the resolvers answered or failed, before the
// reply goes out, as a forward over UDP does, and the place of c with the
// reply's write, which may wait for a client that does not read.
func (s *Server) relayTCP(fw *forwards, c *tcpConn, query []byte, fwd *forward) {
	defer c.inflight.Done()
	resp := s.relay(fw.ctx, make([]byte, 2, 2+udpLimit), query, fwd, true)
	<-fw.slots
	c.writeForward(resp)
}

// tcpConn is the writing side of one TCP connection, which its read loop and
// the goroutines of its forwarded queries share, and the count of those.
type tcpConn struct {
	conn net.Conn
	// idle is the server's tcpIdle.
	idle time.Duration
	// forwards holds a place for each forwarded query of the connection,
	// from the time the loop hands it on until its reply is written or
	// skipped, at most maxConnForwards.
	forwards chan struct{}
	// inflight counts the goroutines of those forwards, which the connection
	// waits for before it closes.
	inflight sync.WaitGroup
	// mu keeps each reply whole on the wire: one reply's frame never lands
	// inside another's, and its deadlines are set with it.
	mu sync.Mutex
}

// write sends the reply resp, whose first two bytes it fills with the length
// of the rest, and reports whether it went out. The write gets a deadline of
// c.idle from now, so a client that stops reading holds it up for no longer
// than that. A reply that went out moves the read deadline to c.idle from
// now, which also extends a read already waiting, so the client has the full
// time for its next query however long a forward took. A write that fails may
// have sent part of the frame, which leaves every frame after it unreadable,
// so write closes the connection, which also ends the read loop.
func (c *tcpConn) write(resp []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeLocked(resp)
}

// writeForward writes the reply resp of one of the connection's forwarded
// queries as write does, unless resp is nil, and gives the forward's place
// back under the same lock, so the place is free before a later reply goes
// out: a client that has read a reply finds free the place of every forward
// whose reply went out before it.
func (c *tcpConn) writeForward(resp []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if resp != nil {
		c.writeLocked(resp)
	}
	<-c.forwards
}

// writeLocked is write for a caller that holds c.mu.
func (c *tcpConn) writeLocked(resp []byte) bool {
	binary.BigEndian.PutUint16(resp, uint16(len(resp)-2))
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		_ = c.conn.Close()
		return false
	}
	if _, err := c.conn.Write(resp); err != nil {
		_ = c.conn.Close()
		return false
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		_ = c.conn.Close()
		return false
	}
	return true
}

// connSet tracks the open TCP connections of one Serve call, so the cap
// counts them and Serve can close every one and wait for its goroutine.
type connSet struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// add records conn and reports true, or reports false when maxTCPConns are
// already open.
func (c *connSet) add(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.conns) >= maxTCPConns {
		return false
	}
	if c.conns == nil {
		c.conns = make(map[net.Conn]struct{})
	}
	c.conns[conn] = struct{}{}
	c.wg.Add(1)
	return true
}

// remove releases the slot of conn once its goroutine is done with it.
func (c *connSet) remove(conn net.Conn) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
	c.wg.Done()
}

// closeAll closes every open connection, which ends the read its goroutine
// waits in, and waits for all of them to finish.
func (c *connSet) closeAll() {
	c.mu.Lock()
	for conn := range c.conns {
		_ = conn.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// respond returns the response to the query msg appended to dst, or nil when
// msg gets no reply: a packet shorter than the header, or one with QR set,
// which is a response itself and answering it could start a loop between two
// servers. udp says whether the response goes out as a datagram. A response
// over UDP that does not fit the limit of the query goes out with TC set and
// no records, so the client asks again over TCP. One over TCP that does not
// fit a message at all, more than 65,535 bytes, goes out as SERVFAIL.
//
// A query that the records refuse and the forwarding table routes gets no
// response from respond, which returns the forward that relay hands to the
// resolvers instead. Only a standard query with one question, at most one
// OPT record and class IN is forwarded, never a zone transfer, and every
// other query is answered as it was before forwarding, so the mesh zones
// always win.
func (s *Server) respond(dst, msg []byte, udp bool) ([]byte, *forward) {
	if len(msg) < headerLen {
		return nil, nil
	}
	var p dnsmessage.Parser
	qh, err := p.Start(msg)
	if err != nil || qh.Response {
		return nil, nil
	}

	h := dnsmessage.Header{
		ID:               qh.ID,
		Response:         true,
		OpCode:           qh.OpCode,
		RecursionDesired: qh.RecursionDesired,
	}
	q, ok := singleQuestion(&p, msg)
	// RFC 6891 6.1.1: a response to a query with an OPT record carries one,
	// a FORMERR included, and a query with more than one gets FORMERR.
	opts, payload := readOPT(&p)
	edns := opts > 0
	limit := maxMessageSize
	if udp {
		limit = udpLimit
		if edns {
			limit = min(max(int(payload), udpLimit), ednsPayloadSize)
		}
	}
	var question *dnsmessage.Question
	if ok {
		question = &q
	}
	var ans Answer
	switch {
	case qh.OpCode != opcodeQuery:
		h.RCode = dnsmessage.RCodeNotImplemented
	case !ok:
		h.RCode = dnsmessage.RCodeFormatError
	case opts > 1:
		h.RCode = dnsmessage.RCodeFormatError
		question = nil
	case q.Class != dnsmessage.ClassINET:
		h.RCode = dnsmessage.RCodeRefused
	default:
		ans = s.records.Load().Lookup(q.Name.String(), q.Type)
		switch ans.Result {
		case ResultNXDomain:
			h.RCode, h.Authoritative = dnsmessage.RCodeNameError, true
		case ResultNoData, ResultFound:
			h.RCode, h.Authoritative = dnsmessage.RCodeSuccess, true
		default:
			if fwd := s.route(h, q, edns, limit); fwd != nil {
				return nil, fwd
			}
			h.RCode = dnsmessage.RCodeRefused
		}
	}

	resp, err := buildResponse(dst, h, question, ans, edns)
	if err != nil {
		// Every name packed was parsed from the query or validated by
		// BuildRecords, so this does not happen; a reply that cannot be
		// packed is dropped rather than sent half built.
		s.logger.Debug("mesh dns could not pack a reply", "error", err)
		return nil, nil
	}
	if size := len(resp) - len(dst); size > limit {
		if udp {
			// The truncated response carries no record, so a client that does
			// not ask again over TCP keeps no part of the set.
			h.Truncated = true
		} else {
			// The two-byte length of a TCP message cannot carry more, so the
			// answer cannot be sent in any form.
			h.RCode, h.Authoritative = dnsmessage.RCodeServerFailure, false
			s.logger.Debug("mesh dns answer does not fit a message", "name", q.Name.String(), "type", q.Type.String(), "bytes", size)
		}
		if resp, err = buildResponse(dst, h, question, Answer{}, edns); err != nil {
			s.logger.Debug("mesh dns could not pack a reply", "error", err)
			return nil, nil
		}
	}
	return resp, nil
}

// forward is a query respond hands on to the resolvers: the resolvers Route
// chose and the zone that chose them, and what the server needs to answer the
// client itself when they fail it. header is the response header with the
// query's ID, opcode and RD bit, question the question as it arrived, edns
// whether the query carried an OPT record, and limit the most a response to
// it may carry, as respond computes it.
type forward struct {
	resolvers []netip.Addr
	zone      string
	header    dnsmessage.Header
	question  dnsmessage.Question
	edns      bool
	limit     int
}

// route returns the forward of the query q, which the records refuse, or nil
// when q asks for a zone transfer or the forwarding table routes its name
// nowhere. h, edns and limit are as respond computed them.
func (s *Server) route(h dnsmessage.Header, q dnsmessage.Question, edns bool, limit int) *forward {
	if q.Type == dnsmessage.TypeAXFR || q.Type == typeIXFR {
		return nil
	}
	resolvers, zone, ok := s.forwarding.Load().Route(q.Name.String())
	if !ok {
		return nil
	}
	return &forward{resolvers: resolvers, zone: zone, header: h, question: q, edns: edns, limit: limit}
}

// relay asks the resolvers of fwd for the query msg, over TCP when tcp is
// set, and returns the response for the client appended to dst: the
// resolver's reply with the client's ID, or SERVFAIL when no resolver
// answered. It runs in the goroutine of the forward, for a query over UDP and
// over TCP alike, so the wait for the resolvers holds up no read loop. A
// reply larger than fwd.limit, which only one over UDP can be, is replaced by
// a response with TC set, the reply's response code and its AA and RA bits,
// the question and no record, so the client asks again over TCP and the
// ceiling the server keeps for its own answers holds for relayed ones too.
// relay returns nil once ctx has ended, because the server is stopping, and
// when a response of its own does not pack; the caller then sends nothing.
func (s *Server) relay(ctx context.Context, dst, msg []byte, fwd *forward, tcp bool) []byte {
	reply, err := s.upstream.exchange(ctx, fwd.resolvers, fwd.zone, msg, tcp)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		s.logger.Debug("mesh dns forwarded query failed",
			"name", fwd.question.Name.String(), "type", fwd.question.Type.String(), "zone", fwd.zone, "error", err)
		return s.serverFailure(dst, fwd)
	}
	if len(reply) <= fwd.limit {
		return append(dst, reply...)
	}
	h := fwd.header
	h.Truncated = true
	var p dnsmessage.Parser
	if rh, err := p.Start(reply); err == nil {
		h.RCode, h.Authoritative, h.RecursionAvailable = rh.RCode, rh.Authoritative, rh.RecursionAvailable
	}
	resp, err := buildResponse(dst, h, &fwd.question, Answer{}, fwd.edns)
	if err != nil {
		s.logger.Debug("mesh dns could not pack a reply", "error", err)
		return nil
	}
	return resp
}

// serverFailure returns the SERVFAIL response to the forwarded query fwd
// appended to dst: the query's ID, opcode, RD bit and question, AA clear, and
// an OPT record when the query had one. It returns nil when the response does
// not pack, which a question parsed from the query always does.
func (s *Server) serverFailure(dst []byte, fwd *forward) []byte {
	h := fwd.header
	h.RCode = dnsmessage.RCodeServerFailure
	resp, err := buildResponse(dst, h, &fwd.question, Answer{}, fwd.edns)
	if err != nil {
		s.logger.Debug("mesh dns could not pack a reply", "error", err)
		return nil
	}
	return resp
}

// singleQuestion parses the question of msg when its header counts exactly
// one. A message with none or several cannot be answered as one query, so
// the caller answers FORMERR.
func singleQuestion(p *dnsmessage.Parser, msg []byte) (dnsmessage.Question, bool) {
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return dnsmessage.Question{}, false
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Question{}, false
	}
	return q, true
}

// readOPT returns how many OPT records the additional section of the
// message p parses carries, and the UDP payload size the first one offers,
// which an OPT record carries in its class. It first skips the questions p
// has not parsed yet, so a message with no question or several is counted
// too. The count stops at the first record that does not parse, and the
// records before it still count. A question that does not parse hides where
// the additional section begins, and then nothing counts.
func readOPT(p *dnsmessage.Parser) (count int, payload uint16) {
	if err := p.SkipAllQuestions(); err != nil {
		return 0, 0
	}
	if err := p.SkipAllAnswers(); err != nil {
		return 0, 0
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return 0, 0
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			return count, payload
		}
		if rh.Type == dnsmessage.TypeOPT {
			if count == 0 {
				payload = uint16(rh.Class)
			}
			count++
		}
		if err := p.SkipAdditional(); err != nil {
			return count, payload
		}
	}
}

// buildResponse packs the response with header h, the question q as it was
// received when it is not nil, the records of ans in its answer section, the
// SOA of ans.Zone in the authority section of a negative answer, and an OPT
// record when edns is set. A record whose owner is the question's name is
// owned by the question's own spelling, so a pointer to it compresses the
// owner, and the SOA by the question's own spelling of the zone, for the same
// reason. Any other owner, such as the target of a CNAME the answer follows,
// is the folded name.
func buildResponse(dst []byte, h dnsmessage.Header, q *dnsmessage.Question, ans Answer, edns bool) ([]byte, error) {
	b := dnsmessage.NewBuilder(dst, h)
	b.EnableCompression()
	if q != nil {
		if err := b.StartQuestions(); err != nil {
			return nil, err
		}
		if err := b.Question(*q); err != nil {
			return nil, err
		}
	}

	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, rr := range ans.RRs {
		if err := addRR(&b, q, rr); err != nil {
			return nil, err
		}
	}

	if err := b.StartAuthorities(); err != nil {
		return nil, err
	}
	if ans.Result == ResultNXDomain || ans.Result == ResultNoData {
		// RFC 2308: the SOA in the authority section is what lets a
		// resolver cache the negative answer.
		if err := addSOA(&b, q, ans.Zone); err != nil {
			return nil, err
		}
	}

	if edns {
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(ednsPayloadSize, dnsmessage.RCodeSuccess, false); err != nil {
			return nil, err
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// addRR adds rr, in a response to q, to the current section of b, with the
// TTL every record of the server carries.
func addRR(b *dnsmessage.Builder, q *dnsmessage.Question, rr RR) error {
	if rr.Type == dnsmessage.TypeSOA {
		return addSOA(b, q, rr.Name)
	}
	var owner dnsmessage.Name
	if q != nil && foldName(strings.TrimSuffix(q.Name.String(), ".")) == rr.Name {
		owner = q.Name
	} else {
		var err error
		if owner, err = dnsmessage.NewName(rr.Name + "."); err != nil {
			return err
		}
	}
	rh := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: recordTTL}
	switch rr.Type {
	case dnsmessage.TypeA:
		return b.AResource(rh, dnsmessage.AResource{A: rr.Addr.As4()})
	case dnsmessage.TypeAAAA:
		return b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: rr.Addr.As16()})
	case dnsmessage.TypeTXT:
		return b.TXTResource(rh, dnsmessage.TXTResource{TXT: rr.Text})
	}
	target, err := dnsmessage.NewName(rr.Target + ".")
	if err != nil {
		return err
	}
	switch rr.Type {
	case dnsmessage.TypePTR:
		return b.PTRResource(rh, dnsmessage.PTRResource{PTR: target})
	case dnsmessage.TypeCNAME:
		return b.CNAMEResource(rh, dnsmessage.CNAMEResource{CNAME: target})
	case dnsmessage.TypeMX:
		return b.MXResource(rh, dnsmessage.MXResource{Pref: rr.Priority, MX: target})
	case dnsmessage.TypeSRV:
		return b.SRVResource(rh, dnsmessage.SRVResource{Priority: rr.Priority, Weight: rr.Weight, Port: rr.Port, Target: target})
	}
	return fmt.Errorf("meshdns: no packing for record type %v", rr.Type)
}

// addSOA adds the SOA the server synthesizes for zone, in a response to q, to
// the current section of b.
func addSOA(b *dnsmessage.Builder, q *dnsmessage.Question, zone string) error {
	owner, err := dnsmessage.NewName(soaOwner(q, zone) + ".")
	if err != nil {
		return err
	}
	return b.SOAResource(
		dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: recordTTL},
		dnsmessage.SOAResource{
			NS:      dnsmessage.MustNewName(soaMName),
			MBox:    dnsmessage.MustNewName(soaRName),
			Serial:  soaSerial,
			Refresh: soaRefresh,
			Retry:   soaRetry,
			Expire:  soaExpire,
			MinTTL:  soaMinimum,
		},
	)
}

// soaOwner returns the owner of the SOA of zone in a response to q, without
// the trailing dot: the last labels of q's name, as many as zone has, as the
// query spelled them. dnsmessage compresses a name only against the same
// bytes, so an owner spelled like the question packs as a two-byte pointer
// into it. The zone as BuildRecords folded it would be written out in full
// whenever the query spells it in another case, and under a long zone that
// pushes a reply without EDNS past the 512 bytes UDP carries. DNS compares
// names without regard to case, so either spelling names the zone. The
// folded zone is the owner when q is nil, has fewer labels than zone, or
// ends in another name.
func soaOwner(q *dnsmessage.Question, zone string) string {
	if q == nil {
		return zone
	}
	name := strings.TrimSuffix(q.Name.String(), ".")
	start := len(name)
	for range strings.Count(zone, ".") + 1 {
		if start < 0 {
			return zone
		}
		// start ends on the dot before the suffix, or on -1 when the
		// suffix is the whole name; start+1 is where it begins either way.
		start = strings.LastIndexByte(name[:start], '.')
	}
	if suffix := name[start+1:]; foldName(suffix) == zone {
		return suffix
	}
	return zone
}
