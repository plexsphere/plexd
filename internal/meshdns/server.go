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
// carries an OPT record. 1232 bytes is the size the DNS flag day 2020 settled
// on, which fits an IPv6 packet into the minimum MTU without fragmentation.
const ednsPayloadSize = 1232

// headerLen is the length of a DNS message header. A packet shorter than it
// cannot even name the query it belongs to, so it gets no reply.
const headerLen = 12

// opcodeQuery is the standard query, the only opcode the server implements.
const opcodeQuery dnsmessage.OpCode = 0

// maxMessageSize is the largest DNS message UDP or the two-byte TCP length can
// carry, so a read never cuts a message short.
const maxMessageSize = 65535

// tcpIdleTimeout bounds how long a TCP connection may take for each complete
// query, so a client that opens a connection and stalls holds its slot for no
// longer than this.
const tcpIdleTimeout = 10 * time.Second

// maxTCPConns caps the open TCP connections. The idle timeout bounds how long
// one connection lasts; the cap bounds how many a local program can hold
// open at once, each with a goroutine and a buffer.
const maxTCPConns = 32

// listenAttempts is how often Listen tries a fresh kernel-chosen port when the
// TCP side finds the port that UDP got already taken.
const listenAttempts = 10

// Server answers DNS queries for the mesh names over UDP and TCP on one
// address. It answers the node itself only: a query from any source other
// than the listen address or a loopback address is dropped, because plexd's
// firewall filters forwarded traffic only and nothing else keeps other hosts
// from using the resolver.
type Server struct {
	addr   netip.AddrPort
	logger *slog.Logger

	// records holds the names the server answers from. A pull swaps it
	// whole, so a query never waits for a pull and never sees half a block.
	records atomic.Pointer[Records]

	// tcpIdle is the deadline for each complete query on a TCP connection,
	// defaulted from tcpIdleTimeout. Tests shorten it.
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
// to do about it before serving starts. The server logs at Debug only, and
// adds no attributes of its own to logger.
func NewServer(addr netip.AddrPort, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		addr:    addr,
		logger:  logger,
		tcpIdle: tcpIdleTimeout,
		bound:   addr,
	}
}

// SetRecords replaces the names the server answers from. The swap is atomic,
// so a pull never blocks a query: a query in flight finishes with the records
// it started with, and the next one sees r. A nil r answers REFUSED for every
// name, as the server does before the first call.
func (s *Server) SetRecords(r *Records) {
	s.records.Store(r)
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
// closes both sockets and every open TCP connection, waits for the goroutine
// of each to finish, and returns nil. A failed UDP read, or a TCP listener
// closed by anything but Serve, while ctx is live stops serving the same way
// and is returned, so the caller can log that the resolver stopped. Any
// other failed accept, such as EMFILE while the process is out of file
// descriptors, is retried after a wait, so a passing shortage stops neither
// TCP nor UDP. Serve without a successful Listen returns an error.
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
	var conns connSet
	var loops sync.WaitGroup
	errs := make(chan error, 2)
	loops.Add(2)
	go func() {
		defer loops.Done()
		errs <- s.serveUDP(udp, stop)
	}()
	go func() {
		defer loops.Done()
		errs <- s.serveTCP(tcp, &conns, stop)
	}()

	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	close(stop)
	_ = udp.Close()
	_ = tcp.Close()
	// The accept loop has returned once loops.Wait does, so no connection
	// joins the set while closeAll closes it.
	loops.Wait()
	conns.closeAll()
	return err
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
// fails. It returns nil when the failure is the close Serve caused.
func (s *Server) serveUDP(conn *net.UDPConn, stop <-chan struct{}) error {
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
		s.handlePacket(conn, buf[:n], src)
	}
}

// packetWriter is the part of *net.UDPConn that handlePacket sends a reply
// with, so a test can watch what it sends to a source no socket can have.
type packetWriter interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// handlePacket answers the datagram msg from src through w, or drops it
// without a reply when src is not allowed or msg gets none.
func (s *Server) handlePacket(w packetWriter, msg []byte, src netip.AddrPort) {
	if !s.allowedSource(src.Addr()) {
		s.logger.Debug("mesh dns dropped a packet from a source it does not answer", "source", src)
		return
	}
	resp := s.respond(nil, msg)
	if resp == nil {
		s.logger.Debug("mesh dns dropped a packet that gets no reply", "source", src, "bytes", len(msg))
		return
	}
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

// serveTCP accepts the connections of ln until ln is closed. It returns nil
// when that is the close Serve caused, and the accept error when it is not.
// Any other accept error is taken to pass, as EMFILE does once the process
// has a file descriptor free again, so serveTCP logs it at Debug, waits and
// accepts again rather than stop the resolver for the rest of the run.
func (s *Server) serveTCP(ln acceptor, conns *connSet, stop <-chan struct{}) error {
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
		s.accept(conns, conn, src)
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
// own that conns tracks.
func (s *Server) accept(conns *connSet, conn net.Conn, src netip.Addr) {
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
		s.serveConn(conn)
	}()
}

// serveConn answers the queries of one TCP connection, each framed by its
// two-byte length, until the client closes it, a read or write fails, or
// s.tcpIdle passes after the accept or the reply before without a complete
// query to answer. A message that gets no reply does not restart the
// deadline: it asks nothing, and a client that sent one now and then would
// otherwise hold its slot for as long as it liked.
func (s *Server) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
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
		resp := s.respond(make([]byte, 2, 2+512), msg)
		if resp == nil {
			s.logger.Debug("mesh dns dropped a message that gets no reply", "bytes", n)
			continue
		}
		binary.BigEndian.PutUint16(resp, uint16(len(resp)-2))
		if _, err := conn.Write(resp); err != nil {
			return
		}
		if err := conn.SetDeadline(time.Now().Add(s.tcpIdle)); err != nil {
			return
		}
	}
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
// servers.
func (s *Server) respond(dst, msg []byte) []byte {
	if len(msg) < headerLen {
		return nil
	}
	var p dnsmessage.Parser
	qh, err := p.Start(msg)
	if err != nil || qh.Response {
		return nil
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
	opts := countOPT(&p)
	edns := opts > 0
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
			h.RCode = dnsmessage.RCodeRefused
		}
	}

	resp, err := buildResponse(dst, h, question, ans, edns)
	if err != nil {
		// Every name packed was parsed from the query or validated by
		// BuildRecords, so this does not happen; a reply that cannot be
		// packed is dropped rather than sent half built.
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

// countOPT returns how many OPT records the additional section of the
// message p parses carries. It first skips the questions p has not parsed
// yet, so a message with no question or several is counted too. The count
// stops at the first record that does not parse, and the records before it
// still count. A question that does not parse hides where the additional
// section begins, and then nothing counts.
func countOPT(p *dnsmessage.Parser) int {
	if err := p.SkipAllQuestions(); err != nil {
		return 0
	}
	if err := p.SkipAllAnswers(); err != nil {
		return 0
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return 0
	}
	n := 0
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			return n
		}
		if rh.Type == dnsmessage.TypeOPT {
			n++
		}
		if err := p.SkipAdditional(); err != nil {
			return n
		}
	}
}

// buildResponse packs the response with header h, the question q as it was
// received when it is not nil, the records ans calls for, and an OPT record
// when edns is set. The records are owned by the question's own spelling, so
// a pointer to it compresses them, and the SOA by the question's own
// spelling of the zone, for the same reason.
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
	if ans.Result == ResultFound {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: recordTTL}
		var err error
		switch {
		case ans.Addr.Is4():
			err = b.AResource(rh, dnsmessage.AResource{A: ans.Addr.As4()})
		case ans.Addr.Is6():
			err = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ans.Addr.As16()})
		case ans.Target != "":
			var target dnsmessage.Name
			if target, err = dnsmessage.NewName(ans.Target + "."); err == nil {
				err = b.PTRResource(rh, dnsmessage.PTRResource{PTR: target})
			}
		default:
			err = addSOA(&b, q, ans.Zone)
		}
		if err != nil {
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
