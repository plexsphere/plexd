package mockapi

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSStubAddress is the address the DNS stub answers every A query with. It
// comes from TEST-NET-2, so nothing answers it, and a suite that resolves a
// name to it knows the answer came from the stub.
const DNSStubAddress = "198.51.100.53"

// dnsStubTTL is the TTL of the A record the stub answers with.
const dnsStubTTL = 10

// dnsStubIdleTimeout bounds how long a TCP connection may wait for its next
// query before the stub closes it.
const dnsStubIdleTimeout = 10 * time.Second

// dnsStubPayloadSize is the UDP payload size the stub advertises in the OPT
// record of a reply to a query that carries one.
const dnsStubPayloadSize = 1232

// dnsStubListenAttempts is how often ListenDNS tries a fresh kernel-chosen
// port when the TCP side finds the port that UDP got already taken.
const dnsStubListenAttempts = 10

// dnsStubMaxMessage is the largest DNS message UDP or the two-byte TCP length
// can carry, so a read never cuts a message short.
const dnsStubMaxMessage = 65535

// dnsStubAddr is the address DNSStubAddress names.
var dnsStubAddr = netip.MustParseAddr(DNSStubAddress)

// DNSStub is a DNS server that stands in for the resolvers a forwarding
// setting names, so the e2e suites can prove a query reaches them through the
// agent. It answers over UDP and TCP on one address, from any source:
//
//   - a name whose first label is "nx", in any case, gets NXDOMAIN;
//   - a name whose first label is "drop", in any case, gets no reply at all;
//   - any other A query gets one A record, DNSStubAddress with a TTL of 10;
//   - any other query gets NOERROR with no record.
//
// Every reply carries the query's ID, opcode, RD bit and question, with QR
// and RA set, and an OPT record when the query carried one.
type DNSStub struct {
	udp  *net.UDPConn
	tcp  *net.TCPListener
	addr netip.AddrPort
}

// ListenDNS binds UDP and TCP on addr, a host:port as net.Listen takes it,
// and returns the stub that serves them once Serve runs. With port 0, UDP
// binds first and TCP takes the port UDP got; when that port is taken for
// TCP, ListenDNS tries a fresh one, up to ten times. A failure of either bind
// fails ListenDNS and closes the socket that did bind.
func ListenDNS(addr string) (*DNSStub, error) {
	local, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("mockapi: listen dns %s: %w", addr, err)
	}
	attempts := 1
	if local.Port == 0 {
		attempts = dnsStubListenAttempts
	}
	for range attempts {
		var udp *net.UDPConn
		udp, err = net.ListenUDP("udp", local)
		if err != nil {
			return nil, fmt.Errorf("mockapi: listen dns %s: %w", addr, err)
		}
		bound := udp.LocalAddr().(*net.UDPAddr).AddrPort()
		var tcp *net.TCPListener
		tcp, err = net.ListenTCP("tcp", &net.TCPAddr{IP: local.IP, Port: int(bound.Port()), Zone: local.Zone})
		if err != nil {
			_ = udp.Close()
			continue
		}
		return &DNSStub{
			udp:  udp,
			tcp:  tcp,
			addr: netip.AddrPortFrom(bound.Addr().Unmap(), bound.Port()),
		}, nil
	}
	return nil, fmt.Errorf("mockapi: listen dns %s: %w", addr, err)
}

// Addr returns the address the stub is bound to, with the port the kernel
// chose when addr named port 0. It is the same for UDP and TCP.
func (s *DNSStub) Addr() netip.AddrPort {
	return s.addr
}

// Serve answers queries until ctx ends, then closes both sockets and every
// open TCP connection, waits for the goroutine of each to finish, and returns
// nil. A UDP read or a TCP accept that fails while ctx is live stops serving
// the same way and is returned. A stub serves once: a second Serve finds the
// sockets closed and serves nothing.
func (s *DNSStub) Serve(ctx context.Context) error {
	// stop is closed before the sockets are, so a loop whose read fails
	// tells the close that Serve caused from a failure of the socket.
	stop := make(chan struct{})
	errs := make(chan error, 2)
	var conns dnsStubConns
	var wg sync.WaitGroup
	wg.Go(func() { errs <- s.serveUDP(stop) })
	wg.Go(func() { errs <- s.serveTCP(&conns, &wg, stop) })

	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	close(stop)
	_ = s.udp.Close()
	_ = s.tcp.Close()
	conns.closeAll()
	wg.Wait()
	return err
}

// serveUDP answers the datagrams of the UDP socket one after the other until
// a read fails. It returns nil when the failure is the close Serve caused.
func (s *DNSStub) serveUDP(stop <-chan struct{}) error {
	buf := make([]byte, dnsStubMaxMessage)
	for {
		n, src, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			return fmt.Errorf("mockapi: dns stub udp: %w", err)
		}
		if reply := dnsStubReply(nil, buf[:n]); reply != nil {
			_, _ = s.udp.WriteToUDPAddrPort(reply, src)
		}
	}
}

// serveTCP accepts the connections of the TCP listener until an accept fails
// and serves each in a goroutine wg tracks. It returns nil when the failure
// is the close Serve caused.
func (s *DNSStub) serveTCP(conns *dnsStubConns, wg *sync.WaitGroup, stop <-chan struct{}) error {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
			}
			return fmt.Errorf("mockapi: dns stub tcp: %w", err)
		}
		if !conns.add(conn) {
			_ = conn.Close()
			continue
		}
		wg.Go(func() {
			defer conns.remove(conn)
			serveDNSStubConn(conn)
		})
	}
}

// serveDNSStubConn answers the queries of one TCP connection, each framed by
// its two-byte length as RFC 7766 has it, until the client closes it, a read
// or write fails, or dnsStubIdleTimeout passes without a complete query.
func serveDNSStubConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	var size [2]byte
	for {
		if err := conn.SetDeadline(time.Now().Add(dnsStubIdleTimeout)); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		reply := dnsStubReply(make([]byte, 2), msg)
		if reply == nil {
			continue
		}
		binary.BigEndian.PutUint16(reply, uint16(len(reply)-2))
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}

// dnsStubReply returns the stub's reply to the query msg appended to dst, or
// nil when msg gets none: a name whose first label is "drop", a message that
// does not parse, one without a question, and one with QR set, which is a
// reply itself.
func dnsStubReply(dst, msg []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	label, _, _ := strings.Cut(q.Name.String(), ".")
	if strings.EqualFold(label, "drop") {
		return nil
	}
	edns := dnsStubHasOPT(&p)

	reply := dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		OpCode:             h.OpCode,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
	}
	if strings.EqualFold(label, "nx") {
		reply.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(dst, reply)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q); err != nil {
		return nil
	}
	if reply.RCode == dnsmessage.RCodeSuccess && q.Type == dnsmessage.TypeA {
		if err := b.StartAnswers(); err != nil {
			return nil
		}
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: dnsStubTTL}
		if err := b.AResource(hdr, dnsmessage.AResource{A: dnsStubAddr.As4()}); err != nil {
			return nil
		}
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			return nil
		}
		var hdr dnsmessage.ResourceHeader
		if err := hdr.SetEDNS0(dnsStubPayloadSize, dnsmessage.RCodeSuccess, false); err != nil {
			return nil
		}
		if err := b.OPTResource(hdr, dnsmessage.OPTResource{}); err != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// dnsStubHasOPT reports whether the rest of the message p has read up to its
// first question carries an OPT record. A message whose rest does not parse
// is taken to carry none.
func dnsStubHasOPT(p *dnsmessage.Parser) bool {
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return false
	}
	for {
		// ErrSectionDone ends the additionals without an OPT record, and
		// any other error is a rest that does not parse.
		h, err := p.AdditionalHeader()
		if err != nil {
			return false
		}
		if h.Type == dnsmessage.TypeOPT {
			return true
		}
		if err := p.SkipAdditional(); err != nil {
			return false
		}
	}
}

// dnsStubConns tracks the open TCP connections of one Serve call, so Serve
// can close every one when it stops.
type dnsStubConns struct {
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

// add records conn and reports true, or reports false once closeAll ran, so
// a connection accepted while Serve stops is closed rather than served.
func (c *dnsStubConns) add(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if c.conns == nil {
		c.conns = make(map[net.Conn]struct{})
	}
	c.conns[conn] = struct{}{}
	return true
}

// remove forgets conn once its goroutine is done with it.
func (c *dnsStubConns) remove(conn net.Conn) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
}

// closeAll closes every open connection, which ends the read its goroutine
// waits in, and makes add refuse any connection after it.
func (c *dnsStubConns) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for conn := range c.conns {
		_ = conn.Close()
	}
}
