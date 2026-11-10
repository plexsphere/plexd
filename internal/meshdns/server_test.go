package meshdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/plexsphere/plexd/internal/api"
)

// ioTimeout bounds every dial, read and shutdown a test waits for. A reply
// takes microseconds on loopback, so running into it means the server did
// not answer or did not close.
const ioTimeout = 5 * time.Second

// v6Zone is the reverse zone of fd00::/48, the contract's example of an IPv6
// mesh CIDR, and v6PTR the reverse name of fd00::2 under it.
const v6Zone = "0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"

var v6PTR = "2.0." + strings.Repeat("0.", 28) + "d.f.ip6.arpa"

// serverBlock is the contract's example block with an IPv6 host and a host
// two labels below lab.internal added, so the server tests reach every row
// of the answer table.
func serverBlock() api.NodeStateDNS {
	b := exampleBlock()
	b.Hosts = append(b.Hosts,
		api.NodeStateDNSHost{NodeID: "n-v6", FQDN: "v6.lab.internal", MeshIP: "fd00::2"},
		api.NodeStateDNSHost{NodeID: "n-rack", FQDN: "app.rack-1.lab.internal", MeshIP: "10.42.0.5"},
	)
	b.ReverseZones = append(b.ReverseZones, v6Zone)
	return b
}

// newTestServer returns a server for 127.0.0.1 on a port the kernel picks,
// logging nowhere.
func newTestServer() *Server {
	return NewServer(netip.MustParseAddrPort("127.0.0.1:0"), slog.New(slog.DiscardHandler))
}

// startServer serves r on a new test server until the test ends. configure
// runs before Listen.
func startServer(t *testing.T, r *Records, configure ...func(*Server)) *Server {
	t.Helper()
	s := newTestServer()
	for _, f := range configure {
		f(s)
	}
	if r != nil {
		s.SetRecords(r)
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	t.Cleanup(serve(t, s))
	return s
}

// serve runs s.Serve in a goroutine and returns a function that cancels it
// and checks that Serve returns nil in time.
func serve(t *testing.T, s *Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	return sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() = %v, want nil after the cancel", err)
			}
		case <-time.After(ioTimeout):
			t.Errorf("Serve did not return within %v of the cancel", ioTimeout)
		}
	})
}

func question(name string, qtype dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}
}

// packQuery packs a message with the header h and the questions qs, and an
// OPT record advertising 4096 bytes when edns is set.
func packQuery(t *testing.T, h dnsmessage.Header, edns bool, qs ...dnsmessage.Question) []byte {
	t.Helper()
	opts := 0
	if edns {
		opts = 1
	}
	return packQueryOPTs(t, h, opts, qs...)
}

// packQueryOPTs packs a message with the header h and the questions qs, and
// opts OPT records advertising 4096 bytes each. No client sends more than
// one; a test sends two to see the server refuse them.
func packQueryOPTs(t *testing.T, h dnsmessage.Header, opts int, qs ...dnsmessage.Question) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, h)
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions() = %v, want nil", err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			t.Fatalf("Question(%v) = %v, want nil", q.Name, err)
		}
	}
	if opts > 0 {
		if err := b.StartAdditionals(); err != nil {
			t.Fatalf("StartAdditionals() = %v, want nil", err)
		}
	}
	for range opts {
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatalf("SetEDNS0() = %v, want nil", err)
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			t.Fatalf("OPTResource() = %v, want nil", err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish() = %v, want nil", err)
	}
	return msg
}

// newQuery packs a standard query for name and qtype with RD set, as a stub
// resolver sends it.
func newQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	return packQuery(t, dnsmessage.Header{ID: id, RecursionDesired: true}, false, question(name, qtype))
}

// parseResponse parses every section of the message b.
func parseResponse(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		t.Fatalf("parse header of %d bytes: %v", len(b), err)
	}
	m := dnsmessage.Message{Header: h}
	if m.Questions, err = p.AllQuestions(); err != nil {
		t.Fatalf("parse questions: %v", err)
	}
	if m.Answers, err = p.AllAnswers(); err != nil {
		t.Fatalf("parse answers: %v", err)
	}
	if m.Authorities, err = p.AllAuthorities(); err != nil {
		t.Fatalf("parse authorities: %v", err)
	}
	if m.Additionals, err = p.AllAdditionals(); err != nil {
		t.Fatalf("parse additionals: %v", err)
	}
	return m
}

// describe renders r in zone file order, so a test compares whole records
// and a failure shows them.
func describe(r dnsmessage.Resource) string {
	var data string
	switch b := r.Body.(type) {
	case *dnsmessage.AResource:
		data = netip.AddrFrom4(b.A).String()
	case *dnsmessage.AAAAResource:
		data = netip.AddrFrom16(b.AAAA).String()
	case *dnsmessage.PTRResource:
		data = b.PTR.String()
	case *dnsmessage.SOAResource:
		data = fmt.Sprintf("%s %s %d %d %d %d %d", b.NS, b.MBox, b.Serial, b.Refresh, b.Retry, b.Expire, b.MinTTL)
	case *dnsmessage.CNAMEResource:
		data = b.CNAME.String()
	case *dnsmessage.MXResource:
		data = fmt.Sprintf("%d %s", b.Pref, b.MX)
	case *dnsmessage.SRVResource:
		data = fmt.Sprintf("%d %d %d %s", b.Priority, b.Weight, b.Port, b.Target)
	case *dnsmessage.TXTResource:
		quoted := make([]string, 0, len(b.TXT))
		for _, t := range b.TXT {
			quoted = append(quoted, strconv.Quote(t))
		}
		data = strings.Join(quoted, " ")
	default:
		data = fmt.Sprintf("%#v", b)
	}
	return fmt.Sprintf("%s %d %v %v %s", r.Header.Name, r.Header.TTL, r.Header.Class, r.Header.Type, data)
}

func describeAll(rs []dnsmessage.Resource) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, describe(r))
	}
	return out
}

// wantSOA is the synthesized SOA of zone as describe renders it, spelled
// out rather than built from the constants it checks.
func wantSOA(zone string) string {
	return zone + ". 10 ClassINET TypeSOA ns.plexd.invalid. hostmaster.plexd.invalid. 1 3600 600 86400 10"
}

// dial opens a connection over network, udp or tcp, to s and closes it when
// the test ends.
func dial(t *testing.T, network string, s *Server) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout(network, s.Addr().String(), ioTimeout)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, s.Addr(), err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// exchangeUDP sends msg on conn and returns the first datagram that comes
// back.
func exchangeUDP(t *testing.T, conn net.Conn, msg []byte) []byte {
	t.Helper()
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write query: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatalf("SetReadDeadline() = %v, want nil", err)
	}
	buf := make([]byte, maxMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return buf[:n]
}

// writeFrame sends msg on a TCP connection behind its two-byte length.
func writeFrame(conn net.Conn, msg []byte) error {
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	_, err := conn.Write(append(frame, msg...))
	return err
}

// readFrame reads one length-framed message from a TCP connection.
func readFrame(conn net.Conn) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func exchangeTCP(t *testing.T, conn net.Conn, msg []byte) []byte {
	t.Helper()
	if err := writeFrame(conn, msg); err != nil {
		t.Fatalf("write query: %v", err)
	}
	resp, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return resp
}

// waitClosed fails the test unless the server closes conn before ioTimeout
// runs out. The server closes a connection without unread data in it, so
// the client reads a clean EOF; a read that times out means it is still
// open.
func waitClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatalf("SetReadDeadline() = %v, want nil", err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read = %d, %v, want 0, EOF from a connection the server closed", n, err)
	}
}

// firstA returns the address of the first A record in the answer section of
// b. It reports failures as errors, so a goroutine other than the test's can
// call it.
func firstA(b []byte) (netip.Addr, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return netip.Addr{}, err
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, fmt.Errorf("rcode %v, want %v", h.RCode, dnsmessage.RCodeSuccess)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, err
	}
	if _, err := p.AnswerHeader(); err != nil {
		return netip.Addr{}, err
	}
	a, err := p.AResource()
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4(a.A), nil
}

func TestServer_AnswersOverUDPAndTCP(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))

	tests := []struct {
		network  string
		rd       bool
		exchange func(*testing.T, net.Conn, []byte) []byte
	}{
		{"udp", true, exchangeUDP},
		{"tcp", false, exchangeTCP},
	}
	for _, tc := range tests {
		t.Run(tc.network, func(t *testing.T) {
			const id = 0x5ec1
			q := question("db-1.openstack.lab.internal.", dnsmessage.TypeA)
			msg := packQuery(t, dnsmessage.Header{ID: id, RecursionDesired: tc.rd}, false, q)
			m := parseResponse(t, tc.exchange(t, dial(t, tc.network, s), msg))

			if m.ID != id {
				t.Errorf("ID = %#x, want %#x", m.ID, id)
			}
			if !m.Response {
				t.Errorf("QR = false, want true")
			}
			if !m.Authoritative {
				t.Errorf("AA = false, want true")
			}
			if m.RecursionAvailable {
				t.Errorf("RA = true, want false")
			}
			if m.RecursionDesired != tc.rd {
				t.Errorf("RD = %v, want %v as in the query", m.RecursionDesired, tc.rd)
			}
			if m.RCode != dnsmessage.RCodeSuccess {
				t.Errorf("RCode = %v, want %v", m.RCode, dnsmessage.RCodeSuccess)
			}
			if !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
				t.Errorf("questions = %v, want %v", m.Questions, q)
			}
			want := []string{"db-1.openstack.lab.internal. 10 ClassINET TypeA 10.42.0.3"}
			if got := describeAll(m.Answers); !slices.Equal(got, want) {
				t.Errorf("answers = %q, want %q", got, want)
			}
			if len(m.Authorities) != 0 || len(m.Additionals) != 0 {
				t.Errorf("authorities, additionals = %q, %q, want none", describeAll(m.Authorities), describeAll(m.Additionals))
			}
		})
	}
}

func TestServer_EchoesQuestionSpelling(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))

	const name = "Db-1.OPENSTACK.lab.internal."
	m := parseResponse(t, exchangeUDP(t, dial(t, "udp", s), newQuery(t, 7, name, dnsmessage.TypeA)))

	if q := question(name, dnsmessage.TypeA); !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
		t.Errorf("questions = %v, want %v", m.Questions, q)
	}
	want := []string{name + " 10 ClassINET TypeA 10.42.0.3"}
	if got := describeAll(m.Answers); !slices.Equal(got, want) {
		t.Errorf("answers = %q, want %q", got, want)
	}
}

func TestServer_AnswerTable(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	conn := dial(t, "udp", s)

	tests := []struct {
		name        string
		qname       string
		qtype       dnsmessage.Type
		rcode       dnsmessage.RCode
		answers     []string
		authorities []string
	}{
		{"name outside every zone", "example.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, nil, nil},
		{"reverse name outside every reverse zone", "1.0.43.10.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeRefused, nil, nil},
		{
			"host A", "db-1.openstack.lab.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess,
			[]string{"db-1.openstack.lab.internal. 10 ClassINET TypeA 10.42.0.3"},
			nil,
		},
		{
			"host AAAA", "v6.lab.internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess,
			[]string{"v6.lab.internal. 10 ClassINET TypeAAAA fd00::2"},
			nil,
		},
		{
			"in-addr.arpa PTR", "3.0.42.10.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeSuccess,
			[]string{"3.0.42.10.in-addr.arpa. 10 ClassINET TypePTR db-1.openstack.lab.internal."},
			nil,
		},
		{
			"ip6.arpa PTR", v6PTR + ".", dnsmessage.TypePTR, dnsmessage.RCodeSuccess,
			[]string{v6PTR + ". 10 ClassINET TypePTR v6.lab.internal."},
			nil,
		},
		{
			"zone SOA", "openstack.lab.internal.", dnsmessage.TypeSOA, dnsmessage.RCodeSuccess,
			[]string{wantSOA("openstack.lab.internal")},
			nil,
		},
		{
			"reverse zone SOA", "42.10.in-addr.arpa.", dnsmessage.TypeSOA, dnsmessage.RCodeSuccess,
			[]string{wantSOA("42.10.in-addr.arpa")},
			nil,
		},
		{
			"host asked for another type", "db-1.openstack.lab.internal.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess,
			nil,
			[]string{wantSOA("openstack.lab.internal")},
		},
		{
			"IPv6 host asked for A", "v6.lab.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess,
			nil,
			[]string{wantSOA("lab.internal")},
		},
		{
			"reverse name asked for A", "3.0.42.10.in-addr.arpa.", dnsmessage.TypeA, dnsmessage.RCodeSuccess,
			nil,
			[]string{wantSOA("42.10.in-addr.arpa")},
		},
		{
			"zone asked for A", "lab.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess,
			nil,
			[]string{wantSOA("lab.internal")},
		},
		{
			"name with a host below it", "rack-1.lab.internal.", dnsmessage.TypeA, dnsmessage.RCodeSuccess,
			nil,
			[]string{wantSOA("lab.internal")},
		},
		{
			"missing name", "nope.openstack.lab.internal.", dnsmessage.TypeA, dnsmessage.RCodeNameError,
			nil,
			[]string{wantSOA("openstack.lab.internal")},
		},
		{
			"missing reverse name", "9.9.42.10.in-addr.arpa.", dnsmessage.TypePTR, dnsmessage.RCodeNameError,
			nil,
			[]string{wantSOA("42.10.in-addr.arpa")},
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := uint16(0x7000 + i)
			m := parseResponse(t, exchangeUDP(t, conn, newQuery(t, id, tc.qname, tc.qtype)))

			if m.ID != id {
				t.Errorf("ID = %#x, want %#x", m.ID, id)
			}
			if m.RCode != tc.rcode {
				t.Errorf("RCode = %v, want %v", m.RCode, tc.rcode)
			}
			if wantAA := tc.rcode != dnsmessage.RCodeRefused; m.Authoritative != wantAA {
				t.Errorf("AA = %v, want %v", m.Authoritative, wantAA)
			}
			if q := question(tc.qname, tc.qtype); !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
				t.Errorf("questions = %v, want %v", m.Questions, q)
			}
			if got := describeAll(m.Answers); !slices.Equal(got, tc.answers) {
				t.Errorf("answers = %q, want %q", got, tc.answers)
			}
			if got := describeAll(m.Authorities); !slices.Equal(got, tc.authorities) {
				t.Errorf("authorities = %q, want %q", got, tc.authorities)
			}
			if len(m.Additionals) != 0 {
				t.Errorf("additionals = %q, want none for a query without OPT", describeAll(m.Additionals))
			}
		})
	}
}

func TestServer_EDNS(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	conn := dial(t, "udp", s)

	tests := []struct {
		name  string
		qname string
		edns  bool
		rcode dnsmessage.RCode
	}{
		{"answer with OPT", "db-1.openstack.lab.internal.", true, dnsmessage.RCodeSuccess},
		{"NXDOMAIN with OPT", "nope.openstack.lab.internal.", true, dnsmessage.RCodeNameError},
		{"REFUSED with OPT", "example.com.", true, dnsmessage.RCodeRefused},
		{"answer without OPT", "db-1.openstack.lab.internal.", false, dnsmessage.RCodeSuccess},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := packQuery(t, dnsmessage.Header{ID: 9, RecursionDesired: true}, tc.edns, question(tc.qname, dnsmessage.TypeA))
			m := parseResponse(t, exchangeUDP(t, conn, msg))
			if m.RCode != tc.rcode {
				t.Errorf("RCode = %v, want %v", m.RCode, tc.rcode)
			}
			checkOPT(t, m, tc.edns)
		})
	}
}

// checkOPT fails the test unless the additional section of m is the one the
// server sends: when edns is set, one OPT record owned by the root with a
// UDP payload size of 1232, EDNS version 0, no flags and no options, and
// otherwise nothing.
func checkOPT(t *testing.T, m dnsmessage.Message, edns bool) {
	t.Helper()
	if !edns {
		if len(m.Additionals) != 0 {
			t.Errorf("additionals = %q, want none for a query without OPT", describeAll(m.Additionals))
		}
		return
	}
	if len(m.Additionals) != 1 {
		t.Errorf("got %d additional records, want one OPT", len(m.Additionals))
		return
	}
	opt := m.Additionals[0]
	if opt.Header.Type != dnsmessage.TypeOPT || opt.Header.Name.String() != "." {
		t.Errorf("additional record = %v %v, want . TypeOPT", opt.Header.Name, opt.Header.Type)
	}
	if size := int(opt.Header.Class); size != 1232 {
		t.Errorf("UDP payload size = %d, want 1232", size)
	}
	if opt.Header.TTL != 0 {
		t.Errorf("extended RCode, version and flags = %#x, want 0", opt.Header.TTL)
	}
	if body, ok := opt.Body.(*dnsmessage.OPTResource); !ok || len(body.Options) != 0 {
		t.Errorf("OPT body = %#v, want no options", opt.Body)
	}
}

func TestServer_SendsNoReply(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	valid := newQuery(t, 0x0101, "db-1.openstack.lab.internal.", dnsmessage.TypeA)

	tests := []struct {
		name string
		msg  []byte
	}{
		{"zero-length packet", []byte{}},
		{"5 bytes", valid[:5]},
		{"QR set", packQuery(t, dnsmessage.Header{ID: 0x0102, Response: true}, false,
			question("db-1.openstack.lab.internal.", dnsmessage.TypeA))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial(t, "udp", s)
			if _, err := conn.Write(tc.msg); err != nil {
				t.Fatalf("write packet: %v", err)
			}
			// The server answers one datagram after the other, so a reply
			// to tc.msg would arrive before the reply to the probe.
			const probe = 0xbeef
			m := parseResponse(t, exchangeUDP(t, conn, newQuery(t, probe, "db-1.openstack.lab.internal.", dnsmessage.TypeA)))
			if m.ID != probe {
				t.Errorf("first reply has ID %#x, want the probe's %#x: the server replied to the %s", m.ID, probe, tc.name)
			}
		})
	}
}

func TestServer_ErrorResponses(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	conn := dial(t, "udp", s)

	db1 := question("db-1.openstack.lab.internal.", dnsmessage.TypeA)
	web := question("web.openstack.lab.internal.", dnsmessage.TypeA)
	chaos := db1
	chaos.Class = dnsmessage.ClassCHAOS
	truncated := newQuery(t, 0x0203, "db-1.openstack.lab.internal.", dnsmessage.TypeA)
	truncated = truncated[:len(truncated)-2]

	// edns says whether the query, and so the reply, carries an OPT record:
	// RFC 6891 6.1.1 asks for one in every reply to a query with one, a
	// FORMERR included.
	tests := []struct {
		name      string
		id        uint16
		msg       []byte
		rcode     dnsmessage.RCode
		questions []dnsmessage.Question
		edns      bool
	}{
		{
			"opcode 2", 0x0201, packQuery(t, dnsmessage.Header{ID: 0x0201, OpCode: 2, RecursionDesired: true}, false, db1),
			dnsmessage.RCodeNotImplemented,
			[]dnsmessage.Question{db1}, false,
		},
		{
			"two questions", 0x0202, packQuery(t, dnsmessage.Header{ID: 0x0202, RecursionDesired: true}, false, db1, web),
			dnsmessage.RCodeFormatError, nil, false,
		},
		{
			"truncated question", 0x0203, truncated,
			dnsmessage.RCodeFormatError, nil, false,
		},
		{
			"class CH", 0x0204, packQuery(t, dnsmessage.Header{ID: 0x0204, RecursionDesired: true}, false, chaos),
			dnsmessage.RCodeRefused,
			[]dnsmessage.Question{chaos}, false,
		},
		{
			// RFC 6891 6.1.1: more than one OPT record is a FORMERR.
			"two OPT records", 0x0205, packQueryOPTs(t, dnsmessage.Header{ID: 0x0205, RecursionDesired: true}, 2, db1),
			dnsmessage.RCodeFormatError, nil, true,
		},
		{
			"two questions with OPT", 0x0206, packQuery(t, dnsmessage.Header{ID: 0x0206, RecursionDesired: true}, true, db1, web),
			dnsmessage.RCodeFormatError, nil, true,
		},
		{
			"no question with OPT", 0x0207, packQuery(t, dnsmessage.Header{ID: 0x0207, RecursionDesired: true}, true),
			dnsmessage.RCodeFormatError, nil, true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := parseResponse(t, exchangeUDP(t, conn, tc.msg))
			if m.ID != tc.id {
				t.Errorf("ID = %#x, want %#x", m.ID, tc.id)
			}
			if m.RCode != tc.rcode {
				t.Errorf("RCode = %v, want %v", m.RCode, tc.rcode)
			}
			if !m.Response || m.Authoritative || m.RecursionAvailable || !m.RecursionDesired {
				t.Errorf("QR, AA, RA, RD = %v, %v, %v, %v, want true, false, false, true",
					m.Response, m.Authoritative, m.RecursionAvailable, m.RecursionDesired)
			}
			if !slices.Equal(m.Questions, tc.questions) {
				t.Errorf("questions = %v, want %v", m.Questions, tc.questions)
			}
			if len(m.Answers) != 0 || len(m.Authorities) != 0 {
				t.Errorf("answers, authorities = %q, %q, want none", describeAll(m.Answers), describeAll(m.Authorities))
			}
			checkOPT(t, m, tc.edns)
		})
	}
}

// longZone is a zone of four 59-character labels under internal, 248
// characters, which BuildRecords accepts.
var longZone = strings.Join([]string{
	strings.Repeat("a", 59), strings.Repeat("b", 59), strings.Repeat("c", 59), strings.Repeat("d", 59), "internal",
}, ".")

// A name in the reply that is spelled like the question compresses to a
// two-byte pointer into it, and one spelled otherwise is written out in
// full. Under a zone this long, an SOA owned by the zone as BuildRecords
// folded it would push the reply to a query in upper case past the 512
// bytes UDP carries without EDNS, with TC clear.
func TestServer_SOAOwnerFollowsQuestionSpelling(t *testing.T) {
	s := startServer(t, mustBuild(t, api.NodeStateDNS{Zones: []string{longZone}}))
	conn := dial(t, "udp", s)
	upper := strings.ToUpper(longZone)

	tests := []struct {
		name     string
		qname    string
		qtype    dnsmessage.Type
		rcode    dnsmessage.RCode
		inAnswer bool
	}{
		{"apex SOA", upper + ".", dnsmessage.TypeSOA, dnsmessage.RCodeSuccess, true},
		{"apex asked for A", upper + ".", dnsmessage.TypeA, dnsmessage.RCodeSuccess, false},
		// 253 characters, the longest name there is.
		{"missing name", "NOPE." + upper + ".", dnsmessage.TypeA, dnsmessage.RCodeNameError, false},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := exchangeUDP(t, conn, newQuery(t, uint16(0x0300+i), tc.qname, tc.qtype))
			if len(resp) > 512 {
				t.Errorf("reply of %d bytes to a query without OPT, want at most 512", len(resp))
			}
			m := parseResponse(t, resp)
			if m.Truncated {
				t.Errorf("TC = true, want false")
			}
			if m.RCode != tc.rcode {
				t.Errorf("RCode = %v, want %v", m.RCode, tc.rcode)
			}
			soa, rest, section := m.Authorities, m.Answers, "authority"
			if tc.inAnswer {
				soa, rest, section = m.Answers, m.Authorities, "answer"
			}
			if len(soa) != 1 || soa[0].Header.Type != dnsmessage.TypeSOA || len(rest) != 0 {
				t.Fatalf("answers, authorities = %q, %q, want one SOA in the %s section only",
					describeAll(m.Answers), describeAll(m.Authorities), section)
			}
			if owner := soa[0].Header.Name.String(); !strings.EqualFold(owner, longZone+".") {
				t.Errorf("SOA owner = %q, want %q in any case", owner, longZone+".")
			}
		})
	}
}

func TestSOAOwner(t *testing.T) {
	tests := []struct {
		qname, zone, want string
	}{
		{"NOPE.OpenStack.Lab.Internal.", "openstack.lab.internal", "OpenStack.Lab.Internal"},
		{"OpenStack.Lab.Internal.", "openstack.lab.internal", "OpenStack.Lab.Internal"},
		{"9.9.42.10.IN-ADDR.ARPA.", "42.10.in-addr.arpa", "42.10.IN-ADDR.ARPA"},
		{"Lab.", "lab", "Lab"},
		// The fallbacks: fewer labels than the zone, and a name that does
		// not end in the zone.
		{"Internal.", "lab.internal", "lab.internal"},
		{"x.Example.Com.", "lab.internal", "lab.internal"},
		{".", "lab", "lab"},
	}
	for _, tc := range tests {
		q := question(tc.qname, dnsmessage.TypeA)
		if got := soaOwner(&q, tc.zone); got != tc.want {
			t.Errorf("soaOwner(%q, %q) = %q, want %q", tc.qname, tc.zone, got, tc.want)
		}
	}
	if got := soaOwner(nil, "lab.internal"); got != "lab.internal" {
		t.Errorf("soaOwner(nil, %q) = %q, want the zone", "lab.internal", got)
	}
}

func TestServer_RefusesBeforeSetRecords(t *testing.T) {
	s := startServer(t, nil)

	q := question("db-1.openstack.lab.internal.", dnsmessage.TypeA)
	m := parseResponse(t, exchangeUDP(t, dial(t, "udp", s), newQuery(t, 3, q.Name.String(), q.Type)))
	if m.RCode != dnsmessage.RCodeRefused {
		t.Errorf("RCode = %v, want %v", m.RCode, dnsmessage.RCodeRefused)
	}
	if m.Authoritative {
		t.Errorf("AA = true, want false")
	}
	if !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
		t.Errorf("questions = %v, want %v", m.Questions, q)
	}
	if len(m.Answers) != 0 || len(m.Authorities) != 0 {
		t.Errorf("answers, authorities = %q, %q, want none", describeAll(m.Answers), describeAll(m.Authorities))
	}
}

func TestServer_AllowedSource(t *testing.T) {
	s := NewServer(netip.MustParseAddrPort("10.99.0.1:5354"), slog.New(slog.DiscardHandler))

	tests := []struct {
		src  string
		want bool
	}{
		{"192.0.2.7", false},
		{"10.99.0.2", false},
		{"::ffff:10.99.0.2", false},
		{"fd00::1", false},
		{"10.99.0.1", true},
		{"::ffff:10.99.0.1", true},
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true},
	}
	for _, tc := range tests {
		if got := s.allowedSource(netip.MustParseAddr(tc.src)); got != tc.want {
			t.Errorf("allowedSource(%s) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

// recordingWriter records where handlePacket sends replies.
type recordingWriter struct {
	to []netip.AddrPort
}

func (w *recordingWriter) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	w.to = append(w.to, addr)
	return len(b), nil
}

// No socket on a test host sends from a source other than loopback to a
// loopback listener, so the drop is proven at the handler the UDP loop calls
// for every datagram, with the source as the socket would report it.
func TestServer_DropsPacketFromDisallowedSource(t *testing.T) {
	s := NewServer(netip.MustParseAddrPort("10.99.0.1:5354"), slog.New(slog.DiscardHandler))
	s.SetRecords(mustBuild(t, serverBlock()))
	msg := newQuery(t, 11, "db-1.openstack.lab.internal.", dnsmessage.TypeA)

	tests := []struct {
		src   string
		reply bool
	}{
		{"192.0.2.7:40000", false},
		{"10.99.0.2:40000", false},
		{"10.99.0.1:40000", true},
		{"127.0.0.1:40000", true},
	}
	for _, tc := range tests {
		w := &recordingWriter{}
		src := netip.MustParseAddrPort(tc.src)
		s.handlePacket(w, msg, src, newForwards(context.Background(), maxForwards))
		var want []netip.AddrPort
		if tc.reply {
			want = []netip.AddrPort{src}
		}
		if !slices.Equal(w.to, want) {
			t.Errorf("replies to a packet from %s went to %v, want %v", src, w.to, want)
		}
	}
}

// As for UDP, the TCP drop is proven at the handler the accept loop calls
// for every connection. net.Pipe has no buffer: a write returns only once
// the other end has read it, so a write that fails with io.ErrClosedPipe
// proves the server closed the connection without reading a byte.
func TestServer_ClosesConnectionFromDisallowedSource(t *testing.T) {
	s := NewServer(netip.MustParseAddrPort("10.99.0.1:5354"), slog.New(slog.DiscardHandler))
	s.SetRecords(mustBuild(t, serverBlock()))
	msg := newQuery(t, 12, "db-1.openstack.lab.internal.", dnsmessage.TypeA)

	tests := []struct {
		src    string
		served bool
	}{
		{"192.0.2.7", false},
		{"10.99.0.2", false},
		{"10.99.0.1", true},
		{"127.0.0.1", true},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			var conns connSet
			server, client := net.Pipe()
			defer conns.closeAll()
			defer func() { _ = client.Close() }()

			s.accept(newForwards(context.Background(), maxForwards), &conns, server, netip.MustParseAddr(tc.src))
			err := writeFrame(client, msg)
			if !tc.served {
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("write to a connection from %s = %v, want %v", tc.src, err, io.ErrClosedPipe)
				}
				return
			}
			if err != nil {
				t.Fatalf("write to a connection from %s = %v, want nil", tc.src, err)
			}
			resp, err := readFrame(client)
			if err != nil {
				t.Fatalf("read reply on a connection from %s: %v", tc.src, err)
			}
			if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
				t.Errorf("reply = %v, %v, want 10.42.0.3", addr, err)
			}
		})
	}
}

func TestServer_TCPAnswersSeveralQueries(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	conn := dial(t, "tcp", s)

	for i, tc := range []struct{ name, want string }{
		{"db-1.openstack.lab.internal.", "10.42.0.3"},
		{"web.openstack.lab.internal.", "10.42.0.2"},
	} {
		id := uint16(i + 1)
		m := parseResponse(t, exchangeTCP(t, conn, newQuery(t, id, tc.name, dnsmessage.TypeA)))
		want := []string{tc.name + " 10 ClassINET TypeA " + tc.want}
		if got := describeAll(m.Answers); m.ID != id || !slices.Equal(got, want) {
			t.Errorf("query %d: ID %#x, answers %q, want ID %#x, answers %q", i+1, m.ID, got, id, want)
		}
	}
}

func TestServer_TCPClosesIdleConnection(t *testing.T) {
	const idle = 300 * time.Millisecond
	s := startServer(t, mustBuild(t, serverBlock()), func(s *Server) { s.tcpIdle = idle })

	start := time.Now()
	conn := dial(t, "tcp", s)
	// A length of 40 followed by 5 bytes: a query that never completes.
	if _, err := conn.Write([]byte{0, 40, 1, 2, 3, 4, 5}); err != nil {
		t.Fatalf("write partial query: %v", err)
	}
	waitClosed(t, conn)
	// The server starts the deadline once it accepted the connection, which
	// is after start, so it cannot close the connection sooner.
	if elapsed := time.Since(start); elapsed < idle {
		t.Errorf("connection closed after %v, want no sooner than the %v deadline", elapsed, idle)
	}
}

func TestServer_TCPDeadlineRestartsWithEachQuery(t *testing.T) {
	const (
		idle = 1500 * time.Millisecond
		gap  = 600 * time.Millisecond
	)
	s := startServer(t, mustBuild(t, serverBlock()), func(s *Server) { s.tcpIdle = idle })
	conn := dial(t, "tcp", s)

	// Four queries with three gaps between them span longer than one
	// deadline, so the last one is answered only if each complete query
	// starts a new one.
	for i := range 4 {
		if i > 0 {
			time.Sleep(gap)
		}
		id := uint16(i + 1)
		if m := parseResponse(t, exchangeTCP(t, conn, newQuery(t, id, "db-1.openstack.lab.internal.", dnsmessage.TypeA))); m.ID != id {
			t.Errorf("query %d: ID = %#x, want %#x", i+1, m.ID, id)
		}
	}
}

// A message that gets no reply is no query, so it must not restart the
// deadline: otherwise a client that sends one now and then holds its slot
// for as long as it likes without asking anything.
func TestServer_TCPSkippedFramesDoNotRestartDeadline(t *testing.T) {
	const idle = time.Second
	s := startServer(t, mustBuild(t, serverBlock()), func(s *Server) { s.tcpIdle = idle })

	start := time.Now()
	conn := dial(t, "tcp", s)
	closed := make(chan time.Time, 1)
	go func() {
		// The server sends nothing on this connection, so the read ends
		// only when the connection does. The server may close it with a
		// frame unread, which the client sees as a reset, not an EOF.
		var b [1]byte
		for {
			if _, err := conn.Read(b[:]); err != nil {
				closed <- time.Now()
				return
			}
		}
	}()

	tick := time.NewTicker(idle / 3)
	defer tick.Stop()
	// The frames go on for two deadlines, so a server that restarts the
	// deadline on each of them never closes the connection in that time.
	giveUp := time.After(2 * idle)
	for {
		select {
		case at := <-closed:
			// The server starts the deadline once it accepted the
			// connection, which is after start, so it cannot close it
			// sooner.
			if elapsed := at.Sub(start); elapsed < idle {
				t.Errorf("connection closed after %v, want no sooner than the %v deadline", elapsed, idle)
			}
			return
		case <-giveUp:
			t.Fatalf("connection still open %v after the dial, with a zero-length frame every %v, want it closed %v after the accept",
				2*idle, idle/3, idle)
		case <-tick.C:
			// A write fails once the server has closed the connection, and
			// the read above reports that.
			_ = writeFrame(conn, nil)
		}
	}
}

// The tests above shorten the deadline, so this pins the one the server
// runs with.
func TestNewServer_TCPIdleDefault(t *testing.T) {
	if got := NewServer(netip.MustParseAddrPort("127.0.0.1:5354"), nil).tcpIdle; got != 10*time.Second {
		t.Errorf("tcpIdle = %v, want 10s", got)
	}
}

func TestServer_TCPConnectionLimit(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	msg := newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA)

	// The limit is spelled out rather than taken from maxTCPConns, so the
	// test pins the documented 32 and the 33rd connection is the one closed.
	const limit = 32
	open := make([]net.Conn, 0, limit)
	for range limit {
		conn := dial(t, "tcp", s)
		// A reply proves the server accepted the connection and counts it.
		exchangeTCP(t, conn, msg)
		open = append(open, conn)
	}
	waitClosed(t, dial(t, "tcp", s))

	// The slot of a closed connection frees once the server has seen the
	// close, which it does on its own time, so a new connection is tried
	// until one is served.
	_ = open[0].Close()
	deadline := time.Now().Add(ioTimeout)
	for {
		conn := dial(t, "tcp", s)
		if err := writeFrame(conn, msg); err == nil {
			if _, err := readFrame(conn); err == nil {
				break
			}
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("no new connection was served within %v of closing one of %d", ioTimeout, limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServer_SetRecordsWhileServing(t *testing.T) {
	records := func(ip string) *Records {
		return mustBuild(t, api.NodeStateDNS{
			Zones: []string{"lab.internal"},
			Hosts: []api.NodeStateDNSHost{{NodeID: "n1", FQDN: "db.lab.internal", MeshIP: ip}},
		})
	}
	before, after := records("10.42.0.3"), records("10.42.0.4")
	s := startServer(t, before)
	msg := newQuery(t, 1, "db.lab.internal.", dnsmessage.TypeA)

	// A second client queries in a loop while the records are swapped
	// under it, so the race detector sees swaps and lookups overlap.
	busy := dial(t, "udp", s)
	stop := make(chan struct{})
	done := make(chan struct{})
	var answered atomic.Int64
	go func() {
		defer close(done)
		buf := make([]byte, maxMessageSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := busy.Write(msg); err != nil {
				t.Errorf("write query: %v", err)
				return
			}
			if err := busy.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
				t.Errorf("SetReadDeadline() = %v, want nil", err)
				return
			}
			n, err := busy.Read(buf)
			if err != nil {
				t.Errorf("read reply: %v", err)
				return
			}
			addr, err := firstA(buf[:n])
			if err != nil || (addr != netip.MustParseAddr("10.42.0.3") && addr != netip.MustParseAddr("10.42.0.4")) {
				t.Errorf("reply during the swaps = %v, %v, want 10.42.0.3 or 10.42.0.4", addr, err)
				return
			}
			answered.Add(1)
		}
	}()
	deadline := time.Now().Add(ioTimeout)
	for i := 0; answered.Load() < 50; i++ {
		if time.Now().After(deadline) {
			t.Errorf("%d queries answered while swapping within %v, want 50", answered.Load(), ioTimeout)
			break
		}
		if i%2 == 0 {
			s.SetRecords(after)
		} else {
			s.SetRecords(before)
		}
	}
	close(stop)
	<-done

	conn := dial(t, "udp", s)
	for _, tc := range []struct {
		records *Records
		want    string
	}{
		{before, "10.42.0.3"},
		{after, "10.42.0.4"},
	} {
		s.SetRecords(tc.records)
		if addr, err := firstA(exchangeUDP(t, conn, msg)); err != nil || addr != netip.MustParseAddr(tc.want) {
			t.Errorf("reply after SetRecords = %v, %v, want %s", addr, err, tc.want)
		}
	}
}

func TestServer_ListenAddressInUse(t *testing.T) {
	checkInUse := func(t *testing.T, err error, addr netip.AddrPort) {
		t.Helper()
		if !errors.Is(err, errAddrInUse) {
			t.Errorf("Listen() = %v, want an error wrapping %v", err, errAddrInUse)
		}
		if prefix := "meshdns: listen " + addr.String() + ": "; err == nil || !strings.HasPrefix(err.Error(), prefix) {
			t.Errorf("Listen() = %v, want an error starting with %q", err, prefix)
		}
	}

	t.Run("udp port taken", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("occupy a UDP port: %v", err)
		}
		defer func() { _ = pc.Close() }()
		addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()

		s := NewServer(addr, slog.New(slog.DiscardHandler))
		checkInUse(t, s.Listen(), addr)
		if err := s.Serve(context.Background()); err == nil {
			t.Errorf("Serve() after the failed Listen = nil, want an error")
		}
	})

	t.Run("tcp port taken", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("occupy a TCP port: %v", err)
		}
		defer func() { _ = ln.Close() }()
		addr := ln.Addr().(*net.TCPAddr).AddrPort()

		s := NewServer(addr, slog.New(slog.DiscardHandler))
		checkInUse(t, s.Listen(), addr)
		// UDP bound first; Listen must have closed it again.
		pc, err := net.ListenPacket("udp", addr.String())
		if err != nil {
			t.Fatalf("ListenPacket(udp, %s) after the failed Listen = %v, want nil: the UDP socket was left open", addr, err)
		}
		_ = pc.Close()
	})
}

func TestServer_ListenPortZero(t *testing.T) {
	s := newTestServer()
	if got, want := s.Addr(), netip.MustParseAddrPort("127.0.0.1:0"); got != want {
		t.Errorf("Addr() before Listen = %v, want %v", got, want)
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	defer serve(t, s)()

	addr := s.Addr()
	if addr.Addr() != netip.MustParseAddr("127.0.0.1") || addr.Port() == 0 {
		t.Fatalf("Addr() = %v, want 127.0.0.1 with the port the kernel chose", addr)
	}
	// Both sockets hold the port Addr reports.
	if pc, err := net.ListenPacket("udp", addr.String()); !errors.Is(err, errAddrInUse) {
		if err == nil {
			_ = pc.Close()
		}
		t.Errorf("ListenPacket(udp, %s) = %v, want an error wrapping %v", addr, err, errAddrInUse)
	}
	if ln, err := net.Listen("tcp", addr.String()); !errors.Is(err, errAddrInUse) {
		if err == nil {
			_ = ln.Close()
		}
		t.Errorf("Listen(tcp, %s) = %v, want an error wrapping %v", addr, err, errAddrInUse)
	}
}

func TestServer_ListenTwice(t *testing.T) {
	s := newTestServer()
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	addr := s.Addr()
	refused := func(when string) {
		t.Helper()
		if err := s.Listen(); err == nil || !strings.Contains(err.Error(), "already listening") {
			t.Errorf("Listen() %s = %v, want an error saying the server is already listening", when, err)
		}
		if got := s.Addr(); got != addr {
			t.Errorf("Addr() after Listen %s = %v, want %v", when, got, addr)
		}
	}

	refused("before Serve")
	defer serve(t, s)()
	// A reply proves Serve has taken the sockets, so the next Listen runs
	// while they are served. The server holds no records and answers
	// REFUSED, which is a reply all the same.
	exchangeUDP(t, dial(t, "udp", s), newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA))
	refused("while serving")
}

func TestServer_ListenWithoutAddress(t *testing.T) {
	for _, addr := range []netip.AddrPort{
		{},
		// An unspecified address binds every interface of the host.
		netip.MustParseAddrPort("0.0.0.0:0"),
		netip.MustParseAddrPort("[::]:0"),
		netip.MustParseAddrPort("[::ffff:0.0.0.0]:0"),
	} {
		s := NewServer(addr, slog.New(slog.DiscardHandler))
		err := s.Listen()
		if err == nil {
			// Serve closes the sockets Listen should not have bound.
			serve(t, s)()
		}
		if want := "meshdns: listen " + addr.String() + ": no address to listen on"; err == nil || err.Error() != want {
			t.Errorf("Listen() on %v = %v, want %q", addr, err, want)
		}
	}
}

func TestServer_ServeBeforeListen(t *testing.T) {
	err := newTestServer().Serve(context.Background())
	if want := "meshdns: serve: not listening"; err == nil || err.Error() != want {
		t.Errorf("Serve() before Listen = %v, want %q", err, want)
	}
}

func TestServer_ServeShutsDown(t *testing.T) {
	s := newTestServer()
	s.SetRecords(mustBuild(t, serverBlock()))
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	addr := s.Addr()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	msg := newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA)
	exchangeUDP(t, dial(t, "udp", s), msg)
	// A connection that stays open across the cancel, so Serve has a
	// connection goroutine to close and wait for.
	held := dial(t, "tcp", s)
	exchangeTCP(t, held, msg)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() = %v, want nil after the cancel", err)
		}
	case <-time.After(ioTimeout):
		t.Fatalf("Serve did not return within %v of the cancel", ioTimeout)
	}

	waitClosed(t, held)
	if conn, err := net.DialTimeout("tcp", addr.String(), ioTimeout); err == nil {
		_ = conn.Close()
		t.Errorf("dial tcp %s after Serve returned = nil, want an error: the listener is still open", addr)
	}
	pc, err := net.ListenPacket("udp", addr.String())
	if err != nil {
		t.Errorf("ListenPacket(udp, %s) after Serve returned = %v, want nil: the UDP socket is still open", addr, err)
	} else {
		_ = pc.Close()
	}
	goleak.VerifyNone(t)
}

func TestServer_ServeReturnsSocketError(t *testing.T) {
	s := newTestServer()
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	addr := s.Addr()
	udp := s.udp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	// A reply proves the UDP loop is reading before its socket goes away.
	exchangeUDP(t, dial(t, "udp", s), newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA))

	_ = udp.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) || !strings.HasPrefix(err.Error(), "meshdns: serve udp: ") {
			t.Errorf("Serve() = %v, want a meshdns: serve udp: error wrapping %v", err, net.ErrClosed)
		}
	case <-time.After(ioTimeout):
		t.Fatalf("Serve did not return within %v of its UDP socket closing", ioTimeout)
	}
	if conn, err := net.DialTimeout("tcp", addr.String(), ioTimeout); err == nil {
		_ = conn.Close()
		t.Errorf("dial tcp %s after Serve returned = nil, want an error: the listener is still open", addr)
	}
}

// acceptResult is what one Accept of a fakeAcceptor returns.
type acceptResult struct {
	conn net.Conn
	err  error
}

// fakeAcceptor returns its results one Accept after the other, and rest for
// every Accept after them. No real listener fails with EMFILE on cue.
type fakeAcceptor struct {
	mu      sync.Mutex
	results []acceptResult
	rest    error
	calls   int
}

func (a *fakeAcceptor) Accept() (net.Conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if len(a.results) == 0 {
		return nil, a.rest
	}
	r := a.results[0]
	a.results = a.results[1:]
	return r.conn, r.err
}

func (a *fakeAcceptor) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// loopbackPipe is one end of a net.Pipe that reports a TCP peer on
// loopback, so the accept loop serves it as a connection from the node.
type loopbackPipe struct {
	net.Conn
}

func (loopbackPipe) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:40000"))
}

// errEMFILE is the error accept fails with while the process has no file
// descriptor left, wrapped as package net wraps it.
var errEMFILE = &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EMFILE)}

// errListenerClosed is the error accept fails with once the listener is
// closed.
var errListenerClosed = &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}

// debugLog keeps every record the server logs, at any level, so a test reads
// the Debug lines the server writes nowhere else. The server adds no
// attributes or groups to its logger, so WithAttrs and WithGroup need not
// keep any.
type debugLog struct {
	mu      sync.Mutex
	records []slog.Record
	// logged is closed with the next record, so a test waits for a line
	// rather than for a while. It is nil while no test waits.
	logged chan struct{}
}

func (l *debugLog) Enabled(context.Context, slog.Level) bool { return true }

func (l *debugLog) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r.Clone())
	if l.logged != nil {
		close(l.logged)
		l.logged = nil
	}
	return nil
}

// wait returns the records that say msg once there are at least n of them,
// and reports false when there are fewer within ioTimeout.
func (l *debugLog) wait(msg string, n int) ([]slog.Record, bool) {
	timeout := time.After(ioTimeout)
	for {
		// The count and the channel are taken under one lock, so a record
		// logged between them still closes the channel.
		l.mu.Lock()
		found := l.findLocked(msg)
		if len(found) >= n {
			l.mu.Unlock()
			return found, true
		}
		if l.logged == nil {
			l.logged = make(chan struct{})
		}
		logged := l.logged
		l.mu.Unlock()
		select {
		case <-logged:
		case <-timeout:
			return l.find(msg), false
		}
	}
}

func (l *debugLog) WithAttrs([]slog.Attr) slog.Handler { return l }

func (l *debugLog) WithGroup(string) slog.Handler { return l }

// find returns the records that say msg.
func (l *debugLog) find(msg string) []slog.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.findLocked(msg)
}

// findLocked is find for a caller that holds l.mu.
func (l *debugLog) findLocked(msg string) []slog.Record {
	var out []slog.Record
	for _, r := range l.records {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// recordAttr returns the value of the attribute key of r, or the zero Value
// when r has none.
func recordAttr(r slog.Record, key string) slog.Value {
	var v slog.Value
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != key {
			return true
		}
		v = a.Value.Resolve()
		return false
	})
	return v
}

// A process out of descriptors fails every accept until one frees up. The
// loop has to wait and accept again, or the resolver is left without TCP,
// and Serve without UDP, for the rest of the run.
func TestServer_TCPAcceptRetriesAfterError(t *testing.T) {
	logs := &debugLog{}
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:5354"), slog.New(logs))
	s.SetRecords(mustBuild(t, serverBlock()))
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	ln := &fakeAcceptor{
		results: []acceptResult{
			{err: errEMFILE},
			{err: errEMFILE},
			{conn: loopbackPipe{server}},
			{err: errEMFILE},
		},
		rest: errListenerClosed,
	}
	var conns connSet
	defer conns.closeAll()

	err := s.serveTCP(newForwards(context.Background(), maxForwards), ln, &conns, make(chan struct{}))
	if !errors.Is(err, net.ErrClosed) || !strings.HasPrefix(err.Error(), "meshdns: serve tcp: ") {
		t.Errorf("serveTCP() = %v, want a meshdns: serve tcp: error wrapping %v", err, net.ErrClosed)
	}
	if got := ln.callCount(); got != 5 {
		t.Fatalf("Accept called %d times, want 5: the loop stopped at an error it should have retried", got)
	}

	// The connection accepted between the errors is served.
	if err := client.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatalf("SetDeadline() = %v, want nil", err)
	}
	if err := writeFrame(client, newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	resp, err := readFrame(client)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Errorf("reply = %v, %v, want 10.42.0.3", addr, err)
	}

	// The wait doubles from one failed accept to the next and starts over
	// after one that succeeded.
	var delays []string
	for _, r := range logs.find("mesh dns could not accept a connection") {
		if r.Level != slog.LevelDebug {
			t.Errorf("accept error logged at %v, want %v", r.Level, slog.LevelDebug)
		}
		if got := recordAttr(r, "error").String(); !strings.Contains(got, "too many open files") {
			t.Errorf("accept error logged with error=%q, want the EMFILE", got)
		}
		delays = append(delays, recordAttr(r, "delay").String())
	}
	if want := []string{"5ms", "10ms", "5ms"}; !slices.Equal(delays, want) {
		t.Errorf("logged delays = %q, want %q", delays, want)
	}
}

// Serve closes stop before the listener, so an accept that fails while
// Serve stops ends the loop with nil, during a run of failures too.
func TestServer_TCPAcceptStopsDuringRetries(t *testing.T) {
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:5354"), slog.New(slog.DiscardHandler))
	ln := &fakeAcceptor{rest: errEMFILE}
	var conns connSet
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- s.serveTCP(newForwards(context.Background(), maxForwards), ln, &conns, stop) }()

	deadline := time.Now().Add(ioTimeout)
	for ln.callCount() < 3 {
		select {
		case err := <-done:
			t.Fatalf("serveTCP() = %v while stop is open, want it to keep accepting", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("Accept called %d times within %v, want 3", ln.callCount(), ioTimeout)
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serveTCP() = %v after stop was closed, want nil", err)
		}
	case <-time.After(ioTimeout):
		t.Fatalf("serveTCP did not return within %v of stop closing", ioTimeout)
	}
}

func TestAcceptDelay(t *testing.T) {
	tests := []struct{ last, want time.Duration }{
		{0, 5 * time.Millisecond},
		{5 * time.Millisecond, 10 * time.Millisecond},
		{10 * time.Millisecond, 20 * time.Millisecond},
		{640 * time.Millisecond, time.Second},
		{time.Second, time.Second},
	}
	for _, tc := range tests {
		if got := acceptDelay(tc.last); got != tc.want {
			t.Errorf("acceptDelay(%v) = %v, want %v", tc.last, got, tc.want)
		}
	}
}

// A wait far longer than the test ends as soon as stop is closed.
func TestWaitAcceptEndsOnStop(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	done := make(chan bool, 1)
	go func() { done <- waitAccept(time.Hour, stop) }()
	select {
	case ok := <-done:
		if ok {
			t.Errorf("waitAccept() = true with stop closed, want false")
		}
	case <-time.After(ioTimeout):
		t.Fatalf("waitAccept did not return within %v of stop closing", ioTimeout)
	}
	if !waitAccept(time.Millisecond, make(chan struct{})) {
		t.Errorf("waitAccept() = false with stop open, want true once the wait is over")
	}
}

// TestServer_AnswersEveryRecordType asks for a record of each of the six
// types over UDP and over TCP and checks the records whole.
func TestServer_AnswersEveryRecordType(t *testing.T) {
	block := serverBlock()
	block.Records = append(block.Records,
		rec("txt.lab.internal", "TXT", text("v=spf1 -all", "", "second")),
	)
	s := startServer(t, mustBuild(t, block))

	tests := []struct {
		qname string
		qtype dnsmessage.Type
		want  []string
	}{
		{"db.lab.internal.", dnsmessage.TypeA, []string{"db.lab.internal. 10 ClassINET TypeA 10.20.0.5"}},
		{"db.lab.internal.", dnsmessage.TypeAAAA, []string{"db.lab.internal. 10 ClassINET TypeAAAA fd00:20::5"}},
		{"wiki.openstack.lab.internal.", dnsmessage.TypeCNAME, []string{"wiki.openstack.lab.internal. 10 ClassINET TypeCNAME wiki.example.com."}},
		{"edge.example.com.", dnsmessage.TypeTXT, []string{`edge.example.com. 10 ClassINET TypeTXT "owner=edge-team"`}},
		{"txt.lab.internal.", dnsmessage.TypeTXT, []string{`txt.lab.internal. 10 ClassINET TypeTXT "v=spf1 -all" "" "second"`}},
		{"_postgres._tcp.openstack.lab.internal.", dnsmessage.TypeSRV, []string{"_postgres._tcp.openstack.lab.internal. 10 ClassINET TypeSRV 0 5 5432 db.lab.internal."}},
		{"lab.internal.", dnsmessage.TypeMX, []string{"lab.internal. 10 ClassINET TypeMX 10 relay.example.com."}},
	}
	for _, network := range []string{"udp", "tcp"} {
		exchange := exchangeUDP
		if network == "tcp" {
			exchange = exchangeTCP
		}
		conn := dial(t, network, s)
		for i, tc := range tests {
			t.Run(fmt.Sprintf("%s %s %v", network, tc.qname, tc.qtype), func(t *testing.T) {
				id := uint16(0x7100 + i)
				m := parseResponse(t, exchange(t, conn, newQuery(t, id, tc.qname, tc.qtype)))
				if m.ID != id || m.RCode != dnsmessage.RCodeSuccess || !m.Authoritative || m.RecursionAvailable || m.Truncated {
					t.Errorf("header ID %#x RCode %v AA %v RA %v TC %v, want %#x %v true false false",
						m.ID, m.RCode, m.Authoritative, m.RecursionAvailable, m.Truncated, id, dnsmessage.RCodeSuccess)
				}
				if got := describeAll(m.Answers); !slices.Equal(got, tc.want) {
					t.Errorf("answers = %q, want %q", got, tc.want)
				}
				if len(m.Authorities) != 0 {
					t.Errorf("authorities = %q, want none", describeAll(m.Authorities))
				}
			})
		}
	}
}

// TestServer_RecordOwners checks who owns each record of an answer: the
// question's spelling for its own name, and the folded name for the records
// of a CNAME target, whose zone owns the SOA of a negative answer.
func TestServer_RecordOwners(t *testing.T) {
	s := startServer(t, mustBuild(t, cnameBlock()))
	conn := dial(t, "udp", s)

	tests := []struct {
		name        string
		qname       string
		rcode       dnsmessage.RCode
		answers     []string
		authorities []string
	}{
		{
			"records of the question's name", "DB.Lab.Internal.", dnsmessage.RCodeSuccess,
			[]string{"DB.Lab.Internal. 10 ClassINET TypeA 10.20.0.5"},
			nil,
		},
		{
			"two records of the question's name", "Multi.LAB.internal.", dnsmessage.RCodeSuccess,
			[]string{"Multi.LAB.internal. 10 ClassINET TypeA 192.0.2.1", "Multi.LAB.internal. 10 ClassINET TypeA 192.0.2.2"},
			nil,
		},
		{
			"CNAME to a host", "Alias.Lab.Internal.", dnsmessage.RCodeSuccess,
			[]string{
				"Alias.Lab.Internal. 10 ClassINET TypeCNAME db-1.openstack.lab.internal.",
				"db-1.openstack.lab.internal. 10 ClassINET TypeA 10.42.0.3",
			},
			nil,
		},
		{
			"CNAME to a missing name in another zone", "Dangling.Lab.Internal.", dnsmessage.RCodeNameError,
			[]string{"Dangling.Lab.Internal. 10 ClassINET TypeCNAME nope.openstack.lab.internal."},
			[]string{wantSOA("openstack.lab.internal")},
		},
		{
			"CNAME out of the zones", "wiki.openstack.lab.internal.", dnsmessage.RCodeSuccess,
			[]string{"wiki.openstack.lab.internal. 10 ClassINET TypeCNAME wiki.example.com."},
			nil,
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := uint16(0x7200 + i)
			m := parseResponse(t, exchangeUDP(t, conn, newQuery(t, id, tc.qname, dnsmessage.TypeA)))
			if m.RCode != tc.rcode || !m.Authoritative {
				t.Errorf("RCode %v AA %v, want %v true", m.RCode, m.Authoritative, tc.rcode)
			}
			if got := describeAll(m.Answers); !slices.Equal(got, tc.answers) {
				t.Errorf("answers = %q, want %q", got, tc.answers)
			}
			if got := describeAll(m.Authorities); !slices.Equal(got, tc.authorities) {
				t.Errorf("authorities = %q, want %q", got, tc.authorities)
			}
		})
	}
}

// TestServer_SetRecordsDropsARecord checks that a block without a record
// takes its answer away with the next query.
func TestServer_SetRecordsDropsARecord(t *testing.T) {
	s := startServer(t, mustBuild(t, serverBlock()))
	conn := dial(t, "udp", s)

	m := parseResponse(t, exchangeUDP(t, conn, newQuery(t, 1, "db.lab.internal.", dnsmessage.TypeA)))
	if got, want := describeAll(m.Answers), []string{"db.lab.internal. 10 ClassINET TypeA 10.20.0.5"}; !slices.Equal(got, want) {
		t.Fatalf("answers before = %q, want %q", got, want)
	}

	block := serverBlock()
	block.Records = slices.DeleteFunc(block.Records, func(r api.NodeStateDNSRecord) bool { return r.FQDN == "db.lab.internal" })
	s.SetRecords(mustBuild(t, block))

	m = parseResponse(t, exchangeUDP(t, conn, newQuery(t, 2, "db.lab.internal.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
		t.Errorf("after the record left: RCode %v answers %q, want %v and none", m.RCode, describeAll(m.Answers), dnsmessage.RCodeNameError)
	}
}

// bigTXT returns n TXT records of one size-byte string each at name, each
// string distinct, so none repeats another.
func bigTXT(name string, n, size int) []api.NodeStateDNSRecord {
	recs := make([]api.NodeStateDNSRecord, 0, n)
	for i := range n {
		s := fmt.Sprintf("%03d-", i)
		recs = append(recs, rec(name, "TXT", text(s+strings.Repeat("x", size-len(s)))))
	}
	return recs
}

// packQueryPayload packs a query for name and qtype with one OPT record that
// offers payload bytes.
func packQueryPayload(t *testing.T, id uint16, name string, qtype dnsmessage.Type, payload int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(question(name, qtype)); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(payload, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// wantTruncated fails the test unless m is a truncated response to q: TC set,
// the question, no record in the answer and authority sections, and one OPT
// record exactly when the query had one.
func wantTruncated(t *testing.T, m dnsmessage.Message, q dnsmessage.Question, edns bool) {
	t.Helper()
	if !m.Truncated || m.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("TC %v RCode %v, want true %v", m.Truncated, m.RCode, dnsmessage.RCodeSuccess)
	}
	if !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
		t.Errorf("questions = %v, want %v", m.Questions, q)
	}
	if len(m.Answers) != 0 || len(m.Authorities) != 0 {
		t.Errorf("answers %d authorities %d, want none", len(m.Answers), len(m.Authorities))
	}
	checkOPT(t, m, edns)
}

func TestServer_TruncatesOverUDP(t *testing.T) {
	block := serverBlock()
	block.Records = append(block.Records, bigTXT("three.lab.internal", 3, 200)...)
	block.Records = append(block.Records, bigTXT("eight.lab.internal", 8, 200)...)
	block.Records = append(block.Records, bigTXT("one.lab.internal", 1, 200)...)
	s := startServer(t, mustBuild(t, block))
	udp := dial(t, "udp", s)
	tcp := dial(t, "tcp", s)
	three := question("three.lab.internal.", dnsmessage.TypeTXT)
	eight := question("eight.lab.internal.", dnsmessage.TypeTXT)

	t.Run("no OPT over 512 bytes", func(t *testing.T) {
		resp := exchangeUDP(t, udp, newQuery(t, 1, "three.lab.internal.", dnsmessage.TypeTXT))
		if len(resp) > 512 {
			t.Errorf("reply of %d bytes, want at most 512", len(resp))
		}
		wantTruncated(t, parseResponse(t, resp), three, false)
	})
	t.Run("the same query over TCP", func(t *testing.T) {
		m := parseResponse(t, exchangeTCP(t, tcp, newQuery(t, 2, "three.lab.internal.", dnsmessage.TypeTXT)))
		if m.Truncated || len(m.Answers) != 3 {
			t.Errorf("TC %v with %d answers, want false and 3", m.Truncated, len(m.Answers))
		}
	})
	t.Run("OPT of 4096 bytes", func(t *testing.T) {
		m := parseResponse(t, exchangeUDP(t, udp, packQueryPayload(t, 3, "three.lab.internal.", dnsmessage.TypeTXT, 4096)))
		if m.Truncated || len(m.Answers) != 3 {
			t.Errorf("TC %v with %d answers, want false and 3", m.Truncated, len(m.Answers))
		}
		checkOPT(t, m, true)
	})
	t.Run("OPT of 4096 bytes over 1232", func(t *testing.T) {
		resp := exchangeUDP(t, udp, packQueryPayload(t, 4, "eight.lab.internal.", dnsmessage.TypeTXT, 4096))
		if len(resp) > 1232 {
			t.Errorf("reply of %d bytes, want at most 1232", len(resp))
		}
		wantTruncated(t, parseResponse(t, resp), eight, true)
	})
	t.Run("eight over TCP", func(t *testing.T) {
		m := parseResponse(t, exchangeTCP(t, tcp, newQuery(t, 5, "eight.lab.internal.", dnsmessage.TypeTXT)))
		if m.Truncated || len(m.Answers) != 8 {
			t.Errorf("TC %v with %d answers, want false and 8", m.Truncated, len(m.Answers))
		}
	})
	t.Run("OPT of 100 bytes counts as 512", func(t *testing.T) {
		wantTruncated(t, parseResponse(t, exchangeUDP(t, udp, packQueryPayload(t, 6, "three.lab.internal.", dnsmessage.TypeTXT, 100))), three, true)
		// One record of 200 bytes takes more than the 100 the client offers
		// and less than 512, so it arrives whole only when 100 counts as 512.
		resp := exchangeUDP(t, udp, packQueryPayload(t, 7, "one.lab.internal.", dnsmessage.TypeTXT, 100))
		if len(resp) <= 100 || len(resp) > 512 {
			t.Fatalf("reply of %d bytes, want between 101 and 512 for this check", len(resp))
		}
		m := parseResponse(t, resp)
		if m.Truncated || len(m.Answers) != 1 {
			t.Errorf("TC %v with %d answers, want false and 1", m.Truncated, len(m.Answers))
		}
	})
}

func TestServer_AnswerTooLargeForTCP(t *testing.T) {
	block := serverBlock()
	block.Records = append(block.Records, bigTXT("huge.lab.internal", 300, 255)...)
	logs := &debugLog{}
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:0"), slog.New(logs))
	s.SetRecords(mustBuild(t, block))
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(serve(t, s))
	q := question("huge.lab.internal.", dnsmessage.TypeTXT)

	m := parseResponse(t, exchangeTCP(t, dial(t, "tcp", s), newQuery(t, 1, "huge.lab.internal.", dnsmessage.TypeTXT)))
	if m.RCode != dnsmessage.RCodeServerFailure || m.Authoritative || m.Truncated {
		t.Errorf("RCode %v AA %v TC %v, want %v false false", m.RCode, m.Authoritative, m.Truncated, dnsmessage.RCodeServerFailure)
	}
	if !slices.Equal(m.Questions, []dnsmessage.Question{q}) || len(m.Answers) != 0 || len(m.Authorities) != 0 {
		t.Errorf("questions %v answers %d authorities %d, want the question and no record", m.Questions, len(m.Answers), len(m.Authorities))
	}
	found := logs.find("mesh dns answer does not fit a message")
	if len(found) != 1 {
		t.Fatalf("%d lines say the answer does not fit, want 1", len(found))
	}
	if found[0].Level != slog.LevelDebug {
		t.Errorf("the answer that does not fit logged at %v, want %v", found[0].Level, slog.LevelDebug)
	}
	if got := recordAttr(found[0], "name").String(); got != "huge.lab.internal." {
		t.Errorf("name = %q, want %q", got, "huge.lab.internal.")
	}
	if got := recordAttr(found[0], "type").String(); got != "TypeTXT" {
		t.Errorf("type = %q, want %q", got, "TypeTXT")
	}
	if got := recordAttr(found[0], "bytes").Int64(); got <= 65535 {
		t.Errorf("bytes = %d, want more than 65535", got)
	}

	wantTruncated(t, parseResponse(t, exchangeUDP(t, dial(t, "udp", s), newQuery(t, 2, "huge.lab.internal.", dnsmessage.TypeTXT))), q, false)
}

// A record BuildRecords would refuse reaches the server only by hand: a TXT
// string of 256 bytes, which dnsmessage cannot pack.
func TestServer_DropsAnswerItCannotPack(t *testing.T) {
	r := mustBuild(t, serverBlock())
	broken := *r
	broken.records = maps.Clone(r.records)
	broken.records["db.lab.internal"] = []RR{{Name: "db.lab.internal", Type: dnsmessage.TypeTXT, Text: []string{strings.Repeat("x", 256)}}}
	logs := &debugLog{}
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:0"), slog.New(logs))
	s.SetRecords(&broken)

	w := &recordingWriter{}
	s.handlePacket(w, newQuery(t, 1, "db.lab.internal.", dnsmessage.TypeTXT), netip.MustParseAddrPort("127.0.0.1:5300"),
		newForwards(context.Background(), maxForwards))
	if got := len(w.to); got != 0 {
		t.Errorf("%d replies sent, want none", got)
	}
	found := logs.find("mesh dns could not pack a reply")
	if len(found) != 1 {
		t.Fatalf("%d lines say the reply could not be packed, want 1", len(found))
	}
	if found[0].Level != slog.LevelDebug {
		t.Errorf("the reply that could not be packed logged at %v, want %v", found[0].Level, slog.LevelDebug)
	}
	if got := recordAttr(found[0], "error").String(); !strings.Contains(got, "character string exceeds maximum length (255)") {
		t.Errorf("error = %q, want the string-length refusal of dnsmessage", got)
	}
}

// startForwarder serves records and table on a new test server whose
// upstream sends the queries for each address of fakes to that fake, and
// returns the server with the log it writes. configure runs before Listen.
func startForwarder(t *testing.T, records *Records, table *Forwarding, fakes map[string]*fakeResolver, configure ...func(*Server)) (*Server, *debugLog) {
	t.Helper()
	logs := &debugLog{}
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:0"), slog.New(logs))
	s.upstream.target = routeFakes(t, fakes)
	for _, f := range configure {
		f(s)
	}
	if records != nil {
		s.SetRecords(records)
	}
	s.SetForwarding(table)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	t.Cleanup(serve(t, s))
	return s, logs
}

// catchAllTable is a forwarding table with the forward zone corp.example.com
// and the catch-all, both on the resolver 192.0.2.1.
func catchAllTable(t *testing.T) *Forwarding {
	t.Helper()
	return mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{fwdZone("corp.example.com", "192.0.2.1")},
		CatchAll:     []string{"192.0.2.1"},
	}, nil)
}

// exchangeOver returns the exchange function of network, udp or tcp.
func exchangeOver(network string) func(*testing.T, net.Conn, []byte) []byte {
	if network == "tcp" {
		return exchangeTCP
	}
	return exchangeUDP
}

func TestServer_Forwards(t *testing.T) {
	corp := newFakeResolver(t, answerA("198.51.100.1"))
	example := newFakeResolver(t, answerA("198.51.100.2"))
	other := newFakeResolver(t, answerA("198.51.100.3"))
	records := mustBuild(t, serverBlock())
	table := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{
			fwdZone("corp.example.com", "192.0.2.1"),
			// Above the mesh zone edge.example.com, which keeps its names.
			fwdZone("example.com", "192.0.2.2"),
		},
		CatchAll: []string{"192.0.2.3"},
	}, records)
	s, _ := startForwarder(t, records, table, map[string]*fakeResolver{"192.0.2.1": corp, "192.0.2.2": example, "192.0.2.3": other})
	asked := func() int { return corp.count() + example.count() + other.count() }

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			exchange := exchangeOver(network)
			conn := dial(t, network, s)

			forwarded := []struct {
				qname string
				fake  *fakeResolver
			}{
				{"host.corp.example.com.", corp},
				{"Host.CORP.example.com.", corp},
				{"www.example.com.", example},
				// Under no forward zone: the catch-all.
				{"example.org.", other},
				{"1.2.0.192.in-addr.arpa.", other},
			}
			for i, tc := range forwarded {
				before := tc.fake.count()
				query := newQuery(t, uint16(0x7300+i), tc.qname, dnsmessage.TypeA)
				resp := exchange(t, conn, query)
				got := tc.fake.received()
				if len(got) != before+1 {
					t.Fatalf("%s: the resolver received %d queries, want %d", tc.qname, len(got), before+1)
				}
				wantSentAsQuery(t, got[before], network, query)
				wantRelayed(t, resp, got[before].replies[0], query)
			}

			// The mesh zones answer from the records, below a forward zone
			// too, and a name missing from one is not forwarded either.
			before := asked()
			for i, tc := range []struct {
				qname string
				rcode dnsmessage.RCode
				want  []string
			}{
				{"db-1.openstack.lab.internal.", dnsmessage.RCodeSuccess, []string{"db-1.openstack.lab.internal. 10 ClassINET TypeA 10.42.0.3"}},
				{"gw.edge.example.com.", dnsmessage.RCodeSuccess, []string{"gw.edge.example.com. 10 ClassINET TypeA 10.42.0.9"}},
				{"nope.edge.example.com.", dnsmessage.RCodeNameError, nil},
				{"9.9.42.10.in-addr.arpa.", dnsmessage.RCodeNameError, nil},
			} {
				m := parseResponse(t, exchange(t, conn, newQuery(t, uint16(0x7400+i), tc.qname, dnsmessage.TypeA)))
				if m.RCode != tc.rcode || !m.Authoritative {
					t.Errorf("%s: RCode %v AA %v, want %v true", tc.qname, m.RCode, m.Authoritative, tc.rcode)
				}
				if got := describeAll(m.Answers); !slices.Equal(got, tc.want) {
					t.Errorf("%s: answers = %q, want %q", tc.qname, got, tc.want)
				}
			}
			if got := asked(); got != before {
				t.Errorf("the resolvers received %d queries for mesh names, want none", got-before)
			}
		})
	}
}

func TestServer_RefusesWithoutRoute(t *testing.T) {
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	records := mustBuild(t, serverBlock())
	zonesOnly := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{fwdZone("corp.example.com", "192.0.2.1")},
		CatchAll:     []string{},
	}, records)
	empty := mustForward(t, api.NodeStateDNSForwarding{ForwardZones: []api.NodeStateDNSForwardZone{}, CatchAll: []string{}}, records)

	tests := []struct {
		name    string
		records *Records
		table   *Forwarding
		refused []string
	}{
		{"forward zones without a catch-all", records, zonesOnly, []string{"example.org."}},
		{"empty table", records, empty, []string{"example.org.", "host.corp.example.com."}},
		{"nil table", records, nil, []string{"example.org.", "host.corp.example.com."}},
		{"before SetRecords", nil, zonesOnly, []string{"example.org.", "db-1.openstack.lab.internal."}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := startForwarder(t, tc.records, tc.table, map[string]*fakeResolver{"192.0.2.1": fake})
			for _, network := range []string{"udp", "tcp"} {
				conn := dial(t, network, s)
				for i, qname := range tc.refused {
					q := question(qname, dnsmessage.TypeA)
					m := parseResponse(t, exchangeOver(network)(t, conn, newQuery(t, uint16(i+1), qname, dnsmessage.TypeA)))
					if m.RCode != dnsmessage.RCodeRefused || m.Authoritative {
						t.Errorf("%s %s: RCode %v AA %v, want %v false", network, qname, m.RCode, m.Authoritative, dnsmessage.RCodeRefused)
					}
					if !slices.Equal(m.Questions, []dnsmessage.Question{q}) || len(m.Answers) != 0 {
						t.Errorf("%s %s: questions %v answers %q, want the question and no answer", network, qname, m.Questions, describeAll(m.Answers))
					}
				}
			}
			if got := fake.count(); got != 0 {
				t.Errorf("the resolver received %d queries, want none", got)
			}
		})
	}
}

// A query that is no standard query for one name of class IN is answered as
// it was before forwarding, for a name the table routes too, and a zone
// transfer is never relayed.
func TestServer_NeverForwards(t *testing.T) {
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	s, _ := startForwarder(t, mustBuild(t, serverBlock()), catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake})

	host := question("host.corp.example.com.", dnsmessage.TypeA)
	chaos := host
	chaos.Class = dnsmessage.ClassCHAOS
	axfr := question("corp.example.com.", dnsmessage.TypeAXFR)
	ixfr := question("corp.example.com.", typeIXFR)
	other := question("example.org.", dnsmessage.TypeA)
	rd := func(id uint16) dnsmessage.Header { return dnsmessage.Header{ID: id, RecursionDesired: true} }

	tests := []struct {
		name  string
		msg   []byte
		rcode dnsmessage.RCode
	}{
		{"class CH", packQuery(t, rd(1), false, chaos), dnsmessage.RCodeRefused},
		{"AXFR", packQuery(t, rd(2), false, axfr), dnsmessage.RCodeRefused},
		{"IXFR", packQuery(t, rd(3), false, ixfr), dnsmessage.RCodeRefused},
		{"opcode 2", packQuery(t, dnsmessage.Header{ID: 4, OpCode: 2, RecursionDesired: true}, false, host), dnsmessage.RCodeNotImplemented},
		{"two questions", packQuery(t, rd(5), false, host, other), dnsmessage.RCodeFormatError},
		{"two OPT records", packQueryOPTs(t, rd(6), 2, host), dnsmessage.RCodeFormatError},
	}
	for _, network := range []string{"udp", "tcp"} {
		conn := dial(t, network, s)
		for _, tc := range tests {
			t.Run(network+" "+tc.name, func(t *testing.T) {
				m := parseResponse(t, exchangeOver(network)(t, conn, tc.msg))
				if m.RCode != tc.rcode || m.Authoritative || m.RecursionAvailable {
					t.Errorf("RCode %v AA %v RA %v, want %v false false", m.RCode, m.Authoritative, m.RecursionAvailable, tc.rcode)
				}
				if len(m.Answers) != 0 {
					t.Errorf("answers = %q, want none", describeAll(m.Answers))
				}
			})
		}
	}
	if got := fake.count(); got != 0 {
		t.Errorf("the resolver received %d queries, want none", got)
	}

	// The same name asked for A is forwarded.
	exchangeUDP(t, dial(t, "udp", s), packQuery(t, rd(7), false, host))
	if got := fake.count(); got != 1 {
		t.Errorf("the resolver received %d queries for host.corp.example.com A, want 1", got)
	}
}

// As for the answers, the drop is proven at the handlers the loops call,
// with the source a socket would report.
func TestServer_DropsForwardFromDisallowedSource(t *testing.T) {
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	s := NewServer(netip.MustParseAddrPort("10.99.0.1:5354"), slog.New(slog.DiscardHandler))
	s.upstream.target = routeFakes(t, map[string]*fakeResolver{"192.0.2.1": fake})
	s.SetForwarding(catchAllTable(t))
	msg := newQuery(t, 13, "example.org.", dnsmessage.TypeA)
	fw := newForwards(context.Background(), maxForwards)

	for _, src := range []string{"192.0.2.7:40000", "10.99.0.2:40000"} {
		w := &recordingWriter{}
		s.handlePacket(w, msg, netip.MustParseAddrPort(src), fw)
		fw.wg.Wait()
		if len(w.to) != 0 {
			t.Errorf("replies to a query from %s went to %v, want none", src, w.to)
		}
	}
	t.Run("tcp", func(t *testing.T) {
		var conns connSet
		server, client := net.Pipe()
		defer conns.closeAll()
		defer func() { _ = client.Close() }()
		s.accept(fw, &conns, server, netip.MustParseAddr("192.0.2.7"))
		if err := writeFrame(client, msg); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("write to a connection from 192.0.2.7 = %v, want %v", err, io.ErrClosedPipe)
		}
	})
	if got := fake.count(); got != 0 {
		t.Errorf("the resolver received %d queries, want none", got)
	}

	// The node itself is forwarded for.
	w := &recordingWriter{}
	src := netip.MustParseAddrPort("10.99.0.1:40000")
	s.handlePacket(w, msg, src, fw)
	fw.wg.Wait()
	if !slices.Equal(w.to, []netip.AddrPort{src}) || fake.count() != 1 {
		t.Errorf("a query from %s: replies to %v and %d queries to the resolver, want one each", src, w.to, fake.count())
	}
}

func TestServer_ForwardFailsWithServfail(t *testing.T) {
	fake := newFakeResolver(t, silent)
	table := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{fwdZone("corp.example.com", "192.0.2.1")},
	}, nil)
	s, logs := startForwarder(t, nil, table, map[string]*fakeResolver{"192.0.2.1": fake}, func(s *Server) {
		// The resolver stays silent; nothing here is about the length of
		// the wait, so an exchange gives up sooner.
		s.upstream.timeout = 300 * time.Millisecond
	})
	q := question("host.corp.example.com.", dnsmessage.TypeA)

	i := 0
	for _, network := range []string{"udp", "tcp"} {
		for _, edns := range []bool{false, true} {
			i++
			t.Run(fmt.Sprintf("%s edns %v", network, edns), func(t *testing.T) {
				id := uint16(0x7500 + i)
				msg := packQuery(t, dnsmessage.Header{ID: id, RecursionDesired: true}, edns, q)
				m := parseResponse(t, exchangeOver(network)(t, dial(t, network, s), msg))
				if m.ID != id || m.RCode != dnsmessage.RCodeServerFailure {
					t.Errorf("ID %#x RCode %v, want %#x %v", m.ID, m.RCode, id, dnsmessage.RCodeServerFailure)
				}
				if !m.Response || m.Authoritative || m.RecursionAvailable || !m.RecursionDesired || m.Truncated {
					t.Errorf("QR, AA, RA, RD, TC = %v, %v, %v, %v, %v, want true, false, false, true, false",
						m.Response, m.Authoritative, m.RecursionAvailable, m.RecursionDesired, m.Truncated)
				}
				if !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
					t.Errorf("questions = %v, want %v", m.Questions, q)
				}
				if len(m.Answers) != 0 || len(m.Authorities) != 0 {
					t.Errorf("answers, authorities = %q, %q, want none", describeAll(m.Answers), describeAll(m.Authorities))
				}
				checkOPT(t, m, edns)
			})
		}
	}

	found := logs.find("mesh dns forwarded query failed")
	if len(found) != 4 {
		t.Fatalf("%d lines say the forwarded query failed, want 4", len(found))
	}
	for _, r := range found {
		if r.Level != slog.LevelDebug {
			t.Errorf("forwarded query failed logged at %v, want %v", r.Level, slog.LevelDebug)
		}
		for k, want := range map[string]string{
			"name":  "host.corp.example.com.",
			"type":  "TypeA",
			"zone":  "corp.example.com",
			"error": "meshdns: forward to corp.example.com: context deadline exceeded",
		} {
			if got := recordAttr(r, k).String(); got != want {
				t.Errorf("forwarded query failed has %s=%q, want %q", k, got, want)
			}
		}
	}
}

func TestServer_AnswersMeshNamesWhileForwarding(t *testing.T) {
	fake := newFakeResolver(t, silent)
	s, _ := startForwarder(t, mustBuild(t, serverBlock()), catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake})

	// The forward waits for a resolver that does not answer, the whole 4
	// seconds of its exchange.
	if _, err := dial(t, "udp", s).Write(newQuery(t, 1, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	fake.waitQueries(t, 1)

	start := time.Now()
	addr, err := firstA(exchangeUDP(t, dial(t, "udp", s), newQuery(t, 2, "db-1.openstack.lab.internal.", dnsmessage.TypeA)))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("mesh name answered after %v while a forward is in flight, want within 1s", elapsed)
	}
	if err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Errorf("reply = %v, %v, want 10.42.0.3", addr, err)
	}
}

func TestServer_ForwardLimit(t *testing.T) {
	const limit = 2
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	fake.hold()
	s, logs := startForwarder(t, nil, catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake}, func(s *Server) { s.forwardLimit = limit })

	held := make([]net.Conn, limit)
	for i := range held {
		held[i] = dial(t, "udp", s)
		if _, err := held[i].Write(newQuery(t, uint16(i+1), "example.org.", dnsmessage.TypeA)); err != nil {
			t.Fatalf("write query %d: %v", i+1, err)
		}
	}
	fake.waitQueries(t, limit)

	// The forwards in flight wait for the resolver, which holds its
	// replies, so a SERVFAIL within a second is not one that waited for it.
	start := time.Now()
	m := parseResponse(t, exchangeUDP(t, dial(t, "udp", s), newQuery(t, 3, "example.org.", dnsmessage.TypeA)))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("query over the limit answered after %v, want at once", elapsed)
	}
	if m.ID != 3 || m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
		t.Errorf("query over the limit: ID %#x RCode %v answers %q, want 0x3 %v and none", m.ID, m.RCode, describeAll(m.Answers), dnsmessage.RCodeServerFailure)
	}
	if got := fake.count(); got != limit {
		t.Errorf("the resolver received %d queries, want %d: the query over the limit reached it", got, limit)
	}
	found := logs.find("mesh dns dropped a forwarded query, too many are in flight")
	if len(found) != 1 {
		t.Fatalf("%d lines say a forwarded query was dropped, want 1", len(found))
	}
	if found[0].Level != slog.LevelDebug || recordAttr(found[0], "limit").Int64() != limit {
		t.Errorf("dropped a forwarded query logged at %v with limit=%v, want %v and %d", found[0].Level, recordAttr(found[0], "limit"), slog.LevelDebug, limit)
	}

	fake.release()
	for i, conn := range held {
		if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
			t.Fatalf("SetReadDeadline() = %v, want nil", err)
		}
		buf := make([]byte, maxMessageSize)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read reply %d: %v", i+1, err)
		}
		if addr, err := firstA(buf[:n]); err != nil || addr != netip.MustParseAddr("198.51.100.1") || binary.BigEndian.Uint16(buf) != uint16(i+1) {
			t.Errorf("reply %d = ID %#x %v, %v, want ID %#x 198.51.100.1", i+1, binary.BigEndian.Uint16(buf), addr, err, i+1)
		}
	}

	// Each slot frees before its reply goes out, so the next query is
	// forwarded again.
	if addr, err := firstA(exchangeUDP(t, dial(t, "udp", s), newQuery(t, 4, "example.org.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("query after the slots freed = %v, %v, want 198.51.100.1", addr, err)
	}
	if got := fake.count(); got != limit+1 {
		t.Errorf("the resolver received %d queries, want %d", got, limit+1)
	}
}

func TestServer_TruncatesRelayedReply(t *testing.T) {
	// Six TXT records of 200 bytes each make a reply of about 1300 bytes.
	fake := newFakeResolver(t, func(query []byte) [][]byte {
		return [][]byte{packReply(query, nil, func(b *dnsmessage.Builder, q dnsmessage.Question) error {
			for i := range 6 {
				rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
				txt := fmt.Sprintf("%03d-%s", i, strings.Repeat("x", 196))
				if err := b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{txt}}); err != nil {
					return err
				}
			}
			return nil
		})}
	})
	s, _ := startForwarder(t, nil, catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake})
	q := question("big.example.org.", dnsmessage.TypeTXT)

	resp := exchangeUDP(t, dial(t, "udp", s), packQueryPayload(t, 1, "big.example.org.", dnsmessage.TypeTXT, 1472))
	if sent := fake.received()[0].replies[0]; len(sent) < 1300 || len(sent) > 1472 {
		t.Fatalf("the resolver's reply has %d bytes, want 1300 to 1472 for this check", len(sent))
	}
	if len(resp) > 1232 {
		t.Errorf("reply of %d bytes over UDP, want at most 1232", len(resp))
	}
	m := parseResponse(t, resp)
	wantTruncated(t, m, q, true)
	if m.ID != 1 {
		t.Errorf("ID = %#x, want 0x1", m.ID)
	}

	query := packQueryPayload(t, 2, "big.example.org.", dnsmessage.TypeTXT, 1472)
	resp = exchangeTCP(t, dial(t, "tcp", s), query)
	wantRelayed(t, resp, fake.received()[1].replies[0], query)
	if m := parseResponse(t, resp); m.Truncated || len(m.Answers) != 6 {
		t.Errorf("over TCP: TC %v with %d answers, want false and 6", m.Truncated, len(m.Answers))
	}
}

// A forward whose resolver answers only after the deadline in force when the
// query arrived has passed still gets its reply, under a write deadline of
// its own, without which the reply would never leave. The connection answers
// on after it: the forward restarted the deadline when it took its slot, so
// the loop read on while it waited, and the reply restarted it again. The
// sleeps are the idle time under test.
func TestServer_TCPForwardOutlastsIdleDeadline(t *testing.T) {
	const idle = time.Second
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	fake.hold()
	s, _ := startForwarder(t, mustBuild(t, serverBlock()), catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake},
		func(s *Server) { s.tcpIdle = idle })
	conn := dial(t, "tcp", s)

	sent := time.Now()
	if addr, err := firstA(exchangeTCP(t, conn, newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Fatalf("first reply = %v, %v, want 10.42.0.3", addr, err)
	}
	// The server wrote the reply after the query left and before the reply
	// arrived, so the deadline it set, for the read and for a write, passes
	// between idle after sent and idle after answered.
	answered := time.Now()

	time.Sleep(time.Until(sent.Add(idle / 2)))
	if err := writeFrame(conn, newQuery(t, 2, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write forwarded query: %v", err)
	}
	fake.waitQueries(t, 1)
	// Past the deadline the first reply set, and before the one the forward
	// set when it took its slot, idle after the write above.
	time.Sleep(time.Until(answered.Add(idle + idle/4)))
	fake.release()

	resp, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read the forward's reply: %v", err)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("198.51.100.1") || binary.BigEndian.Uint16(resp) != 2 {
		t.Errorf("forward's reply = ID %#x %v, %v, want ID 0x2 198.51.100.1", binary.BigEndian.Uint16(resp), addr, err)
	}
	// The reply set a fresh deadline, so the connection answers on.
	if addr, err := firstA(exchangeTCP(t, conn, newQuery(t, 3, "db-1.openstack.lab.internal.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Errorf("reply after the forward = %v, %v, want 10.42.0.3", addr, err)
	}
}

// A forwarded query restarts the deadline of its connection when it takes
// its slot, as a reply does, because it gets one. Without that, the deadline
// of the reply before it passes while the forward waits for its resolver,
// the loop stops reading, and a mesh name asked behind the forward after that
// deadline is never read: the connection sends the forward's reply and
// closes with the query unread, which the client sees as a reset. The sleeps
// are the idle time under test.
func TestServer_TCPForwardKeepsConnectionReading(t *testing.T) {
	const idle = 1500 * time.Millisecond
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	fake.hold()
	s, _ := startForwarder(t, mustBuild(t, serverBlock()), catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake},
		func(s *Server) { s.tcpIdle = idle })
	conn := dial(t, "tcp", s)

	sent := time.Now()
	if addr, err := firstA(exchangeTCP(t, conn, newQuery(t, 1, "db-1.openstack.lab.internal.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Fatalf("first reply = %v, %v, want 10.42.0.3", addr, err)
	}
	// The server wrote the reply after the query left and before the reply
	// arrived, so the deadline it set passes between idle after sent and
	// idle after answered.
	answered := time.Now()

	// Before that deadline, so the loop reads the forwarded query.
	time.Sleep(time.Until(sent.Add(time.Second)))
	if err := writeFrame(conn, newQuery(t, 2, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write forwarded query: %v", err)
	}
	fake.waitQueries(t, 1)
	// Past that deadline, while the forward waits for its resolver.
	time.Sleep(time.Until(answered.Add(1800 * time.Millisecond)))
	if err := writeFrame(conn, newQuery(t, 3, "web.openstack.lab.internal.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write mesh query: %v", err)
	}
	time.Sleep(time.Until(answered.Add(2500 * time.Millisecond)))
	fake.release()

	// The mesh name was answered when it arrived, before the resolver
	// answered the forward.
	resp, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("10.42.0.2") || binary.BigEndian.Uint16(resp) != 3 {
		t.Errorf("reply 1 = ID %#x %v, %v, want the mesh name's ID 0x3 10.42.0.2", binary.BigEndian.Uint16(resp), addr, err)
	}
	if resp, err = readFrame(conn); err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("198.51.100.1") || binary.BigEndian.Uint16(resp) != 2 {
		t.Errorf("reply 2 = ID %#x %v, %v, want the forward's ID 0x2 198.51.100.1", binary.BigEndian.Uint16(resp), addr, err)
	}
	if addr, err := firstA(exchangeTCP(t, conn, newQuery(t, 4, "db-1.openstack.lab.internal.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Errorf("reply after the forward = %v, %v, want 10.42.0.3", addr, err)
	}
}

// A forwarded reply restarts the deadline as a mesh answer does, for the read
// that already waits too, so a client whose query was forwarded has the full
// time for its next one. The sleeps are the idle time under test.
func TestServer_TCPForwardedReplyRestartsDeadline(t *testing.T) {
	const (
		idle = 1500 * time.Millisecond
		gap  = 900 * time.Millisecond
	)
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	fake.hold()
	s, _ := startForwarder(t, mustBuild(t, serverBlock()), catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake},
		func(s *Server) { s.tcpIdle = idle })
	conn := dial(t, "tcp", s)

	if err := writeFrame(conn, newQuery(t, 1, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	fake.waitQueries(t, 1)
	// The server accepted the connection, and the forward took its slot,
	// before the query reached the resolver, so the deadlines both set pass
	// no later than idle from now.
	queried := time.Now()
	time.Sleep(gap)
	fake.release()
	resp, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("reply = %v, %v, want 198.51.100.1", addr, err)
	}

	// Past the deadlines the accept and the forward's slot set, and before
	// the one the reply set.
	time.Sleep(time.Until(queried.Add(idle + gap/2)))
	if addr, err := firstA(exchangeTCP(t, conn, newQuery(t, 2, "db-1.openstack.lab.internal.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Errorf("reply after the forward = %v, %v, want 10.42.0.3", addr, err)
	}
}

// systemd-resolved sends the queries of concurrent lookups over one TCP
// connection to plexd's server without waiting for each reply, so a forward
// that waits for its resolver must not hold up a mesh name asked behind it.
func TestServer_TCPAnswersMeshNamesWhileForwarding(t *testing.T) {
	fake := newFakeResolver(t, silent)
	records := mustBuild(t, serverBlock())
	table := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{fwdZone("corp.example.com", "192.0.2.1")},
	}, records)
	s, _ := startForwarder(t, records, table, map[string]*fakeResolver{"192.0.2.1": fake}, func(s *Server) {
		// The resolver stays silent, so the forward ends at the timeout. A
		// shorter one keeps the test short and still outlasts the second
		// the mesh name has.
		s.upstream.timeout = 2 * time.Second
	})
	conn := dial(t, "tcp", s)
	q := question("host.corp.example.com.", dnsmessage.TypeA)

	if err := writeFrame(conn, packQuery(t, dnsmessage.Header{ID: 1, RecursionDesired: true}, false, q)); err != nil {
		t.Fatalf("write forwarded query: %v", err)
	}
	fake.waitQueries(t, 1)
	start := time.Now()
	if err := writeFrame(conn, newQuery(t, 2, "db-1.openstack.lab.internal.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write mesh query: %v", err)
	}

	resp, err := readFrame(conn)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("read first reply: %v", err)
	}
	if id := binary.BigEndian.Uint16(resp); id != 2 {
		t.Fatalf("first reply has ID %#x after %v, want the mesh name's 0x2 before the forward's", id, elapsed)
	}
	if elapsed > time.Second {
		t.Errorf("mesh name answered after %v while a forward is in flight on its connection, want within 1s", elapsed)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("10.42.0.3") {
		t.Errorf("mesh reply = %v, %v, want 10.42.0.3", addr, err)
	}

	resp, err = readFrame(conn)
	if err != nil {
		t.Fatalf("read the forward's reply: %v", err)
	}
	m := parseResponse(t, resp)
	if m.ID != 1 || m.RCode != dnsmessage.RCodeServerFailure || !slices.Equal(m.Questions, []dnsmessage.Question{q}) {
		t.Errorf("forward's reply: ID %#x RCode %v questions %v, want 0x1 %v %v", m.ID, m.RCode, m.Questions, dnsmessage.RCodeServerFailure, q)
	}
}

// Two forwards on one connection whose resolvers answer in the opposite
// order: each reply goes out once its resolver answered, whole and behind
// its own length, and the stream stays in step for the query after them.
func TestServer_TCPRepliesInCompletionOrder(t *testing.T) {
	slow := newFakeResolver(t, answerA("198.51.100.1"))
	fast := newFakeResolver(t, answerA("198.51.100.2"))
	slow.hold()
	fast.hold()
	table := mustForward(t, api.NodeStateDNSForwarding{
		ForwardZones: []api.NodeStateDNSForwardZone{
			fwdZone("corp.example.com", "192.0.2.1"),
			fwdZone("example.org", "192.0.2.2"),
		},
	}, nil)
	s, _ := startForwarder(t, nil, table, map[string]*fakeResolver{"192.0.2.1": slow, "192.0.2.2": fast})
	conn := dial(t, "tcp", s)

	first := newQuery(t, 1, "host.corp.example.com.", dnsmessage.TypeA)
	second := newQuery(t, 2, "www.example.org.", dnsmessage.TypeA)
	// One write carries both, as a client that pipelines sends them.
	frames := binary.BigEndian.AppendUint16(nil, uint16(len(first)))
	frames = append(frames, first...)
	frames = binary.BigEndian.AppendUint16(frames, uint16(len(second)))
	frames = append(frames, second...)
	if _, err := conn.Write(frames); err != nil {
		t.Fatalf("write queries: %v", err)
	}
	slow.waitQueries(t, 1)
	fast.waitQueries(t, 1)

	fast.release()
	resp, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read first reply: %v", err)
	}
	wantRelayed(t, resp, fast.received()[0].replies[0], second)

	slow.release()
	if resp, err = readFrame(conn); err != nil {
		t.Fatalf("read second reply: %v", err)
	}
	wantRelayed(t, resp, slow.received()[0].replies[0], first)

	// No name of the table: the next frame is this query's REFUSED.
	if m := parseResponse(t, exchangeTCP(t, conn, newQuery(t, 3, "example.net.", dnsmessage.TypeA))); m.ID != 3 || m.RCode != dnsmessage.RCodeRefused {
		t.Errorf("reply after the forwards: ID %#x RCode %v, want 0x3 %v", m.ID, m.RCode, dnsmessage.RCodeRefused)
	}
}

// The slots are shared: forwards over UDP and TCP count against one limit,
// and a TCP forward over it gets SERVFAIL at once, on a connection that has a
// forward in flight too.
func TestServer_TCPForwardLimit(t *testing.T) {
	const limit = 2
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	fake.hold()
	s, logs := startForwarder(t, nil, catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake}, func(s *Server) { s.forwardLimit = limit })

	udp := dial(t, "udp", s)
	if _, err := udp.Write(newQuery(t, 1, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query over UDP: %v", err)
	}
	held := dial(t, "tcp", s)
	if err := writeFrame(held, newQuery(t, 2, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query over TCP: %v", err)
	}
	fake.waitQueries(t, limit)

	// The forwards in flight wait for the resolver, which holds its
	// replies, so a SERVFAIL within a second is not one that waited for it.
	over := []struct {
		network string
		conn    net.Conn
	}{
		{"tcp", held},
		{"tcp", dial(t, "tcp", s)},
		{"udp", dial(t, "udp", s)},
	}
	for i, tc := range over {
		id := uint16(3 + i)
		start := time.Now()
		m := parseResponse(t, exchangeOver(tc.network)(t, tc.conn, newQuery(t, id, "example.org.", dnsmessage.TypeA)))
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("%s query %#x over the limit answered after %v, want at once", tc.network, id, elapsed)
		}
		if m.ID != id || m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
			t.Errorf("%s query over the limit: ID %#x RCode %v answers %q, want %#x %v and none",
				tc.network, m.ID, m.RCode, describeAll(m.Answers), id, dnsmessage.RCodeServerFailure)
		}
	}
	if got := fake.count(); got != limit {
		t.Errorf("the resolver received %d queries, want %d: a query over the limit reached it", got, limit)
	}
	found := logs.find("mesh dns dropped a forwarded query, too many are in flight")
	if len(found) != len(over) {
		t.Fatalf("%d lines say a forwarded query was dropped, want %d", len(found), len(over))
	}
	for _, r := range found {
		if r.Level != slog.LevelDebug || recordAttr(r, "limit").Int64() != limit {
			t.Errorf("dropped a forwarded query logged at %v with limit=%v, want %v and %d", r.Level, recordAttr(r, "limit"), slog.LevelDebug, limit)
		}
	}

	fake.release()
	if err := udp.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatalf("SetReadDeadline() = %v, want nil", err)
	}
	buf := make([]byte, maxMessageSize)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatalf("read UDP reply: %v", err)
	}
	if addr, err := firstA(buf[:n]); err != nil || addr != netip.MustParseAddr("198.51.100.1") || binary.BigEndian.Uint16(buf) != 1 {
		t.Errorf("UDP reply = ID %#x %v, %v, want ID 0x1 198.51.100.1", binary.BigEndian.Uint16(buf), addr, err)
	}
	resp, err := readFrame(held)
	if err != nil {
		t.Fatalf("read TCP reply: %v", err)
	}
	if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("198.51.100.1") || binary.BigEndian.Uint16(resp) != 2 {
		t.Errorf("TCP reply = ID %#x %v, %v, want ID 0x2 198.51.100.1", binary.BigEndian.Uint16(resp), addr, err)
	}

	// Each slot frees before its reply goes out, so the next TCP query is
	// forwarded again.
	if addr, err := firstA(exchangeTCP(t, held, newQuery(t, 6, "example.org.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("TCP query after the slots freed = %v, %v, want 198.51.100.1", addr, err)
	}
	if got := fake.count(); got != limit+1 {
		t.Errorf("the resolver received %d queries, want %d", got, limit+1)
	}
}

// One TCP connection holds at most 16 forwards, each from the slot it takes
// until its reply is written. A client that pipelines more of them while the
// resolver holds its replies gets SERVFAIL at once for the queries over that
// limit, though the server's 256 slots are far from taken.
func TestServer_TCPConnectionForwardLimit(t *testing.T) {
	// The limit is spelled out rather than taken from maxConnForwards, so the
	// test pins the documented 16.
	const (
		limit = 16
		over  = 3
	)
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	fake.hold()
	s, logs := startForwarder(t, nil, catchAllTable(t), map[string]*fakeResolver{"192.0.2.1": fake})
	conn := dial(t, "tcp", s)

	// One write carries them all, as a client that pipelines sends them.
	var frames []byte
	for i := range limit + over {
		q := newQuery(t, uint16(i+1), "example.org.", dnsmessage.TypeA)
		frames = binary.BigEndian.AppendUint16(frames, uint16(len(q)))
		frames = append(frames, q...)
	}
	if _, err := conn.Write(frames); err != nil {
		t.Fatalf("write queries: %v", err)
	}
	fake.waitQueries(t, limit)

	// The forwards wait for the resolver, which holds its replies, so the
	// first replies are the SERVFAILs of the queries over the limit, in
	// their order, and a SERVFAIL within a second is not one that waited.
	start := time.Now()
	for i := range over {
		id := uint16(limit + 1 + i)
		resp, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read the reply to query %#x: %v", id, err)
		}
		if m := parseResponse(t, resp); m.ID != id || m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 {
			t.Errorf("reply %d: ID %#x RCode %v answers %q, want %#x %v and none", i+1, m.ID, m.RCode, describeAll(m.Answers), id, dnsmessage.RCodeServerFailure)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("queries over the limit answered after %v, want at once", elapsed)
	}
	if got := fake.count(); got != limit {
		t.Errorf("the resolver received %d queries, want %d: a query over the limit reached it", got, limit)
	}
	found := logs.find("mesh dns dropped a forwarded query, too many are in flight")
	if len(found) != over {
		t.Fatalf("%d lines say a forwarded query was dropped, want %d", len(found), over)
	}
	for _, r := range found {
		if r.Level != slog.LevelDebug || recordAttr(r, "limit").Int64() != limit {
			t.Errorf("dropped a forwarded query logged at %v with limit=%v, want %v and %d", r.Level, recordAttr(r, "limit"), slog.LevelDebug, limit)
		}
	}

	fake.release()
	ids := make(map[uint16]bool, limit)
	for i := range limit {
		resp, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read relayed reply %d: %v", i+1, err)
		}
		id := binary.BigEndian.Uint16(resp)
		if addr, err := firstA(resp); err != nil || addr != netip.MustParseAddr("198.51.100.1") || id < 1 || id > limit || ids[id] {
			t.Errorf("relayed reply %d = ID %#x %v, %v, want 198.51.100.1 under a forwarded ID not seen before", i+1, id, addr, err)
		}
		ids[id] = true
	}

	// A forward gives its place back with its reply's write, before the next
	// reply goes out, so the client that read them all finds room again.
	if addr, err := firstA(exchangeTCP(t, conn, newQuery(t, 0x100, "example.org.", dnsmessage.TypeA))); err != nil || addr != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("forwarded query after the replies = %v, %v, want 198.51.100.1", addr, err)
	}
	if got := fake.count(); got != limit+1 {
		t.Errorf("the resolver received %d queries, want %d", got, limit+1)
	}
}

// goroutinesIn returns how many goroutines have a frame of fn on their stack,
// fn named as a traceback prints it, such as "meshdns.(*tcpConn).write".
func goroutinesIn(fn string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, fn+"(") {
			count++
		}
	}
	return count
}

// A client that sends forwarded queries and reads none of the replies keeps
// each forward, with its goroutine and its reply, waiting for the write that
// waits for the client. The connection holds 16 of them at most: the
// forwarded query after them gets SERVFAIL from the read loop, whose write
// waits behind theirs, so the loop reads nothing more until the client reads.
// net.Pipe has no buffer, so every write waits for the client from the first
// reply on, as writes do once a client that stopped reading has let the
// socket buffers fill up.
func TestServer_TCPUnreadRepliesStopReading(t *testing.T) {
	// The limit is spelled out rather than taken from maxConnForwards.
	const (
		limit = 16
		sent  = 4 * limit
	)
	fake := newFakeResolver(t, answerA("198.51.100.1"))
	logs := &debugLog{}
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:0"), slog.New(logs))
	s.upstream.target = routeFakes(t, map[string]*fakeResolver{"192.0.2.1": fake})
	s.SetForwarding(catchAllTable(t))
	fw := newForwards(context.Background(), maxForwards)

	queries := make([][]byte, sent)
	for i := range queries {
		queries[i] = newQuery(t, uint16(i+1), "example.org.", dnsmessage.TypeA)
	}
	server, client := net.Pipe()
	served := make(chan struct{})
	go func() {
		defer close(served)
		s.serveConn(fw, server)
	}()
	// read gets the number of each query the server has read whole: a write
	// to a net.Pipe returns once the other end has read all of it.
	read := make(chan int, sent)
	stop := make(chan struct{})
	go func() {
		for i, q := range queries {
			if err := writeFrame(client, q); err != nil {
				return
			}
			read <- i + 1
			if i >= limit {
				continue
			}
			// The first 16 queries go out one at a time: the next one only
			// once this one's forward has reached the resolver and given
			// its slot of fw back, which it does with the resolver's reply
			// in hand, right before it writes that reply. So each of them
			// has a reply waiting for the client before the next arrives,
			// and the queries after them come as fast as the loop reads.
			for {
				fake.mu.Lock()
				got, arrived := len(fake.queries), fake.arrived
				fake.mu.Unlock()
				if got > i {
					break
				}
				select {
				case <-arrived:
				case <-stop:
					return
				}
			}
			for range cap(fw.slots) {
				select {
				case fw.slots <- struct{}{}:
				case <-stop:
					return
				}
			}
			for range cap(fw.slots) {
				<-fw.slots
			}
		}
	}()
	defer func() {
		// Closing the client fails every write that waits for it, so the
		// connection's goroutines end.
		close(stop)
		_ = client.Close()
		select {
		case <-served:
		case <-time.After(ioTimeout):
			t.Errorf("serveConn did not return within %v of the client closing", ioTimeout)
		}
		fw.wg.Wait()
	}()

	found, ok := logs.wait("mesh dns dropped a forwarded query, too many are in flight", 1)
	if !ok {
		t.Fatalf("no forwarded query was dropped within %v: the resolver received %d of the %d queries and %d goroutines wait in tcpConn.write, want %d and at most %d",
			ioTimeout, fake.count(), sent, goroutinesIn("meshdns.(*tcpConn).write"), limit, limit+1)
	}
	if len(found) != 1 || found[0].Level != slog.LevelDebug || recordAttr(found[0], "limit").Int64() != limit {
		t.Errorf("%d drop lines, the first at %v with limit=%v, want one at %v with %d", len(found), found[0].Level, recordAttr(found[0], "limit"), slog.LevelDebug, limit)
	}

	// Each of the 16 forwards had its resolver's reply before the next query
	// went out, and the loop dropped the query after them and waits to write
	// its SERVFAIL. So the 16 are all there will be, each with a reply that
	// waits for the client, and none of them ends while it waits.
	if got := goroutinesIn("meshdns.(*Server).relayTCP"); got != limit {
		t.Errorf("%d forwards hold the connection, want %d", got, limit)
	}
	if got := fake.count(); got != limit {
		t.Errorf("the resolver received %d queries, want %d", got, limit)
	}
	for want := 1; want <= limit+1; want++ {
		select {
		case got := <-read:
			if got != want {
				t.Fatalf("the server read query %d, want %d", got, want)
			}
		case <-time.After(ioTimeout):
			t.Fatalf("the server did not read query %d within %v", want, ioTimeout)
		}
	}
	select {
	case got := <-read:
		t.Errorf("the server read query %d while its SERVFAIL for query %d waits, want it to read nothing more", got, limit+1)
	default:
	}
}

// A forwarded query restarts the deadline of its connection when it takes
// its slot, and it ends within forwardTimeout, so the read of its connection
// does not run out while it waits for its resolvers. That holds only while
// forwardTimeout stays below tcpIdleTimeout.
func TestTCPIdleOutlastsForward(t *testing.T) {
	if forward, idle := forwardTimeout, tcpIdleTimeout; forward >= idle {
		t.Errorf("forwardTimeout = %v, want below tcpIdleTimeout = %v", forward, idle)
	}
}

func TestServer_ServeEndsForwardsInFlight(t *testing.T) {
	fake := newFakeResolver(t, silent)
	// The fake runs on until the test ends; every goroutine the server
	// starts must be gone once Serve returns.
	ignore := goleak.IgnoreCurrent()
	s := newTestServer()
	s.upstream.target = routeFakes(t, map[string]*fakeResolver{"192.0.2.1": fake})
	s.SetForwarding(catchAllTable(t))
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	if _, err := dial(t, "udp", s).Write(newQuery(t, 1, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query over UDP: %v", err)
	}
	tcp := dial(t, "tcp", s)
	if err := writeFrame(tcp, newQuery(t, 2, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query over TCP: %v", err)
	}
	fake.waitQueries(t, 2)

	cancel()
	cancelled := time.Now()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() = %v, want nil after the cancel", err)
		}
		// Both forwards had about 4 seconds left, so a return within one
		// second is the cancel ending them.
		if waited := time.Since(cancelled); waited > time.Second {
			t.Errorf("Serve returned %v after the cancel, want at once", waited)
		}
	case <-time.After(ioTimeout):
		t.Fatalf("Serve did not return within %v of the cancel", ioTimeout)
	}
	waitClosed(t, tcp)
	goleak.VerifyNone(t, ignore)
}

// Each TCP forward runs in a goroutine of its own, several on one connection,
// and Serve ends every one of them: none writes a reply, and none outlives
// Serve.
func TestServer_ServeEndsTCPForwardsInFlight(t *testing.T) {
	fake := newFakeResolver(t, silent)
	ignore := goleak.IgnoreCurrent()
	s := newTestServer()
	s.upstream.target = routeFakes(t, map[string]*fakeResolver{"192.0.2.1": fake})
	s.SetForwarding(catchAllTable(t))
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	pipelined := dial(t, "tcp", s)
	for id := range uint16(2) {
		if err := writeFrame(pipelined, newQuery(t, id+1, "example.org.", dnsmessage.TypeA)); err != nil {
			t.Fatalf("write query %d: %v", id+1, err)
		}
	}
	single := dial(t, "tcp", s)
	if err := writeFrame(single, newQuery(t, 3, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query 3: %v", err)
	}
	fake.waitQueries(t, 3)

	cancel()
	cancelled := time.Now()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() = %v, want nil after the cancel", err)
		}
		if waited := time.Since(cancelled); waited > time.Second {
			t.Errorf("Serve returned %v after the cancel, want at once", waited)
		}
	case <-time.After(ioTimeout):
		t.Fatalf("Serve did not return within %v of the cancel", ioTimeout)
	}
	// A clean EOF as the first read: no reply went out before the close.
	waitClosed(t, pipelined)
	waitClosed(t, single)
	goleak.VerifyNone(t, ignore)
}

// A socket that fails stops Serve while its context is live, so Serve ends
// the forwards itself rather than wait out their resolvers.
func TestServer_SocketErrorEndsForwardsInFlight(t *testing.T) {
	fake := newFakeResolver(t, silent)
	ignore := goleak.IgnoreCurrent()
	s := newTestServer()
	s.upstream.target = routeFakes(t, map[string]*fakeResolver{"192.0.2.1": fake})
	s.SetForwarding(catchAllTable(t))
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	udp := s.udp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	if _, err := dial(t, "udp", s).Write(newQuery(t, 1, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query over UDP: %v", err)
	}
	if err := writeFrame(dial(t, "tcp", s), newQuery(t, 2, "example.org.", dnsmessage.TypeA)); err != nil {
		t.Fatalf("write query over TCP: %v", err)
	}
	fake.waitQueries(t, 2)

	_ = udp.Close()
	closed := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve() = %v, want an error wrapping %v", err, net.ErrClosed)
		}
		if waited := time.Since(closed); waited > time.Second {
			t.Errorf("Serve returned %v after its socket closed, want at once", waited)
		}
	case <-time.After(ioTimeout):
		t.Fatalf("Serve did not return within %v of its UDP socket closing", ioTimeout)
	}
	goleak.VerifyNone(t, ignore)
}

func TestNewServer_ForwardDefaults(t *testing.T) {
	s := NewServer(netip.MustParseAddrPort("127.0.0.1:5354"), nil)
	if s.forwardLimit != 256 {
		t.Errorf("forwardLimit = %d, want 256", s.forwardLimit)
	}
	if s.upstream == nil || s.upstream.timeout != forwardTimeout {
		t.Errorf("upstream = %+v, want one with the default timeout", s.upstream)
	}
	if f := s.forwarding.Load(); f != nil {
		t.Errorf("forwarding = %+v, want nil before SetForwarding", f)
	}
}

func TestServer_SetForwardingPrunesMarks(t *testing.T) {
	s := newTestServer()
	for _, r := range []string{"192.0.2.1", "192.0.2.2"} {
		s.upstream.down[netip.MustParseAddr(r)] = time.Now().Add(resolverRetry)
	}
	s.SetForwarding(catchAllTable(t))
	wantDown(t, s.upstream, "192.0.2.1")
	s.SetForwarding(nil)
	wantDown(t, s.upstream)
}
