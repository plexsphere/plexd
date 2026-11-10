package mockapi_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/plexsphere/plexd/test/e2e/mockapi"
)

// stubReplyTimeout bounds the wait for a reply the stub sends. The stub
// answers from memory at once, so the bound only keeps a broken stub from
// hanging the test.
const stubReplyTimeout = 5 * time.Second

// stubSilenceWindow is how long a test waits to see that no reply comes. The
// tests that use it first prove the stub has handled the query that gets no
// reply, by reading the reply to a query sent after it, so the window only
// catches a reply that is late on top of that.
const stubSilenceWindow = 200 * time.Millisecond

// serveDNSStub binds a stub on 127.0.0.1 with a port the kernel picks and
// serves it until the test ends, failing the test when Serve returns an
// error.
func serveDNSStub(t *testing.T) *mockapi.DNSStub {
	t.Helper()
	stub, stop := startStub(t)
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return stub
}

// stubQuery returns a query for name and typ with the given ID and RD bit,
// carrying an OPT record that offers 1232 bytes when edns is set.
func stubQuery(t *testing.T, id uint16, name string, typ dnsmessage.Type, rd, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: rd})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		var hdr dnsmessage.ResourceHeader
		if err := hdr.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(hdr, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// dialStub opens a connection to the stub over network, "udp" or "tcp",
// closed when the test ends.
func dialStub(t *testing.T, network string, addr netip.AddrPort) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout(network, addr.String(), stubReplyTimeout)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// sendStub writes msg to conn, framed by its two-byte length when conn is a
// TCP connection.
func sendStub(t *testing.T, conn net.Conn, msg []byte) {
	t.Helper()
	if _, ok := conn.(*net.TCPConn); ok {
		msg = append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
	}
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readStub reads one reply from conn within d, unframing it when conn is a
// TCP connection, and returns the read error as it is.
func readStub(conn net.Conn, d time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		return nil, err
	}
	if _, ok := conn.(*net.TCPConn); ok {
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
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// unpackReply reads one reply from conn and unpacks it, failing the test when
// none comes within stubReplyTimeout or it does not parse.
func unpackReply(t *testing.T, conn net.Conn) dnsmessage.Message {
	t.Helper()
	raw, err := readStub(conn, stubReplyTimeout)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("unpack reply %x: %v", raw, err)
	}
	return m
}

// TestDNSStub_Answers pins what the stub answers, over UDP and over TCP: an
// A query gets DNSStubAddress, a name whose first label is nx gets NXDOMAIN
// in any case, any other type gets NOERROR without a record, and every reply
// carries the query's ID, RD bit and question with QR and RA set, and an OPT
// record exactly when the query carried one.
func TestDNSStub_Answers(t *testing.T) {
	stub := serveDNSStub(t)
	stubA := dnsmessage.AResource{A: netip.MustParseAddr(mockapi.DNSStubAddress).As4()}
	if stubA.A != [4]byte{198, 51, 100, 53} {
		t.Fatalf("DNSStubAddress = %s, want 198.51.100.53", mockapi.DNSStubAddress)
	}
	tests := []struct {
		name    string
		qname   string
		qtype   dnsmessage.Type
		rd      bool
		edns    bool
		rcode   dnsmessage.RCode
		answers bool
	}{
		{name: "A", qname: "host.fwd.e2e.test.", qtype: dnsmessage.TypeA, rd: true, rcode: dnsmessage.RCodeSuccess, answers: true},
		{name: "A without RD in mixed case", qname: "Host.Other.E2E.Test.", qtype: dnsmessage.TypeA, rcode: dnsmessage.RCodeSuccess, answers: true},
		{name: "A with OPT", qname: "db.corp.example.com.", qtype: dnsmessage.TypeA, rd: true, edns: true, rcode: dnsmessage.RCodeSuccess, answers: true},
		{name: "nx", qname: "nx.fwd.e2e.test.", qtype: dnsmessage.TypeA, rd: true, rcode: dnsmessage.RCodeNameError},
		{name: "NX AAAA with OPT", qname: "NX.example.com.", qtype: dnsmessage.TypeAAAA, rd: true, edns: true, rcode: dnsmessage.RCodeNameError},
		{name: "nx as a later label", qname: "host.nx.e2e.test.", qtype: dnsmessage.TypeA, rd: true, rcode: dnsmessage.RCodeSuccess, answers: true},
		{name: "AAAA", qname: "host.fwd.e2e.test.", qtype: dnsmessage.TypeAAAA, rd: true, rcode: dnsmessage.RCodeSuccess},
		{name: "TXT", qname: "host.fwd.e2e.test.", qtype: dnsmessage.TypeTXT, rd: true, rcode: dnsmessage.RCodeSuccess},
	}
	for _, network := range []string{"udp", "tcp"} {
		for i, tt := range tests {
			t.Run(network+"/"+tt.name, func(t *testing.T) {
				id := uint16(0x5300 + i)
				query := stubQuery(t, id, tt.qname, tt.qtype, tt.rd, tt.edns)
				conn := dialStub(t, network, stub.Addr())
				sendStub(t, conn, query)
				got := unpackReply(t, conn)

				want := dnsmessage.Header{
					ID:                 id,
					Response:           true,
					RecursionDesired:   tt.rd,
					RecursionAvailable: true,
					RCode:              tt.rcode,
				}
				if got.Header != want {
					t.Errorf("header = %+v, want %+v", got.Header, want)
				}
				wantQ := []dnsmessage.Question{{Name: dnsmessage.MustNewName(tt.qname), Type: tt.qtype, Class: dnsmessage.ClassINET}}
				if !reflect.DeepEqual(got.Questions, wantQ) {
					t.Errorf("questions = %+v, want %+v", got.Questions, wantQ)
				}
				if len(got.Authorities) != 0 {
					t.Errorf("authorities = %+v, want none", got.Authorities)
				}
				if tt.answers {
					if len(got.Answers) != 1 {
						t.Fatalf("answers = %+v, want one A record", got.Answers)
					}
					a := got.Answers[0]
					wantH := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(tt.qname), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10, Length: 4}
					if a.Header != wantH {
						t.Errorf("answer header = %+v, want %+v", a.Header, wantH)
					}
					if body, ok := a.Body.(*dnsmessage.AResource); !ok || *body != stubA {
						t.Errorf("answer body = %+v, want %s", a.Body, mockapi.DNSStubAddress)
					}
				} else if len(got.Answers) != 0 {
					t.Errorf("answers = %+v, want none", got.Answers)
				}
				var opts int
				for _, r := range got.Additionals {
					if r.Header.Type != dnsmessage.TypeOPT {
						t.Errorf("additional %+v, want only an OPT record", r.Header)
						continue
					}
					opts++
					if size := r.Header.Class; size != 1232 {
						t.Errorf("OPT payload size = %d, want 1232", size)
					}
				}
				wantOpts := 0
				if tt.edns {
					wantOpts = 1
				}
				if opts != wantOpts {
					t.Errorf("reply carries %d OPT records, want %d", opts, wantOpts)
				}
			})
		}
	}
}

// TestDNSStub_DropGetsNoReply pins that a name whose first label is drop, in
// any case, gets no reply over UDP or TCP. The stub handles the messages of a
// socket in order, so the reply to an A query sent after the dropped one
// coming first proves no reply was sent before it, and a short wait after it
// that none comes late.
func TestDNSStub_DropGetsNoReply(t *testing.T) {
	stub := serveDNSStub(t)
	for _, network := range []string{"udp", "tcp"} {
		for _, name := range []string{"drop.fwd.e2e.test.", "DROP.example.com."} {
			t.Run(network+"/"+name, func(t *testing.T) {
				conn := dialStub(t, network, stub.Addr())
				sendStub(t, conn, stubQuery(t, 0xd0d0, name, dnsmessage.TypeA, true, false))
				sendStub(t, conn, stubQuery(t, 0xa0a0, "host.fwd.e2e.test.", dnsmessage.TypeA, true, false))
				if got := unpackReply(t, conn); got.ID != 0xa0a0 {
					t.Fatalf("first reply has ID %#04x, want the A query's 0xa0a0", got.ID)
				}
				raw, err := readStub(conn, stubSilenceWindow)
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("read after the A reply = %x, %v; want no reply until the deadline", raw, err)
				}
			})
		}
	}
}

// TestDNSStub_TCPServesSeveralQueriesOnOneConnection pins that a TCP
// connection carries one query after the other, including two sent before
// either reply is read, and gets the replies in order.
func TestDNSStub_TCPServesSeveralQueriesOnOneConnection(t *testing.T) {
	stub := serveDNSStub(t)
	conn := dialStub(t, "tcp", stub.Addr())
	sendStub(t, conn, stubQuery(t, 1, "one.fwd.e2e.test.", dnsmessage.TypeA, true, false))
	sendStub(t, conn, stubQuery(t, 2, "nx.fwd.e2e.test.", dnsmessage.TypeA, true, false))
	for _, want := range []struct {
		id    uint16
		rcode dnsmessage.RCode
	}{{1, dnsmessage.RCodeSuccess}, {2, dnsmessage.RCodeNameError}} {
		got := unpackReply(t, conn)
		if got.ID != want.id || got.RCode != want.rcode {
			t.Errorf("reply ID %d rcode %v, want ID %d rcode %v", got.ID, got.RCode, want.id, want.rcode)
		}
	}
	sendStub(t, conn, stubQuery(t, 3, "three.fwd.e2e.test.", dnsmessage.TypeAAAA, true, false))
	if got := unpackReply(t, conn); got.ID != 3 || len(got.Answers) != 0 {
		t.Errorf("third reply ID %d with %d answers, want ID 3 with none", got.ID, len(got.Answers))
	}
}

// TestDNSStub_ListenBindsOnePortForBoth pins that ListenDNS on port 0 binds
// UDP and TCP on the one port Addr reports.
func TestDNSStub_ListenBindsOnePortForBoth(t *testing.T) {
	stub := serveDNSStub(t)
	addr := stub.Addr()
	if addr.Addr() != netip.MustParseAddr("127.0.0.1") || addr.Port() == 0 {
		t.Fatalf("Addr() = %s, want 127.0.0.1 with the port the kernel chose", addr)
	}
	for _, network := range []string{"udp", "tcp"} {
		conn := dialStub(t, network, addr)
		sendStub(t, conn, stubQuery(t, 7, "host.fwd.e2e.test.", dnsmessage.TypeA, true, false))
		if got := unpackReply(t, conn); got.ID != 7 {
			t.Errorf("%s reply ID %d, want 7", network, got.ID)
		}
	}
}

// TestDNSStub_ListenFailsWhenEitherPortIsTaken pins that ListenDNS fails when
// the UDP or the TCP port is taken, and that a failed TCP bind closes the UDP
// socket that did bind.
func TestDNSStub_ListenFailsWhenEitherPortIsTaken(t *testing.T) {
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if stub, err := mockapi.ListenDNS(udp.LocalAddr().String()); err == nil {
		t.Errorf("ListenDNS on a taken UDP port = %s, want an error", stub.Addr())
	}

	tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	taken := tcp.Addr().(*net.TCPAddr).AddrPort()
	if stub, err := mockapi.ListenDNS(taken.String()); err == nil {
		t.Errorf("ListenDNS on a taken TCP port = %s, want an error", stub.Addr())
	}
	freed, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(taken))
	if err != nil {
		t.Fatalf("UDP bind of %s after the failed ListenDNS: %v, want the stub's UDP socket closed", taken, err)
	}
	_ = freed.Close()
}

// startStub binds a stub on 127.0.0.1 with a port the kernel picks and
// serves it until stop is called, which waits for Serve and returns its
// result.
func startStub(t *testing.T) (stub *mockapi.DNSStub, stop func() error) {
	t.Helper()
	stub, err := mockapi.ListenDNS("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenDNS: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- stub.Serve(ctx) }()
	return stub, func() error {
		cancel()
		// The ceiling is half the stub's 10-second idle deadline, so Serve
		// returning within it is Serve closing an open connection, not the
		// connection's deadline passing.
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after its context ended")
			return nil
		}
	}
}

// TestDNSStub_ServeClosesOpenConnections pins that Serve returns nil once its
// context ends, closing a TCP connection that waits for its next query
// rather than waiting for the idle deadline.
func TestDNSStub_ServeClosesOpenConnections(t *testing.T) {
	stub, stop := startStub(t)
	conn := dialStub(t, "tcp", stub.Addr())
	sendStub(t, conn, stubQuery(t, 9, "host.fwd.e2e.test.", dnsmessage.TypeA, true, false))
	if got := unpackReply(t, conn); got.ID != 9 {
		t.Fatalf("reply ID %d, want 9", got.ID)
	}

	if err := stop(); err != nil {
		t.Errorf("Serve = %v, want nil", err)
	}
	if raw, err := readStub(conn, stubReplyTimeout); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("read on the open connection after Serve = %x, %v; want the stub's close", raw, err)
	}
}

// TestDNSStub_ServeReleasesThePorts pins that both sockets are closed once
// Serve returns, so a new stub binds the same address. The stub sees UDP
// only: a TCP connection the stub closed would leave the port in TIME_WAIT,
// which says nothing about the listener.
func TestDNSStub_ServeReleasesThePorts(t *testing.T) {
	stub, stop := startStub(t)
	conn := dialStub(t, "udp", stub.Addr())
	sendStub(t, conn, stubQuery(t, 10, "host.fwd.e2e.test.", dnsmessage.TypeA, true, false))
	if got := unpackReply(t, conn); got.ID != 10 {
		t.Fatalf("reply ID %d, want 10", got.ID)
	}
	if err := stop(); err != nil {
		t.Errorf("Serve = %v, want nil", err)
	}

	again, err := mockapi.ListenDNS(stub.Addr().String())
	if err != nil {
		t.Fatalf("ListenDNS on %s after Serve returned: %v, want both ports free", stub.Addr(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := again.Serve(ctx); err != nil {
		t.Errorf("Serve of the stub bound again = %v, want nil", err)
	}
}
