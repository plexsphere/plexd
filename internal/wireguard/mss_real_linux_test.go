//go:build linux

package wireguard

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/plexsphere/plexd/internal/nettest"
)

// tcpSendMSS returns the send MSS the kernel keeps for the TCP connection
// conn, the field tcpi_snd_mss of TCP_INFO.
func tcpSendMSS(t *testing.T, conn net.Conn) uint32 {
	t.Helper()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatalf("raw connection of %s to %s: %v", conn.LocalAddr(), conn.RemoteAddr(), err)
	}
	var (
		info    *unix.TCPInfo
		infoErr error
	)
	if err := raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		t.Fatalf("control the socket of %s to %s: %v", conn.LocalAddr(), conn.RemoteAddr(), err)
	}
	if infoErr != nil {
		t.Fatalf("read TCP_INFO of %s to %s: %v", conn.LocalAddr(), conn.RemoteAddr(), infoErr)
	}
	return info.Snd_mss
}

// connectSendMSS opens one TCP connection from clientIP in the namespace
// client to a listener on serverIP in the namespace server and returns the
// send MSS of the client's socket and of the socket the listener accepted.
// The listener and the client are created inside their namespaces, so their
// sockets belong there, and the accepted socket belongs to the listener's.
// Each socket is closed before the function returns.
func connectSendMSS(t *testing.T, client *nettest.Netns, clientIP string, server *nettest.Netns, serverIP string) (dialed, accepted uint32) {
	t.Helper()
	var ln net.Listener
	if err := server.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", net.JoinHostPort(serverIP, "0"))
		return err
	}); err != nil {
		t.Fatalf("namespace %s: listen on %s: %v", server.Name, serverIP, err)
	}
	defer ln.Close()

	var conn net.Conn
	if err := client.Do(func() error {
		d := net.Dialer{
			Timeout:   3 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientIP)},
		}
		var err error
		conn, err = d.Dial("tcp", ln.Addr().String())
		return err
	}); err != nil {
		t.Fatalf("namespace %s: dial %s from %s: %v", client.Name, ln.Addr(), clientIP, err)
	}
	defer conn.Close()

	// The kernel completes the handshake without Accept, so the accept after
	// the dial takes a connection that is already established.
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("namespace %s: set the deadline of the listener on %s: %v", server.Name, ln.Addr(), err)
	}
	acc, err := ln.Accept()
	if err != nil {
		t.Fatalf("namespace %s: accept the connection from %s on %s: %v", server.Name, clientIP, ln.Addr(), err)
	}
	defer acc.Close()

	return tcpSendMSS(t, conn), tcpSendMSS(t, acc)
}

// TestNetlinkController_RealClampMSS proves on a real kernel that the rules
// ClampMSS writes lower the MSS of forwarded SYNs in both directions, that a
// second call replaces the first value, and that UnclampMSS removes them. It
// runs in the namespaces nettest.NewMeshLAN builds: the node N holds
// 10.98.0.1 on nt-mesh, a veth to the mesh peer P (10.98.0.2), and
// 192.0.2.1 on nt-lan, a veth to the host L (192.0.2.2). N forwards, L routes
// P's mesh IP through N and P routes L's network through N, so the
// connections between L and P cross N and the clamp sits on nt-mesh in N, as
// it sits on plexd0 on a node.
//
// Both veths carry 1500 bytes, so without the clamp each end announces and
// keeps an MSS of 1460. L and P send no TCP timestamps, so a socket's send
// MSS is the MSS its peer announced and not 12 bytes less. Each check opens
// one connection from L to a listener in P and one from P to a listener in
// L and reads TCP_INFO on all four sockets. A SYN from L leaves nt-mesh and
// one from P enters it, and so do the SYN-ACKs, so the four sockets report
// the clamp only when both rules lower what they see.
//
// A second ClampMSS has to replace the rules and not add two more, and the
// first UnclampMSS has to remove the table, after which connections keep
// 1460 again; a second UnclampMSS finds no table and returns nil. The rules
// and tables are read with the nftables library inside N.
//
// The namespaces are created for the test alone. The gate is a variable
// besides the effective uid, as for TestNetlinkController_RealReplaceAddress,
// and CI runs it in the step "Run privileged Linux tests".
func TestNetlinkController_RealClampMSS(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to write nftables rules in a test network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces and nftables rules")
	}

	lan := nettest.NewMeshLAN(t)
	lan.Node.Sysctl(t, "ip_forward", "1")
	lan.LANHost.Route(t, nettest.HostLink, nettest.PeerMeshIP+"/32", nettest.NodeLANIP)
	lan.Peer.Route(t, nettest.PeerLink, "192.0.2.0/24", nettest.NodeMeshIP)
	lan.LANHost.Sysctl(t, "tcp_timestamps", "0")
	lan.Peer.Sysctl(t, "tcp_timestamps", "0")

	c := NewNetlinkController(discardLogger())

	// inNode runs fn inside N, so the nftables sockets ClampMSS, UnclampMSS
	// and the reads open belong to N.
	inNode := func(what string, fn func() error) {
		t.Helper()
		if err := lan.Node.Do(fn); err != nil {
			t.Fatalf("namespace %s: %s: %v", lan.Node.Name, what, err)
		}
	}

	// checkSendMSS opens a connection in each direction and requires want
	// on all four sockets.
	checkSendMSS := func(when string, want uint32) {
		t.Helper()
		for _, d := range []struct {
			name     string
			client   *nettest.Netns
			clientIP string
			server   *nettest.Netns
			serverIP string
		}{
			{name: "L to P", client: lan.LANHost, clientIP: nettest.LANHostIP, server: lan.Peer, serverIP: nettest.PeerMeshIP},
			{name: "P to L", client: lan.Peer, clientIP: nettest.PeerMeshIP, server: lan.LANHost, serverIP: nettest.LANHostIP},
		} {
			dialed, accepted := connectSendMSS(t, d.client, d.clientIP, d.server, d.serverIP)
			t.Logf("%s: the connection %s reports a send MSS of %d on the client and %d on the accepted socket", when, d.name, dialed, accepted)
			if dialed != want {
				t.Errorf("%s: the client socket of the connection %s reports a send MSS of %d, want %d", when, d.name, dialed, want)
			}
			if accepted != want {
				t.Errorf("%s: the accepted socket of the connection %s reports a send MSS of %d, want %d", when, d.name, accepted, want)
			}
		}
	}

	// mssTable returns the table ip plexd-mss in N, or nil when N has none.
	mssTable := func(conn *nftables.Conn) (*nftables.Table, error) {
		tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
		if err != nil {
			return nil, err
		}
		for _, table := range tables {
			if table.Name == mssTableName {
				return table, nil
			}
		}
		return nil, nil
	}

	// checkRules requires the chain of ip plexd-mss in N to hold exactly two
	// rules, each of which sets mss, and logs their counters.
	checkRules := func(when string, mss uint16) {
		t.Helper()
		var rules []*nftables.Rule
		var found bool
		inNode("read the rules of ip "+mssTableName, func() error {
			conn, err := nftables.New()
			if err != nil {
				return err
			}
			table, err := mssTable(conn)
			if err != nil || table == nil {
				return err
			}
			found = true
			rules, err = conn.GetRules(table, &nftables.Chain{Name: mssChainName, Table: table})
			return err
		})
		if !found {
			t.Fatalf("%s: namespace %s holds no table ip %s", when, lan.Node.Name, mssTableName)
		}
		if len(rules) != 2 {
			t.Errorf("%s: the chain %s of ip %s holds %d rules, want 2", when, mssChainName, mssTableName, len(rules))
		}
		want := []byte{byte(mss >> 8), byte(mss)}
		for i, r := range rules {
			var sets bool
			var packets uint64
			for _, e := range r.Exprs {
				switch e := e.(type) {
				case *expr.Immediate:
					sets = bytes.Equal(e.Data, want)
				case *expr.Counter:
					packets = e.Packets
				}
			}
			if !sets {
				t.Errorf("%s: rule %d of the chain %s does not set the MSS %d", when, i, mssChainName, mss)
			}
			t.Logf("%s: rule %d of the chain %s lowered %d SYNs", when, i, mssChainName, packets)
		}
	}

	checkSendMSS("before the clamp", 1460)

	inNode("clamp the mss on "+nettest.MeshLink+" to 1200", func() error { return c.ClampMSS(nettest.MeshLink, 1200) })
	checkSendMSS("with the clamp at 1200", 1200)
	checkRules("with the clamp at 1200", 1200)

	inNode("clamp the mss on "+nettest.MeshLink+" to 1000", func() error { return c.ClampMSS(nettest.MeshLink, 1000) })
	checkSendMSS("after a second clamp at 1000", 1000)
	checkRules("after a second clamp at 1000", 1000)

	inNode("remove the clamp on "+nettest.MeshLink, func() error { return c.UnclampMSS(nettest.MeshLink) })
	var left bool
	inNode("list the tables", func() error {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		table, err := mssTable(conn)
		left = table != nil
		return err
	})
	if left {
		t.Errorf("after UnclampMSS: namespace %s still holds the table ip %s", lan.Node.Name, mssTableName)
	}
	checkSendMSS("after UnclampMSS", 1460)

	inNode("remove the clamp on "+nettest.MeshLink+" again", func() error { return c.UnclampMSS(nettest.MeshLink) })
}
