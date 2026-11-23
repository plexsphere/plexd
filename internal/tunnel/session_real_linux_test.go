//go:build linux

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/nettest"
)

// sessionBanner is what the target of TestSession_RealAcceptsOnlyMeshAndLocal
// writes to each connection it accepts before it closes the connection.
const sessionBanner = "plexd-session-banner\n"

// startBannerTarget opens a TCP listener on 127.0.0.1 in the test's own
// namespace that writes sessionBanner to each connection it accepts and
// closes it, and returns the listener's port. The test's cleanup closes the
// listener and waits until its accept loop ended.
func startBannerTarget(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the target on 127.0.0.1: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, sessionBanner)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().(*net.TCPAddr).Port
}

// dialBanner dials addr from inside namespace n and reads until EOF, with a
// deadline of 3 s, and returns what it read and the error of the dial or the
// read. from is the client's source address; empty leaves the choice to the
// kernel.
func dialBanner(t *testing.T, n *nettest.Netns, from, addr string) (string, error) {
	t.Helper()
	var got []byte
	var connErr error
	if err := n.Do(func() error {
		d := net.Dialer{Timeout: 3 * time.Second}
		if from != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
		}
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			connErr = err
			return nil
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			connErr = err
			return nil
		}
		got, connErr = io.ReadAll(conn)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return string(got), connErr
}

// waitForwardEnded waits up to 3 s until s forwards no connection. A session
// forwards one connection at a time and closes every other it accepts
// meanwhile, so the next client dials only once the last forward ended.
func waitForwardEnded(t *testing.T, s *Session) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		ended := s.conn == nil && s.copyDone == nil
		s.mu.Unlock()
		if ended {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %s still forwards a connection after 3 s, want the forward ended", s.SessionID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSession_RealAcceptsOnlyMeshAndLocal proves on a real kernel that a tcp
// session listener bound to the mesh interface takes the mesh and the node
// and refuses another network. It runs in the namespaces nettest.NewMeshLAN
// builds: the node N holds the mesh IP 10.98.0.1 on nt-mesh, a veth to the
// mesh peer P (10.98.0.2), and 192.0.2.1 on nt-lan, a veth to a host L on
// another network. L routes the mesh IP through N and holds the mesh address
// 10.98.0.3 on its loopback, so what L sends to the mesh IP arrives on
// nt-lan. The session listens on the mesh IP in N and forwards to a target in
// the test's own namespace that writes a banner to each connection, so a
// client that reads the banner went through the listener.
//
// A listener bound to the mesh IP alone hands L's connection to the forward,
// which the first subtest shows as the control: Linux delivers a segment for
// a local address on whichever interface it arrives. Bound to nt-mesh, the
// listener still takes P over the mesh interface, and the kernel refuses L
// with a reset, from L's own address and from the mesh source alike. A client
// in N that dials the mesh IP still reads the banner: the kernel picks the
// mesh IP as its source and attributes a local packet for that address to
// nt-mesh, the device that owns it. A client in N that sends from 127.0.0.1
// or from another address of N would not connect, because the bound socket
// routes its answer out of nt-mesh; the test dials no such client.
func TestSession_RealAcceptsOnlyMeshAndLocal(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_LINKS") != "1" {
		t.Skip("set PLEXD_TEST_REAL_LINKS=1 to run against real network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}

	lan := nettest.NewMeshLAN(t)
	// Session.forward dials its target from a runtime thread outside N, so the
	// target listens in the test's own namespace.
	targetPort := startBannerTarget(t)

	// start opens a session's listener on the mesh IP inside N, bound to
	// iface; the test's cleanup closes it.
	start := func(t *testing.T, iface string) (*Session, string) {
		t.Helper()
		s := NewSession("sess-real", "127.0.0.1", targetPort, nettest.NodeMeshIP, time.Now().Add(5*time.Minute), discardLogger())
		s.MeshInterface = iface
		var addr string
		if err := lan.Node.Do(func() error {
			var err error
			addr, err = s.Start(context.Background())
			return err
		}); err != nil {
			t.Fatalf("namespace %s: start the session with MeshInterface %q: %v", lan.Node.Name, iface, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s, addr
	}

	t.Run("a listener bound to the mesh IP alone accepts the other network", func(t *testing.T) {
		s, addr := start(t, "")
		got, err := dialBanner(t, lan.LANHost, nettest.LANHostIP, addr)
		if err != nil || got != sessionBanner {
			t.Fatalf("L's connection from %s through %s got %q, %v, want the banner: the control shows nothing, so the next subtest would prove nothing", nettest.LANHostIP, nettest.LANLink, got, err)
		}
		waitForwardEnded(t, s)
	})

	t.Run("a listener bound to the mesh interface accepts the mesh and the node only", func(t *testing.T) {
		s, addr := start(t, nettest.MeshLink)

		got, err := dialBanner(t, lan.Peer, nettest.PeerMeshIP, addr)
		if err != nil || got != sessionBanner {
			t.Errorf("P's connection over %s got %q, %v, want the banner", nettest.MeshLink, got, err)
		} else {
			waitForwardEnded(t, s)
		}

		for _, from := range []string{nettest.LANHostIP, nettest.LANMeshSource} {
			got, err := dialBanner(t, lan.LANHost, from, addr)
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Errorf("L's connection from %s through %s got %q, %v, want ECONNREFUSED: the listener is bound to %s", from, nettest.LANLink, got, err, nettest.MeshLink)
			}
			if err == nil {
				// The listener took L, so the next client waits for that
				// forward to end.
				waitForwardEnded(t, s)
			}
		}

		got, err = dialBanner(t, lan.Node, "", addr)
		if err != nil || got != sessionBanner {
			t.Errorf("a client in N that dials %s from the default source got %q, %v, want the banner", addr, got, err)
		} else {
			waitForwardEnded(t, s)
		}
	})
}
