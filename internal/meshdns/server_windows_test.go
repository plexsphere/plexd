//go:build windows

package meshdns

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errAddrInUse is the errno a bind fails with when another socket holds the
// address and port. Winsock reports WSAEADDRINUSE, which Go returns as a
// plain syscall.Errno that does not match syscall.EADDRINUSE.
var errAddrInUse error = windows.WSAEADDRINUSE

// errConnRefused is the errno a TCP dial fails with when nothing listens on
// the port. Winsock reports WSAECONNREFUSED, which Go returns as a plain
// syscall.Errno that does not match syscall.ECONNREFUSED.
var errConnRefused error = windows.WSAECONNREFUSED

var (
	modIphlpapi                            = windows.NewLazySystemDLL("iphlpapi.dll")
	procCreatePersistentTCPPortReservation = modIphlpapi.NewProc("CreatePersistentTcpPortReservation")
	procDeletePersistentTCPPortReservation = modIphlpapi.NewProc("DeletePersistentTcpPortReservation")
)

// reservedPorts is how many neighbouring ports reserveTCPPorts reserves. The
// windows-latest runner boots with reservations of that size, two side by
// side for TCP and two for UDP on most boots.
const reservedPorts = 100

// reserveTCPPorts makes a persistent TCP port reservation of reservedPorts
// neighbouring dynamic ports and returns the first of them. The test's
// cleanup deletes it. A bind of a reserved port for TCP fails with WSAEACCES
// for everyone but the holder of the reservation's token, and the kernel no
// longer hands those numbers out for TCP on port 0, while it still does for
// UDP. Both protocols could bind every one of the ports before, so the
// kernel's UDP pick walks through all of them.
func reserveTCPPorts(t *testing.T) int {
	t.Helper()
	loopback := net.IPv4(127, 0, 0, 1)
	free := func(first int) bool {
		for port := first; port < first+reservedPorts; port++ {
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback, Port: port})
			if err != nil {
				return false
			}
			_ = udp.Close()
			tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: loopback, Port: port})
			if err != nil {
				return false
			}
			_ = tcp.Close()
		}
		return true
	}
	// Both calls take the first port in network byte order.
	htons := func(port int) uintptr { return uintptr(uint16(port)<<8 | uint16(port)>>8) }
	for first := 56000; first < 64000; first += 2 * reservedPorts {
		if !free(first) {
			continue
		}
		var token uint64
		if rc, _, _ := procCreatePersistentTCPPortReservation.Call(htons(first), reservedPorts, uintptr(unsafe.Pointer(&token))); rc != 0 {
			t.Fatalf("CreatePersistentTcpPortReservation(%d, %d) = %v", first, reservedPorts, syscall.Errno(rc))
		}
		t.Cleanup(func() {
			if rc, _, _ := procDeletePersistentTCPPortReservation.Call(htons(first), reservedPorts); rc != 0 {
				t.Errorf("DeletePersistentTcpPortReservation(%d, %d) = %v", first, reservedPorts, syscall.Errno(rc))
			}
		})
		tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: loopback, Port: first})
		if !errors.Is(err, windows.WSAEACCES) {
			if err == nil {
				_ = tcp.Close()
			}
			t.Fatalf("ListenTCP on the reserved port %d = %v, want an error wrapping %v", first, err, error(windows.WSAEACCES))
		}
		return first
	}
	t.Fatalf("no %d neighbouring ports between 56000 and 64000 are free for UDP and TCP", reservedPorts)
	return 0
}

// udpPick returns the port the kernel hands out next for UDP on port 0.
func udpPick(t *testing.T) int {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP on port 0: %v", err)
	}
	defer func() { _ = udp.Close() }()
	return udp.LocalAddr().(*net.UDPAddr).Port
}

// windUDPPick takes UDP ports from the kernel until its pick has reached the
// reserved ports that start at first. Windows hands the dynamic ports out
// for port 0 one after the other, to every process alike, so the next UDP
// binds on port 0 get reserved ports, 2*listenAttempts of them at least.
func windUDPPick(t *testing.T, first int) {
	t.Helper()
	// Two laps of the 16384 dynamic ports.
	for range 2 * 16384 {
		if port := udpPick(t); port >= first-1 && port < first+reservedPorts-2*listenAttempts {
			return
		}
	}
	t.Fatalf("the kernel's UDP pick never reached the reserved ports %d to %d", first, first+reservedPorts-1)
}

// TestServer_ListenPortZeroAtReservedTCPPorts pins that Listen on port 0 and
// the fake resolver of the tests find a port while the kernel's UDP pick
// sits in a run of ports reserved for TCP. The windows-latest runner boots
// with such runs, and ten tries on ten neighbouring ports all failed there
// with "listen tcp 127.0.0.1:49851: bind: An attempt was made to access a
// socket in a way forbidden by its access permissions."
//
// It reserves ports of the host, and a reservation outlives a killed test
// and a reboot, so it needs PLEXD_TEST_REAL_PORT_RESERVATION=1 on top of
// Administrator. It moves the kernel's UDP pick, which every process of the
// host shares, so no other test may run beside it: CI gives it a step of
// its own.
func TestServer_ListenPortZeroAtReservedTCPPorts(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_PORT_RESERVATION") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PORT_RESERVATION=1 to reserve TCP ports on this host")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("reserving TCP ports needs Administrator")
	}
	first := reserveTCPPorts(t)
	// checkMet fails the test unless the kernel's UDP pick still sits in the
	// reserved ports, which is what shows that the bind before it was handed
	// one of them.
	checkMet := func(t *testing.T) {
		t.Helper()
		if port := udpPick(t); port < first || port >= first+reservedPorts {
			t.Errorf("the kernel's UDP pick is at %d after the bind, outside the reserved ports %d to %d: the bind met none of them",
				port, first, first+reservedPorts-1)
		}
	}

	t.Run("Server.Listen", func(t *testing.T) {
		windUDPPick(t, first)
		s := newTestServer()
		if err := s.Listen(); err != nil {
			t.Fatalf("Listen() = %v, want nil", err)
		}
		defer serve(t, s)()
		checkMet(t)
	})

	t.Run("fake resolver", func(t *testing.T) {
		windUDPPick(t, first)
		newFakeResolver(t, func([]byte) [][]byte { return nil })
		checkMet(t)
	})
}
