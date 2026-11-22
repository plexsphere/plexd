//go:build windows

package mockapi_test

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestDNSStub_ListenPortZeroAtReservedTCPPorts pins that ListenDNS on port 0
// finds a port while the kernel's UDP pick sits in a run of ports reserved
// for TCP. The windows-latest runner boots with such runs of 100 and 200
// ports, and ten tries on ten neighbouring ports all failed there with
// WSAEACCES, "An attempt was made to access a socket in a way forbidden by
// its access permissions."
//
// The test makes a persistent TCP port reservation of 100 dynamic ports that
// both protocols could bind before. A TCP bind of one then fails with
// WSAEACCES, and the kernel no longer hands those numbers out for TCP on
// port 0, while it still does for UDP. Windows hands the dynamic ports out
// for port 0 one after the other, to every process alike, so the test takes
// UDP ports until the pick has reached the reserved ones.
//
// It reserves ports of the host, and a reservation outlives a killed test
// and a reboot, so it needs PLEXD_TEST_REAL_PORT_RESERVATION=1 on top of
// Administrator. It moves the kernel's UDP pick, which every process of the
// host shares, so no other test may run beside it: CI gives it a step of
// its own.
func TestDNSStub_ListenPortZeroAtReservedTCPPorts(t *testing.T) {
	if os.Getenv("PLEXD_TEST_REAL_PORT_RESERVATION") != "1" {
		t.Skip("set PLEXD_TEST_REAL_PORT_RESERVATION=1 to reserve TCP ports on this host")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("reserving TCP ports needs Administrator")
	}
	const reserved = 100
	loopback := net.IPv4(127, 0, 0, 1)
	udpPick := func() int {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback})
		if err != nil {
			t.Fatalf("ListenUDP on port 0: %v", err)
		}
		defer udp.Close()
		return udp.LocalAddr().(*net.UDPAddr).Port
	}
	free := func(first int) bool {
		for port := first; port < first+reserved; port++ {
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
	first := 56000
	for !free(first) {
		if first += 2 * reserved; first >= 64000 {
			t.Fatalf("no %d neighbouring ports between 56000 and 64000 are free for UDP and TCP", reserved)
		}
	}

	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	// Both calls take the first port in network byte order.
	start := uintptr(uint16(first)<<8 | uint16(first)>>8)
	var token uint64
	if rc, _, _ := iphlpapi.NewProc("CreatePersistentTcpPortReservation").Call(start, reserved, uintptr(unsafe.Pointer(&token))); rc != 0 {
		t.Fatalf("CreatePersistentTcpPortReservation(%d, %d) = %v", first, reserved, syscall.Errno(rc))
	}
	t.Cleanup(func() {
		if rc, _, _ := iphlpapi.NewProc("DeletePersistentTcpPortReservation").Call(start, reserved); rc != 0 {
			t.Errorf("DeletePersistentTcpPortReservation(%d, %d) = %v", first, reserved, syscall.Errno(rc))
		}
	})
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: loopback, Port: first})
	if !errors.Is(err, windows.WSAEACCES) {
		if err == nil {
			_ = tcp.Close()
		}
		t.Fatalf("ListenTCP on the reserved port %d = %v, want an error wrapping %v", first, err, error(windows.WSAEACCES))
	}

	// Stop with 20 reserved ports or more ahead, twice what ListenDNS tries.
	wound := false
	for range 2 * 16384 {
		if port := udpPick(); port >= first-1 && port < first+reserved-20 {
			wound = true
			break
		}
	}
	if !wound {
		t.Fatalf("the kernel's UDP pick never reached the reserved ports %d to %d", first, first+reserved-1)
	}

	// serveDNSStub asks ListenDNS for 127.0.0.1:0 and fails the test when
	// that fails.
	serveDNSStub(t)
	// The pick still sits in the reserved ports, which is what shows that
	// ListenDNS was handed one of them.
	if port := udpPick(); port < first || port >= first+reserved {
		t.Errorf("the kernel's UDP pick is at %d after ListenDNS, outside the reserved ports %d to %d: ListenDNS met none of them",
			port, first, first+reserved-1)
	}
}
