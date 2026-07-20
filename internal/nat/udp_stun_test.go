package nat

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
)

// Compile-time interface check.
var _ STUNClient = (*UDPSTUNClient)(nil)

func TestUDPSTUNClient_ImplementsInterface(t *testing.T) {
	// Verified at compile time by the var declaration above.
	// This test exists to be explicit in test output.
	var c interface{} = &UDPSTUNClient{}
	if _, ok := c.(STUNClient); !ok {
		t.Fatal("UDPSTUNClient does not implement STUNClient")
	}
}

func TestUDPSTUNClient_Bind_Success(t *testing.T) {
	// Start a local UDP listener that simulates a STUN server.
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()
	wantIP := net.IPv4(203, 0, 113, 5)
	wantPort := 54321

	// Run the simulated STUN server in a goroutine.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		n, clientAddr, err := serverConn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 20 {
			return
		}

		// Extract the transaction ID from the incoming request (bytes 8:20).
		var txID [12]byte
		copy(txID[:], buf[8:20])

		// Build a valid STUN Binding Success Response with XOR-MAPPED-ADDRESS.
		resp := buildUDPTestResponse(txID, wantIP, wantPort)
		_, _ = serverConn.WriteTo(resp, clientAddr)
	}()

	client := &UDPSTUNClient{Timeout: 5 * time.Second}
	addr, boundPort, err := client.Bind(context.Background(), serverAddr, 0)
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}

	if !addr.IP.Equal(wantIP) {
		t.Errorf("IP = %v, want %v", addr.IP, wantIP)
	}
	if addr.Port != wantPort {
		t.Errorf("Port = %d, want %d", addr.Port, wantPort)
	}
	if boundPort == 0 {
		t.Error("boundPort = 0, want the ephemeral port the OS assigned")
	}

	// Ensure the server goroutine finishes.
	<-serverDone
}

func TestUDPSTUNClient_Bind_Timeout(t *testing.T) {
	// Listen on a port but never respond, to trigger a timeout.
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	client := &UDPSTUNClient{Timeout: 50 * time.Millisecond}
	_, _, err = client.Bind(context.Background(), serverAddr, 0)
	if err == nil {
		t.Fatal("Bind() = nil error, want timeout error")
	}
}

func TestUDPSTUNClient_Bind_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	client := &UDPSTUNClient{Timeout: 10 * time.Second}

	// A pre-cancelled context should return immediately.
	_, _, err := client.Bind(ctx, "127.0.0.1:3478", 0)
	if err == nil {
		t.Fatal("Bind() = nil error, want error from cancelled context")
	}
}

func TestUDPSTUNClient_Bind_InvalidServer(t *testing.T) {
	client := &UDPSTUNClient{Timeout: time.Second}
	_, _, err := client.Bind(context.Background(), "not-a-valid-address", 0)
	if err == nil {
		t.Fatal("Bind() = nil error, want error for invalid server address")
	}
}

// Discovery must succeed while another socket owns the WireGuard listen
// port — on a real node the kernel WireGuard socket always does, and binding
// it for STUN fails with EADDRINUSE. This drives a real UDPSTUNClient
// through Discover with the advertised port deliberately occupied.
func TestDiscover_SucceedsWhileListenPortIsHeld(t *testing.T) {
	// Stand-in for the kernel WireGuard socket.
	wgConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgConn.Close()
	wgPort := wgConn.LocalAddr().(*net.UDPAddr).Port

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr().String()

	wantIP := net.IPv4(203, 0, 113, 9)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 1024)
		n, clientAddr, err := serverConn.ReadFrom(buf)
		if err != nil || n < 20 {
			return
		}
		var txID [12]byte
		copy(txID[:], buf[8:20])
		// A mapped port unequal to the source port, so classification takes
		// the NAT path rather than the no-NAT shortcut.
		resp := buildUDPTestResponse(txID, wantIP, 23456)
		_, _ = serverConn.WriteTo(resp, clientAddr)
	}()

	client := &UDPSTUNClient{Timeout: 5 * time.Second}
	cfg := Config{
		Enabled:           true,
		STUNServers:       []string{serverAddr},
		RefreshInterval:   60 * time.Second,
		Timeout:           5 * time.Second,
		MinReportInterval: DefaultMinReportInterval,
	}
	d := NewDiscoverer(client, cfg, wgPort, discardLogger())

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v, want success from an ephemeral source port", err)
	}
	wantEndpoint := net.JoinHostPort(wantIP.String(), strconv.Itoa(wgPort))
	if result.Endpoint != wantEndpoint {
		t.Errorf("endpoint = %q, want %q (mapped IP with the held listen port)", result.Endpoint, wantEndpoint)
	}

	<-serverDone
}

// buildUDPTestResponse constructs a STUN Binding Success Response with an
// XOR-MAPPED-ADDRESS attribute for the given IP and port.
func buildUDPTestResponse(txID [12]byte, ip net.IP, port int) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		panic("buildUDPTestResponse: requires IPv4 address")
	}

	// XOR the port with the high 16 bits of the magic cookie.
	xorPort := uint16(port) ^ uint16(stunMagicCookie>>16)

	// XOR the IP with the magic cookie.
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
	xorIP := make([]byte, 4)
	for i := 0; i < 4; i++ {
		xorIP[i] = ip4[i] ^ cookieBytes[i]
	}

	// Build the XOR-MAPPED-ADDRESS attribute.
	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:2], stunAttrXORMappedAddress) // type
	binary.BigEndian.PutUint16(attr[2:4], 8)                       // length
	attr[4] = 0x00                                                  // reserved
	attr[5] = stunFamilyIPv4                                        // family
	binary.BigEndian.PutUint16(attr[6:8], xorPort)
	copy(attr[8:12], xorIP)

	// Build the 20-byte STUN header.
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], stunBindingSuccessResponse)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(header[4:8], stunMagicCookie)
	copy(header[8:20], txID[:])

	return append(header, attr...)
}
