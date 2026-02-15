package bridge

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// buildClientHello builds a minimal TLS ClientHello with the given SNI hostname.
func buildClientHello(hostname string) []byte {
	// SNI extension
	hostBytes := []byte(hostname)
	sniEntry := make([]byte, 0, 5+len(hostBytes))
	sniEntry = append(sniEntry, 0x00) // host name type
	sniEntry = append(sniEntry, byte(len(hostBytes)>>8), byte(len(hostBytes)))
	sniEntry = append(sniEntry, hostBytes...)

	sniListLen := len(sniEntry)
	sniExt := make([]byte, 0, 4+2+sniListLen)
	sniExt = append(sniExt, 0x00, 0x00) // SNI extension type
	sniExt = append(sniExt, byte((2+sniListLen)>>8), byte(2+sniListLen))
	sniExt = append(sniExt, byte(sniListLen>>8), byte(sniListLen))
	sniExt = append(sniExt, sniEntry...)

	extensionsLen := len(sniExt)
	extensions := make([]byte, 0, 2+extensionsLen)
	extensions = append(extensions, byte(extensionsLen>>8), byte(extensionsLen))
	extensions = append(extensions, sniExt...)

	// ClientHello body: version(2) + random(32) + session_id_len(1) +
	// cipher_suites_len(2) + one_suite(2) + compression_len(1) + one_method(1) + extensions
	body := make([]byte, 0, 2+32+1+2+2+1+1+len(extensions))
	body = append(body, 0x03, 0x03) // TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)       // session ID length = 0
	body = append(body, 0x00, 0x02) // cipher suites length = 2
	body = append(body, 0x00, 0xff) // one cipher suite
	body = append(body, 0x01)       // compression methods length = 1
	body = append(body, 0x00)       // null compression
	body = append(body, extensions...)

	// Handshake header: type(1) + length(3)
	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record: type(1) + version(2) + length(2) + data
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)       // handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 (record layer version)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// ---------------------------------------------------------------------------
// SNIRouter tests
// ---------------------------------------------------------------------------

func TestSNIRouter_NewSNIRouter(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	if r.Active() {
		t.Error("new router should not be active")
	}
	if routes := r.Routes(); len(routes) != 0 {
		t.Errorf("Routes() = %v, want empty", routes)
	}
	if r.ConnCount() != 0 {
		t.Errorf("ConnCount() = %d, want 0", r.ConnCount())
	}
}

func TestSNIRouter_Start_Stop(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if !r.Active() {
		t.Error("router should be active after Start")
	}

	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if r.Active() {
		t.Error("router should not be active after Stop")
	}
}

func TestSNIRouter_Stop_Idempotent(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	// Stop when not active should return nil.
	if err := r.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestSNIRouter_AddRoute_Success(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	route := SNIRoute{
		Hostname:    "example.com",
		BackendAddr: "10.0.0.1:443",
	}
	if err := r.AddRoute(route); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	routes := r.Routes()
	if len(routes) != 1 {
		t.Fatalf("len(Routes()) = %d, want 1", len(routes))
	}
	if routes[0].Hostname != "example.com" {
		t.Errorf("Hostname = %q, want %q", routes[0].Hostname, "example.com")
	}
	if routes[0].BackendAddr != "10.0.0.1:443" {
		t.Errorf("BackendAddr = %q, want %q", routes[0].BackendAddr, "10.0.0.1:443")
	}
}

func TestSNIRouter_AddRoute_NotActive(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	err := r.AddRoute(SNIRoute{
		Hostname:    "example.com",
		BackendAddr: "10.0.0.1:443",
	})
	if err == nil {
		t.Fatal("AddRoute should return error when not active")
	}
	if !strings.Contains(err.Error(), "not active") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "not active")
	}
}

func TestSNIRouter_AddRoute_EmptyHostname(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	err = r.AddRoute(SNIRoute{
		Hostname:    "",
		BackendAddr: "10.0.0.1:443",
	})
	if err == nil {
		t.Fatal("AddRoute should return error for empty hostname")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "hostname")
	}
}

func TestSNIRouter_AddRoute_EmptyBackend(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	err = r.AddRoute(SNIRoute{
		Hostname:    "example.com",
		BackendAddr: "",
	})
	if err == nil {
		t.Fatal("AddRoute should return error for empty backend")
	}
	if !strings.Contains(err.Error(), "backend") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "backend")
	}
}

func TestSNIRouter_AddRoute_Overwrite(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	// Add first route.
	if err := r.AddRoute(SNIRoute{Hostname: "example.com", BackendAddr: "10.0.0.1:443"}); err != nil {
		t.Fatalf("first AddRoute: %v", err)
	}

	// Add same hostname with different backend — should overwrite.
	if err := r.AddRoute(SNIRoute{Hostname: "example.com", BackendAddr: "10.0.0.2:8443"}); err != nil {
		t.Fatalf("second AddRoute: %v", err)
	}

	routes := r.Routes()
	if len(routes) != 1 {
		t.Fatalf("len(Routes()) = %d, want 1", len(routes))
	}
	if routes[0].BackendAddr != "10.0.0.2:8443" {
		t.Errorf("BackendAddr = %q, want %q", routes[0].BackendAddr, "10.0.0.2:8443")
	}
}

func TestSNIRouter_RemoveRoute_Success(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	if err := r.AddRoute(SNIRoute{Hostname: "example.com", BackendAddr: "10.0.0.1:443"}); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	if err := r.RemoveRoute("example.com"); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}

	routes := r.Routes()
	if len(routes) != 0 {
		t.Errorf("Routes() = %v, want empty", routes)
	}
}

func TestSNIRouter_RemoveRoute_NotFound(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	// Remove non-existent route should return nil (idempotent).
	if err := r.RemoveRoute("nonexistent.com"); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}
}

func TestSNIRouter_Routes_Sorted(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	// Add routes in non-sorted order.
	for _, h := range []string{"charlie.com", "alpha.com", "bravo.com"} {
		if err := r.AddRoute(SNIRoute{Hostname: h, BackendAddr: "10.0.0.1:443"}); err != nil {
			t.Fatalf("AddRoute(%q): %v", h, err)
		}
	}

	routes := r.Routes()
	if len(routes) != 3 {
		t.Fatalf("len(Routes()) = %d, want 3", len(routes))
	}
	want := []string{"alpha.com", "bravo.com", "charlie.com"}
	for i, r := range routes {
		if r.Hostname != want[i] {
			t.Errorf("Routes()[%d].Hostname = %q, want %q", i, r.Hostname, want[i])
		}
	}
}

func TestSNIRouter_ExtractSNI_Valid(t *testing.T) {
	hello := buildClientHello("example.com")

	got := extractSNI(hello)
	if got != "example.com" {
		t.Errorf("extractSNI = %q, want %q", got, "example.com")
	}
}

func TestSNIRouter_ExtractSNI_Invalid(t *testing.T) {
	// Garbage data should return empty string.
	got := extractSNI([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02})
	if got != "" {
		t.Errorf("extractSNI(garbage) = %q, want empty", got)
	}
}

func TestSNIRouter_ExtractSNI_TooShort(t *testing.T) {
	// Truncated TLS record header (only 3 bytes instead of 5+).
	got := extractSNI([]byte{0x16, 0x03, 0x01})
	if got != "" {
		t.Errorf("extractSNI(truncated) = %q, want empty", got)
	}
}

func TestSNIRouter_HandleConnection_NoRoute(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	if err := r.Start(ln); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	// No routes added — connection for "unknown.com" should be closed.

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	hello := buildClientHello("unknown.com")
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// The router should close the connection. Read should get EOF.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected read error (EOF or closed) when no route matches")
	}
}

func TestSNIRouter_HandleConnection_Success(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	// Start a TCP backend that reads a fixed amount, writes a response, then closes.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()

	hello := buildClientHello("example.com")
	payload := []byte("extra payload data")
	expectedLen := len(hello) + len(payload)

	backendPayload := "hello from backend"
	var backendReceived []byte
	var backendMu sync.Mutex
	backendDone := make(chan struct{})

	go func() {
		defer close(backendDone)
		bConn, acceptErr := backendLn.Accept()
		if acceptErr != nil {
			return
		}
		defer bConn.Close()

		// Read the exact expected number of bytes from the client.
		buf := make([]byte, expectedLen)
		n, _ := io.ReadFull(bConn, buf)
		backendMu.Lock()
		backendReceived = buf[:n]
		backendMu.Unlock()

		// Write response back to client, then close write side.
		_, _ = bConn.Write([]byte(backendPayload))
	}()

	// Start the SNI router.
	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("router listen: %v", err)
	}
	if err := r.Start(routerLn); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	// Add a route for "example.com" pointing to the backend.
	if err := r.AddRoute(SNIRoute{
		Hostname:    "example.com",
		BackendAddr: backendLn.Addr().String(),
	}); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	// Dial the SNI router and send a ClientHello + payload.
	clientConn, err := net.Dial("tcp", routerLn.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write(hello); err != nil {
		t.Fatalf("Write hello: %v", err)
	}
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("Write payload: %v", err)
	}

	// Read response from backend via the SNI router.
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, len(backendPayload))
	n, err := io.ReadFull(clientConn, resp)
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	// Wait for backend goroutine to finish.
	<-backendDone

	// Verify the backend received the full ClientHello + payload.
	backendMu.Lock()
	received := backendReceived
	backendMu.Unlock()

	expectedReceived := append(hello, payload...)
	if len(received) != len(expectedReceived) {
		t.Errorf("backend received %d bytes, want %d", len(received), len(expectedReceived))
	}

	// Verify client received the backend response.
	if string(resp[:n]) != backendPayload {
		t.Errorf("client received %q, want %q", string(resp[:n]), backendPayload)
	}
}

func TestSNIRouter_ConnCount(t *testing.T) {
	r := NewSNIRouter(5*time.Second, discardLogger())

	// Start a backend that holds the connection open until signaled.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()

	backendReady := make(chan struct{})
	backendRelease := make(chan struct{})
	go func() {
		bConn, acceptErr := backendLn.Accept()
		if acceptErr != nil {
			return
		}
		close(backendReady)
		<-backendRelease
		bConn.Close()
	}()

	// Start the SNI router.
	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("router listen: %v", err)
	}
	if err := r.Start(routerLn); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Stop() }()

	if err := r.AddRoute(SNIRoute{
		Hostname:    "example.com",
		BackendAddr: backendLn.Addr().String(),
	}); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	// Dial the router.
	clientConn, err := net.Dial("tcp", routerLn.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	hello := buildClientHello("example.com")
	if _, err := clientConn.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Wait for backend to accept the forwarded connection.
	<-backendReady

	// Give the router a moment to establish the proxy.
	time.Sleep(50 * time.Millisecond)

	if r.ConnCount() < 1 {
		t.Errorf("ConnCount() = %d, want >= 1", r.ConnCount())
	}

	// Release backend and close client to let the connection finish.
	close(backendRelease)
	clientConn.Close()

	// Wait a moment for the proxy goroutine to decrement.
	time.Sleep(100 * time.Millisecond)

	if r.ConnCount() != 0 {
		t.Errorf("ConnCount() after close = %d, want 0", r.ConnCount())
	}
}
