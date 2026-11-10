package api

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	fallbackWarn = "control plane name does not resolve, dialing its last address"
	resolvesInfo = "control plane name resolves again"
)

// capturedLog is one line a logCapture recorded.
type capturedLog struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

// logCapture is a slog.Handler that records every line with its attributes
// as strings.
type logCapture struct {
	mu      sync.Mutex
	entries []capturedLog
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]string, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Resolve().String()
		return true
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, capturedLog{level: r.Level, msg: r.Message, attrs: attrs})
	return nil
}

// WithAttrs returns c unchanged: the dialer adds no attributes through With.
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }

// WithGroup returns c unchanged: the dialer logs no groups.
func (c *logCapture) WithGroup(string) slog.Handler { return c }

// find returns the lines that say msg, at any level.
func (c *logCapture) find(msg string) []capturedLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []capturedLog
	for _, e := range c.entries {
		if e.msg == msg {
			out = append(out, e)
		}
	}
	return out
}

// count returns the number of lines recorded so far.
func (c *logCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// stubAddr is a net.Addr that prints as the string it holds.
type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }

// stubConn is a net.Conn that answers RemoteAddr only, the one method the
// dialer calls.
type stubConn struct {
	net.Conn
	remote net.Addr
}

func (c *stubConn) RemoteAddr() net.Addr { return c.remote }

// connFrom returns a stubConn whose remote end is addrPort.
func connFrom(addrPort string) *stubConn {
	return &stubConn{remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addrPort))}
}

// dialResult is what scriptedDial answers for one address.
type dialResult struct {
	conn net.Conn
	err  error
}

// scriptedDial is a dial function that answers each address from a table
// and records every address it is asked to dial.
type scriptedDial struct {
	mu      sync.Mutex
	answers map[string]dialResult
	calls   []string
}

func (s *scriptedDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, address)
	r, ok := s.answers[address]
	if !ok {
		return nil, fmt.Errorf("scriptedDial: no answer for %s", address)
	}
	return r.conn, r.err
}

// set makes a dial of address return conn and err.
func (s *scriptedDial) set(address string, conn net.Conn, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[address] = dialResult{conn: conn, err: err}
}

// dialed returns the addresses dialed so far, in order.
func (s *scriptedDial) dialed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// newScriptedFallbackDialer returns a fallbackDialer over a scriptedDial and
// the handler its logger writes to.
func newScriptedFallbackDialer() (*fallbackDialer, *scriptedDial, *logCapture) {
	sd := &scriptedDial{answers: make(map[string]dialResult)}
	logs := &logCapture{}
	return newFallbackDialer(sd.dial, slog.New(logs)), sd, logs
}

// storedAddr returns the address d holds for host.
func storedAddr(d *fallbackDialer, host string) (netip.Addr, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	addr, ok := d.last[host]
	return addr, ok
}

// storedCount returns the number of hosts d holds an address for.
func storedCount(d *fallbackDialer) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.last)
}

// notResolving returns the error net.Dialer gives for a name that does not
// resolve.
func notResolving(host string) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{
		Err: "no such host", Name: host, IsNotFound: true,
	}}
}

// refused returns an error shaped like the one net.Dialer gives for a refused
// connection. It is built here from syscall.ECONNREFUSED, so the tests compare
// the value itself and depend on no platform's errno.
func refused() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func TestFallbackDialer_StoresTheAddressOfAName(t *testing.T) {
	d, sd, logs := newScriptedFallbackDialer()
	ctx := context.Background()

	first := connFrom("192.0.2.10:443")
	sd.set("cp.example.com:443", first, nil)
	got, err := d.DialContext(ctx, "tcp", "cp.example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if got != first {
		t.Fatalf("DialContext returned %v, want the ordinary connection", got)
	}
	if addr, ok := storedAddr(d, "cp.example.com"); !ok || addr != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("stored address = %v, %v; want 192.0.2.10, true", addr, ok)
	}

	// A later dial replaces the address, and an IPv4-mapped one is stored
	// unmapped.
	second := &stubConn{remote: stubAddr("[::ffff:192.0.2.11]:443")}
	sd.set("cp.example.com:443", second, nil)
	got, err = d.DialContext(ctx, "tcp", "cp.example.com:443")
	if err != nil {
		t.Fatalf("second DialContext: %v", err)
	}
	if got != second {
		t.Fatalf("second DialContext returned %v, want the ordinary connection", got)
	}
	if addr, ok := storedAddr(d, "cp.example.com"); !ok || addr != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("stored address = %v, %v; want 192.0.2.11, true", addr, ok)
	}
	if n := storedCount(d); n != 1 {
		t.Errorf("stored hosts = %d, want 1", n)
	}
	if n := logs.count(); n != 0 {
		t.Errorf("logged %d lines, want none", n)
	}
}

func TestFallbackDialer_StoresNothingForAnIPLiteral(t *testing.T) {
	d, sd, _ := newScriptedFallbackDialer()

	for _, address := range []string{"192.0.2.10:443", "[2001:db8::1]:443"} {
		conn := connFrom(address)
		sd.set(address, conn, nil)
		got, err := d.DialContext(context.Background(), "tcp", address)
		if err != nil {
			t.Fatalf("DialContext(%s): %v", address, err)
		}
		if got != conn {
			t.Fatalf("DialContext(%s) returned %v, want the ordinary connection", address, got)
		}
	}
	if n := storedCount(d); n != 0 {
		t.Errorf("stored hosts = %d, want 0 for IP literals", n)
	}
}

func TestFallbackDialer_DialsTheLastAddressWhenTheNameDoesNotResolve(t *testing.T) {
	d, sd, logs := newScriptedFallbackDialer()
	ctx := context.Background()

	sd.set("cp.example.com:443", connFrom("192.0.2.10:443"), nil)
	if _, err := d.DialContext(ctx, "tcp", "cp.example.com:443"); err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	// The fallback dials the stored address with the request's port, which
	// differs from the port the address was stored with.
	dnsErr := notResolving("cp.example.com")
	fallbackConn := connFrom("192.0.2.10:8443")
	sd.set("cp.example.com:8443", nil, dnsErr)
	sd.set("192.0.2.10:8443", fallbackConn, nil)
	for i := range 2 {
		got, err := d.DialContext(ctx, "tcp", "cp.example.com:8443")
		if err != nil {
			t.Fatalf("fallback %d: DialContext: %v", i+1, err)
		}
		if got != fallbackConn {
			t.Fatalf("fallback %d: DialContext returned %v, want the fallback connection", i+1, got)
		}
	}
	wantCalls := []string{
		"cp.example.com:443",
		"cp.example.com:8443", "192.0.2.10:8443",
		"cp.example.com:8443", "192.0.2.10:8443",
	}
	if got := sd.dialed(); !slices.Equal(got, wantCalls) {
		t.Fatalf("dialed %q, want %q", got, wantCalls)
	}

	warns := logs.find(fallbackWarn)
	if len(warns) != 1 {
		t.Fatalf("logged %q %d times over two fallbacks, want once", fallbackWarn, len(warns))
	}
	w := warns[0]
	if w.level != slog.LevelWarn {
		t.Errorf("level = %v, want WARN", w.level)
	}
	if w.attrs["host"] != "cp.example.com" || w.attrs["address"] != "192.0.2.10:8443" || w.attrs["error"] != dnsErr.Error() {
		t.Errorf("attrs = %v, want host=cp.example.com address=192.0.2.10:8443 error=%q", w.attrs, dnsErr.Error())
	}
	if n := len(logs.find(resolvesInfo)); n != 0 {
		t.Errorf("logged %q %d times before the name resolved, want none", resolvesInfo, n)
	}

	// The name resolves again: the first ordinary success logs it, the next
	// one does not.
	sd.set("cp.example.com:8443", connFrom("192.0.2.10:8443"), nil)
	for i := range 2 {
		if _, err := d.DialContext(ctx, "tcp", "cp.example.com:8443"); err != nil {
			t.Fatalf("ordinary dial %d: %v", i+1, err)
		}
	}
	infos := logs.find(resolvesInfo)
	if len(infos) != 1 {
		t.Fatalf("logged %q %d times over two ordinary dials, want once", resolvesInfo, len(infos))
	}
	if infos[0].level != slog.LevelInfo || infos[0].attrs["host"] != "cp.example.com" {
		t.Errorf("line = %v %v, want INFO with host=cp.example.com", infos[0].level, infos[0].attrs)
	}

	// After the name resolved once more, the next fallback is logged again.
	sd.set("cp.example.com:8443", nil, dnsErr)
	if _, err := d.DialContext(ctx, "tcp", "cp.example.com:8443"); err != nil {
		t.Fatalf("third fallback: DialContext: %v", err)
	}
	if n := len(logs.find(fallbackWarn)); n != 2 {
		t.Errorf("logged %q %d times, want twice after the name resolved in between", fallbackWarn, n)
	}
}

func TestFallbackDialer_ReturnsTheFallbackDialError(t *testing.T) {
	d, sd, _ := newScriptedFallbackDialer()
	ctx := context.Background()

	sd.set("cp.example.com:443", connFrom("192.0.2.10:443"), nil)
	if _, err := d.DialContext(ctx, "tcp", "cp.example.com:443"); err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	fallbackErr := refused()
	sd.set("cp.example.com:443", nil, notResolving("cp.example.com"))
	sd.set("192.0.2.10:443", nil, fallbackErr)
	conn, err := d.DialContext(ctx, "tcp", "cp.example.com:443")
	if err != fallbackErr {
		t.Fatalf("DialContext error = %v, want the fallback dial's error %v", err, fallbackErr)
	}
	if conn != nil {
		t.Errorf("DialContext returned connection %v with an error", conn)
	}
}

func TestFallbackDialer_ReturnsOtherErrorsUnchanged(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		// stored dials cp.example.com successfully first, so an address is
		// stored for it.
		stored bool
		ctx    context.Context
		err    error
	}{
		{name: "name without a stored address", ctx: context.Background(), err: notResolving("cp.example.com")},
		{name: "refused with a stored address", stored: true, ctx: context.Background(), err: refused()},
		{name: "name after the context ended", stored: true, ctx: cancelled, err: notResolving("cp.example.com")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, sd, logs := newScriptedFallbackDialer()
			sd.set("192.0.2.10:443", connFrom("192.0.2.10:443"), nil)
			if tt.stored {
				sd.set("cp.example.com:443", connFrom("192.0.2.10:443"), nil)
				if _, err := d.DialContext(context.Background(), "tcp", "cp.example.com:443"); err != nil {
					t.Fatalf("DialContext: %v", err)
				}
			}
			before := len(sd.dialed())

			sd.set("cp.example.com:443", nil, tt.err)
			conn, err := d.DialContext(tt.ctx, "tcp", "cp.example.com:443")
			if err != tt.err {
				t.Fatalf("DialContext error = %v, want %v unchanged", err, tt.err)
			}
			if conn != nil {
				t.Errorf("DialContext returned connection %v with an error", conn)
			}
			if got := sd.dialed()[before:]; !slices.Equal(got, []string{"cp.example.com:443"}) {
				t.Errorf("dialed %q, want only cp.example.com:443", got)
			}
			if n := logs.count(); n != 0 {
				t.Errorf("logged %d lines, want none", n)
			}
		})
	}
}

// The client reaches an httptest TLS server through the name example.com,
// which httptest's certificate names, then through the stored address once
// the name stops resolving. Verification stays on, and the server name the
// client sends is the URL's on both connections.
func TestNewControlPlane_DialsTheLastAddressWhenTheNameStopsResolving(t *testing.T) {
	var (
		serverNamesMu sync.Mutex
		serverNames   []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverNamesMu.Lock()
		serverNames = append(serverNames, r.TLS.ServerName)
		serverNamesMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	serverAddr := srv.Listener.Addr().(*net.TCPAddr)
	port := strconv.Itoa(serverAddr.Port)
	nameAddr := net.JoinHostPort("example.com", port)

	logs := &logCapture{}
	c, err := NewControlPlane(Config{BaseURL: "https://" + nameAddr}, "1.2.3", slog.New(logs))
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}
	defer c.httpClient.CloseIdleConnections()

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.httpClient.Transport)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("certificate verification is off, want it on")
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	transport.TLSClientConfig.RootCAs = roots

	// The fake dial function stands in for name resolution: example.com is
	// the server's address while it resolves, and a *net.DNSError after.
	// IP literals reach the server through a real dialer.
	var resolves atomic.Bool
	resolves.Store(true)
	var (
		dialedMu sync.Mutex
		dialed   []string
	)
	netDialer := &net.Dialer{Timeout: 10 * time.Second}
	c.dialer.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialedMu.Lock()
		dialed = append(dialed, address)
		dialedMu.Unlock()
		if address == nameAddr {
			if !resolves.Load() {
				return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{
					Err: "no such host", Name: "example.com", IsNotFound: true,
				}}
			}
			return netDialer.DialContext(ctx, network, serverAddr.String())
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("fake dial: %s is neither example.com nor an IP literal", address)
		}
		return netDialer.DialContext(ctx, network, address)
	}

	ctx := context.Background()
	if err := c.GetJSON(ctx, "/v1/health", nil); err != nil {
		t.Fatalf("first request: %v", err)
	}
	c.httpClient.CloseIdleConnections()
	resolves.Store(false)
	if err := c.GetJSON(ctx, "/v1/health", nil); err != nil {
		t.Fatalf("request after the name stopped resolving: %v", err)
	}

	dialedMu.Lock()
	gotDialed := slices.Clone(dialed)
	dialedMu.Unlock()
	wantDialed := []string{nameAddr, nameAddr, serverAddr.String()}
	if !slices.Equal(gotDialed, wantDialed) {
		t.Errorf("dialed %q, want %q", gotDialed, wantDialed)
	}

	serverNamesMu.Lock()
	gotNames := slices.Clone(serverNames)
	serverNamesMu.Unlock()
	if want := []string{"example.com", "example.com"}; !slices.Equal(gotNames, want) {
		t.Errorf("TLS server names = %q, want %q", gotNames, want)
	}

	warns := logs.find(fallbackWarn)
	if len(warns) != 1 {
		t.Fatalf("logged %q %d times, want once", fallbackWarn, len(warns))
	}
	if warns[0].attrs["host"] != "example.com" || warns[0].attrs["address"] != serverAddr.String() {
		t.Errorf("attrs = %v, want host=example.com address=%s", warns[0].attrs, serverAddr)
	}
}
