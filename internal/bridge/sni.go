package bridge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SNIRoute maps an SNI hostname to a backend address.
type SNIRoute struct {
	Hostname    string // SNI hostname to match (exact match, lowercase)
	BackendAddr string // TCP address to forward to (host:port)
}

// SNIRouter accepts TCP connections, peeks at the TLS ClientHello to extract
// the SNI hostname, and routes connections to the appropriate backend.
// SNIRouter is concurrent-safe via mu.
type SNIRouter struct {
	logger      *slog.Logger
	dialTimeout time.Duration

	mu       sync.Mutex
	active   bool
	routes   map[string]SNIRoute // keyed by lowercase hostname
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{} // closed when accept loop exits
	connCount atomic.Int64
}

// NewSNIRouter creates a new SNIRouter.
func NewSNIRouter(dialTimeout time.Duration, logger *slog.Logger) *SNIRouter {
	return &SNIRouter{
		logger:      logger,
		dialTimeout: dialTimeout,
		routes:      make(map[string]SNIRoute),
	}
}

// Start begins accepting connections on the given listener.
func (r *SNIRouter) Start(ln net.Listener) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.listener = ln
	r.active = true
	r.done = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	go r.acceptLoop(ctx)

	r.logger.Info("sni router started",
		"component", "bridge",
		"addr", ln.Addr().String(),
	)

	return nil
}

// Stop stops the router. Idempotent: if not active, returns nil.
func (r *SNIRouter) Stop() error {
	r.mu.Lock()

	if !r.active {
		r.mu.Unlock()
		return nil
	}

	r.cancel()
	_ = r.listener.Close()

	done := r.done
	r.active = false
	r.routes = make(map[string]SNIRoute)
	r.mu.Unlock()

	// Wait for the accept loop to exit outside the lock.
	<-done

	r.logger.Info("sni router stopped",
		"component", "bridge",
	)

	return nil
}

// Active returns whether the router is currently active.
func (r *SNIRouter) Active() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

// ConnCount returns the number of active proxy connections.
func (r *SNIRouter) ConnCount() int64 {
	return r.connCount.Load()
}

// AddRoute adds an SNI route. If a route for the hostname already exists,
// it is overwritten.
func (r *SNIRouter) AddRoute(route SNIRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return fmt.Errorf("bridge: sni: router is not active")
	}
	if route.Hostname == "" {
		return fmt.Errorf("bridge: sni: empty hostname")
	}
	if route.BackendAddr == "" {
		return fmt.Errorf("bridge: sni: empty backend address")
	}

	hostname := strings.ToLower(route.Hostname)
	route.Hostname = hostname
	r.routes[hostname] = route

	r.logger.Info("sni route added",
		"component", "bridge",
		"hostname", hostname,
		"backend", route.BackendAddr,
	)

	return nil
}

// RemoveRoute removes the route for the given hostname.
// Idempotent: removing a non-existent route returns nil.
func (r *SNIRouter) RemoveRoute(hostname string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	hostname = strings.ToLower(hostname)
	if _, ok := r.routes[hostname]; !ok {
		return nil
	}
	delete(r.routes, hostname)

	r.logger.Info("sni route removed",
		"component", "bridge",
		"hostname", hostname,
	)

	return nil
}

// Routes returns a copy of all routes, sorted by hostname.
func (r *SNIRouter) Routes() []SNIRoute {
	r.mu.Lock()
	defer r.mu.Unlock()

	routes := make([]SNIRoute, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Hostname < routes[j].Hostname
	})
	return routes
}

// acceptLoop accepts connections on the listener and handles them.
func (r *SNIRouter) acceptLoop(ctx context.Context) {
	defer close(r.done)
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.connCount.Add(1)
		go r.handleConnection(ctx, conn)
	}
}

// sniPeekSize is the maximum number of bytes to read when peeking at
// the TLS ClientHello to extract the SNI hostname.
const sniPeekSize = 1024

// sniPeekTimeout is the maximum time to wait for the TLS ClientHello.
// This prevents slowloris-style attacks that hold connections open.
const sniPeekTimeout = 5 * time.Second

// handleConnection peeks at the TLS ClientHello, extracts the SNI hostname,
// looks up the backend route, and proxies the connection.
func (r *SNIRouter) handleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		r.connCount.Add(-1)
	}()

	// Set a read deadline before peeking to prevent slowloris attacks.
	_ = conn.SetReadDeadline(time.Now().Add(sniPeekTimeout))

	// Peek at the initial bytes to extract SNI.
	buf := make([]byte, sniPeekSize)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	peeked := buf[:n]

	hostname := extractSNI(peeked)
	if hostname == "" {
		r.logger.Warn("bridge: sni: no SNI hostname found",
			"component", "bridge",
			"remote", conn.RemoteAddr().String(),
		)
		return
	}

	// Look up the route.
	r.mu.Lock()
	route, ok := r.routes[hostname]
	r.mu.Unlock()

	if !ok {
		r.logger.Warn("bridge: sni: no route for hostname",
			"component", "bridge",
			"hostname", hostname,
			"remote", conn.RemoteAddr().String(),
		)
		return
	}

	// Clear the read deadline now that SNI has been extracted.
	_ = conn.SetReadDeadline(time.Time{})

	// Dial the backend with timeout.
	dialer := net.Dialer{Timeout: r.dialTimeout}
	backendConn, err := dialer.DialContext(ctx, "tcp", route.BackendAddr)
	if err != nil {
		r.logger.Error("bridge: sni: dial backend failed",
			"component", "bridge",
			"hostname", hostname,
			"backend", route.BackendAddr,
			"error", err,
		)
		return
	}
	defer backendConn.Close()

	// Wrap the client connection so the peeked bytes are replayed.
	clientConn := newPeekConn(conn, peeked)

	// Bidirectional copy.
	clientToBackend := make(chan struct{})
	go func() {
		defer close(clientToBackend)
		_, _ = io.Copy(backendConn, clientConn)
	}()

	backendToClient := make(chan struct{})
	go func() {
		defer close(backendToClient)
		_, _ = io.Copy(conn, backendConn)
	}()

	select {
	case <-ctx.Done():
	case <-clientToBackend:
	case <-backendToClient:
	}
}

// peekConn wraps a net.Conn, prepending already-read bytes before the underlying connection.
type peekConn struct {
	net.Conn
	reader io.Reader
}

func newPeekConn(conn net.Conn, peeked []byte) *peekConn {
	return &peekConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peeked), conn),
	}
}

func (c *peekConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// extractSNI parses a TLS ClientHello record and returns the SNI hostname.
// Returns an empty string if the data is not a valid ClientHello or does
// not contain an SNI extension.
func extractSNI(data []byte) string {
	// TLS record header: type(1) + version(2) + length(2)
	if len(data) < 5 {
		return ""
	}
	if data[0] != 0x16 { // handshake
		return ""
	}

	recordLen := int(data[3])<<8 | int(data[4])
	data = data[5:]
	// Allow partial records — we use whatever data we have.
	// Clamp to recordLen if we have enough.
	if len(data) > recordLen {
		data = data[:recordLen]
	}

	// Handshake header: type(1) + length(3)
	if len(data) < 4 {
		return ""
	}
	if data[0] != 0x01 { // ClientHello
		return ""
	}
	// handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	data = data[4:]

	// ClientHello body: version(2) + random(32) + session_id
	if len(data) < 34 {
		return ""
	}
	data = data[34:] // skip version + random

	// Session ID: length(1) + data
	if len(data) < 1 {
		return ""
	}
	sessionIDLen := int(data[0])
	data = data[1:]
	if len(data) < sessionIDLen {
		return ""
	}
	data = data[sessionIDLen:]

	// Cipher suites: length(2) + data
	if len(data) < 2 {
		return ""
	}
	cipherSuitesLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < cipherSuitesLen {
		return ""
	}
	data = data[cipherSuitesLen:]

	// Compression methods: length(1) + data
	if len(data) < 1 {
		return ""
	}
	compressionLen := int(data[0])
	data = data[1:]
	if len(data) < compressionLen {
		return ""
	}
	data = data[compressionLen:]

	// Extensions: length(2) + data
	if len(data) < 2 {
		return ""
	}
	extensionsLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) > extensionsLen {
		data = data[:extensionsLen]
	}

	// Parse extensions looking for SNI (type 0x0000).
	for len(data) >= 4 {
		extType := int(data[0])<<8 | int(data[1])
		extLen := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < extLen {
			return ""
		}

		if extType == 0x0000 { // SNI extension
			return parseSNIExtension(data[:extLen])
		}

		data = data[extLen:]
	}

	return ""
}

// parseSNIExtension parses the SNI extension data and returns the hostname.
func parseSNIExtension(data []byte) string {
	// SNI list: length(2) + entries
	if len(data) < 2 {
		return ""
	}
	sniListLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < sniListLen {
		return ""
	}
	data = data[:sniListLen]

	// Parse SNI entries.
	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < nameLen {
			return ""
		}

		if nameType == 0x00 { // host_name
			return strings.ToLower(string(data[:nameLen]))
		}

		data = data[nameLen:]
	}

	return ""
}
