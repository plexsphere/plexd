package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// shutdownTimeout bounds the graceful shutdown of the health listener.
const shutdownTimeout = 5 * time.Second

// Timeouts and header cap of the probe listener. net/http's zero value applies
// none of them, which leaves a connection that never completes its request
// headers open for as long as the peer keeps it: every such connection pins a
// goroutine plus its read and write buffers. On an unauthenticated listener
// that is a remote memory-exhaustion lever against the very process that
// programs the WireGuard interface and the nftables chain, so the listener
// bounds every phase of a request itself.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 30 * time.Second

	// maxHeaderBytes caps per-connection header headroom far below net/http's
	// 1 MiB default: a probe is a request line and a handful of headers.
	maxHeaderBytes = 8 << 10
)

// maxConns caps concurrent probe connections. The timeouts above bound how long
// a single connection may stall; they do not bound how many a peer may hold
// open at once.
//
// Two properties keep the cap from turning into a lever against the consumer it
// protects. Keep-alive is disabled in Serve, so a slot is held for one request
// and released, never for as long as a peer keeps talking; and limitListener
// refuses over-cap connections immediately instead of queueing them, so a
// saturated cap never delays the accept of the next one. A cap that queues would
// be a restart lever: the kubelet's liveness probe waiting behind held slots
// fails its 1s timeout three times and the container restarts, which runs the
// drain path and tears the mesh data plane down.
const maxConns = 64

// dataPlaneCheckPeriod is how often the background poller re-runs the
// data-plane check. It sits below the readiness period of the shipped DaemonSet
// (10s), so a probe never reads a verdict older than one probe interval, and it
// is a fixed cost: unlike a per-probe check it does not scale with how often the
// unauthenticated endpoint is called.
const dataPlaneCheckPeriod = 5 * time.Second

// Response bodies and content type of the probe endpoints. They are constants
// with no interpolation: the listener is unauthenticated, so a body must never
// carry a node ID, a peer list, a token or a control-plane URL.
const (
	bodyOK                  = "ok\n"
	bodyRegistrationPending = "not ready: registration pending\n"
	bodyDataPlanePending    = "not ready: data plane not configured\n"
	bodyDataPlaneLost       = "not ready: data plane lost\n"
	bodyDeliveryStopped     = "not ready: event delivery stopped\n"
	bodyDeliveryDegraded    = "not ready: event delivery degraded\n"
	bodySubsystemStopped    = "not ready: subsystem stopped\n"

	contentTypePlain = "text/plain; charset=utf-8"
)

// Server is the health listener. It serves the unauthenticated Kubernetes
// probe endpoints /healthz and /readyz over TCP, separate from the local node
// API so that a probe never needs credentials.
type Server struct {
	cfg    Config
	logger *slog.Logger

	// checkPeriod is the data-plane poller's interval, defaulted from
	// dataPlaneCheckPeriod. Tests shorten it.
	checkPeriod time.Duration

	mu               sync.Mutex
	registered       bool
	dataPlaneReady   bool
	dataPlaneLost    bool
	deliveryStopped  bool
	subsystemStopped bool
	mode             api.DeliveryMode
}

// NewServer creates a new Server. Config defaults are applied automatically.
// The delivery mode is seeded to api.DeliveryModeStreaming, mirroring the
// initial mode of the ReconnectEngine (internal/api/reconnect.go:127), so that
// readiness after registration does not depend on the order in which the
// caller wires up the mode-change callback.
func NewServer(cfg Config, logger *slog.Logger) *Server {
	cfg.ApplyDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:         cfg,
		logger:      logger.With("component", "health"),
		checkPeriod: dataPlaneCheckPeriod,
		mode:        api.DeliveryModeStreaming,
	}
}

// SetRegistered marks the node identity as registered. The caller invokes it
// once registration has succeeded, and on restart as soon as a persisted
// identity has been loaded.
func (s *Server) SetRegistered() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registered = true
}

// SetDataPlaneReady marks the mesh data plane as established: the WireGuard
// interface is configured and up, and the firewall baseline is installed. The
// caller invokes it once, after both have succeeded.
//
// Readiness waits for it because a node without a tunnel carries no mesh
// traffic. Reporting such a node ready lets a DaemonSet rolling update march
// across the whole fleet while not a single node holds a data plane.
func (s *Server) SetDataPlaneReady() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataPlaneReady = true
}

// SetDataPlaneCheck starts a background poller that re-runs fn every
// dataPlaneCheckPeriod until ctx is cancelled; probes read its last verdict.
// It complements SetDataPlaneReady, which records the initial bring-up.
//
// The latch alone reports ready for the rest of the process's life: the mesh
// data plane is ordinary kernel state that other actors mutate afterwards — a
// node admin deleting the interface, a WireGuard module gone after a kernel
// upgrade — and a latched readiness would keep a node in rotation and let the
// next rolling update sweep the fleet.
//
// The poll runs in the background rather than in the request path because the
// probe endpoints are unauthenticated: a per-probe check lets any caller that
// can reach the port drive one kernel query per GET, inside the process that
// programs the WireGuard interface and the nftables chain. A nil fn keeps the
// latch-only behaviour.
//
// Note that what fn can observe bounds this: the caller checks the WireGuard
// interface, while a firewall baseline flushed by a co-resident actor stays
// undetected — neither the WireGuard nor the firewall controller exposes a read
// operation today.
func (s *Server) SetDataPlaneCheck(ctx context.Context, fn func() error) {
	if fn == nil {
		return
	}

	go func() {
		t := time.NewTicker(s.checkPeriod)
		defer t.Stop()
		for {
			err := fn()
			s.recordDataPlaneVerdict(err != nil, err)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// SetDeliveryMode records the current control-plane delivery mode.
func (s *Server) SetDeliveryMode(m api.DeliveryMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// SetDeliveryStopped marks control-plane event delivery as stopped for good.
//
// The delivery mode cannot express this on its own: the reconnect engine fires
// its mode-change callback only on an actual transition, and it returns without
// one on a permanent failure or a rejected node secret. The last recorded mode
// then stays whatever it was while no events arrive at all, so readiness needs
// a separate signal for "the delivery goroutine is gone".
func (s *Server) SetDeliveryStopped() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveryStopped = true
}

// SetSubsystemStopped records that a long-running subsystem exited before
// shutdown. Readiness answers 503 from then on: nothing restarts these
// goroutines, so the process stays alive while no longer doing the work the node
// was admitted for — and liveness is a constant by design, so the kubelet does
// not rescue it either.
//
// name goes to the log, never to the response: the endpoint is unauthenticated,
// so the body stays a constant like every other one.
func (s *Server) SetSubsystemStopped(name string) {
	s.mu.Lock()
	s.subsystemStopped = true
	s.mu.Unlock()

	s.logger.Error("subsystem stopped, reporting not ready", "subsystem", name)
}

// Handler returns the probe routes: GET /healthz and GET /readyz, and nothing
// else.
//
// The responses are plain text rather than the node API's JSON error shape.
// That is deliberate: the kubelet ignores probe bodies entirely and Kubernetes'
// own healthz convention is plain text, so a human reading `curl` output is the
// only consumer. Do not "improve" this into a JSON status document — the fixed
// bodies are what guarantees the unauthenticated endpoint leaks nothing about
// the node or the control plane.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return mux
}

// handleHealthz answers liveness. It is always 200 for as long as the process
// serves requests: liveness asks whether this process is alive, not whether the
// control plane is reachable. Reporting the control-plane state here would make
// the kubelet restart a node that is merely waiting for it.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writePlain(w, http.StatusOK, bodyOK)
}

// handleReadyz answers readiness: 200 only when the node has a registered
// identity, a mesh data plane that is still in place, a working event-delivery
// path to the control plane, and every long-running subsystem alive. The
// conditions are checked in the order the agent establishes them, so the
// reported reason names the first one still unmet: an unregistered node has no
// data plane to bring up yet, and a node without a data plane is not serving
// regardless of how its event stream is doing.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	registered, dataPlaneReady := s.registered, s.dataPlaneReady
	dataPlaneLost := s.dataPlaneLost
	deliveryStopped, subsystemStopped := s.deliveryStopped, s.subsystemStopped
	mode := s.mode
	s.mu.Unlock()

	switch {
	case !registered:
		writePlain(w, http.StatusServiceUnavailable, bodyRegistrationPending)
	case !dataPlaneReady:
		writePlain(w, http.StatusServiceUnavailable, bodyDataPlanePending)
	case dataPlaneLost:
		writePlain(w, http.StatusServiceUnavailable, bodyDataPlaneLost)
	case deliveryStopped:
		writePlain(w, http.StatusServiceUnavailable, bodyDeliveryStopped)
	case !deliveryReady(mode):
		writePlain(w, http.StatusServiceUnavailable, bodyDeliveryDegraded)
	case subsystemStopped:
		// Last: the reasons above name a specific condition, this one only says
		// that some subsystem is gone. The log line carries which.
		writePlain(w, http.StatusServiceUnavailable, bodySubsystemStopped)
	default:
		writePlain(w, http.StatusOK, bodyOK)
	}
}

// recordDataPlaneVerdict stores the poller's latest verdict for readiness to
// read, and logs it on a change only. A line per poll would repeat the same
// fact every period for as long as the interface is gone.
func (s *Server) recordDataPlaneVerdict(lost bool, err error) {
	s.mu.Lock()
	changed := s.dataPlaneLost != lost
	s.dataPlaneLost = lost
	s.mu.Unlock()

	if !changed {
		return
	}
	if lost {
		s.logger.Error("data plane check failed, reporting not ready", "error", err)
		return
	}
	s.logger.Info("data plane check recovered, reporting ready")
}

// deliveryReady reports whether m is a delivery path that counts as working for
// readiness purposes.
//
// api.DeliveryModeStreaming and api.DeliveryModePullOnly are working delivery
// paths: pull-only is the control plane's deliberate descope of the event bus,
// and the node still reconciles through its own loop, so a pull-only node is
// serving correctly and must not be taken out of rotation.
// api.DeliveryModeDegradedPolling is not a working delivery path: it means SSE
// has been failing transiently past the fallback window.
func deliveryReady(m api.DeliveryMode) bool {
	switch m {
	case api.DeliveryModeStreaming, api.DeliveryModePullOnly:
		return true
	default:
		return false
	}
}

// writePlain writes a constant plain-text probe response.
func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", contentTypePlain)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// Listen binds the configured health address. It is split from Serve so the
// caller can fail fast on an address already in use, before registration
// starts.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("health: listen %s: %w", s.cfg.Listen, err)
	}
	return ln, nil
}

// Serve serves the probe routes on ln until ctx is cancelled, then shuts the
// listener down gracefully. It returns nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ln = &limitListener{Listener: ln, sem: make(chan struct{}, maxConns)}

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	// A probe is one request. Keep-alive is what would let a peer hold a slot
	// under maxConns for as long as it likes, which delays the kubelet's probe
	// past its 1s timeout and turns the cap into a restart lever.
	srv.SetKeepAlivesEnabled(false)

	// serveCtx bounds the watcher to this call: srv.Serve also returns on an
	// accept failure, and a watcher parked on the caller's context would then
	// stay parked for the rest of the process's life.
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()

	go func() {
		<-serveCtx.Done()
		if ctx.Err() == nil {
			return // srv.Serve returned on its own; nothing left to shut down.
		}
		s.logger.Info("health listener shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.logger.Info("health listener started", "listen", ln.Addr().String())

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("health: serve: %w", err)
	}

	s.logger.Info("health listener stopped")
	return nil
}

// limitListener bounds how many connections its caller holds at once. It accepts
// every connection and closes the ones past the cap right away, so a saturated
// cap refuses instead of queueing.
//
// golang.org/x/net/netutil's LimitListener takes its slot before calling Accept,
// which blocks the accept loop once the cap is reached: the next connection then
// waits in the kernel backlog for a slot the held peers control, and the caller
// that waits is whoever dialled next — the kubelet, not the peer holding the
// slots.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: conn, release: sync.OnceFunc(func() { <-l.sem })}, nil
		default:
			// Over the cap: refuse now rather than make the next caller wait.
			_ = conn.Close()
		}
	}
}

// limitConn returns its slot when it is closed. net/http may close a connection
// more than once, so the release is guarded.
type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
