package health

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/plexsphere/plexd/internal/api"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// probe issues a GET against the server's handler and returns status and body.
func probe(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("%s Content-Type = %q, want %q", path, ct, "text/plain; charset=utf-8")
	}
	return res.StatusCode, string(body)
}

func TestHealthz_AlwaysOK(t *testing.T) {
	srv := NewServer(Config{}, testLogger())
	h := srv.Handler()

	// Liveness must not depend on control-plane state: neither before
	// registration nor while delivery is degraded.
	status, body := probe(t, h, "/healthz")
	if status != http.StatusOK || body != "ok\n" {
		t.Errorf("before registration: got %d %q, want %d %q", status, body, http.StatusOK, "ok\n")
	}

	srv.SetDeliveryMode(api.DeliveryModeDegradedPolling)

	status, body = probe(t, h, "/healthz")
	if status != http.StatusOK || body != "ok\n" {
		t.Errorf("with degraded delivery: got %d %q, want %d %q", status, body, http.StatusOK, "ok\n")
	}
}

func TestReadyz_Transitions(t *testing.T) {
	srv := NewServer(Config{}, testLogger())
	h := srv.Handler()

	// One server walked through its lifecycle; each step asserts the exact
	// body, which doubles as the lockdown against leaking node details.
	steps := []struct {
		name       string
		transition func()
		wantStatus int
		wantBody   string
	}{
		{
			name:       "initial state is unregistered",
			transition: func() {},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "not ready: registration pending\n",
		},
		{
			// Registration alone is not readiness: the WireGuard interface
			// comes up after it, and a node without a tunnel carries no mesh
			// traffic.
			name:       "registered but the data plane is not up yet",
			transition: srv.SetRegistered,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "not ready: data plane not configured\n",
		},
		{
			name:       "data plane up with seeded streaming delivery",
			transition: srv.SetDataPlaneReady,
			wantStatus: http.StatusOK,
			wantBody:   "ok\n",
		},
		{
			name:       "delivery falls back to degraded polling",
			transition: func() { srv.SetDeliveryMode(api.DeliveryModeDegradedPolling) },
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "not ready: event delivery degraded\n",
		},
		{
			name:       "streaming recovers",
			transition: func() { srv.SetDeliveryMode(api.DeliveryModeStreaming) },
			wantStatus: http.StatusOK,
			wantBody:   "ok\n",
		},
		{
			// The reconnect engine returns without a mode transition on a
			// permanent or auth failure, so streaming stays the last recorded
			// mode while no events arrive at all.
			name:       "delivery stops for good while the mode still reads streaming",
			transition: srv.SetDeliveryStopped,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "not ready: event delivery stopped\n",
		},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.transition()
			status, body := probe(t, h, "/readyz")
			if status != step.wantStatus {
				t.Errorf("status = %d, want %d", status, step.wantStatus)
			}
			if body != step.wantBody {
				t.Errorf("body = %q, want %q", body, step.wantBody)
			}
		})
	}
}

// TestReadyz_DataPlaneCheckIsRepeated guards against a latched data-plane
// readiness. SetDataPlaneReady records the initial bring-up, but the WireGuard
// interface is kernel state that other actors delete afterwards — and a node
// that reports ready without a tunnel lets the next rolling update sweep the
// fleet.
func TestReadyz_DataPlaneCheckIsRepeated(t *testing.T) {
	srv := NewServer(Config{}, testLogger())
	srv.checkPeriod = time.Millisecond
	h := srv.Handler()

	var mu sync.Mutex
	present := true
	setPresent := func(v bool) {
		mu.Lock()
		defer mu.Unlock()
		present = v
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.SetDataPlaneCheck(ctx, func() error {
		mu.Lock()
		defer mu.Unlock()
		if !present {
			return errors.New("interface plexd0 not found")
		}
		return nil
	})
	srv.SetRegistered()
	srv.SetDataPlaneReady()

	if status, body := probe(t, h, "/readyz"); status != http.StatusOK || body != "ok\n" {
		t.Fatalf("with the data plane in place: got %d %q, want %d %q", status, body, http.StatusOK, "ok\n")
	}

	// The interface goes away long after startup; the latch is still set.
	setPresent(false)
	awaitReadyz(t, h, http.StatusServiceUnavailable, "not ready: data plane lost\n")

	// And it recovers without a restart once the interface is back.
	setPresent(true)
	awaitReadyz(t, h, http.StatusOK, "ok\n")
}

// TestReadyz_DataPlaneCheckDoesNotRunPerProbe guards the cost of an
// unauthenticated endpoint. The shipped check dumps the node's whole interface
// table; running it per request would let any caller that reaches the port drive
// that dump as fast as it can issue GETs, inside the process that programs
// WireGuard and nftables.
func TestReadyz_DataPlaneCheckDoesNotRunPerProbe(t *testing.T) {
	srv := NewServer(Config{}, testLogger())
	// Longer than the test runs: every call the check sees is one the request
	// path made.
	srv.checkPeriod = time.Hour
	h := srv.Handler()

	var calls atomic.Int64
	ran := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.SetDataPlaneCheck(ctx, func() error {
		if calls.Add(1) == 1 {
			close(ran)
		}
		return nil
	})
	srv.SetRegistered()
	srv.SetDataPlaneReady()

	const probes = 50
	for i := 0; i < probes; i++ {
		if status, _ := probe(t, h, "/readyz"); status != http.StatusOK {
			t.Fatalf("probe %d: status = %d, want %d", i, status, http.StatusOK)
		}
	}

	// Wait for the poller's own run so the count below is not just a race.
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("the data-plane check never ran")
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("data-plane check ran %d times across %d probes, want 1 (the poller's own run)", got, probes)
	}
}

// awaitReadyz polls /readyz until it answers wantStatus with wantBody, which is
// how the background data-plane poller's verdict becomes visible.
func awaitReadyz(t *testing.T, h http.Handler, wantStatus int, wantBody string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var status int
	var body string
	for time.Now().Before(deadline) {
		if status, body = probe(t, h, "/readyz"); status == wantStatus && body == wantBody {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("/readyz = %d %q, want %d %q", status, body, wantStatus, wantBody)
}

// TestReadyz_SubsystemStopped guards the readiness signal for a subsystem that
// exits before shutdown. Nothing restarts those goroutines and liveness is a
// constant by design, so without this the process stays alive behind two green
// probes while no longer doing the work the node was admitted for.
func TestReadyz_SubsystemStopped(t *testing.T) {
	srv := NewServer(Config{}, testLogger())
	h := srv.Handler()

	srv.SetRegistered()
	srv.SetDataPlaneReady()

	if status, _ := probe(t, h, "/readyz"); status != http.StatusOK {
		t.Fatalf("fully started: status = %d, want %d", status, http.StatusOK)
	}

	srv.SetSubsystemStopped("node-api")

	status, body := probe(t, h, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", status, http.StatusServiceUnavailable)
	}
	// The name goes to the log, never to the unauthenticated response.
	if body != "not ready: subsystem stopped\n" {
		t.Errorf("body = %q, want %q", body, "not ready: subsystem stopped\n")
	}

	// Liveness stays 200: a restart would run the drain path and tear the mesh
	// data plane down, which is not the answer to a dead subsystem.
	if status, _ := probe(t, h, "/healthz"); status != http.StatusOK {
		t.Errorf("/healthz status = %d, want %d", status, http.StatusOK)
	}
}

func TestReadyz_PullOnlyIsReady(t *testing.T) {
	srv := NewServer(Config{}, testLogger())
	srv.SetRegistered()
	srv.SetDataPlaneReady()
	srv.SetDeliveryMode(api.DeliveryModePullOnly)

	status, body := probe(t, srv.Handler(), "/readyz")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d (pull-only is a working delivery path)", status, http.StatusOK)
	}
	if body != "ok\n" {
		t.Errorf("body = %q, want %q", body, "ok\n")
	}
}

// TestServe_ClosesStalledConnection guards the listener's request timeouts.
// With net/http's zero-value timeouts a client that opens a connection and
// never terminates its request headers holds a goroutine and its buffers for as
// long as it likes — on an unauthenticated listener that is a remote
// memory-exhaustion lever, so the server has to drop the connection itself.
func TestServe_ClosesStalledConnection(t *testing.T) {
	srv := NewServer(Config{Listen: "127.0.0.1:0"}, testLogger())

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A request line and one header, but never the blank line that ends them:
	// the server is left waiting for headers that do not come.
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	// Reading returns once the server hangs up, with or without a 408 first.
	// The slack over readHeaderTimeout keeps a loaded machine from flaking.
	if err := conn.SetReadDeadline(time.Now().Add(readHeaderTimeout + 10*time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("server never closed the stalled connection: %v", err)
	}
}

// TestServe_HeldConnectionsDoNotDelayProbe guards the connection cap against
// becoming the restart lever it is meant to prevent. Peers that keep their
// connections open must not be able to occupy every slot: the kubelet's liveness
// probe would queue behind them, fail its 1s timeout three times, and the
// restart runs the drain path that deletes the WireGuard interface and the
// deny-by-default chain.
func TestServe_HeldConnectionsDoNotDelayProbe(t *testing.T) {
	srv := NewServer(Config{Listen: "127.0.0.1:0"}, testLogger())

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	addr := ln.Addr().String()

	held := make([]net.Conn, 0, maxConns)
	t.Cleanup(func() {
		for _, conn := range held {
			conn.Close()
		}
	})

	// maxConns peers that each complete one cheap GET and then keep their
	// connection open, the pattern a leaking sidecar produces for free.
	for i := 0; i < maxConns; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, conn)
		if err := probeConn(conn, 10*time.Second); err != nil {
			t.Fatalf("probe on held connection %d: %v", i, err)
		}
	}

	// The kubelet's turn, with its default 1s timeout. The server hangs up after
	// each response, so every slot above was returned and this connection is
	// served without waiting for a peer to go away.
	kubelet, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial past the held connections: %v", err)
	}
	defer kubelet.Close()

	if err := probeConn(kubelet, time.Second); err != nil {
		t.Fatalf("liveness probe behind %d held connections: %v", maxConns, err)
	}
}

// TestServe_CapRefusesRatherThanQueues guards the other half of the cap: while
// every slot is genuinely occupied, the next connection must be refused at once
// rather than left waiting in the kernel backlog. A queued accept makes the
// caller that waits whoever dialled next — the kubelet — instead of the peer
// that filled the slots.
func TestServe_CapRefusesRatherThanQueues(t *testing.T) {
	srv := NewServer(Config{Listen: "127.0.0.1:0"}, testLogger())

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	addr := ln.Addr().String()

	held := make([]net.Conn, 0, maxConns)
	t.Cleanup(func() {
		for _, conn := range held {
			conn.Close()
		}
	})

	// Occupy every slot with a request that never terminates its headers, so the
	// server holds each connection until readHeaderTimeout.
	for i := 0; i < maxConns; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, conn)
		if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
			t.Fatalf("write partial request %d: %v", i, err)
		}
	}

	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial past the cap: %v", err)
	}
	defer extra.Close()

	// Well under readHeaderTimeout: the connection must come back closed rather
	// than wait for one of the stalled peers to time out.
	if err := extra.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.Copy(io.Discard, extra); err != nil {
		t.Fatalf("connection past the cap was queued, want it refused at once: %v", err)
	}
}

// TestServe_NoLeakWhenServeFails guards the shutdown watcher's lifetime. Serve
// also returns on an accept failure, with the caller's context still live; a
// watcher parked on that context would stay parked for the rest of the process.
func TestServe_NoLeakWhenServeFails(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	srv := NewServer(Config{Listen: "127.0.0.1:0"}, testLogger())

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}
	// Closing the listener first makes the first Accept fail, so Serve returns
	// an error without the context ever being cancelled.
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("Serve() = nil, want an error from the closed listener")
	}
}

// probeConn issues one GET /healthz on conn and drains the response. The server
// hangs up afterwards, so a connection serves exactly one probe.
func probeConn(conn net.Conn, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		return err
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return errors.New(res.Status)
	}
	return nil
}

func TestServe_NoCredentialsRequired(t *testing.T) {
	srv := NewServer(Config{Listen: "127.0.0.1:0"}, testLogger())

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, ln)
	}()

	base := "http://" + ln.Addr().String()

	// No Authorization header anywhere: the probes must never answer 401.
	// Readiness answering 503 before registration is the expected state here.
	cases := []struct {
		path       string
		wantStatus int
	}{
		{path: "/healthz", wantStatus: http.StatusOK},
		{path: "/readyz", wantStatus: http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			res, err := http.Get(base + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer res.Body.Close()
			if _, err := io.Copy(io.Discard, res.Body); err != nil {
				t.Fatalf("drain body: %v", err)
			}
			if res.StatusCode == http.StatusUnauthorized {
				t.Fatalf("GET %s = 401, want no authentication", tc.path)
			}
			if res.StatusCode != tc.wantStatus {
				t.Errorf("GET %s = %d, want %d", tc.path, res.StatusCode, tc.wantStatus)
			}
		})
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Serve() = %v, want nil after cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve() did not return after context cancellation")
	}
}
