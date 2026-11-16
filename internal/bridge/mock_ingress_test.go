package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// mockIngressCall records a single method invocation on mockIngressController.
type mockIngressCall struct {
	Method string
	Args   []interface{}
}

// mockIngressController is a test double for IngressController.
type mockIngressController struct {
	mu    sync.Mutex
	calls []mockIngressCall

	listenErr error
	closeErr  error

	// listenFn allows custom listener creation for tests that need real TCP.
	listenFn func(addr string, tlsCfg *tls.Config) (net.Listener, error)
}

func (m *mockIngressController) Listen(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	m.mu.Lock()
	m.calls = append(m.calls, mockIngressCall{Method: "Listen", Args: []interface{}{addr, tlsCfg}})
	listenFn := m.listenFn
	err := m.listenErr
	m.mu.Unlock()
	if listenFn != nil {
		return listenFn(addr, tlsCfg)
	}
	if err != nil {
		return nil, err
	}
	// Default: create a real TCP listener for basic tests
	ln, listenErr := net.Listen("tcp", addr)
	if listenErr != nil {
		return nil, listenErr
	}
	if tlsCfg != nil {
		return tls.NewListener(ln, tlsCfg), nil
	}
	return ln, nil
}

func (m *mockIngressController) Close(listener net.Listener) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockIngressCall{Method: "Close", Args: []interface{}{listener}})
	err := m.closeErr
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (m *mockIngressController) ingressCallsFor(method string) []mockIngressCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []mockIngressCall
	for _, c := range m.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

// Verify mockIngressController satisfies IngressController at compile time.
var _ IngressController = (*mockIngressController)(nil)

// loopbackIngressController records calls like mockIngressController and binds
// 127.0.0.1:0 for each port it is asked to listen on, so a test names port 443
// and dials the ephemeral port addr returns.
type loopbackIngressController struct {
	*mockIngressController

	lmu      sync.Mutex
	addrs    map[int]string
	failures map[int]error
}

func newLoopbackIngressController(t *testing.T) *loopbackIngressController {
	t.Helper()
	c := &loopbackIngressController{
		mockIngressController: &mockIngressController{},
		addrs:                 make(map[int]string),
		failures:              make(map[int]error),
	}
	c.listenFn = func(addr string, _ *tls.Config) (net.Listener, error) {
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		c.lmu.Lock()
		defer c.lmu.Unlock()
		if err := c.failures[port]; err != nil {
			return nil, err
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		c.addrs[port] = ln.Addr().String()
		return ln, nil
	}
	return c
}

// addr returns the address the listener for port was last bound to.
func (c *loopbackIngressController) addr(port int) string {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	return c.addrs[port]
}

// failListen makes every Listen for port fail with err; a nil err lets it
// bind again.
func (c *loopbackIngressController) failListen(port int, err error) {
	c.lmu.Lock()
	defer c.lmu.Unlock()
	if err == nil {
		delete(c.failures, port)
		return
	}
	c.failures[port] = err
}

// setCloseErr makes every Close return err, without closing the listener.
func (c *loopbackIngressController) setCloseErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeErr = err
}

// listenAddrs returns the address argument of every Listen call, in order.
func (c *loopbackIngressController) listenAddrs() []string {
	var out []string
	for _, call := range c.ingressCallsFor("Listen") {
		out = append(out, call.Args[0].(string))
	}
	return out
}

// certVersion is one version of a Secret.
type certVersion struct {
	name    string
	version int
}

// fakeCertFetcher is a CertificateSecretFetcher that serves values by Secret
// name and version, records every call, and fails every call with err while
// it is set. A version it holds no value for fails with api.ErrNotFound.
type fakeCertFetcher struct {
	mu     sync.Mutex
	values map[certVersion][]byte
	err    error
	calls  []certVersion
}

var _ CertificateSecretFetcher = (*fakeCertFetcher)(nil)

func (f *fakeCertFetcher) FetchCertificateSecret(_ context.Context, name string, version int) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, certVersion{name: name, version: version})
	if f.err != nil {
		return nil, f.err
	}
	value, ok := f.values[certVersion{name: name, version: version}]
	if !ok {
		return nil, fmt.Errorf("fake: secret %q version %d: %w", name, version, api.ErrNotFound)
	}
	// The manager clears the value it was handed.
	return bytes.Clone(value), nil
}

// set makes version of name hold value.
func (f *fakeCertFetcher) set(name string, version int, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.values == nil {
		f.values = make(map[certVersion][]byte)
	}
	f.values[certVersion{name: name, version: version}] = value
}

// setErr makes every later call fail with err; nil serves the values again.
func (f *fakeCertFetcher) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// fetches returns every call so far, in order.
func (f *fakeCertFetcher) fetches() []certVersion {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]certVersion(nil), f.calls...)
}

// errNoNetwork is what acmeTestTransport answers every request with.
var errNoNetwork = errors.New("test transport: no network")

// acmeTestTransport records the URL of every ACME request and fails each with
// errNoNetwork, so no test reaches a CA.
type acmeTestTransport struct {
	mu   sync.Mutex
	urls []string
}

func (t *acmeTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.urls = append(t.urls, req.URL.String())
	t.mu.Unlock()
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, errNoNetwork
}

// requests returns the URL of every request so far, in order.
func (t *acmeTestTransport) requests() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.urls...)
}

// ingressFixture is an IngressManager with a fake certificate fetcher and an
// ACMEManager whose requests never leave the test, logging to one sink.
type ingressFixture struct {
	mgr       *IngressManager
	acme      *ACMEManager
	certs     *fakeCertFetcher
	transport *acmeTestTransport
	logs      *relayLog
}

// buildIngressFixture builds the fixture without setting the manager up. Both
// managers are torn down when the test ends, the ingress manager first.
func buildIngressFixture(t *testing.T, ctrl IngressController, cfg Config) *ingressFixture {
	t.Helper()
	logger, logs := newRelayLogger()
	transport := &acmeTestTransport{}
	acmeMgr := NewACMEManager(ACMEConfig{CacheDir: t.TempDir(), HTTPTransport: transport}, logger)
	t.Cleanup(func() { _ = acmeMgr.Teardown() })
	certs := &fakeCertFetcher{}
	mgr := NewIngressManager(ctrl, cfg, logger, acmeMgr, certs)
	t.Cleanup(func() { _ = mgr.Teardown() })
	return &ingressFixture{mgr: mgr, acme: acmeMgr, certs: certs, transport: transport, logs: logs}
}

// newIngressFixture builds the fixture with the manager set up.
func newIngressFixture(t *testing.T, ctrl IngressController) *ingressFixture {
	t.Helper()
	fx := buildIngressFixture(t, ctrl, ingressTestConfig(true))
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return fx
}

// requireSignal waits up to 2 s for a signal on ch.
func requireSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("no signal within 2s after %s", what)
	}
}

// requireNoSignal fails the test if ch holds a signal now.
func requireNoSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Errorf("a signal after %s, want none", what)
	default:
	}
}

// fakeDialPolicy is an IngressDialPolicy that answers denied and records
// every target it was asked about.
type fakeDialPolicy struct {
	mu      sync.Mutex
	denied  bool
	targets []netip.AddrPort
}

var _ IngressDialPolicy = (*fakeDialPolicy)(nil)

func (p *fakeDialPolicy) DialDenied(target netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = append(p.targets, target)
	return p.denied
}

// asked returns every target the policy was asked about, in order.
func (p *fakeDialPolicy) asked() []netip.AddrPort {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.AddrPort(nil), p.targets...)
}
