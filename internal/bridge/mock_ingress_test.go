package bridge

import (
	"crypto/tls"
	"net"
	"strconv"
	"sync"
	"testing"
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
