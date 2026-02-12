package bridge

import (
	"crypto/tls"
	"net"
	"sync"
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

func (m *mockIngressController) resetIngress() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// Verify mockIngressController satisfies IngressController at compile time.
var _ IngressController = (*mockIngressController)(nil)
