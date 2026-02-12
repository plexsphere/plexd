package bridge

import (
	"log/slog"
	"sync"
)

// mockCall records a single method invocation on mockRouteController.
type mockCall struct {
	Method string
	Args   []interface{}
}

// mockRouteController is a test double for RouteController.
// It records all calls and supports configurable error returns per method.
type mockRouteController struct {
	mu sync.Mutex

	calls []mockCall

	enableForwardingErr    error
	disableForwardingErr   error
	addRouteErr            error
	removeRouteErr         error
	addNATMasqueradeErr    error
	removeNATMasqueradeErr error

	// addRouteErrFor allows per-subnet error injection.
	addRouteErrFor    map[string]error
	removeRouteErrFor map[string]error
}

func (m *mockRouteController) EnableForwarding(meshIface, accessIface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "EnableForwarding", Args: []interface{}{meshIface, accessIface}})
	err := m.enableForwardingErr
	m.mu.Unlock()
	return err
}

func (m *mockRouteController) DisableForwarding(meshIface, accessIface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "DisableForwarding", Args: []interface{}{meshIface, accessIface}})
	err := m.disableForwardingErr
	m.mu.Unlock()
	return err
}

func (m *mockRouteController) AddRoute(subnet, iface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "AddRoute", Args: []interface{}{subnet, iface}})
	err := errForKey(m.addRouteErrFor, subnet, m.addRouteErr)
	m.mu.Unlock()
	return err
}

func (m *mockRouteController) RemoveRoute(subnet, iface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "RemoveRoute", Args: []interface{}{subnet, iface}})
	err := errForKey(m.removeRouteErrFor, subnet, m.removeRouteErr)
	m.mu.Unlock()
	return err
}

// errForKey returns the per-key error if present, otherwise the fallback.
func errForKey(perKey map[string]error, key string, fallback error) error {
	if perKey != nil {
		if e, ok := perKey[key]; ok {
			return e
		}
	}
	return fallback
}

func (m *mockRouteController) AddNATMasquerade(iface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "AddNATMasquerade", Args: []interface{}{iface}})
	err := m.addNATMasqueradeErr
	m.mu.Unlock()
	return err
}

func (m *mockRouteController) RemoveNATMasquerade(iface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "RemoveNATMasquerade", Args: []interface{}{iface}})
	err := m.removeNATMasqueradeErr
	m.mu.Unlock()
	return err
}

// callsFor returns all recorded calls for the given method name.
func (m *mockRouteController) callsFor(method string) []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []mockCall
	for _, c := range m.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

// reset clears all recorded calls.
func (m *mockRouteController) reset() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}
