package bridge

import "sync"

// mockAccessCall records a single method invocation on mockAccessController.
type mockAccessCall struct {
	Method string
	Args   []interface{}
}

// mockAccessController is a test double for AccessController.
type mockAccessController struct {
	mu    sync.Mutex
	calls []mockAccessCall

	createInterfaceErr error
	removeInterfaceErr error
	configurePeerErr   error
	removePeerErr      error

	// Per-key error injection.
	configurePeerErrFor map[string]error // keyed by publicKey
	removePeerErrFor    map[string]error // keyed by publicKey
}

func (m *mockAccessController) CreateInterface(name string, listenPort int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockAccessCall{Method: "CreateInterface", Args: []interface{}{name, listenPort}})
	err := m.createInterfaceErr
	m.mu.Unlock()
	return err
}

func (m *mockAccessController) RemoveInterface(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockAccessCall{Method: "RemoveInterface", Args: []interface{}{name}})
	err := m.removeInterfaceErr
	m.mu.Unlock()
	return err
}

func (m *mockAccessController) ConfigurePeer(iface string, publicKey string, allowedIPs []string, psk string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockAccessCall{Method: "ConfigurePeer", Args: []interface{}{iface, publicKey, allowedIPs, psk}})
	err := errForKey(m.configurePeerErrFor, publicKey, m.configurePeerErr)
	m.mu.Unlock()
	return err
}

func (m *mockAccessController) RemovePeer(iface string, publicKey string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockAccessCall{Method: "RemovePeer", Args: []interface{}{iface, publicKey}})
	err := errForKey(m.removePeerErrFor, publicKey, m.removePeerErr)
	m.mu.Unlock()
	return err
}

func (m *mockAccessController) accessCallsFor(method string) []mockAccessCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []mockAccessCall
	for _, c := range m.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

func (m *mockAccessController) resetAccess() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// Verify mockAccessController satisfies AccessController at compile time.
var _ AccessController = (*mockAccessController)(nil)
