package bridge

import "sync"

// mockVPNCall records a single method invocation on mockVPNController.
type mockVPNCall struct {
	Method string
	Args   []interface{}
}

// mockVPNController is a test double for VPNController.
type mockVPNController struct {
	mu    sync.Mutex
	calls []mockVPNCall

	createErr     error
	removeErr     error
	configureErr  error
	removePeerErr error

	// Per-key error injection.
	createErrFor    map[string]error // keyed by interface name
	configureErrFor map[string]error // keyed by publicKey
}

func (m *mockVPNController) CreateTunnelInterface(name string, listenPort int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "CreateTunnelInterface", Args: []interface{}{name, listenPort}})
	err := errForKey(m.createErrFor, name, m.createErr)
	m.mu.Unlock()
	return err
}

func (m *mockVPNController) RemoveTunnelInterface(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "RemoveTunnelInterface", Args: []interface{}{name}})
	err := m.removeErr
	m.mu.Unlock()
	return err
}

func (m *mockVPNController) ConfigureTunnelPeer(iface string, publicKey string, allowedIPs []string, endpoint string, psk string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "ConfigureTunnelPeer", Args: []interface{}{iface, publicKey, allowedIPs, endpoint, psk}})
	err := errForKey(m.configureErrFor, publicKey, m.configureErr)
	m.mu.Unlock()
	return err
}

func (m *mockVPNController) RemoveTunnelPeer(iface string, publicKey string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "RemoveTunnelPeer", Args: []interface{}{iface, publicKey}})
	err := m.removePeerErr
	m.mu.Unlock()
	return err
}

func (m *mockVPNController) vpnCallsFor(method string) []mockVPNCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []mockVPNCall
	for _, c := range m.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

func (m *mockVPNController) resetVPN() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// Verify mockVPNController satisfies VPNController at compile time.
var _ VPNController = (*mockVPNController)(nil)
