package wireguard

import (
	"log/slog"
	"sync"
)

// mockCall records a single method invocation on mockController.
type mockCall struct {
	Method string
	Args   []interface{}
}

// mockController is a test double for WGController.
// It records all calls and supports configurable error returns per method.
type mockController struct {
	mu sync.Mutex

	// Call records
	calls []mockCall

	// Configurable error returns (set before test)
	createInterfaceErr  error
	deleteInterfaceErr  error
	configureAddressErr error
	setInterfaceUpErr   error
	setMTUErr           error
	addPeerErr          error
	removePeerErr       error
}

func (m *mockController) CreateInterface(name string, privateKey []byte, listenPort int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "CreateInterface", Args: []interface{}{name, privateKey, listenPort}})
	err := m.createInterfaceErr
	m.mu.Unlock()
	return err
}

func (m *mockController) DeleteInterface(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "DeleteInterface", Args: []interface{}{name}})
	err := m.deleteInterfaceErr
	m.mu.Unlock()
	return err
}

func (m *mockController) ConfigureAddress(name string, address string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "ConfigureAddress", Args: []interface{}{name, address}})
	err := m.configureAddressErr
	m.mu.Unlock()
	return err
}

func (m *mockController) SetInterfaceUp(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "SetInterfaceUp", Args: []interface{}{name}})
	err := m.setInterfaceUpErr
	m.mu.Unlock()
	return err
}

func (m *mockController) SetMTU(name string, mtu int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "SetMTU", Args: []interface{}{name, mtu}})
	err := m.setMTUErr
	m.mu.Unlock()
	return err
}

func (m *mockController) AddPeer(iface string, cfg PeerConfig) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "AddPeer", Args: []interface{}{iface, cfg}})
	err := m.addPeerErr
	m.mu.Unlock()
	return err
}

func (m *mockController) RemovePeer(iface string, publicKey []byte) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "RemovePeer", Args: []interface{}{iface, publicKey}})
	err := m.removePeerErr
	m.mu.Unlock()
	return err
}

// callsFor returns all recorded calls for the given method name.
func (m *mockController) callsFor(method string) []mockCall {
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

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}
