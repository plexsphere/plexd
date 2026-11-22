package bridge

import (
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/wireguard"
)

// mockVPNCall records a single method invocation on mockVPNController.
type mockVPNCall struct {
	Method string
	Args   []interface{}
}

// mockVPNController is a test double for VPNController. It records every
// call; each method returns the error set for it, and TunnelPeerHandshake the
// handshake set for the interface. A test that changes a field while the code
// under test calls the mock holds mu.
type mockVPNController struct {
	mu    sync.Mutex
	calls []mockVPNCall

	createErr     error // CreateTunnelInterface
	createXfrmErr error // CreateXfrmInterface
	createTunErr  error // CreateTunInterface
	removeErr     error // RemoveTunnelInterface
	removeAllErr  error // RemoveTunnelInterfaces
	configureErr  error // ConfigureTunnelPeer
	removePeerErr error // RemoveTunnelPeer
	handshakeErr  error // TunnelPeerHandshake

	// Per-key error injection, ahead of the errors above.
	createErrFor     map[string]error // keyed by interface name
	createXfrmErrFor map[string]error // keyed by interface name
	createTunErrFor  map[string]error // keyed by interface name
	configureErrFor  map[string]error // keyed by publicKey

	// handshakes is what TunnelPeerHandshake returns, keyed by interface
	// name; an interface without an entry gives the zero time.
	handshakes map[string]time.Time
}

func (m *mockVPNController) CreateTunnelInterface(name string, privateKey []byte, listenPort int) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "CreateTunnelInterface", Args: []interface{}{name, privateKey, listenPort}})
	err := errForKey(m.createErrFor, name, m.createErr)
	m.mu.Unlock()
	return err
}

func (m *mockVPNController) CreateXfrmInterface(name string, ifID uint32) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "CreateXfrmInterface", Args: []interface{}{name, ifID}})
	err := errForKey(m.createXfrmErrFor, name, m.createXfrmErr)
	m.mu.Unlock()
	return err
}

func (m *mockVPNController) CreateTunInterface(name string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "CreateTunInterface", Args: []interface{}{name}})
	err := errForKey(m.createTunErrFor, name, m.createTunErr)
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

func (m *mockVPNController) RemoveTunnelInterfaces(prefixes []string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockVPNCall{Method: "RemoveTunnelInterfaces", Args: []interface{}{prefixes}})
	err := m.removeAllErr
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

// TunnelPeerHandshake records the call and returns handshakeErr when it is
// set, and otherwise the time handshakes holds for iface, the zero time when
// it holds none.
func (m *mockVPNController) TunnelPeerHandshake(iface string, publicKey string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockVPNCall{Method: "TunnelPeerHandshake", Args: []interface{}{iface, publicKey}})
	if m.handshakeErr != nil {
		return time.Time{}, m.handshakeErr
	}
	return m.handshakes[iface], nil
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

// vpnMethods returns the methods of the recorded calls, in order.
func (m *mockVPNController) vpnMethods() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	methods := make([]string, len(m.calls))
	for i, c := range m.calls {
		methods[i] = c.Method
	}
	return methods
}

// set runs f on the mock under its mutex, for a test that changes a field
// while the code under test may call the mock.
func (m *mockVPNController) set(f func(m *mockVPNController)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

func (m *mockVPNController) resetVPN() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// Verify mockVPNController satisfies VPNController at compile time.
var _ VPNController = (*mockVPNController)(nil)

// namerVPNController is a mockVPNController that maps configured names to
// kernel names, as WGVPNController does over the utun controller on macOS.
type namerVPNController struct {
	*mockVPNController

	names map[string]string // guarded by mockVPNController.mu
}

var _ wireguard.OSInterfaceNamer = (*namerVPNController)(nil)

func (m *namerVPNController) OSInterfaceName(name string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	osName, ok := m.names[name]
	return osName, ok
}

// unmap drops the mapping of name, as the utun controller does once the
// interface is gone.
func (m *namerVPNController) unmap(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.names, name)
}
