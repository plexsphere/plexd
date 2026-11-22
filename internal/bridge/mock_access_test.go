package bridge

import (
	"maps"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/wireguard"
)

// mockAccessCall records a single method invocation on mockAccessController.
type mockAccessCall struct {
	Method string
	Args   []interface{}
}

// mockAccessController is a test double for AccessController.
type mockAccessController struct {
	mu    sync.Mutex
	calls []mockAccessCall

	createInterfaceErr  error
	removeInterfaceErr  error
	removeInterfacesErr error
	configurePeerErr    error
	removePeerErr       error
	peerHandshakesErr   error

	// Per-key error injection.
	createInterfaceErrFor map[string]error // keyed by interface name
	configurePeerErrFor   map[string]error // keyed by publicKey
	removePeerErrFor      map[string]error // keyed by publicKey
	peerHandshakesErrFor  map[string]error // keyed by interface name

	// peerHandshakes is what PeerHandshakes returns for an interface, keyed
	// by interface name; an interface it does not list reads as no peers.
	peerHandshakes map[string]map[string]time.Time
}

// CreateInterface records name, privateKey, listenPort and address, in that
// order, as the call's Args.
func (m *mockAccessController) CreateInterface(name string, privateKey []byte, listenPort int, address string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockAccessCall{Method: "CreateInterface", Args: []interface{}{name, privateKey, listenPort, address}})
	err := errForKey(m.createInterfaceErrFor, name, m.createInterfaceErr)
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

func (m *mockAccessController) RemoveInterfaces(prefix string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockAccessCall{Method: "RemoveInterfaces", Args: []interface{}{prefix}})
	err := m.removeInterfacesErr
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

// PeerHandshakes returns a copy of the handshakes configured for iface, so a
// caller that changes the map leaves the configuration alone.
func (m *mockAccessController) PeerHandshakes(iface string) (map[string]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockAccessCall{Method: "PeerHandshakes", Args: []interface{}{iface}})
	if err := errForKey(m.peerHandshakesErrFor, iface, m.peerHandshakesErr); err != nil {
		return nil, err
	}
	handshakes := maps.Clone(m.peerHandshakes[iface])
	if handshakes == nil {
		handshakes = map[string]time.Time{}
	}
	return handshakes, nil
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

// accessMethods returns the methods of the recorded calls, in order.
func (m *mockAccessController) accessMethods() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	methods := make([]string, len(m.calls))
	for i, c := range m.calls {
		methods[i] = c.Method
	}
	return methods
}

func (m *mockAccessController) resetAccess() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// Verify mockAccessController satisfies AccessController at compile time.
var _ AccessController = (*mockAccessController)(nil)

// namerAccessController is a mockAccessController that maps configured names
// to kernel names, as WGAccessController does over the utun controller on
// macOS.
type namerAccessController struct {
	*mockAccessController

	names map[string]string // guarded by mockAccessController.mu
}

var _ wireguard.OSInterfaceNamer = (*namerAccessController)(nil)

func (m *namerAccessController) OSInterfaceName(name string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	osName, ok := m.names[name]
	return osName, ok
}

// unmap drops the mapping of name, as the utun controller does once the
// interface is gone.
func (m *namerAccessController) unmap(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.names, name)
}
