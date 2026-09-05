package bridge

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgCall records a single method invocation on fakeWGController.
type wgCall struct {
	Method string
	Args   []interface{}
}

// fakeWGController is a test double for wireguard.WGController. It records all
// calls and supports configurable error returns per method. It does not
// implement wireguard.OSInterfaceNamer, which is the Windows case;
// namerWGController covers the macOS one.
type fakeWGController struct {
	mu sync.Mutex

	calls []wgCall

	createInterfaceErr  error
	deleteInterfaceErr  error
	configureAddressErr error
	setInterfaceUpErr   error
	setMTUErr           error
	addPeerErr          error
	removePeerErr       error
	setPrivateKeyErr    error
}

var _ wireguard.WGController = (*fakeWGController)(nil)

func (f *fakeWGController) CreateInterface(name string, privateKey []byte, listenPort int) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "CreateInterface", Args: []interface{}{name, privateKey, listenPort}})
	err := f.createInterfaceErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) DeleteInterface(name string) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "DeleteInterface", Args: []interface{}{name}})
	err := f.deleteInterfaceErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) ConfigureAddress(name string, address string) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "ConfigureAddress", Args: []interface{}{name, address}})
	err := f.configureAddressErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) SetInterfaceUp(name string) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "SetInterfaceUp", Args: []interface{}{name}})
	err := f.setInterfaceUpErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) SetMTU(name string, mtu int) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "SetMTU", Args: []interface{}{name, mtu}})
	err := f.setMTUErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) AddPeer(iface string, cfg wireguard.PeerConfig) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "AddPeer", Args: []interface{}{iface, cfg}})
	err := f.addPeerErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) RemovePeer(iface string, publicKey []byte) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "RemovePeer", Args: []interface{}{iface, publicKey}})
	err := f.removePeerErr
	f.mu.Unlock()
	return err
}

func (f *fakeWGController) SetPrivateKey(name string, privateKey []byte) error {
	f.mu.Lock()
	f.calls = append(f.calls, wgCall{Method: "SetPrivateKey", Args: []interface{}{name, privateKey}})
	err := f.setPrivateKeyErr
	f.mu.Unlock()
	return err
}

// wgCallsFor returns all recorded calls for the given method name.
func (f *fakeWGController) wgCallsFor(method string) []wgCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []wgCall
	for _, c := range f.calls {
		if c.Method == method {
			result = append(result, c)
		}
	}
	return result
}

// wgMethods returns the names of all recorded calls in the order they arrived,
// which is how the tests spell the sequence a create walks through.
func (f *fakeWGController) wgMethods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	methods := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		methods = append(methods, c.Method)
	}
	return methods
}

// namerWGController is a fakeWGController that maps configured names to kernel
// names, as DarwinController does for its utun devices.
type namerWGController struct {
	*fakeWGController

	names map[string]string
}

var _ wireguard.OSInterfaceNamer = (*namerWGController)(nil)

func (f *namerWGController) OSInterfaceName(name string) (string, bool) {
	osName, ok := f.names[name]
	return osName, ok
}

// testPeerKey returns a generated peer public key as base64 and as its 32 raw
// bytes, which is what the controllers hand to the WGController.
func testPeerKey(t *testing.T) (string, []byte) {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}

	pub := key.PublicKey()
	return base64.StdEncoding.EncodeToString(pub[:]), pub[:]
}

// wantWGErrPrefix fails the test unless err reports the given prefix.
func wantWGErrPrefix(t *testing.T, err error, prefix string) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want prefix %q", prefix)
	}
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("error = %q, want prefix %q", err.Error(), prefix)
	}
}
