package bridge

import (
	"bytes"
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

// methods returns the methods of the recorded calls, in order.
func (m *mockRouteController) methods() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	methods := make([]string, len(m.calls))
	for i, c := range m.calls {
		methods[i] = c.Method
	}
	return methods
}

// reset clears all recorded calls.
func (m *mockRouteController) reset() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// mockMeshSourceRewriter is a test double for MeshSourceRewriter.
// It records all calls and supports configurable error returns per method.
type mockMeshSourceRewriter struct {
	mu sync.Mutex

	calls []mockCall

	addMeshSourceRewriteErr    error
	removeMeshSourceRewriteErr error
	resetMeshSourceRewriteErr  error
}

// Verify mockMeshSourceRewriter satisfies MeshSourceRewriter at compile time.
var _ MeshSourceRewriter = (*mockMeshSourceRewriter)(nil)

func (m *mockMeshSourceRewriter) AddMeshSourceRewrite(fromIface, meshIface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "AddMeshSourceRewrite", Args: []interface{}{fromIface, meshIface}})
	err := m.addMeshSourceRewriteErr
	m.mu.Unlock()
	return err
}

func (m *mockMeshSourceRewriter) RemoveMeshSourceRewrite(fromIface, meshIface string) error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "RemoveMeshSourceRewrite", Args: []interface{}{fromIface, meshIface}})
	err := m.removeMeshSourceRewriteErr
	m.mu.Unlock()
	return err
}

func (m *mockMeshSourceRewriter) ResetMeshSourceRewrite() error {
	m.mu.Lock()
	m.calls = append(m.calls, mockCall{Method: "ResetMeshSourceRewrite"})
	err := m.resetMeshSourceRewriteErr
	m.mu.Unlock()
	return err
}

// callsFor returns all recorded calls for the given method name.
func (m *mockMeshSourceRewriter) callsFor(method string) []mockCall {
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

// methods returns the methods of the recorded calls, in order.
func (m *mockMeshSourceRewriter) methods() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	methods := make([]string, len(m.calls))
	for i, c := range m.calls {
		methods[i] = c.Method
	}
	return methods
}

// reset clears all recorded calls.
func (m *mockMeshSourceRewriter) reset() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// mockNATExempter is a test double for NATExempter. It records all calls and
// supports configurable error returns per method. With snapshot set, each
// call also keeps what snapshot returned as it was made, which is how a test
// tells the calls of other doubles that came before an exemption call from
// those that came after it.
type mockNATExempter struct {
	mu sync.Mutex

	calls []mockCall
	// before holds, for each recorded call, what snapshot returned when it
	// was made.
	before [][]string
	// snapshot, when set, is called by each method before it records the
	// call, outside mu.
	snapshot func() []string

	exemptFromNATErr      error
	unexemptFromNATErr    error
	resetNATExemptionsErr error
}

// Verify mockNATExempter satisfies NATExempter at compile time.
var _ NATExempter = (*mockNATExempter)(nil)

func (m *mockNATExempter) ExemptFromNAT(iface string) error {
	return m.record(mockCall{Method: "ExemptFromNAT", Args: []interface{}{iface}}, &m.exemptFromNATErr)
}

func (m *mockNATExempter) UnexemptFromNAT(iface string) error {
	return m.record(mockCall{Method: "UnexemptFromNAT", Args: []interface{}{iface}}, &m.unexemptFromNATErr)
}

func (m *mockNATExempter) ResetNATExemptions() error {
	return m.record(mockCall{Method: "ResetNATExemptions"}, &m.resetNATExemptionsErr)
}

// record records call with the snapshot taken as it was made and returns the
// error *errp holds.
func (m *mockNATExempter) record(call mockCall, errp *error) error {
	m.mu.Lock()
	snapshot := m.snapshot
	m.mu.Unlock()
	var before []string
	if snapshot != nil {
		before = snapshot()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, call)
	m.before = append(m.before, before)
	return *errp
}

// set runs f on the double under its mutex.
func (m *mockNATExempter) set(f func(m *mockNATExempter)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

// callsFor returns all recorded calls for the given method name.
func (m *mockNATExempter) callsFor(method string) []mockCall {
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

// methods returns the methods of the recorded calls, in order.
func (m *mockNATExempter) methods() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	methods := make([]string, len(m.calls))
	for i, c := range m.calls {
		methods[i] = c.Method
	}
	return methods
}

// snapshots returns, for each recorded call of method in order, what
// snapshot returned when it was made.
func (m *mockNATExempter) snapshots(method string) [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result [][]string
	for i, c := range m.calls {
		if c.Method == method {
			result = append(result, m.before[i])
		}
	}
	return result
}

// reset clears all recorded calls.
func (m *mockNATExempter) reset() {
	m.mu.Lock()
	m.calls, m.before = nil, nil
	m.mu.Unlock()
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

// debugLogger returns a debug-level text logger and the buffer it writes to,
// for asserting the levels and attributes a controller emits.
func debugLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}
