package nat

import (
	"context"
	"log/slog"
	"sync"
)

// mockBindCall records a single Bind invocation.
type mockBindCall struct {
	ServerAddr string
	LocalPort  int
}

// mockBindResult holds the configured return values for a specific server.
type mockBindResult struct {
	Addr MappedAddress
	Err  error
}

// mockSTUNClient is a test double for STUNClient.
// It records all Bind calls and supports configurable results per server address.
type mockSTUNClient struct {
	mu sync.Mutex

	// Call records
	calls []mockBindCall

	// Per-server results: map server address to {MappedAddress, error}
	results map[string]mockBindResult

	// Default error returned when server not in results map
	defaultErr error
}

func (m *mockSTUNClient) Bind(ctx context.Context, serverAddr string, localPort int) (MappedAddress, error) {
	m.mu.Lock()
	m.calls = append(m.calls, mockBindCall{ServerAddr: serverAddr, LocalPort: localPort})
	results := m.results
	defaultErr := m.defaultErr
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return MappedAddress{}, err
	}

	if results != nil {
		if r, ok := results[serverAddr]; ok {
			return r.Addr, r.Err
		}
	}
	return MappedAddress{}, defaultErr
}

// allCalls returns all recorded Bind calls.
func (m *mockSTUNClient) allCalls() []mockBindCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockBindCall, len(m.calls))
	copy(out, m.calls)
	return out
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}
