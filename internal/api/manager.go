package api

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// SSEManager is the top-level orchestrator that wires SSEStream,
// ReconnectEngine, EventVerifier, and EventDispatcher together.
type SSEManager struct {
	client     *ControlPlane
	verifier   EventVerifier
	dispatcher *EventDispatcher
	reconnect  *ReconnectEngine
	logger     *slog.Logger

	mu       sync.Mutex
	cancel   context.CancelFunc
	pollFunc PollFunc
}

// NewSSEManager creates a new SSEManager. If verifier is nil, NoOpVerifier is used.
func NewSSEManager(client *ControlPlane, verifier EventVerifier, logger *slog.Logger) *SSEManager {
	if verifier == nil {
		verifier = NoOpVerifier{}
	}
	return &SSEManager{
		client:     client,
		verifier:   verifier,
		dispatcher: NewEventDispatcher(logger),
		reconnect:  NewReconnectEngine(logger),
		logger:     logger,
	}
}

// RegisterHandler adds a handler for the given event type.
// Must be called before Start.
func (m *SSEManager) RegisterHandler(eventType string, handler EventHandler) {
	m.dispatcher.Register(eventType, handler)
}

// SetReconnectIntervals configures the base and max backoff intervals.
// Useful for testing with fast intervals.
func (m *SSEManager) SetReconnectIntervals(base, max time.Duration) {
	m.reconnect.SetIntervals(base, max)
}

// SetPollingFallback configures when to enter polling mode and how often to poll.
func (m *SSEManager) SetPollingFallback(fallbackAfter, pollInterval time.Duration) {
	m.reconnect.SetPollingFallbackConfig(fallbackAfter, pollInterval)
}

// SetPollFunc sets the function called during polling fallback to fetch full state.
func (m *SSEManager) SetPollFunc(fn PollFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pollFunc = fn
}

// Start begins the SSE connection loop with automatic reconnection.
// It blocks until the context is cancelled, Shutdown is called, or a
// permanent error occurs.
func (m *SSEManager) Start(ctx context.Context, nodeID string) error {
	ctx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	pollFn := m.pollFunc
	m.mu.Unlock()
	defer cancel()

	stream := NewSSEStream(m.client, m.verifier, m.dispatcher, 90*time.Second, m.logger)

	connectFn := func(ctx context.Context) error {
		return stream.Connect(ctx, nodeID)
	}

	if pollFn == nil {
		pollFn = func(ctx context.Context) error {
			_, err := m.client.FetchState(ctx, nodeID)
			return err
		}
	}

	return m.reconnect.Run(ctx, connectFn, pollFn)
}

// Shutdown gracefully stops the manager by cancelling its context.
func (m *SSEManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}
