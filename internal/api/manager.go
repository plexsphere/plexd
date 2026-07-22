package api

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ReconcileTrigger requests a full state reconcile. *reconcile.Reconciler satisfies it.
type ReconcileTrigger interface {
	TriggerReconcile()
}

// SSEManager is the top-level orchestrator that wires SSEStream,
// ReconnectEngine, EventVerifier, and EventDispatcher together.
type SSEManager struct {
	client     *ControlPlane
	verifier   EventVerifier
	dispatcher *EventDispatcher
	reconnect  *ReconnectEngine
	logger     *slog.Logger

	mu               sync.Mutex
	cancel           context.CancelFunc
	pollFunc         PollFunc
	idleTimeout      time.Duration
	reconcileTrigger ReconcileTrigger
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

// Mode returns the delivery mode currently reported by the reconnect engine.
func (m *SSEManager) Mode() DeliveryMode {
	return m.reconnect.Mode()
}

// SetOnModeChange registers a callback invoked on every delivery-mode
// transition. The callback may be nil.
func (m *SSEManager) SetOnModeChange(fn func(DeliveryMode)) {
	m.reconnect.SetOnModeChange(fn)
}

// SetPollFunc sets the function called during polling fallback to fetch full state.
func (m *SSEManager) SetPollFunc(fn PollFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pollFunc = fn
}

// SetIdleTimeout sets the SSE idle timeout used for connections opened by Start.
// A zero duration falls back to DefaultSSEIdleTimeout.
func (m *SSEManager) SetIdleTimeout(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idleTimeout = d
}

// SetReprobeInterval sets how often pull-only mode re-probes the SSE endpoint.
// It delegates to the reconnect engine.
func (m *SSEManager) SetReprobeInterval(d time.Duration) {
	m.reconnect.SetReprobeInterval(d)
}

// SetReconcileTrigger sets the trigger fired once after every successful SSE
// connect so the client covers replay gaps with a full reconcile pull. A nil
// trigger disables the pull.
func (m *SSEManager) SetReconcileTrigger(t ReconcileTrigger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileTrigger = t
}

// Start begins the SSE connection loop with automatic reconnection.
// It blocks until the context is cancelled, Shutdown is called, or a
// permanent error occurs.
func (m *SSEManager) Start(ctx context.Context, nodeID string) error {
	ctx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	m.cancel = cancel
	pollFn := m.pollFunc
	idleTimeout := m.idleTimeout
	trigger := m.reconcileTrigger
	m.mu.Unlock()
	defer cancel()

	if idleTimeout == 0 {
		idleTimeout = DefaultSSEIdleTimeout
	}

	stream := NewSSEStream(m.client, m.verifier, m.dispatcher, idleTimeout, m.logger)

	// On every real HTTP 200 the engine's mode flips to streaming and the
	// client fires exactly one reconcile pull to cover any replay gap. A nil
	// trigger tolerates the feature being off.
	stream.SetOnConnected(func() {
		m.reconnect.notifyConnected()
		if trigger != nil {
			trigger.TriggerReconcile()
		}
	})

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
