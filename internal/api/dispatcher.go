package api

import (
	"context"
	"log/slog"
	"sync"
)

// EventHandler is a function that handles a verified SSE event.
type EventHandler func(ctx context.Context, envelope SignedEnvelope) error

// EventDispatcher routes verified events to registered handlers by event type.
type EventDispatcher struct {
	mu       sync.RWMutex
	handlers map[string][]EventHandler
	logger   *slog.Logger
}

// NewEventDispatcher creates a new EventDispatcher.
func NewEventDispatcher(logger *slog.Logger) *EventDispatcher {
	return &EventDispatcher{
		handlers: make(map[string][]EventHandler),
		logger:   logger,
	}
}

// Register adds a handler for the given event type.
// Multiple handlers can be registered for the same event type.
func (d *EventDispatcher) Register(eventType string, handler EventHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[eventType] = append(d.handlers[eventType], handler)
}

// Dispatch invokes all handlers registered for the event's type.
// Handler errors are logged but do not stop processing of subsequent handlers.
// Events with no registered handler are logged at debug level and discarded.
func (d *EventDispatcher) Dispatch(ctx context.Context, envelope SignedEnvelope) {
	d.mu.RLock()
	handlers, ok := d.handlers[envelope.EventType]
	d.mu.RUnlock()

	if !ok || len(handlers) == 0 {
		d.logger.Debug("no handler registered for event type",
			"event_type", envelope.EventType,
			"event_id", envelope.EventID,
		)
		return
	}

	for i, handler := range handlers {
		if err := handler(ctx, envelope); err != nil {
			d.logger.Error("event handler failed",
				"event_type", envelope.EventType,
				"event_id", envelope.EventID,
				"handler_index", i,
				"error", err,
			)
		}
	}
}
