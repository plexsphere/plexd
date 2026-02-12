package api

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrSSEIdleTimeout is returned when the SSE stream receives no data
// within the configured idle timeout period.
var ErrSSEIdleTimeout = errors.New("api: SSE idle timeout")

// idleTimeoutReader wraps an io.ReadCloser and enforces an idle timeout.
// If no data is read within the timeout, the underlying reader is closed
// to unblock any pending Read call, and subsequent reads return ErrSSEIdleTimeout.
type idleTimeoutReader struct {
	rc      io.ReadCloser
	timer   *time.Timer
	timeout time.Duration

	mu      sync.Mutex
	err     error
	stopped bool
}

// newIdleTimeoutReader creates a reader that closes the underlying reader
// if no data arrives within the given timeout.
func newIdleTimeoutReader(rc io.ReadCloser, timeout time.Duration) *idleTimeoutReader {
	r := &idleTimeoutReader{
		rc:      rc,
		timeout: timeout,
	}
	if timeout > 0 {
		r.timer = time.AfterFunc(timeout, r.onTimeout)
	}
	return r
}

// Read implements io.Reader. Each successful read resets the idle timer.
func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)

	r.mu.Lock()
	idleErr := r.err
	r.mu.Unlock()

	if idleErr != nil {
		return 0, idleErr
	}

	if n > 0 && r.timer != nil {
		r.timer.Reset(r.timeout)
	}

	return n, err
}

// Err returns any idle timeout error that occurred.
func (r *idleTimeoutReader) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Stop cancels the idle timer. Must be called when done with the reader.
func (r *idleTimeoutReader) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.timer != nil {
		r.timer.Stop()
	}
}

// onTimeout is called when the idle timer fires.
func (r *idleTimeoutReader) onTimeout() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.err = ErrSSEIdleTimeout
	// Close the underlying reader to unblock any pending Read call.
	r.rc.Close()
}

// SSEEvent represents a single parsed SSE event.
type SSEEvent struct {
	Type string // from "event:" field, defaults to "message"
	Data string // concatenated data fields
	ID   string // from "id:" field
}

// RetryCallback is called when the SSE server sends a retry: field.
type RetryCallback func(interval time.Duration)

// SSEParser reads from an io.Reader and emits parsed SSE events.
type SSEParser struct {
	scanner       *bufio.Scanner
	lastEventID   string
	retryCallback RetryCallback
}

// NewSSEParser creates a parser reading from the given reader.
func NewSSEParser(r io.Reader) *SSEParser {
	return &SSEParser{
		scanner: bufio.NewScanner(r),
	}
}

// SetRetryCallback sets the function called when a retry: field is received.
func (p *SSEParser) SetRetryCallback(cb RetryCallback) {
	p.retryCallback = cb
}

// LastEventID returns the most recently received event ID.
func (p *SSEParser) LastEventID() string {
	return p.lastEventID
}

// Next reads lines until a complete event is found. Returns the event
// and true, or a zero event and false when the reader is exhausted.
func (p *SSEParser) Next() (SSEEvent, bool) {
	// Per W3C SSE spec:
	// - Lines starting with ":" are comments (ignore but useful as keepalives)
	// - "event:" sets the event type
	// - "data:" appends to the data buffer (multiple data lines concatenated with \n)
	// - "id:" sets the last event ID (also stored on the event)
	// - "retry:" sends a retry interval to the client
	// - An empty line dispatches the accumulated event
	// - Fields with no colon use the whole line as field name with empty value

	var eventType string
	var data []string
	var id string

	for p.scanner.Scan() {
		line := p.scanner.Text()

		// Empty line dispatches the event
		if line == "" {
			if len(data) > 0 {
				if eventType == "" {
					eventType = "message"
				}
				evt := SSEEvent{
					Type: eventType,
					Data: strings.Join(data, "\n"),
					ID:   id,
				}
				if id != "" {
					p.lastEventID = id
				}
				return evt, true
			}
			// Reset for next event
			eventType = ""
			data = nil
			id = ""
			continue
		}

		// Comment line
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Parse field
		field, value, _ := strings.Cut(line, ":")
		// Remove leading space from value per spec
		value = strings.TrimPrefix(value, " ")

		switch field {
		case "event":
			eventType = value
		case "data":
			data = append(data, value)
		case "id":
			id = value
		case "retry":
			if ms, err := strconv.Atoi(value); err == nil && p.retryCallback != nil {
				p.retryCallback(time.Duration(ms) * time.Millisecond)
			}
		}
	}

	return SSEEvent{}, false
}

// SSEStream connects to the SSE endpoint, parses events, verifies envelopes,
// and dispatches them to registered handlers.
type SSEStream struct {
	client      *ControlPlane
	verifier    EventVerifier
	dispatcher  *EventDispatcher
	logger      *slog.Logger
	idleTimeout time.Duration

	mu          sync.Mutex
	lastEventID string
}

// NewSSEStream creates a new SSEStream.
func NewSSEStream(client *ControlPlane, verifier EventVerifier, dispatcher *EventDispatcher, idleTimeout time.Duration, logger *slog.Logger) *SSEStream {
	if verifier == nil {
		verifier = NoOpVerifier{}
	}
	return &SSEStream{
		client:      client,
		verifier:    verifier,
		dispatcher:  dispatcher,
		logger:      logger,
		idleTimeout: idleTimeout,
	}
}

// LastEventID returns the last received event ID (for reconnection).
func (s *SSEStream) LastEventID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastEventID
}

// Connect establishes the SSE connection and processes events until
// the connection drops or context is cancelled.
// Returns nil when the connection closes cleanly, or an error.
func (s *SSEStream) Connect(ctx context.Context, nodeID string) error {
	s.mu.Lock()
	lastID := s.lastEventID
	s.mu.Unlock()

	resp, err := s.client.ConnectSSE(ctx, nodeID, lastID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Wrap body with idle timeout enforcement (REQ-011).
	// If no data arrives within idleTimeout, the reader returns an error
	// which breaks out of the parse loop and triggers reconnection.
	idleReader := newIdleTimeoutReader(resp.Body, s.idleTimeout)
	defer idleReader.Stop()

	parser := NewSSEParser(idleReader)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		evt, ok := parser.Next()
		if !ok {
			// Stream ended — check if due to idle timeout.
			if err := idleReader.Err(); err != nil {
				return err
			}
			return nil
		}

		// Update last event ID
		if evt.ID != "" {
			s.mu.Lock()
			s.lastEventID = evt.ID
			s.mu.Unlock()
		}

		// Parse envelope from data
		envelope, err := ParseEnvelope([]byte(evt.Data))
		if err != nil {
			s.logger.Error("failed to parse event envelope",
				"event_type", evt.Type,
				"event_id", evt.ID,
				"error", err,
			)
			continue // skip malformed events
		}

		// Verify envelope
		if err := s.verifier.Verify(ctx, envelope); err != nil {
			s.logger.Error("event verification failed",
				"event_type", envelope.EventType,
				"event_id", envelope.EventID,
				"error", err,
			)
			continue
		}

		// Dispatch
		s.dispatcher.Dispatch(ctx, envelope)
	}
}
