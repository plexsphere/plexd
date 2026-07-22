package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// SSEParser tests
// ---------------------------------------------------------------------------

func TestSSEParser_SingleLineEvent(t *testing.T) {
	input := "event: node_state_updated\ndata: {\"foo\":\"bar\"}\nid: evt_001\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Type != "node_state_updated" {
		t.Errorf("Type = %q, want %q", evt.Type, "node_state_updated")
	}
	if evt.Data != `{"foo":"bar"}` {
		t.Errorf("Data = %q, want %q", evt.Data, `{"foo":"bar"}`)
	}
	if evt.ID != "evt_001" {
		t.Errorf("ID = %q, want %q", evt.ID, "evt_001")
	}
}

func TestSSEParser_MultiLineData(t *testing.T) {
	input := "data: line1\ndata: line2\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "line1\nline2" {
		t.Errorf("Data = %q, want %q", evt.Data, "line1\nline2")
	}
}

func TestSSEParser_CommentLinesIgnored(t *testing.T) {
	input := ":keepalive\ndata: hello\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "hello" {
		t.Errorf("Data = %q, want %q", evt.Data, "hello")
	}

	// No more events
	_, ok = parser.Next()
	if ok {
		t.Error("expected no more events after comment + single event")
	}
}

func TestSSEParser_RetryFieldUpdatesInterval(t *testing.T) {
	input := "retry: 5000\ndata: x\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	var gotInterval time.Duration
	parser.SetRetryCallback(func(interval time.Duration) {
		gotInterval = interval
	})

	parser.Next()

	if gotInterval != 5*time.Second {
		t.Errorf("retry interval = %v, want %v", gotInterval, 5*time.Second)
	}
}

func TestSSEParser_DefaultEventType(t *testing.T) {
	input := "data: test\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Type != "message" {
		t.Errorf("Type = %q, want %q", evt.Type, "message")
	}
}

func TestSSEParser_LastEventIDTracked(t *testing.T) {
	input := "data: first\nid: id-1\n\ndata: second\nid: id-2\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	parser.Next()
	if parser.LastEventID() != "id-1" {
		t.Errorf("LastEventID after first = %q, want %q", parser.LastEventID(), "id-1")
	}

	parser.Next()
	if parser.LastEventID() != "id-2" {
		t.Errorf("LastEventID after second = %q, want %q", parser.LastEventID(), "id-2")
	}
}

func TestSSEParser_EmptyLinesResetState(t *testing.T) {
	// First block: event: type1 with no data -> empty line dispatches nothing (no data).
	// Second block: data: value -> dispatches with default type "message".
	input := "event: type1\n\ndata: value\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	// The first block (event: type1) has no data lines, so it's not dispatched.
	// The second block has data: value with no event: field, so Type defaults to "message".
	if evt.Type != "message" {
		t.Errorf("Type = %q, want %q", evt.Type, "message")
	}
	if evt.Data != "value" {
		t.Errorf("Data = %q, want %q", evt.Data, "value")
	}
}

// ---------------------------------------------------------------------------
// SSEStream tests
// ---------------------------------------------------------------------------

func sseHandler(events string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, events)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func newTestSSEStream(t *testing.T, srv *httptest.Server) (*SSEStream, *EventDispatcher) {
	t.Helper()
	cfg := Config{BaseURL: srv.URL}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")
	dispatcher := NewEventDispatcher(logger)
	stream := NewSSEStream(client, nil, dispatcher, 90*time.Second, logger)
	return stream, dispatcher
}

func TestSSE_LastEventIDSentOnReconnect(t *testing.T) {
	var gotLastEventID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLastEventID = r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		// Send a minimal event so the stream ends cleanly.
		fmt.Fprint(w, "data: {\"id\":\"e1\",\"type\":\"node_state_updated\",\"issued_at\":\"2025-01-01T00:00:00Z\",\"payload\":{},\"signature\":\"s\"}\nid: e1\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	stream, _ := newTestSSEStream(t, srv)

	// Preset lastEventID to simulate reconnection.
	stream.mu.Lock()
	stream.lastEventID = "evt-42"
	stream.mu.Unlock()

	err := stream.Connect(context.Background(), "n1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if gotLastEventID != "evt-42" {
		t.Errorf("Last-Event-ID = %q, want %q", gotLastEventID, "evt-42")
	}
}

func TestSSE_NoLastEventIDOnFirstConnect(t *testing.T) {
	var gotLastEventID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLastEventID = r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: {\"id\":\"e1\",\"type\":\"node_state_updated\",\"issued_at\":\"2025-01-01T00:00:00Z\",\"payload\":{},\"signature\":\"s\"}\nid: e1\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	stream, _ := newTestSSEStream(t, srv)

	err := stream.Connect(context.Background(), "n1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if gotLastEventID != "" {
		t.Errorf("Last-Event-ID = %q, want empty", gotLastEventID)
	}
}

func TestSSE_MalformedDataSkipped(t *testing.T) {
	envelopeJSON := `{"id":"evt_002","type":"node_state_updated","issued_at":"2025-01-01T00:00:00Z","payload":{},"signature":"sig"}`
	sseData := fmt.Sprintf("data: NOT-VALID-JSON\nid: bad\n\nevent: node_state_updated\ndata: %s\nid: evt_002\n\n", envelopeJSON)

	var dispatched atomic.Int64
	srv := httptest.NewServer(sseHandler(sseData))
	defer srv.Close()

	stream, dispatcher := newTestSSEStream(t, srv)

	dispatcher.Register("node_state_updated", func(_ context.Context, env Envelope) error {
		dispatched.Add(1)
		if env.ID != "evt_002" {
			t.Errorf("EventID = %q, want %q", env.ID, "evt_002")
		}
		return nil
	})

	err := stream.Connect(context.Background(), "n1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if dispatched.Load() != 1 {
		t.Errorf("dispatched = %d, want 1 (malformed event should be skipped)", dispatched.Load())
	}
}

func TestSSE_GracefulShutdownOnContextCancel(t *testing.T) {
	// Server that holds connection open until client disconnects.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Block until the client goes away.
		<-r.Context().Done()
	}))
	defer srv.Close()

	stream, _ := newTestSSEStream(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- stream.Connect(ctx, "n1")
	}()

	// Give Connect a moment to establish then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		// Either nil or context.Canceled is acceptable.
		if err != nil && err != context.Canceled {
			t.Fatalf("Connect returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return within 2s after context cancellation")
	}
}

func TestSSE_DispatchesVerifiedEvents(t *testing.T) {
	envelopeJSON := `{"id":"evt_001","type":"node_state_updated","issued_at":"2025-01-01T00:00:00Z","payload":{},"signature":"sig"}`
	sseData := fmt.Sprintf("event: node_state_updated\ndata: %s\nid: evt_001\n\n", envelopeJSON)

	srv := httptest.NewServer(sseHandler(sseData))
	defer srv.Close()

	stream, dispatcher := newTestSSEStream(t, srv)

	var called atomic.Int64
	var receivedEnvelope Envelope

	dispatcher.Register("node_state_updated", func(_ context.Context, env Envelope) error {
		called.Add(1)
		receivedEnvelope = env
		return nil
	})

	err := stream.Connect(context.Background(), "n1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if called.Load() != 1 {
		t.Fatalf("handler called %d times, want 1", called.Load())
	}
	if receivedEnvelope.Type != "node_state_updated" {
		t.Errorf("EventType = %q, want %q", receivedEnvelope.Type, "node_state_updated")
	}
	if receivedEnvelope.ID != "evt_001" {
		t.Errorf("EventID = %q, want %q", receivedEnvelope.ID, "evt_001")
	}

	// Verify lastEventID was tracked.
	if stream.LastEventID() != "evt_001" {
		t.Errorf("LastEventID = %q, want %q", stream.LastEventID(), "evt_001")
	}
}

// TestSSE_DispatchesByEnvelopeTypeNotFrame proves dispatch keys on the verified
// envelope's type, never the SSE frame's event: field. Here the frame advertises
// a different event name than the envelope carries.
func TestSSE_DispatchesByEnvelopeTypeNotFrame(t *testing.T) {
	envelopeJSON := `{"id":"evt_777","type":"node_state_updated","issued_at":"2025-01-01T00:00:00Z","payload":{},"signature":"sig"}`
	// The SSE event: field deliberately disagrees with the envelope type.
	sseData := fmt.Sprintf("event: policy_updated\ndata: %s\nid: evt_777\n\n", envelopeJSON)

	srv := httptest.NewServer(sseHandler(sseData))
	defer srv.Close()

	stream, dispatcher := newTestSSEStream(t, srv)

	var peerAdded, policyUpdated atomic.Int64
	dispatcher.Register("node_state_updated", func(_ context.Context, _ Envelope) error {
		peerAdded.Add(1)
		return nil
	})
	dispatcher.Register("policy_updated", func(_ context.Context, _ Envelope) error {
		policyUpdated.Add(1)
		return nil
	})

	if err := stream.Connect(context.Background(), "n1"); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if peerAdded.Load() != 1 {
		t.Errorf("node_state_updated handler called %d times, want 1 (dispatch must key on envelope type)", peerAdded.Load())
	}
	if policyUpdated.Load() != 0 {
		t.Errorf("policy_updated handler called %d times, want 0 (SSE frame event: must be ignored)", policyUpdated.Load())
	}
}

// ---------------------------------------------------------------------------
// SSE parser edge case tests
// ---------------------------------------------------------------------------

func TestSSEParser_ColonInDataValue(t *testing.T) {
	// Colon in data value after the "data:" prefix should be preserved.
	input := "data: key:value:more\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "key:value:more" {
		t.Errorf("Data = %q, want %q", evt.Data, "key:value:more")
	}
}

func TestSSEParser_InvalidRetryField(t *testing.T) {
	// Non-numeric retry field should be ignored.
	input := "retry: not-a-number\ndata: x\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	var retryCalled bool
	parser.SetRetryCallback(func(interval time.Duration) {
		retryCalled = true
	})

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "x" {
		t.Errorf("Data = %q, want %q", evt.Data, "x")
	}
	if retryCalled {
		t.Error("retry callback should not be called for non-numeric retry value")
	}
}

func TestSSEParser_ConsecutiveEmptyLines(t *testing.T) {
	// Multiple consecutive empty lines should not produce extra events.
	input := "\n\n\ndata: hello\n\n\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "hello" {
		t.Errorf("Data = %q, want %q", evt.Data, "hello")
	}

	// No more events.
	_, ok = parser.Next()
	if ok {
		t.Error("expected no more events after consecutive empty lines")
	}
}

func TestSSEParser_FieldWithNoColon(t *testing.T) {
	// Per spec, a line with no colon uses the whole line as field name with empty value.
	// Unknown fields are ignored, so this should not affect event parsing.
	input := "unknownfield\ndata: test\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "test" {
		t.Errorf("Data = %q, want %q", evt.Data, "test")
	}
}

func TestSSEParser_EmptyDataField(t *testing.T) {
	// "data:" with no value should produce an empty string in the data.
	input := "data:\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt, ok := parser.Next()
	if !ok {
		t.Fatal("expected an event, got none")
	}
	if evt.Data != "" {
		t.Errorf("Data = %q, want empty string", evt.Data)
	}
}

func TestSSEParser_MultipleEventsInSequence(t *testing.T) {
	input := "event: a\ndata: first\n\nevent: b\ndata: second\n\n"
	parser := NewSSEParser(strings.NewReader(input))

	evt1, ok := parser.Next()
	if !ok {
		t.Fatal("expected first event")
	}
	if evt1.Type != "a" || evt1.Data != "first" {
		t.Errorf("event 1: Type=%q Data=%q, want Type=a Data=first", evt1.Type, evt1.Data)
	}

	evt2, ok := parser.Next()
	if !ok {
		t.Fatal("expected second event")
	}
	if evt2.Type != "b" || evt2.Data != "second" {
		t.Errorf("event 2: Type=%q Data=%q, want Type=b Data=second", evt2.Type, evt2.Data)
	}
}

// ---------------------------------------------------------------------------
// SSE on-connected hook and 400 cursor-reset tests
// ---------------------------------------------------------------------------

// TestSSE_OnConnectedFiresOncePerConnect proves the on-connected hook fires
// exactly once for every successful connect: two sequential Connect calls
// against a healthy server yield exactly two invocations.
func TestSSE_OnConnectedFiresOncePerConnect(t *testing.T) {
	sseData := "data: {\"id\":\"e1\",\"type\":\"node_state_updated\",\"issued_at\":\"2025-01-01T00:00:00Z\",\"payload\":{},\"signature\":\"s\"}\nid: e1\n\n"
	srv := httptest.NewServer(sseHandler(sseData))
	defer srv.Close()

	stream, _ := newTestSSEStream(t, srv)

	var connects atomic.Int64
	stream.SetOnConnected(func() { connects.Add(1) })

	for i := 0; i < 2; i++ {
		if err := stream.Connect(context.Background(), "n1"); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
	}

	if got := connects.Load(); got != 2 {
		t.Errorf("onConnected fired %d times, want 2", got)
	}
}

// TestSSE_BadRequestClearsCursor proves that a 400 while a cursor was sent
// clears the stored cursor so the next connect tails from now: the error is
// returned unchanged and the next request carries no Last-Event-ID header.
func TestSSE_BadRequestClearsCursor(t *testing.T) {
	var mu sync.Mutex
	var requestCount int
	var lastEventIDs []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		n := requestCount
		lastEventIDs = append(lastEventIDs, r.Header.Get("Last-Event-ID"))
		mu.Unlock()

		if n == 1 {
			// Reject the cursor with a problem+json 400 so errors.Is matches.
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"title":"bad cursor","code":"invalid_cursor"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: {\"id\":\"e1\",\"type\":\"node_state_updated\",\"issued_at\":\"2025-01-01T00:00:00Z\",\"payload\":{},\"signature\":\"s\"}\nid: e1\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()

	stream, _ := newTestSSEStream(t, srv)

	// Seed a cursor to simulate a prior stream position.
	stream.mu.Lock()
	stream.lastEventID = "evt-42"
	stream.mu.Unlock()

	err := stream.Connect(context.Background(), "n1")
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("Connect error = %v, want ErrBadRequest", err)
	}
	if got := stream.LastEventID(); got != "" {
		t.Errorf("cursor after 400 = %q, want empty", got)
	}

	// The next connect must tail from now: no Last-Event-ID header.
	if err := stream.Connect(context.Background(), "n1"); err != nil {
		t.Fatalf("second Connect: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(lastEventIDs) < 2 {
		t.Fatalf("expected 2 requests, got %d", len(lastEventIDs))
	}
	if lastEventIDs[0] != "evt-42" {
		t.Errorf("first request Last-Event-ID = %q, want %q", lastEventIDs[0], "evt-42")
	}
	if lastEventIDs[1] != "" {
		t.Errorf("second request Last-Event-ID = %q, want empty", lastEventIDs[1])
	}
}

// TestSSE_BadRequestNoCursorNoReset proves a 400 with no cursor sent gets no
// special handling: the error propagates unchanged and the cursor stays empty.
func TestSSE_BadRequestNoCursorNoReset(t *testing.T) {
	var gotLastEventID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLastEventID = r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"title":"bad request","code":"malformed"}`)
	}))
	defer srv.Close()

	stream, _ := newTestSSEStream(t, srv)

	err := stream.Connect(context.Background(), "n1")
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("Connect error = %v, want ErrBadRequest", err)
	}
	if gotLastEventID != "" {
		t.Errorf("Last-Event-ID = %q, want empty (no cursor was seeded)", gotLastEventID)
	}
	if got := stream.LastEventID(); got != "" {
		t.Errorf("cursor = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// SSE idle timeout test
// ---------------------------------------------------------------------------

func TestSSE_IdleTimeoutTriggersReconnect(t *testing.T) {
	// Server holds connection open without sending data — triggers idle timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Hold the connection open without sending data.
		<-r.Context().Done()
	}))
	defer srv.Close()

	cfg := Config{BaseURL: srv.URL}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := NewControlPlane(cfg, "1.0.0-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAuthToken("test-token")

	dispatcher := NewEventDispatcher(logger)
	// Very short idle timeout for testing.
	stream := NewSSEStream(client, nil, dispatcher, 100*time.Millisecond, logger)

	done := make(chan error, 1)
	go func() {
		done <- stream.Connect(context.Background(), "n1")
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrSSEIdleTimeout) {
			t.Fatalf("expected ErrSSEIdleTimeout, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return within 5s — idle timeout not enforced")
	}
}
