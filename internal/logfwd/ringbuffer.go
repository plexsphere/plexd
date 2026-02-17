package logfwd

import (
	"sync"

	"github.com/plexsphere/plexd/internal/api"
)

// DefaultRingBufferCapacity is the default number of log lines retained.
const DefaultRingBufferCapacity = 1000

// RingBuffer is a thread-safe, fixed-capacity circular buffer for log entries.
// When the buffer is full, the oldest entry is overwritten.
type RingBuffer struct {
	mu    sync.Mutex
	buf   []api.LogEntry
	cap   int
	head  int // next write position
	count int // number of valid entries
}

// NewRingBuffer creates a RingBuffer with the given capacity.
// If capacity is <= 0, DefaultRingBufferCapacity is used.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = DefaultRingBufferCapacity
	}
	return &RingBuffer{
		buf: make([]api.LogEntry, capacity),
		cap: capacity,
	}
}

// Write adds an entry to the ring buffer, overwriting the oldest if full.
func (rb *RingBuffer) Write(entry api.LogEntry) {
	rb.mu.Lock()
	rb.buf[rb.head] = entry
	rb.head = (rb.head + 1) % rb.cap
	if rb.count < rb.cap {
		rb.count++
	}
	rb.mu.Unlock()
}

// WriteBatch adds multiple entries to the ring buffer.
func (rb *RingBuffer) WriteBatch(entries []api.LogEntry) {
	rb.mu.Lock()
	for _, e := range entries {
		rb.buf[rb.head] = e
		rb.head = (rb.head + 1) % rb.cap
		if rb.count < rb.cap {
			rb.count++
		}
	}
	rb.mu.Unlock()
}

// Recent returns the most recent n entries in chronological order.
// If n exceeds the number of stored entries, all stored entries are returned.
func (rb *RingBuffer) Recent(n int) []api.LogEntry {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if n <= 0 || rb.count == 0 {
		return nil
	}
	if n > rb.count {
		n = rb.count
	}

	result := make([]api.LogEntry, n)
	// Start reading from (head - n) mod cap.
	start := (rb.head - n + rb.cap) % rb.cap
	for i := 0; i < n; i++ {
		result[i] = rb.buf[(start+i)%rb.cap]
	}
	return result
}

// RecentLines returns the message field of the most recent n entries.
func (rb *RingBuffer) RecentLines(n int) []string {
	entries := rb.Recent(n)
	if entries == nil {
		return nil
	}
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = e.Message
	}
	return lines
}

// Len returns the number of entries currently stored.
func (rb *RingBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.count
}
