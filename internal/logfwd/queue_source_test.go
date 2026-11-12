package logfwd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQueueSource_CollectEmpty(t *testing.T) {
	src := NewQueueSource("host1")

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries != nil {
		t.Fatalf("Collect() = %v, want nil", entries)
	}
}

func TestQueueSource_CollectReturnsAndEmpties(t *testing.T) {
	src := NewQueueSource("host1")
	first := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	src.Add(first, "info", `level=INFO msg="policy rule allowed connection"`)
	src.Add(second, "warning", `level=WARN msg="policy connection lines dropped"`)

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	want := []struct {
		ts       time.Time
		severity string
		message  string
	}{
		{first, "info", `level=INFO msg="policy rule allowed connection"`},
		{second, "warning", `level=WARN msg="policy connection lines dropped"`},
	}
	for i, w := range want {
		e := entries[i]
		if !e.Timestamp.Equal(w.ts) {
			t.Errorf("entries[%d].Timestamp = %v, want %v", i, e.Timestamp, w.ts)
		}
		if e.Source != "plexd" {
			t.Errorf("entries[%d].Source = %q, want %q", i, e.Source, "plexd")
		}
		if e.Unit != "plexd" {
			t.Errorf("entries[%d].Unit = %q, want %q", i, e.Unit, "plexd")
		}
		if e.Hostname != "host1" {
			t.Errorf("entries[%d].Hostname = %q, want %q", i, e.Hostname, "host1")
		}
		if e.Severity != w.severity {
			t.Errorf("entries[%d].Severity = %q, want %q", i, e.Severity, w.severity)
		}
		if e.Message != w.message {
			t.Errorf("entries[%d].Message = %q, want %q", i, e.Message, w.message)
		}
	}

	again, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if again != nil {
		t.Fatalf("second Collect() = %v, want nil", again)
	}
}

func TestQueueSource_DropsOldestBeyondCapacity(t *testing.T) {
	src := NewQueueSource("host1")
	ts := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for i := range queueSourceCapacity + 1 {
		src.Add(ts, "info", fmt.Sprintf("line %d", i))
	}

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != queueSourceCapacity {
		t.Fatalf("len(entries) = %d, want %d", len(entries), queueSourceCapacity)
	}
	if got, want := entries[0].Message, "line 1"; got != want {
		t.Errorf("first entry = %q, want %q", got, want)
	}
	if got, want := entries[len(entries)-1].Message, fmt.Sprintf("line %d", queueSourceCapacity); got != want {
		t.Errorf("last entry = %q, want %q", got, want)
	}
}

// TestQueueSource_ConcurrentAddAndCollect adds from several goroutines while
// another collects, the way the policy connection logger and the forwarder
// share the queue. Under -race it proves the locking; the count proves no
// entry is lost below the capacity.
func TestQueueSource_ConcurrentAddAndCollect(t *testing.T) {
	const writers, perWriter = 8, 100
	src := NewQueueSource("host1")
	ts := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				src.Add(ts, "info", fmt.Sprintf("writer %d line %d", w, i))
			}
		}()
	}

	done := make(chan struct{})
	collected := make(chan int)
	go func() {
		n := 0
		for {
			entries, _ := src.Collect(context.Background())
			n += len(entries)
			select {
			case <-done:
				entries, _ = src.Collect(context.Background())
				collected <- n + len(entries)
				return
			default:
			}
		}
	}()

	wg.Wait()
	close(done)
	if got, want := <-collected, writers*perWriter; got != want {
		t.Fatalf("collected %d entries, want %d", got, want)
	}
}
