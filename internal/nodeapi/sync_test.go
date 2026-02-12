package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"go.uber.org/goleak"
)

var errSyncFailed = errors.New("sync failed")

type mockSyncClient struct {
	mu    sync.Mutex
	calls []api.ReportSyncRequest
	err   error
}

func (m *mockSyncClient) SyncReports(_ context.Context, _ string, req api.ReportSyncRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, req)
	return m.err
}

func (m *mockSyncClient) getCalls() []api.ReportSyncRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	dst := make([]api.ReportSyncRequest, len(m.calls))
	copy(dst, m.calls)
	return dst
}

func (m *mockSyncClient) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func testEntry(key string) api.ReportEntry {
	return api.ReportEntry{
		Key:         key,
		ContentType: "application/json",
		Payload:     json.RawMessage(`{"v":1}`),
		Version:     1,
		UpdatedAt:   time.Now(),
	}
}

func TestReportSync_SingleWriteSyncedAfterDebounce(t *testing.T) {
	mock := &mockSyncClient{}
	syncer := NewReportSyncer(mock, "node-1", 20*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- syncer.Run(ctx) }()

	entries := []api.ReportEntry{testEntry("key-1")}
	syncer.NotifyChange(entries, nil)

	// Wait for debounce + processing.
	time.Sleep(100 * time.Millisecond)

	calls := mock.getCalls()
	if len(calls) != 1 {
		t.Fatalf("SyncReports called %d times, want 1", len(calls))
	}
	if len(calls[0].Entries) != 1 {
		t.Fatalf("entries count = %d, want 1", len(calls[0].Entries))
	}
	if calls[0].Entries[0].Key != "key-1" {
		t.Errorf("entry key = %q, want %q", calls[0].Entries[0].Key, "key-1")
	}

	cancel()
	<-done
}

func TestReportSync_MultipleWritesCoalesced(t *testing.T) {
	mock := &mockSyncClient{}
	syncer := NewReportSyncer(mock, "node-1", 50*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- syncer.Run(ctx) }()

	// Send two notifications rapidly.
	syncer.NotifyChange([]api.ReportEntry{testEntry("key-1")}, nil)
	time.Sleep(5 * time.Millisecond)
	syncer.NotifyChange([]api.ReportEntry{testEntry("key-2")}, nil)

	// Wait for debounce + processing.
	time.Sleep(150 * time.Millisecond)

	calls := mock.getCalls()
	if len(calls) != 1 {
		t.Fatalf("SyncReports called %d times, want 1", len(calls))
	}
	if len(calls[0].Entries) != 2 {
		t.Fatalf("entries count = %d, want 2", len(calls[0].Entries))
	}

	cancel()
	<-done
}

func TestReportSync_DeleteIncluded(t *testing.T) {
	mock := &mockSyncClient{}
	syncer := NewReportSyncer(mock, "node-1", 20*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- syncer.Run(ctx) }()

	syncer.NotifyChange(nil, []string{"old-key-1", "old-key-2"})

	time.Sleep(100 * time.Millisecond)

	calls := mock.getCalls()
	if len(calls) != 1 {
		t.Fatalf("SyncReports called %d times, want 1", len(calls))
	}
	if len(calls[0].Deleted) != 2 {
		t.Fatalf("deleted count = %d, want 2", len(calls[0].Deleted))
	}
	if calls[0].Deleted[0] != "old-key-1" || calls[0].Deleted[1] != "old-key-2" {
		t.Errorf("deleted = %v, want [old-key-1 old-key-2]", calls[0].Deleted)
	}

	cancel()
	<-done
}

func TestReportSync_RetryOnFailure(t *testing.T) {
	mock := &mockSyncClient{err: errSyncFailed}
	syncer := NewReportSyncer(mock, "node-1", 20*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- syncer.Run(ctx) }()

	syncer.NotifyChange([]api.ReportEntry{testEntry("key-1")}, nil)

	// Wait for first attempt + debounce for retry.
	time.Sleep(100 * time.Millisecond)

	// Clear the error so the retry succeeds.
	mock.setErr(nil)

	// Wait for retry to complete.
	time.Sleep(100 * time.Millisecond)

	calls := mock.getCalls()
	if len(calls) < 2 {
		t.Fatalf("SyncReports called %d times, want >= 2 (initial failure + retry)", len(calls))
	}
	// The retry should include the same entry.
	lastCall := calls[len(calls)-1]
	if len(lastCall.Entries) != 1 || lastCall.Entries[0].Key != "key-1" {
		t.Errorf("retry call entries = %v, want key-1", lastCall.Entries)
	}

	cancel()
	<-done
}

func TestReportSync_ContextCancellation(t *testing.T) {
	mock := &mockSyncClient{}
	syncer := NewReportSyncer(mock, "node-1", 20*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- syncer.Run(ctx) }()

	// Let Run settle into its select loop.
	time.Sleep(10 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Run() = %v, want %v", err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after context cancellation")
	}
}

func TestReportSync_NoGoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	mock := &mockSyncClient{}
	syncer := NewReportSyncer(mock, "node-1", 10*time.Millisecond, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- syncer.Run(ctx) }()

	syncer.NotifyChange([]api.ReportEntry{testEntry("key-1")}, nil)
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done
}
