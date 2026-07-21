package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// publishedReport records a single PublishReport call.
type publishedReport struct {
	key         string
	contentType string
	payload     []byte
}

// fakeReportPublisher stands in for the node API report store: it records every
// PublishReport call, keeps the resulting per-key payload so ReportPayload can
// serve it back, and can be told to fail for a single key. Failed calls are
// still recorded so a test can assert the key was attempted, but they leave the
// stored payload untouched.
type fakeReportPublisher struct {
	calls   []publishedReport
	stored  map[string][]byte
	failKey string
}

func (f *fakeReportPublisher) PublishReport(key, contentType string, payload json.RawMessage) error {
	f.calls = append(f.calls, publishedReport{
		key:         key,
		contentType: contentType,
		payload:     append([]byte(nil), payload...),
	})
	if key == f.failKey {
		return fmt.Errorf("publish %s failed", key)
	}
	if f.stored == nil {
		f.stored = make(map[string][]byte)
	}
	f.stored[key] = append([]byte(nil), payload...)
	return nil
}

func (f *fakeReportPublisher) ReportPayload(key string) (json.RawMessage, bool) {
	payload, ok := f.stored[key]
	return payload, ok
}

// keys returns the report keys of the recorded calls in order.
func (f *fakeReportPublisher) keys() []string {
	ks := make([]string, len(f.calls))
	for i, c := range f.calls {
		ks[i] = c.key
	}
	return ks
}

// newTestPublisher builds a publisher with nil bridge managers (so every bridge
// block falls back to its disabled payload) and a discard logger.
func newTestPublisher(pub reportPublisher, peerCount func() int) *statusReportPublisher {
	return &statusReportPublisher{
		publisher:  pub,
		peerCount:  peerCount,
		ifaceName:  "plexd0",
		listenPort: 51820,
		interval:   time.Hour,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestStatusReportPublisher_FirstPublishAllKeys(t *testing.T) {
	fake := &fakeReportPublisher{}
	p := newTestPublisher(fake, func() int { return 3 })

	p.publishOnce()

	wantKeys := map[string]bool{
		statusMeshKey:       false,
		statusBridgeKey:     false,
		statusUserAccessKey: false,
		statusIngressKey:    false,
		statusSiteToSiteKey: false,
	}
	if len(fake.calls) != len(wantKeys) {
		t.Fatalf("got %d publishes, want %d: %v", len(fake.calls), len(wantKeys), fake.keys())
	}
	for _, c := range fake.calls {
		seen, known := wantKeys[c.key]
		if !known {
			t.Errorf("unexpected report key %q", c.key)
			continue
		}
		if seen {
			t.Errorf("report key %q published twice", c.key)
		}
		wantKeys[c.key] = true
		if c.contentType != "application/json" {
			t.Errorf("key %q content_type = %q, want application/json", c.key, c.contentType)
		}
	}

	// The mesh payload carries the injected fields.
	mesh := findPayload(t, fake, statusMeshKey)
	if !strings.Contains(string(mesh), `"interface":"plexd0"`) ||
		!strings.Contains(string(mesh), `"peer_count":3`) ||
		!strings.Contains(string(mesh), `"listen_port":51820`) {
		t.Errorf("status.mesh payload = %s, want interface/peer_count/listen_port fields", mesh)
	}
}

func TestStatusReportPublisher_UnchangedPublishesNothing(t *testing.T) {
	fake := &fakeReportPublisher{}
	p := newTestPublisher(fake, func() int { return 3 })

	p.publishOnce()
	fake.calls = nil

	p.publishOnce()

	if len(fake.calls) != 0 {
		t.Fatalf("second publishOnce published %v, want nothing", fake.keys())
	}
}

func TestStatusReportPublisher_ChangedFieldRepublishesOnlyThatKey(t *testing.T) {
	fake := &fakeReportPublisher{}
	count := 3
	p := newTestPublisher(fake, func() int { return count })

	p.publishOnce()
	fake.calls = nil

	// Only the peer count changes: just status.mesh should republish.
	count = 7
	p.publishOnce()

	if got := fake.keys(); len(got) != 1 || got[0] != statusMeshKey {
		t.Fatalf("republished %v, want only %q", got, statusMeshKey)
	}
	if payload := fake.calls[0].payload; !strings.Contains(string(payload), `"peer_count":7`) {
		t.Errorf("republished mesh payload = %s, want peer_count 7", payload)
	}
}

func TestStatusReportPublisher_NilBridgeManagersDisabled(t *testing.T) {
	fake := &fakeReportPublisher{}
	p := newTestPublisher(fake, func() int { return 0 })

	p.publishOnce()

	for _, key := range []string{statusBridgeKey, statusUserAccessKey, statusIngressKey, statusSiteToSiteKey} {
		payload := findPayload(t, fake, key)
		if !strings.Contains(string(payload), `"enabled":false`) {
			t.Errorf("key %q payload = %s, want \"enabled\":false", key, payload)
		}
	}
}

func TestStatusReportPublisher_PublishErrorRetriesOnlyThatKey(t *testing.T) {
	fake := &fakeReportPublisher{failKey: statusIngressKey}
	p := newTestPublisher(fake, func() int { return 1 })

	// First pass: all five attempted, ingress fails so its last value is not
	// recorded; the other four succeed and are recorded.
	p.publishOnce()
	if !contains(fake.keys(), statusIngressKey) {
		t.Fatalf("first publishOnce did not attempt %q: %v", statusIngressKey, fake.keys())
	}

	// Ingress recovers; nothing else changed, so only ingress republishes.
	fake.failKey = ""
	fake.calls = nil
	p.publishOnce()

	if got := fake.keys(); len(got) != 1 || got[0] != statusIngressKey {
		t.Fatalf("retry published %v, want only %q", got, statusIngressKey)
	}
}

func TestStatusReportPublisher_ForgedReportIsReasserted(t *testing.T) {
	fake := &fakeReportPublisher{}
	p := newTestPublisher(fake, func() int { return 3 })

	p.publishOnce()
	published := findPayload(t, fake, statusMeshKey)
	fake.calls = nil

	// A local caller overwrites the mesh status with a forged value. Nothing the
	// publisher samples has changed, so only a read-back of the stored payload
	// can detect it.
	fake.stored[statusMeshKey] = []byte(`{"interface":"evil0","peer_count":0,"listen_port":0}`)

	p.publishOnce()

	if got := fake.keys(); len(got) != 1 || got[0] != statusMeshKey {
		t.Fatalf("republished %v, want only %q", got, statusMeshKey)
	}
	if got := fake.stored[statusMeshKey]; !bytes.Equal(got, published) {
		t.Errorf("stored payload = %s, want the sampled status %s", got, published)
	}
}

func TestStatusReportPublisher_DeletedReportIsRecreated(t *testing.T) {
	fake := &fakeReportPublisher{}
	p := newTestPublisher(fake, func() int { return 3 })

	p.publishOnce()
	published := findPayload(t, fake, statusBridgeKey)
	fake.calls = nil

	// A local caller deletes the bridge status report.
	delete(fake.stored, statusBridgeKey)

	p.publishOnce()

	if got := fake.keys(); len(got) != 1 || got[0] != statusBridgeKey {
		t.Fatalf("republished %v, want only %q", got, statusBridgeKey)
	}
	if got := fake.stored[statusBridgeKey]; !bytes.Equal(got, published) {
		t.Errorf("stored payload = %s, want the sampled status %s", got, published)
	}
}

// findPayload returns the payload of the first recorded call for key.
func findPayload(t *testing.T, f *fakeReportPublisher, key string) []byte {
	t.Helper()
	for _, c := range f.calls {
		if c.key == key {
			return c.payload
		}
	}
	t.Fatalf("no publish recorded for key %q", key)
	return nil
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
