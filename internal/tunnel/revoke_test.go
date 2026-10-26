package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// The lines the session_revoked handler and the dispatcher's guard log.
const (
	revokedClosedMsg  = "session_revoked closed the session"
	revokedNoLiveMsg  = "session_revoked names no live session; nothing to close"
	revokedUnknownMsg = "session_revoked carries an unrecognised revoke_reason; reporting operator_revoke"
	revokedSettledMsg = "session was revoked by a signed event; not provisioning it"
	// revokedDuringProvisionMsg is Handle closing a listener it bound for a
	// session the event revoked while the listener came up.
	revokedDuringProvisionMsg = "session was revoked by a signed event while its listener came up; closing it"
)

// fakeTrigger is an api.ReconcileTrigger that signals every call on a channel,
// so a test can wait for the handler's asynchronous close to finish before it
// asserts. onTrigger, when set, runs at the moment the trigger is called.
type fakeTrigger struct {
	calls     chan struct{}
	onTrigger func()
}

func newFakeTrigger() *fakeTrigger {
	return &fakeTrigger{calls: make(chan struct{}, 64)}
}

func (f *fakeTrigger) TriggerReconcile() {
	if f.onTrigger != nil {
		f.onTrigger()
	}
	f.calls <- struct{}{}
}

// wait blocks until the trigger has been called once more.
func (f *fakeTrigger) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.calls:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile not triggered within 5s")
	}
}

// revokedEnvelope builds a session_revoked envelope carrying payload verbatim as
// its raw payload; an empty payload leaves the field absent.
func revokedEnvelope(payload string) api.Envelope {
	env := api.Envelope{ID: "evt-session-revoked", Type: api.EventSessionRevoked}
	if payload != "" {
		env.Payload = json.RawMessage(payload)
	}
	return env
}

// revocationPayload renders a well-formed session_revoked payload naming
// sessionID, with jti equal to it, as the contract requires.
func revocationPayload(t *testing.T, sessionID, revokeReason string) string {
	t.Helper()
	data, err := json.Marshal(api.SessionRevocation{
		SessionID:    sessionID,
		JTI:          sessionID,
		RevokedAt:    time.Now().UTC(),
		RevokeReason: revokeReason,
	})
	if err != nil {
		t.Fatalf("marshal revocation: %v", err)
	}
	return string(data)
}

// provisionLive brings up a live tcp session through the manager.
func provisionLive(t *testing.T, mgr *SessionManager, sessionID, echoAddr string) {
	t.Helper()
	if _, err := mgr.CreateSession(context.Background(), echoSession(t, sessionID, echoAddr)); err != nil {
		t.Fatalf("CreateSession(%q) error: %v", sessionID, err)
	}
}

func TestSessionRevokedHandler_ClosesLiveSession(t *testing.T) {
	tests := []struct {
		revokeReason     string
		wantReason       string
		wantTerminatedBy string
	}{
		{api.RevokeReasonOperatorRequest, reasonRevoked, api.TerminatedByOperatorRevoke},
		{api.RevokeReasonPolicyViolation, reasonRevoked, api.TerminatedByOperatorRevoke},
		{api.RevokeReasonIdentityCompromise, reasonRevoked, api.TerminatedByOperatorRevoke},
		{api.RevokeReasonResourceDecommissioned, reasonRevoked, api.TerminatedByOperatorRevoke},
		{api.RevokeReasonTTLExpired, reasonExpired, api.TerminatedByTTLExpired},
		{api.RevokeReasonIdleTimeout, reasonIdle, api.TerminatedByIdleTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.revokeReason, func(t *testing.T) {
			echoAddr := startEchoServer(t)
			d, mgr, _, logs := newTestDispatcher(t, Config{})
			mu, records := recordCloses(mgr)
			provisionLive(t, mgr, "sess-revoked", echoAddr)

			trigger := newFakeTrigger()
			handler := d.SessionRevokedHandler(trigger)
			if err := handler(context.Background(), revokedEnvelope(revocationPayload(t, "sess-revoked", tt.revokeReason))); err != nil {
				t.Fatalf("handler error: %v", err)
			}
			trigger.wait(t)

			if mgr.ActiveCount() != 0 {
				t.Errorf("expected ActiveCount()=0 after the revocation, got %d", mgr.ActiveCount())
			}
			mu.Lock()
			closes := append([]closedRecord(nil), *records...)
			mu.Unlock()
			if len(closes) != 1 {
				t.Fatalf("expected 1 close, got %d", len(closes))
			}
			got := closes[0]
			if got.sessionID != "sess-revoked" || got.reason != tt.wantReason {
				t.Errorf("close = (%q, %q), want (%q, %q)", got.sessionID, got.reason, "sess-revoked", tt.wantReason)
			}
			if tb := TerminatedByFromReason(got.reason); tb != tt.wantTerminatedBy {
				t.Errorf("terminated_by = %q, want %q", tb, tt.wantTerminatedBy)
			}
			if n := len(trigger.calls); n != 0 {
				t.Errorf("reconcile triggered %d more times, want exactly once", n)
			}
			if n := logs.count(revokedClosedMsg); n != 1 {
				t.Fatalf("%q logged %d times, want 1", revokedClosedMsg, n)
			}
			if lvl := logs.level(revokedClosedMsg); lvl != slog.LevelInfo {
				t.Errorf("%q logged at %v, want INFO", revokedClosedMsg, lvl)
			}
			if tb := logs.attr(revokedClosedMsg, "terminated_by"); tb != tt.wantTerminatedBy {
				t.Errorf("%q terminated_by = %q, want %q", revokedClosedMsg, tb, tt.wantTerminatedBy)
			}
			if n := logs.count(revokedUnknownMsg); n != 0 {
				t.Errorf("a contract reason was warned about as unrecognised %d times", n)
			}
		})
	}
}

// TestSessionRevokedHandler_TriggersAfterClose pins the order: the pull the
// event triggers must not run until the session is closed, or the pull's drain
// could close it first and report plexd_close.
func TestSessionRevokedHandler_TriggersAfterClose(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)
	provisionLive(t, mgr, "sess-order", echoAddr)

	activeAtTrigger, closesAtTrigger := -1, -1
	trigger := newFakeTrigger()
	trigger.onTrigger = func() {
		activeAtTrigger = mgr.ActiveCount()
		mu.Lock()
		closesAtTrigger = len(*records)
		mu.Unlock()
	}
	handler := d.SessionRevokedHandler(trigger)
	if err := handler(context.Background(), revokedEnvelope(revocationPayload(t, "sess-order", api.RevokeReasonOperatorRequest))); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	trigger.wait(t)

	if activeAtTrigger != 0 {
		t.Errorf("ActiveCount() when the reconcile was triggered = %d, want 0", activeAtTrigger)
	}
	if closesAtTrigger != 1 {
		t.Errorf("closes recorded when the reconcile was triggered = %d, want 1", closesAtTrigger)
	}
}

func TestSessionRevokedHandler_UnrecognisedReason(t *testing.T) {
	for _, revokeReason := range []string{"", "quota_exceeded"} {
		t.Run(fmt.Sprintf("%q", revokeReason), func(t *testing.T) {
			echoAddr := startEchoServer(t)
			d, mgr, _, logs := newTestDispatcher(t, Config{})
			mu, records := recordCloses(mgr)
			provisionLive(t, mgr, "sess-unknown-reason", echoAddr)

			trigger := newFakeTrigger()
			handler := d.SessionRevokedHandler(trigger)
			if err := handler(context.Background(), revokedEnvelope(revocationPayload(t, "sess-unknown-reason", revokeReason))); err != nil {
				t.Fatalf("handler error: %v", err)
			}
			trigger.wait(t)

			// The event is verified and names the session, so it still closes it.
			mu.Lock()
			if len(*records) != 1 || (*records)[0].reason != reasonRevoked {
				t.Errorf("closes = %+v, want one with reason %q", *records, reasonRevoked)
			}
			mu.Unlock()
			if n := logs.count(revokedUnknownMsg); n != 1 {
				t.Fatalf("%q logged %d times, want 1", revokedUnknownMsg, n)
			}
			if lvl := logs.level(revokedUnknownMsg); lvl != slog.LevelWarn {
				t.Errorf("%q logged at %v, want WARN", revokedUnknownMsg, lvl)
			}
			if got := logs.attr(revokedUnknownMsg, "revoke_reason"); got != revokeReason {
				t.Errorf("%q revoke_reason = %q, want %q", revokedUnknownMsg, got, revokeReason)
			}
		})
	}
}

func TestSessionRevokedHandler_NoLiveSession(t *testing.T) {
	d, mgr, _, logs := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)

	trigger := newFakeTrigger()
	handler := d.SessionRevokedHandler(trigger)
	if err := handler(context.Background(), revokedEnvelope(revocationPayload(t, "sess-elsewhere", api.RevokeReasonOperatorRequest))); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	trigger.wait(t)

	mu.Lock()
	if len(*records) != 0 {
		t.Errorf("expected no close for a session that is not live, got %d", len(*records))
	}
	mu.Unlock()
	if n := len(trigger.calls); n != 0 {
		t.Errorf("reconcile triggered %d more times, want exactly once", n)
	}
	if n := logs.count(revokedNoLiveMsg); n != 1 {
		t.Fatalf("%q logged %d times, want 1", revokedNoLiveMsg, n)
	}
	if lvl := logs.level(revokedNoLiveMsg); lvl != slog.LevelInfo {
		t.Errorf("%q logged at %v, want INFO", revokedNoLiveMsg, lvl)
	}
}

func TestSessionRevokedHandler_MalformedPayload(t *testing.T) {
	isSyntaxError := func(err error) bool {
		var target *json.SyntaxError
		return errors.As(err, &target)
	}
	isTypeError := func(err error) bool {
		var target *json.UnmarshalTypeError
		return errors.As(err, &target)
	}
	isParseError := func(err error) bool {
		var target *time.ParseError
		return errors.As(err, &target)
	}
	isUnnamed := func(err error) bool { return errors.Is(err, errRevocationUnnamed) }

	tests := []struct {
		name    string
		payload string
		wantErr func(error) bool
	}{
		{"absent payload", "", isSyntaxError},
		{"json string payload", `"{}"`, isTypeError},
		{"unparseable revoked_at", `{"session_id":"s","jti":"s","revoked_at":"yesterday","revoke_reason":"operator_request"}`, isParseError},
		{"null payload", `null`, isUnnamed},
		{"empty object", `{}`, isUnnamed},
		{"jti absent", `{"session_id":"s","revoke_reason":"operator_request"}`, isUnnamed},
		{"jti differs", `{"session_id":"s","jti":"other","revoke_reason":"operator_request"}`, isUnnamed},
	}

	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)
	// The live session carries the id the malformed payloads name, so a payload
	// that slipped through would close it.
	provisionLive(t, mgr, "s", echoAddr)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trigger := newFakeTrigger()
			err := d.SessionRevokedHandler(trigger)(context.Background(), revokedEnvelope(tt.payload))
			if err == nil || !tt.wantErr(err) {
				t.Fatalf("handler error = %v (%T), want the case's error", err, errors.Unwrap(err))
			}
			// The reconcile is triggered synchronously, before the handler returns.
			if n := len(trigger.calls); n != 1 {
				t.Errorf("reconcile triggered %d times before the handler returned, want 1", n)
			}
			if mgr.ActiveCount() != 1 {
				t.Errorf("expected the live session to stay open, ActiveCount()=%d", mgr.ActiveCount())
			}
			mu.Lock()
			if len(*records) != 0 {
				t.Errorf("expected no close, got %d", len(*records))
			}
			mu.Unlock()
		})
	}
}

// TestSessionRevokedHandler_ReplayIsNoOp covers a replayed envelope inside the
// verifier's staleness window: the session it names is already closed, so the
// replay closes nothing and only pulls.
func TestSessionRevokedHandler_ReplayIsNoOp(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)
	provisionLive(t, mgr, "sess-replayed", echoAddr)

	env := revokedEnvelope(revocationPayload(t, "sess-replayed", api.RevokeReasonOperatorRequest))
	trigger := newFakeTrigger()
	handler := d.SessionRevokedHandler(trigger)
	for range 2 {
		if err := handler(context.Background(), env); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		trigger.wait(t)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*records) != 1 {
		t.Errorf("expected 1 close across the event and its replay, got %d", len(*records))
	}
}

// TestSessionRevokedHandler_ConcurrentWithHandle runs the handler on its own
// goroutine against a Handle that drains the same session, as the SSE and
// reconcile goroutines do, so the race detector sees the revoked set written
// and pruned at once. Whichever closes the session first wins; it closes once.
func TestSessionRevokedHandler_ConcurrentWithHandle(t *testing.T) {
	echoAddr := startEchoServer(t)
	d, mgr, _, _ := newTestDispatcher(t, Config{})
	mu, records := recordCloses(mgr)
	trigger := newFakeTrigger()
	handler := d.SessionRevokedHandler(trigger)

	for i := range 50 {
		id := fmt.Sprintf("sess-%d", i)
		d.Handle(context.Background(), sessionsSnapshot(echoSession(t, id, echoAddr)))
		env := revokedEnvelope(revocationPayload(t, id, api.RevokeReasonOperatorRequest))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := handler(context.Background(), env); err != nil {
				t.Errorf("handler error: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			d.Handle(context.Background(), sessionsSnapshot())
		}()
		wg.Wait()
		trigger.wait(t)

		mu.Lock()
		closes := 0
		for _, r := range *records {
			if r.sessionID == id {
				closes++
			}
		}
		mu.Unlock()
		if closes != 1 {
			t.Fatalf("%s closed %d times, want 1", id, closes)
		}
	}
}
