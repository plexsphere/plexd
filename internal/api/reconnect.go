package api

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"
)

// FailureAction indicates how the reconnect engine should handle a failure.
type FailureAction int

const (
	// RetryTransient means use exponential backoff (network errors, 5xx).
	RetryTransient FailureAction = iota
	// RetryAuth means invoke OnAuthFailure callback and pause (401).
	RetryAuth
	// RespectServer means use the server-provided Retry-After delay (429).
	RespectServer
	// PermanentFailure means stop reconnection entirely (403, 404).
	PermanentFailure
	// RetryDescoped means the endpoint is descoped long-term (a 501
	// signed_event_bus_not_provisioned) — switch to pull-only delivery
	// immediately, with no backoff, rather than retrying a channel that is
	// not there.
	RetryDescoped
)

// ClassifyError determines the appropriate reconnection action for an error.
func ClassifyError(err error) FailureAction {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		// Network errors or other non-API errors are transient
		return RetryTransient
	}
	switch {
	case errors.Is(err, ErrUnauthorized):
		return RetryAuth
	case errors.Is(err, ErrRateLimit):
		return RespectServer
	// 422 is deliberately absent: on a long-running SSE connection it signals
	// deploy skew, which clears on its own. Registration stops on it locally.
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound):
		return PermanentFailure
	// A 501 signed_event_bus_not_provisioned matches the any-5xx ErrServer
	// sentinel below, so it must be classified first: it is a long-term
	// descope answered by pull-only delivery, not a transient 5xx.
	case IsEventBusNotProvisioned(err):
		return RetryDescoped
	case errors.Is(err, ErrServer):
		return RetryTransient
	default:
		return RetryTransient
	}
}

// DeliveryMode identifies which channel currently delivers control-plane state.
type DeliveryMode string

const (
	// DeliveryModeStreaming means the SSE event stream is the live channel.
	DeliveryModeStreaming DeliveryMode = "streaming"
	// DeliveryModePullOnly means the event stream is descoped and the
	// reconciler's own loop is the only delivery channel; SSE is re-probed at
	// a low cadence to detect its return.
	DeliveryModePullOnly DeliveryMode = "pull_only"
	// DeliveryModeDegradedPolling means SSE has been failing transiently long
	// enough that the legacy polling fallback is driving state.
	DeliveryModeDegradedPolling DeliveryMode = "degraded_polling"
)

// Clock abstracts time operations for testing.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// realClock uses the actual system time.
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// ConnectFunc is called to establish an SSE connection.
// It should block while the connection is active and return when it drops.
type ConnectFunc func(ctx context.Context) error

// PollFunc is called during polling fallback to fetch full state.
type PollFunc func(ctx context.Context) error

// ReconnectEngine manages SSE reconnection with backoff and polling fallback.
type ReconnectEngine struct {
	baseInterval    time.Duration
	multiplier      float64
	maxInterval     time.Duration
	jitterFraction  float64
	pollingFallback time.Duration // how long before switching to polling
	pollInterval    time.Duration // how often to poll during fallback

	onAuthFailure func()
	logger        *slog.Logger
	clock         Clock

	mu              sync.Mutex
	currentInterval time.Duration
	failingSince    time.Time
	mode            DeliveryMode
	onModeChange    func(DeliveryMode)
	reprobeInterval time.Duration // how often pull-only mode re-probes SSE
}

// NewReconnectEngine creates a new ReconnectEngine with default settings.
func NewReconnectEngine(logger *slog.Logger) *ReconnectEngine {
	return &ReconnectEngine{
		baseInterval:    1 * time.Second,
		multiplier:      2.0,
		maxInterval:     60 * time.Second,
		jitterFraction:  0.25,
		pollingFallback: 5 * time.Minute,
		pollInterval:    60 * time.Second,
		logger:          logger,
		clock:           realClock{},
		currentInterval: 1 * time.Second,
		mode:            DeliveryModeStreaming,
		reprobeInterval: DefaultSSEReprobeInterval,
	}
}

// SetOnAuthFailure sets the callback invoked on authentication failures.
func (r *ReconnectEngine) SetOnAuthFailure(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onAuthFailure = fn
}

// SetBaseInterval updates the base backoff interval.
// This is called when the SSE retry: field is received from the server.
func (r *ReconnectEngine) SetBaseInterval(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.baseInterval = d
}

// SetClock sets a custom clock implementation for testing.
func (r *ReconnectEngine) SetClock(c Clock) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clock = c
}

// SetPollInterval sets how often to poll during polling fallback mode.
func (r *ReconnectEngine) SetPollInterval(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pollInterval = d
}

// SetIntervals configures the base and max backoff intervals and resets
// the current interval to the new base. Useful for testing with fast intervals.
func (r *ReconnectEngine) SetIntervals(base, max time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.baseInterval = base
	r.maxInterval = max
	r.currentInterval = base
}

// SetPollingFallbackConfig configures when to enter polling mode and how often to poll.
func (r *ReconnectEngine) SetPollingFallbackConfig(fallbackAfter, pollInterval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pollingFallback = fallbackAfter
	r.pollInterval = pollInterval
}

// Mode returns the delivery mode currently reported by the engine.
func (r *ReconnectEngine) Mode() DeliveryMode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode
}

// SetOnModeChange sets the callback invoked on every delivery-mode transition.
// The callback is fired outside the engine's lock and may be nil.
func (r *ReconnectEngine) SetOnModeChange(fn func(DeliveryMode)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onModeChange = fn
}

// SetReprobeInterval sets how often pull-only mode re-probes the SSE endpoint.
// A non-positive duration is ignored.
func (r *ReconnectEngine) SetReprobeInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reprobeInterval = d
}

// setMode transitions the delivery mode and fires the on-change callback exactly
// once per actual transition. It is a no-op when the mode is unchanged. The
// callback is captured under the lock and invoked outside it; a nil callback is
// tolerated.
func (r *ReconnectEngine) setMode(m DeliveryMode) {
	r.mu.Lock()
	if r.mode == m {
		r.mu.Unlock()
		return
	}
	r.mode = m
	fn := r.onModeChange
	r.mu.Unlock()

	if fn != nil {
		fn(m)
	}
}

// notifyConnected records that the SSE stream reached an HTTP 200. A later
// package wires the stream's on-connected hook to it; for now it lets a
// re-probe that connects before dropping return the engine to streaming mode.
func (r *ReconnectEngine) notifyConnected() {
	r.setMode(DeliveryModeStreaming)
}

// jitter adds random jitter (plus or minus jitterFraction) to a duration.
func (r *ReconnectEngine) jitter(d time.Duration) time.Duration {
	jit := float64(d) * r.jitterFraction
	delta := (rand.Float64()*2 - 1) * jit // random in [-jit, +jit]
	return time.Duration(float64(d) + delta)
}

// Run is the main state machine loop that manages SSE reconnection.
//
// States: Connecting -> Connected | Backoff
//
//	Backoff -> Connecting | Polling
//	Polling -> Connecting (periodic SSE retry)
//
// Context cancellation exits from any state.
func (r *ReconnectEngine) Run(ctx context.Context, connectFn ConnectFunc, pollFn PollFunc) error {
	r.resetBackoff()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := connectFn(ctx)
		if err == nil {
			r.resetBackoff()
			r.logger.Info("SSE connection dropped, reconnecting")
			continue
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := r.handleConnectError(ctx, err, connectFn, pollFn); err != nil {
			return err
		}
	}
}

// resetBackoff resets the backoff state to initial values.
func (r *ReconnectEngine) resetBackoff() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentInterval = r.baseInterval
	r.failingSince = time.Time{}
}

// handleConnectError classifies a connection error and takes the appropriate action.
// Returns nil to continue the reconnect loop, or an error to stop it.
func (r *ReconnectEngine) handleConnectError(ctx context.Context, err error, connectFn ConnectFunc, pollFn PollFunc) error {
	action := ClassifyError(err)
	switch action {
	case PermanentFailure:
		r.logger.Error("permanent failure, stopping reconnection", "error", err)
		return err

	case RetryAuth:
		return r.handleAuthFailure(err)

	case RespectServer:
		return r.handleRateLimit(ctx, err)

	case RetryTransient:
		return r.handleTransientError(ctx, err, connectFn, pollFn)

	case RetryDescoped:
		return r.runPullOnly(ctx, connectFn)

	default:
		return err
	}
}

// handleAuthFailure invokes the auth failure callback and returns the error.
func (r *ReconnectEngine) handleAuthFailure(err error) error {
	r.mu.Lock()
	fn := r.onAuthFailure
	r.mu.Unlock()
	if fn != nil {
		fn()
	}
	r.logger.Error("authentication failure", "error", err)
	return err
}

// handleRateLimit waits for the server-specified retry-after delay.
// Returns nil to continue the reconnect loop, or an error on context cancellation.
func (r *ReconnectEngine) handleRateLimit(ctx context.Context, err error) error {
	var apiErr *APIError
	r.mu.Lock()
	delay := r.currentInterval
	r.mu.Unlock()
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		delay = apiErr.RetryAfter
	}
	r.logger.Warn("rate limited, respecting server retry-after", "delay", delay)
	return r.wait(ctx, delay)
}

// handleTransientError applies exponential backoff or enters polling fallback.
// Returns nil to continue the reconnect loop, or an error to stop it.
func (r *ReconnectEngine) handleTransientError(ctx context.Context, err error, connectFn ConnectFunc, pollFn PollFunc) error {
	r.mu.Lock()
	if r.failingSince.IsZero() {
		r.failingSince = r.clock.Now()
	}
	failingSince := r.failingSince
	currentInterval := r.currentInterval
	pollingFallback := r.pollingFallback
	clk := r.clock
	r.mu.Unlock()

	// Check if we should enter polling fallback.
	if clk.Now().Sub(failingSince) >= pollingFallback {
		if err := r.runPollingFallback(ctx, connectFn, pollFn); err != nil {
			return err
		}
		r.resetBackoff()
		return nil
	}

	// Exponential backoff with jitter.
	delay := r.jitter(currentInterval)
	r.logger.Warn("transient error, backing off", "error", err, "delay", delay)

	if err := r.wait(ctx, delay); err != nil {
		return err
	}

	r.incrementInterval()
	return nil
}

// incrementInterval increases the backoff interval for the next retry.
func (r *ReconnectEngine) incrementInterval() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentInterval = time.Duration(
		math.Min(
			float64(r.currentInterval)*r.multiplier,
			float64(r.maxInterval),
		),
	)
}

// wait blocks until the given duration has elapsed or the context is cancelled.
func (r *ReconnectEngine) wait(ctx context.Context, d time.Duration) error {
	r.mu.Lock()
	clk := r.clock
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clk.After(d):
		return nil
	}
}

// runPullOnly enters pull-only delivery: the SSE endpoint has been descoped
// long-term (a 501 signed_event_bus_not_provisioned), so the reconciler's own
// loop is the only delivery channel. The engine stops polling entirely and
// re-probes SSE at a low cadence to detect that the endpoint has come back.
//
// It returns nil when a re-probe reconnects — the main Run loop then resumes
// normal streaming — and an error only on context cancellation or a permanent
// or auth failure surfaced by a re-probe.
func (r *ReconnectEngine) runPullOnly(ctx context.Context, connectFn ConnectFunc) error {
	r.logger.Warn("SSE events endpoint descoped, entering pull-only delivery; the reconciler loop owns the pull")
	r.setMode(DeliveryModePullOnly)

	for {
		r.mu.Lock()
		reprobe := r.reprobeInterval
		r.mu.Unlock()

		if err := r.wait(ctx, reprobe); err != nil {
			return err
		}

		err := connectFn(ctx)
		if err == nil {
			// The re-probe reconnected and the stream later closed cleanly.
			// setMode covers the case where the on-connected hook is not wired.
			r.resetBackoff()
			r.setMode(DeliveryModeStreaming)
			return nil
		}

		if r.Mode() == DeliveryModeStreaming {
			// connectFn saw an HTTP 200 (notifyConnected fired) before the
			// stream dropped with an error: SSE is back, resume streaming.
			r.resetBackoff()
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		switch ClassifyError(err) {
		case RetryDescoped:
			// Still descoped — stay in pull-only at the re-probe cadence.
		case RetryAuth:
			return r.handleAuthFailure(err)
		case PermanentFailure:
			r.logger.Error("permanent failure during pull-only re-probe, stopping", "error", err)
			return err
		default:
			r.logger.Debug("SSE re-probe failed during pull-only delivery", "error", err)
		}
	}
}

// runPollingFallback enters polling mode, periodically calling pollFn
// and attempting to reconnect SSE.
func (r *ReconnectEngine) runPollingFallback(ctx context.Context, connectFn ConnectFunc, pollFn PollFunc) error {
	r.logger.Warn("SSE unavailable, falling back to polling")
	r.setMode(DeliveryModeDegradedPolling)

	r.mu.Lock()
	pollInterval := r.pollInterval
	clk := r.clock
	r.mu.Unlock()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Try polling
		if err := pollFn(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.logger.Error("poll failed", "error", err)
		}

		// Wait for poll interval, then try SSE reconnect
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-clk.After(pollInterval):
		}

		// Attempt SSE reconnect
		sseErr := connectFn(ctx)
		if sseErr == nil {
			// SSE reconnected successfully
			r.logger.Info("SSE reconnected from polling fallback")
			r.setMode(DeliveryModeStreaming)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Check if the SSE error is permanent, auth, or a long-term descope.
		// On a descope, return so the main loop reconnects, draws the 501
		// again, and enters pull-only delivery via classification.
		action := ClassifyError(sseErr)
		if action == PermanentFailure || action == RetryAuth {
			return sseErr
		}
		if action == RetryDescoped {
			return nil
		}

		// Otherwise continue polling
		r.logger.Debug("SSE reconnect attempt failed during polling", "error", sseErr)
	}
}
