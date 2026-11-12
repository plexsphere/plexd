package policy

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The bounds of the connection lines. At the default log_fwd report interval
// of 30 s, 5 lines a second with a burst of 50 make at most 200 lines a batch,
// half of the forwarder's buffer of twice the batch size.
const (
	connLogRate            = 5
	connLogBurst           = 50
	connLogSummaryInterval = time.Minute
)

// connLine is the message of the line logged for a connection a logged rule
// admitted.
const connLine = "policy rule allowed connection"

// connRule is what a tag names: the revision the rule came from, the rule's
// index in that revision's rules array, and the rule as the backend got it.
type connRule struct {
	revisionID string
	index      int
	rule       FirewallRule
}

// ConnLogger turns what the backends' readers report into one line in plexd's
// own log per connection a logged rule admitted. It knows the tags of the
// ruleset the Enforcer applied last and of the one before, so an event the
// kernel produced just before or after an apply still finds its rule. It
// bounds the rate of its lines with a token bucket and reports what it
// dropped once a minute.
//
// All methods are safe for concurrent use.
type ConnLogger struct {
	logger *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	current  map[string]connRule
	previous map[string]connRule
	tokens   float64
	refilled time.Time
	limited  int
	lost     int
	forward  func(ts time.Time, severity, message string)
}

// NewConnLogger returns a ConnLogger that writes to logger.
func NewConnLogger(logger *slog.Logger) *ConnLogger {
	return &ConnLogger{
		logger: logger.With("component", "policy"),
		now:    time.Now,
		tokens: connLogBurst,
	}
}

// SetRuleset records the tagged rules of a ruleset about to be applied for
// revisionID. The rules it held become the previous ruleset, and the ones
// before that are forgotten. A tag is "<generation>/<index>", and a rule whose
// tag carries no index after the slash is ignored.
func (c *ConnLogger) SetRuleset(revisionID string, rules []FirewallRule) {
	next := make(map[string]connRule)
	for _, r := range rules {
		if r.LogTag == "" {
			continue
		}
		_, idx, ok := strings.Cut(r.LogTag, "/")
		if !ok {
			continue
		}
		index, err := strconv.Atoi(idx)
		if err != nil {
			continue
		}
		next[r.LogTag] = connRule{revisionID: revisionID, index: index, rule: r}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.previous = c.current
	c.current = next
}

// Revert undoes the last SetRuleset after its apply failed: the previous
// ruleset, the one still in the kernel, becomes current again. It does
// nothing when there is no previous ruleset.
func (c *ConnLogger) Revert() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.previous == nil {
		return
	}
	c.current = c.previous
	c.previous = nil
}

// ForwardTo makes every line and every summary also go to fn, with severity
// info or warning and the record as plexd's text handler renders it. A nil fn
// stops forwarding.
func (c *ConnLogger) ForwardTo(fn func(ts time.Time, severity, message string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forward = fn
}

// Event logs the connection ev reports, when its tag names a rule of the
// current or the previous ruleset, the rule admits it, and the rate allows
// it. It implements ConnSink.
func (c *ConnLogger) Event(ev ConnEvent) {
	c.mu.Lock()
	entry, ok := c.current[ev.Tag]
	if !ok {
		entry, ok = c.previous[ev.Tag]
	}
	if !ok {
		c.mu.Unlock()
		c.logger.Debug("policy connection event names no logged rule", "tag", ev.Tag)
		return
	}
	if !entry.rule.admits(ev) {
		c.mu.Unlock()
		c.logger.Debug("policy connection event does not match its rule", "tag", ev.Tag)
		return
	}
	now := c.now()
	if !c.take(now) {
		c.limited++
		c.mu.Unlock()
		return
	}
	forward := c.forward
	c.mu.Unlock()

	attrs := []slog.Attr{
		slog.String("revision_id", entry.revisionID),
		slog.Int("rule", entry.index),
		slog.String("direction", ev.Dir.String()),
		slog.String("protocol", protocolName(ev.Protocol)),
		slog.String("src", ev.Src.String()),
		slog.String("dst", ev.Dst.String()),
	}
	if ev.Protocol == ipProtoTCP || ev.Protocol == ipProtoUDP {
		attrs = append(attrs, slog.Int("dst_port", int(ev.DstPort)))
	}
	c.emit(forward, now, slog.LevelInfo, connLine, attrs)
}

// Lost counts n records a reader knows it missed. It implements ConnSink.
func (c *ConnLogger) Lost(n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lost += n
}

// Run logs, once a minute, how many lines the rate limit dropped and how many
// records the readers lost since the last summary, when either is above 0.
// It returns when ctx ends.
func (c *ConnLogger) Run(ctx context.Context) {
	ticker := time.NewTicker(connLogSummaryInterval)
	defer ticker.Stop()
	c.run(ctx, ticker.C)
}

func (c *ConnLogger) run(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			c.summarize()
		}
	}
}

// summarize logs and resets the counts, when either is above 0.
func (c *ConnLogger) summarize() {
	c.mu.Lock()
	limited, lost := c.limited, c.lost
	c.limited, c.lost = 0, 0
	forward := c.forward
	c.mu.Unlock()

	if limited == 0 && lost == 0 {
		return
	}
	c.emit(forward, c.now(), slog.LevelWarn, "policy connection lines dropped", []slog.Attr{
		slog.Int("rate_limited", limited),
		slog.Int("lost", lost),
	})
}

// take spends a token, refilling the bucket for the time since the last
// refill first. The caller holds c.mu.
func (c *ConnLogger) take(now time.Time) bool {
	if elapsed := now.Sub(c.refilled); elapsed > 0 {
		c.tokens = min(connLogBurst, c.tokens+elapsed.Seconds()*connLogRate)
		c.refilled = now
	}
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

// emit logs a record and hands it to forward, when one is set.
func (c *ConnLogger) emit(forward func(time.Time, string, string), ts time.Time, level slog.Level, msg string, attrs []slog.Attr) {
	c.logger.LogAttrs(context.Background(), level, msg, attrs...)
	if forward == nil {
		return
	}
	severity := "info"
	if level >= slog.LevelWarn {
		severity = "warning"
	}
	forward(ts, severity, renderRecord(ts, level, msg, attrs))
}

// renderRecord renders a record the way plexd's text handler writes it, with
// the component the logger adds, without the trailing newline.
func renderRecord(ts time.Time, level slog.Level, msg string, attrs []slog.Attr) string {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	r := slog.NewRecord(ts, level, msg, 0)
	r.AddAttrs(slog.String("component", "policy"))
	r.AddAttrs(attrs...)
	_ = h.Handle(context.Background(), r)
	return strings.TrimSuffix(buf.String(), "\n")
}

// protocolName names an IP protocol the way a connection line writes it.
func protocolName(proto uint8) string {
	switch proto {
	case ipProtoTCP:
		return "tcp"
	case ipProtoUDP:
		return "udp"
	case ipProtoICMP:
		return "icmp"
	case ipProtoICMPv6:
		return "icmpv6"
	}
	return strconv.Itoa(int(proto))
}
