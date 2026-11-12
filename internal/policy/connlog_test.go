package policy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// debugLogger returns a logger whose lines from Debug up land in buf.
func debugLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// fixedClock returns a clock the test moves by hand.
func fixedClock(start time.Time) (now func() time.Time, advance func(time.Duration)) {
	var mu sync.Mutex
	t := start
	return func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return t
		}, func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			t = t.Add(d)
		}
}

var (
	connPeer = netip.MustParseAddr("10.99.0.3")
	connNode = netip.MustParseAddr("10.99.0.1")
)

// tcp7001 is the rule a logged revision's rule 0 becomes in the tests.
func tcp7001(tag string) FirewallRule {
	return FirewallRule{Interface: "plexd0", SrcIP: "10.99.0.3/32", DstIP: "10.99.0.1/32", Port: 7001, Protocol: "tcp", Action: "allow", LogTag: tag}
}

func syn7001(tag string, srcPort uint16) ConnEvent {
	return ConnEvent{Tag: tag, Dir: ConnIn, Src: connPeer, Dst: connNode, Protocol: ipProtoTCP, SrcPort: srcPort, DstPort: 7001}
}

func countLines(s, substr string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func TestConnLogger_LogsAdmittedEvent(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	c.SetRuleset("R", []FirewallRule{tcp7001("1/0"), {Interface: "plexd0", Action: "deny"}})

	c.Event(syn7001("1/0", 41001))

	const want = `level=INFO msg="policy rule allowed connection" component=policy revision_id=R rule=0 direction=in protocol=tcp src=10.99.0.3 dst=10.99.0.1 dst_port=7001`
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log = %q, want a line containing %q", buf.String(), want)
	}
}

func TestConnLogger_ProtocolNames(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	c.SetRuleset("R", []FirewallRule{
		{Interface: "plexd0", SrcIP: "fd00:99::/64", DstIP: "fd00:99::1/128", Action: "allow", LogTag: "1/0"},
		{Interface: "plexd0", SrcIP: "10.99.0.0/24", DstIP: "10.99.0.1/32", Action: "allow", LogTag: "1/1"},
	})

	c.Event(ConnEvent{Tag: "1/0", Dir: ConnIn, Src: netip.MustParseAddr("fd00:99::3"), Dst: netip.MustParseAddr("fd00:99::1"), Protocol: ipProtoICMPv6})
	c.Event(ConnEvent{Tag: "1/1", Dir: ConnForward, Src: connPeer, Dst: connNode, Protocol: 47})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log has %d lines, want 2: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "rule=0 direction=in protocol=icmpv6 src=fd00:99::3 dst=fd00:99::1") || strings.Contains(lines[0], "dst_port") {
		t.Errorf("ICMPv6 line = %q, want protocol=icmpv6 and no dst_port", lines[0])
	}
	if !strings.Contains(lines[1], "direction=forward protocol=47 ") || strings.Contains(lines[1], "dst_port") {
		t.Errorf("protocol 47 line = %q, want protocol=47 and no dst_port", lines[1])
	}
}

func TestConnLogger_PreviousRuleset(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	c.SetRuleset("R1", []FirewallRule{tcp7001("1/0")})
	c.SetRuleset("R2", []FirewallRule{tcp7001("2/0")})

	c.Event(syn7001("1/0", 41001))
	if !strings.Contains(buf.String(), "revision_id=R1 rule=0") {
		t.Fatalf("an event for the previous ruleset's tag logged %q, want a line for R1", buf.String())
	}

	buf.Reset()
	c.SetRuleset("R3", []FirewallRule{tcp7001("3/0")})
	c.Event(syn7001("1/0", 41002))
	if strings.Contains(buf.String(), connLine) {
		t.Errorf("an event for a ruleset two applies back logged %q", buf.String())
	}
	if !strings.Contains(buf.String(), `level=DEBUG msg="policy connection event names no logged rule" component=policy tag=1/0`) {
		t.Errorf("log = %q, want the Debug line naming tag 1/0", buf.String())
	}
}

func TestConnLogger_RevertKeepsTheInstalledRuleset(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	c.SetRuleset("R1", []FirewallRule{tcp7001("1/0")})
	c.SetRuleset("R2", []FirewallRule{tcp7001("2/0")})
	// Revision 3 fails to apply, and then revision 4 does as well.
	c.SetRuleset("R3", []FirewallRule{tcp7001("3/0")})
	c.Revert()
	c.SetRuleset("R4", []FirewallRule{tcp7001("4/0")})
	c.Revert()

	c.Event(syn7001("2/0", 41001))
	if !strings.Contains(buf.String(), "revision_id=R2 rule=0") {
		t.Errorf("after two failed applies, revision 2's tag logged %q, want a line for R2", buf.String())
	}

	// A second Revert has no previous ruleset to go back to.
	fresh := NewConnLogger(testLogger())
	fresh.Revert()
	fresh.SetRuleset("R", []FirewallRule{tcp7001("1/0")})
	fresh.Revert()
	fresh.Revert()
}

func TestConnLogger_DropsWhatNamesNoRule(t *testing.T) {
	for name, setup := range map[string]func(c *ConnLogger){
		"before any SetRuleset":    func(*ConnLogger) {},
		"after SetRuleset(R, nil)": func(c *ConnLogger) { c.SetRuleset("R", nil) },
		"a rule without an index":  func(c *ConnLogger) { c.SetRuleset("R", []FirewallRule{tcp7001("1")}) },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			c := NewConnLogger(debugLogger(&buf))
			setup(c)
			c.Event(syn7001("1", 41001))
			c.Event(syn7001("1/0", 41001))
			if strings.Contains(buf.String(), connLine) {
				t.Errorf("log = %q, want no connection line", buf.String())
			}
			if n := countLines(buf.String(), "policy connection event names no logged rule"); n != 2 {
				t.Errorf("log has %d Debug lines naming no rule, want 2: %q", n, buf.String())
			}
		})
	}

	t.Run("an empty tag", func(t *testing.T) {
		var buf bytes.Buffer
		c := NewConnLogger(debugLogger(&buf))
		c.SetRuleset("R", []FirewallRule{tcp7001("1/0"), {Interface: "plexd0", Action: "allow"}})
		c.Event(syn7001("", 41001))
		if strings.Contains(buf.String(), connLine) || !strings.Contains(buf.String(), "policy connection event names no logged rule") {
			t.Errorf("log = %q, want the Debug line and no connection line", buf.String())
		}
	})
}

func TestConnLogger_DropsWhatItsRuleDoesNotAdmit(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	c.SetRuleset("R", []FirewallRule{tcp7001("1/0")})

	ev := syn7001("1/0", 41001)
	ev.DstPort = 7002
	c.Event(ev)

	if strings.Contains(buf.String(), connLine) {
		t.Errorf("log = %q, want no connection line", buf.String())
	}
	if !strings.Contains(buf.String(), `msg="policy connection event does not match its rule" component=policy tag=1/0`) {
		t.Errorf("log = %q, want the Debug line naming tag 1/0", buf.String())
	}
}

func TestConnLogger_RateLimit(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	now, advance := fixedClock(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC))
	c.now = now
	c.SetRuleset("R", []FirewallRule{tcp7001("1/0")})

	for i := range 60 {
		c.Event(syn7001("1/0", uint16(40000+i)))
	}
	if n := countLines(buf.String(), connLine); n != 50 {
		t.Fatalf("60 events at one instant logged %d lines, want 50", n)
	}

	advance(time.Second)
	buf.Reset()
	for i := range 6 {
		c.Event(syn7001("1/0", uint16(41000+i)))
	}
	if n := countLines(buf.String(), connLine); n != 5 {
		t.Errorf("6 events one second later logged %d lines, want 5", n)
	}

	c.mu.Lock()
	limited := c.limited
	c.mu.Unlock()
	if limited != 11 {
		t.Errorf("rate-limited count = %d, want 11", limited)
	}
}

func TestConnLogger_Summary(t *testing.T) {
	var buf bytes.Buffer
	c := NewConnLogger(debugLogger(&buf))
	now, _ := fixedClock(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC))
	c.now = now
	c.SetRuleset("R", []FirewallRule{tcp7001("1/0")})

	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		c.run(ctx, tick)
		close(done)
	}()

	// No tick reaches run before the events, so no summary runs while they
	// happen.
	for i := range connLogBurst + 10 {
		c.Event(syn7001("1/0", uint16(40000+i)))
	}
	c.Lost(3)
	c.Lost(0)
	c.Lost(-2)
	buf.Reset()
	tick <- time.Time{}
	// A send returns once run took the tick, so this one returns only after
	// the summary ran. Its own summary finds both counts reset and logs
	// nothing, which the count of summary lines below checks.
	tick <- time.Time{}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}

	const want = `level=WARN msg="policy connection lines dropped" component=policy rate_limited=10 lost=3`
	if n := countLines(buf.String(), "policy connection lines dropped"); n != 1 || !strings.Contains(buf.String(), want) {
		t.Errorf("log = %q, want exactly one line containing %q", buf.String(), want)
	}
}

func TestConnLogger_ForwardTo(t *testing.T) {
	c := NewConnLogger(testLogger())
	now, _ := fixedClock(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC))
	c.now = now
	c.SetRuleset("R", []FirewallRule{tcp7001("1/0")})

	type forwarded struct {
		ts                time.Time
		severity, message string
	}
	var got []forwarded
	c.ForwardTo(func(ts time.Time, severity, message string) {
		got = append(got, forwarded{ts, severity, message})
	})

	c.Event(syn7001("1/0", 41001))
	c.Lost(1)
	c.summarize()

	if len(got) != 2 {
		t.Fatalf("forwarded %d records, want 2: %+v", len(got), got)
	}
	if got[0].severity != "info" || !strings.Contains(got[0].message, `msg="policy rule allowed connection" component=policy revision_id=R rule=0`) {
		t.Errorf("forwarded line = %+v, want severity info and the connection line", got[0])
	}
	if !strings.HasPrefix(got[0].message, "time=2026-11-12T10:00:00.000Z level=INFO ") {
		t.Errorf("forwarded line = %q, want it to start with the time and level", got[0].message)
	}
	if !got[0].ts.Equal(now()) {
		t.Errorf("forwarded time = %v, want %v", got[0].ts, now())
	}
	if got[1].severity != "warning" || !strings.Contains(got[1].message, `msg="policy connection lines dropped" component=policy rate_limited=0 lost=1`) {
		t.Errorf("forwarded summary = %+v, want severity warning and the summary", got[1])
	}
	for _, f := range got {
		if strings.HasSuffix(f.message, "\n") {
			t.Errorf("forwarded message %q ends in a newline", f.message)
		}
	}

	c.ForwardTo(nil)
	c.Event(syn7001("1/0", 41002))
	if len(got) != 2 {
		t.Errorf("ForwardTo(nil) still forwarded: %+v", got)
	}
}

func TestConnLogger_Concurrent(t *testing.T) {
	c := NewConnLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				switch i % 3 {
				case 0:
					c.SetRuleset("R", []FirewallRule{tcp7001("1/0")})
				case 1:
					c.Event(syn7001("1/0", uint16(g*1000+i)))
				default:
					c.Lost(1)
				}
			}
		}()
	}
	wg.Wait()
	c.summarize()
}
