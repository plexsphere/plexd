package logfwd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// slogStamp renders ts the way slog.TextHandler writes its time token.
func slogStamp(ts time.Time) string {
	return ts.Format("2006-01-02T15:04:05.000Z07:00")
}

// slogLine builds one slog.TextHandler record.
func slogLine(ts time.Time, level, msg string) string {
	return fmt.Sprintf("time=%s level=%s msg=%q", slogStamp(ts), level, msg)
}

// appendLines appends lines to path, creating the file if it is absent.
func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseSlogLine(t *testing.T) {
	const stamp = "2026-09-04T10:00:00.000+02:00"
	want := time.Date(2026, 9, 4, 10, 0, 0, 0, time.FixedZone("", 2*3600))

	tests := []struct {
		name         string
		line         string
		wantSeverity string
		wantOK       bool
	}{
		{"warn", "time=" + stamp + ` level=WARN msg="x"`, "warning", true},
		{"level with offset", "time=" + stamp + ` level=INFO+2 msg="x"`, "info", true},
		{"error", "time=" + stamp + ` level=ERROR msg="x"`, "err", true},
		{"debug", "time=" + stamp + ` level=DEBUG msg="x"`, "debug", true},
		{"unknown level", "time=" + stamp + ` level=NOTICE msg="x"`, "info", true},
		{"level is the last token", "time=" + stamp + " level=INFO", "info", true},
		{"empty line", "", "", false},
		{"no time token", `level=INFO msg="x"`, "", false},
		{"unparsable time", "time=not-a-time level=INFO", "", false},
		{"second token is not the level", "time=" + stamp + ` msg="x"`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, severity, ok := parseSlogLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if !ts.IsZero() {
					t.Errorf("ts = %v, want the zero time", ts)
				}
				if severity != "" {
					t.Errorf("severity = %q, want %q", severity, "")
				}
				return
			}
			if !ts.Equal(want) {
				t.Errorf("ts = %v, want %v", ts, want)
			}
			if severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", severity, tt.wantSeverity)
			}
		})
	}
}

func TestSlogLevelSeverity(t *testing.T) {
	tests := []struct {
		level string
		want  string
	}{
		{"DEBUG", "debug"},
		{"INFO", "info"},
		{"WARN", "warning"},
		{"ERROR", "err"},
		{"NOTICE", "info"},
		{"", "info"},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			if got := slogLevelSeverity(tt.level); got != tt.want {
				t.Errorf("slogLevelSeverity(%q) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestDaemonLogSource_MapsFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	now := time.Now().Truncate(time.Millisecond)

	first := slogLine(now, "INFO", "one")
	second := "time=" + slogStamp(now) + ` level=WARN msg="two" key=value`
	appendLines(t, path, first, second)

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}

	wantMessages := []string{first, second}
	wantSeverities := []string{"info", "warning"}
	for i, entry := range entries {
		if entry.Source != "daemonlog" {
			t.Errorf("entries[%d].Source = %q, want %q", i, entry.Source, "daemonlog")
		}
		if entry.Unit != "plexd" {
			t.Errorf("entries[%d].Unit = %q, want %q", i, entry.Unit, "plexd")
		}
		if entry.Hostname != "host1" {
			t.Errorf("entries[%d].Hostname = %q, want %q", i, entry.Hostname, "host1")
		}
		if entry.Message != wantMessages[i] {
			t.Errorf("entries[%d].Message = %q, want %q", i, entry.Message, wantMessages[i])
		}
		if entry.Severity != wantSeverities[i] {
			t.Errorf("entries[%d].Severity = %q, want %q", i, entry.Severity, wantSeverities[i])
		}
		if !entry.Timestamp.Equal(now) {
			t.Errorf("entries[%d].Timestamp = %v, want %v", i, entry.Timestamp, now)
		}
	}
}

func TestDaemonLogSource_FirstCollectWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	now := time.Now().Truncate(time.Millisecond)
	old := now.Add(-2 * time.Minute)

	fresh := slogLine(now, "INFO", "fresh")
	appendLines(t, path, slogLine(old, "INFO", "stale"), fresh, "panic: something")

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("first Collect: len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Message != fresh {
		t.Errorf("first Collect: Message = %q, want %q", entries[0].Message, fresh)
	}

	// Every later collection starts at a line boundary, so it forwards what it
	// reads, the stale stamp and the unparsable line included.
	stale := slogLine(old, "ERROR", "late arrival")
	appendLines(t, path, stale, "panic: again")

	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("second Collect: len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Message != stale {
		t.Errorf("second Collect: entries[0].Message = %q, want %q", entries[0].Message, stale)
	}
	if entries[0].Severity != "err" {
		t.Errorf("second Collect: entries[0].Severity = %q, want %q", entries[0].Severity, "err")
	}
	if entries[1].Message != "panic: again" {
		t.Errorf("second Collect: entries[1].Message = %q, want %q", entries[1].Message, "panic: again")
	}
	if entries[1].Severity != "info" {
		t.Errorf("second Collect: entries[1].Severity = %q, want %q", entries[1].Severity, "info")
	}
	if entries[1].Source != "daemonlog" {
		t.Errorf("second Collect: entries[1].Source = %q, want %q", entries[1].Source, "daemonlog")
	}
}

func TestDaemonLogSource_TailsLargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	now := time.Now().Truncate(time.Millisecond)

	// More than 100 KiB, so the 64 KiB tail cannot cover the whole file.
	var lines []string
	for size := 0; size <= 100<<10; {
		line := slogLine(now, "INFO", fmt.Sprintf("filler %05d", len(lines)))
		lines = append(lines, line)
		size += len(line) + 1
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("len(entries) = 0, want the tail of the file")
	}
	if len(entries) >= len(lines) {
		t.Fatalf("len(entries) = %d, want fewer than the %d lines in the file", len(entries), len(lines))
	}
	for i, entry := range entries {
		if !strings.HasPrefix(entry.Message, "time=") {
			t.Fatalf("entries[%d].Message = %q, want a whole slog line", i, entry.Message)
		}
	}
	if got, want := entries[len(entries)-1].Message, lines[len(lines)-1]; got != want {
		t.Errorf("last message = %q, want %q", got, want)
	}
}

func TestDaemonLogSource_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	now := time.Now().Truncate(time.Millisecond)

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	if entries != nil {
		t.Fatalf("first Collect: entries = %v, want nil", entries)
	}

	// The file appears once the service manager starts the daemon.
	appendLines(t, path, slogLine(now, "INFO", "started"))

	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("second Collect: len(entries) = %d, want 1", len(entries))
	}
}

func TestDaemonLogSource_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	now := time.Now().Truncate(time.Millisecond)

	// Same length, so only the file identity reveals the rotation.
	lineA := slogLine(now, "INFO", "aaa")
	lineB := slogLine(now, "INFO", "bbb")
	appendLines(t, path, lineA)

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("first Collect: len(entries) = %d, want 1", len(entries))
	}

	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatal(err)
	}
	appendLines(t, path, lineB)

	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("second Collect: len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Message != lineB {
		t.Errorf("second Collect: Message = %q, want %q", entries[0].Message, lineB)
	}
}

func TestDaemonLogSource_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	src := NewDaemonLogSource(filepath.Join(dir, "plexd.log"), "plexd", "host1", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := src.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Collect() error = %v, want context.Canceled", err)
	}
}

func TestDaemonLogSource_UnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not deny reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a file with mode 0")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	now := time.Now().Truncate(time.Millisecond)
	appendLines(t, path, slogLine(now, "INFO", "unreachable"))

	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Error(err)
		}
	})

	var buf bytes.Buffer
	src := NewDaemonLogSource(path, "plexd", "host1", slog.New(slog.NewTextHandler(&buf, nil)))
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries != nil {
		t.Errorf("entries = %v, want nil", entries)
	}
	if !strings.Contains(buf.String(), "logfwd: daemonlog: tail failed") {
		t.Errorf("log does not report the failed tail: %q", buf.String())
	}
}

// TestDaemonLogSource_SymlinkedPath covers the substitution the write side
// refuses through O_NOFOLLOW: /Library/Logs is writable by the admin group on
// macOS, so an unprivileged member of it can point the daemon log path at a
// file root can read and have this source forward its lines as this node's
// daemon log. Nothing of the target may reach the collection.
func TestDaemonLogSource_SymlinkedPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the daemon log file only exists on macOS, and only unix has O_NOFOLLOW")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	target := filepath.Join(dir, "planted.log")
	now := time.Now().Truncate(time.Millisecond)
	appendLines(t, target, slogLine(now, "ERROR", "planted by somebody else"))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if entries != nil {
		t.Errorf("entries = %v, want nothing forwarded from the symlink target", entries)
	}
}

// TestDaemonLogSource_SymlinkRefusedByTheOpen pins where the refusal sits. A
// check on the path in front of the read only describes the file the path held
// at the moment of the check: the two opens the collection performs resolve the
// path again, and a rename between them is enough to have the target read and
// forwarded. Driving the file source underneath directly is that rename, made
// deterministic - it is the read with no check in front of it.
func TestDaemonLogSource_SymlinkRefusedByTheOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("only unix has O_NOFOLLOW")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "plexd.log")
	target := filepath.Join(dir, "planted.log")
	now := time.Now().Truncate(time.Millisecond)
	appendLines(t, target, slogLine(now, "ERROR", "planted by somebody else"))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())

	if err := src.inner.seekTail(path, daemonLogTailBytes); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("seekTail() error = %v, want it to wrap syscall.ELOOP", err)
	}
	entries, err := src.inner.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want the read to refuse the symlink", entries)
	}
}

// TestParseSlogLine_MatchesTextHandlerOutput reads a record the real handler
// wrote, rather than one the test built to the parser's assumptions. The
// daemon logs through slog.TextHandler, and Collect drops every line the
// parser rejects on the first collection after a restart, so a handler option
// that moved those tokens would silently empty that collection.
func TestParseSlogLine_MatchesTextHandlerOutput(t *testing.T) {
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).
		Warn("tunnel down", slog.String("peer", "node-1"))

	line := strings.TrimSuffix(buf.String(), "\n")
	ts, severity, ok := parseSlogLine(line)
	if !ok {
		t.Fatalf("parseSlogLine(%q) = _, _, false, want it to parse real handler output", line)
	}
	if severity != "warning" {
		t.Errorf("severity = %q, want %q", severity, "warning")
	}
	if time.Since(ts) > time.Minute {
		t.Errorf("ts = %v, want a stamp from just now", ts)
	}
}

// TestDaemonLogSource_DropsOwnRecords pins the loop the macOS pair would
// otherwise close: the daemon logs into the file this source reads, so the
// forwarder's own warnings must not come back as input to its next collection.
func TestDaemonLogSource_DropsOwnRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plexd.log")
	now := time.Now().Truncate(time.Millisecond)

	own := "time=" + slogStamp(now) + ` level=WARN msg="log report failed" component=logfwd error="refused"`
	other := slogLine(now, "INFO", "peer added")
	appendLines(t, path, own, other)

	src := NewDaemonLogSource(path, "plexd", "host1", discardLogger())
	src.now = func() time.Time { return now }

	entries, err := src.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Message != other {
		t.Errorf("Message = %q, want %q", entries[0].Message, other)
	}

	// The same has to hold after the first collection, which forwards every
	// line it reads rather than only the ones it can date.
	appendLines(t, path, own)
	entries, err = src.Collect(context.Background())
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("second Collect: entries = %v, want none", entries)
	}
}
