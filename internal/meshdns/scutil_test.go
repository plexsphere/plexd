package meshdns

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// scutilList is the script every Apply and Revert starts with.
const scutilList = "open\nlist State:/Network/Service/plexd-meshdns-.*/DNS\nquit\n"

// The keys plexd writes, spelled out rather than built from the constants,
// so a test pins the names an operator finds in the dynamic store.
const (
	keySearch  = "State:/Network/Service/plexd-meshdns-search/DNS"
	keyMatch0  = "State:/Network/Service/plexd-meshdns-match-0/DNS"
	keyMatch1  = "State:/Network/Service/plexd-meshdns-match-1/DNS"
	keyMatch3  = "State:/Network/Service/plexd-meshdns-match-3/DNS"
	keyDefault = "State:/Network/Service/plexd-meshdns-default/DNS"
)

// scutilReply is what the fake scutil answers one run with.
type scutilReply struct {
	out string
	err error
}

// fakeScutil stands in for scutil and the cache flush. It answers each run
// with the next reply, and with no output and no error once the replies run
// out, and it records every script it was given.
type fakeScutil struct {
	mu       sync.Mutex
	replies  []scutilReply
	scripts  []string
	flushes  int
	flushErr error
	// block makes every run wait for its context to end, as a scutil that
	// hangs would until exec kills it; blockRun does that for the run with
	// that number only, counting from 1.
	block    bool
	blockRun int
}

func (f *fakeScutil) run(ctx context.Context, script string) ([]byte, error) {
	// exec does not start a command whose context is done, so such a script
	// never reaches scutil.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.scripts = append(f.scripts, script)
	var reply scutilReply
	if len(f.replies) > 0 {
		reply, f.replies = f.replies[0], f.replies[1:]
	}
	block := f.block || f.blockRun == len(f.scripts)
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, errors.New("signal: killed")
	}
	return []byte(reply.out), reply.err
}

func (f *fakeScutil) flush(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	return f.flushErr
}

func (f *fakeScutil) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.scripts)
}

func (f *fakeScutil) flushed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

// newScutilTest returns a registrar on f that logs to the returned recorder.
func newScutilTest(f *fakeScutil) (*ScutilRegistrar, *logRecorder) {
	logs := &logRecorder{}
	return &ScutilRegistrar{logger: slog.New(&recordingHandler{rec: logs}), run: f.run, flush: f.flush}, logs
}

// listOf returns the output of scutil's list command for keys.
func listOf(keys ...string) scutilReply {
	if len(keys) == 0 {
		return scutilReply{out: "  no subKey(s).\n"}
	}
	var b strings.Builder
	for i, k := range keys {
		fmt.Fprintf(&b, "  subKey [%d] = %s\n", i, k)
	}
	return scutilReply{out: b.String()}
}

// mockRegistration is the registration of the mock control plane's block on
// macOS, where the resolver listens on 127.0.0.1, with a catch-all.
func mockRegistration() Registration {
	return Registration{
		Interface:      "utun7",
		Server:         netip.MustParseAddrPort("127.0.0.1:5354"),
		SearchDomain:   "app.e2e.internal",
		RoutingDomains: []string{"e2e.internal", "0.99.10.in-addr.arpa"},
		DefaultRoute:   true,
	}
}

// wantScripts fails the test unless the fake ran exactly want, in order.
func wantScripts(t *testing.T, f *fakeScutil, want ...string) {
	t.Helper()
	got := f.ran()
	if !slices.Equal(got, want) {
		t.Errorf("scutil ran %d scripts, want %d", len(got), len(want))
		for i := range max(len(got), len(want)) {
			var g, w string
			if i < len(got) {
				g = got[i]
			}
			if i < len(want) {
				w = want[i]
			}
			if g != w {
				t.Errorf("script %d:\n got: %q\nwant: %q", i, g, w)
			}
		}
	}
}

// wantFlushes fails the test unless the cache was flushed n times.
func wantFlushes(t *testing.T, f *fakeScutil, n int) {
	t.Helper()
	if got := f.flushed(); got != n {
		t.Errorf("cache flushed %d times, want %d", got, n)
	}
}

// setsIn returns the keys a script sets, in order.
func setsIn(script string) []string {
	var keys []string
	for line := range strings.SplitSeq(script, "\n") {
		if key, ok := strings.CutPrefix(line, "set "); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// removesIn returns the keys a script removes, in order.
func removesIn(script string) []string {
	var keys []string
	for line := range strings.SplitSeq(script, "\n") {
		if key, ok := strings.CutPrefix(line, "remove "); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func TestScutilRegistrar_Name(t *testing.T) {
	r, _ := newScutilTest(&fakeScutil{})
	if got := r.Name(); got != "configd" {
		t.Errorf("Name() = %q, want %q", got, "configd")
	}
}

// The script for the mock control plane's registration with a catch-all and
// a stale match-1 is the one the issue and the docs show, byte for byte.
func TestScutilApply_Script(t *testing.T) {
	f := &fakeScutil{replies: []scutilReply{listOf(keyMatch1)}}
	r, _ := newScutilTest(f)

	if err := r.Apply(context.Background(), mockRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}

	wantScripts(t, f, scutilList, `open
remove State:/Network/Service/plexd-meshdns-match-1/DNS
d.init
d.add ServerAddresses * 127.0.0.1
d.add ServerPort # 5354
d.add SupplementalMatchDomains * app.e2e.internal
d.add SupplementalMatchDomainsNoSearch # 0
set State:/Network/Service/plexd-meshdns-search/DNS
d.init
d.add ServerAddresses * 127.0.0.1
d.add ServerPort # 5354
d.add SupplementalMatchDomains * e2e.internal 0.99.10.in-addr.arpa
d.add SupplementalMatchDomainsNoSearch # 1
set State:/Network/Service/plexd-meshdns-match-0/DNS
d.init
d.add ServerAddresses * 127.0.0.1
d.add ServerPort # 5354
d.add SupplementalMatchDomains * ""
d.add SearchOrder # 100000
set State:/Network/Service/plexd-meshdns-default/DNS
quit
`)
	wantFlushes(t, f, 1)
}

// A key the registration does not write goes, and before anything is set,
// so a catch-all that ends stops taking every name first.
func TestScutilApply_RemovesStaleKeysFirst(t *testing.T) {
	tests := []struct {
		name        string
		edit        func(*Registration)
		listed      []string
		wantSets    []string
		wantRemoves []string
	}{
		{
			name:        "no catch-all",
			edit:        func(r *Registration) { r.DefaultRoute = false },
			listed:      []string{keySearch, keyMatch0, keyDefault},
			wantSets:    []string{keySearch, keyMatch0},
			wantRemoves: []string{keyDefault},
		},
		{
			name:        "no search domain",
			edit:        func(r *Registration) { r.SearchDomain = "" },
			listed:      []string{keySearch},
			wantSets:    []string{keyMatch0, keyDefault},
			wantRemoves: []string{keySearch},
		},
		{
			name:        "no routing domain",
			edit:        func(r *Registration) { r.RoutingDomains = nil; r.DefaultRoute = false },
			listed:      []string{keyMatch0, keySearch},
			wantSets:    []string{keySearch},
			wantRemoves: []string{keyMatch0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeScutil{replies: []scutilReply{listOf(tt.listed...)}}
			r, _ := newScutilTest(f)
			reg := mockRegistration()
			tt.edit(&reg)

			if err := r.Apply(context.Background(), reg); err != nil {
				t.Fatalf("Apply() = %v, want nil", err)
			}
			scripts := f.ran()
			if len(scripts) != 2 {
				t.Fatalf("scutil ran %d scripts, want the list and one more", len(scripts))
			}
			script := scripts[1]
			if got := setsIn(script); !slices.Equal(got, tt.wantSets) {
				t.Errorf("set %q, want %q", got, tt.wantSets)
			}
			if got := removesIn(script); !slices.Equal(got, tt.wantRemoves) {
				t.Errorf("removed %q, want %q", got, tt.wantRemoves)
			}
			if strings.Index(script, "remove ") > strings.Index(script, "d.init") {
				t.Errorf("a remove comes after the first d.init in\n%s", script)
			}
		})
	}
}

// An IPv6 server is written as it is, and every key carries the port.
func TestScutilApply_IPv6Server(t *testing.T) {
	f := &fakeScutil{replies: []scutilReply{listOf()}}
	r, _ := newScutilTest(f)
	reg := mockRegistration()
	reg.Server = netip.MustParseAddrPort("[fd00::1]:5354")

	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	script := f.ran()[1]
	sets := len(setsIn(script))
	if got := strings.Count(script, "d.add ServerAddresses * fd00::1\n"); got != sets {
		t.Errorf("%d keys name fd00::1, want all %d", got, sets)
	}
	if got := strings.Count(script, "d.add ServerPort # 5354\n"); got != sets {
		t.Errorf("%d keys carry port 5354, want all %d", got, sets)
	}
}

// The routing domains go into keys of at most 50 domains and 1500 bytes.
func TestScutilApply_Batches(t *testing.T) {
	short := make([]string, 120)
	for i := range short {
		short[i] = fmt.Sprintf("d%03d.e.tst", i)
	}
	long := make([]string, 10)
	for i := range long {
		long[i] = strings.Repeat("a", 195) + fmt.Sprintf(".n%03d", i)
	}
	tests := []struct {
		name    string
		domains []string
		size    int
		want    []int
	}{
		{"120 domains of 10 bytes", short, 10, []int{50, 50, 20}},
		{"10 domains of 200 bytes", long, 200, []int{7, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, d := range tt.domains {
				if len(d) != tt.size {
					t.Fatalf("test domain %q has %d bytes, want %d", d, len(d), tt.size)
				}
			}
			f := &fakeScutil{replies: []scutilReply{listOf(keyMatch3)}}
			r, _ := newScutilTest(f)
			reg := Registration{Interface: "utun7", Server: netip.MustParseAddrPort("127.0.0.1:5354"), RoutingDomains: tt.domains}

			if err := r.Apply(context.Background(), reg); err != nil {
				t.Fatalf("Apply() = %v, want nil", err)
			}
			script := f.ran()[1]
			var got []int
			var all []string
			for line := range strings.SplitSeq(script, "\n") {
				if list, ok := strings.CutPrefix(line, "d.add SupplementalMatchDomains * "); ok {
					domains := strings.Split(list, " ")
					got = append(got, len(domains))
					all = append(all, domains...)
					if len(list) > maxDomainBytesPerKey {
						t.Errorf("a key holds %d bytes of domains, want at most %d", len(list), maxDomainBytesPerKey)
					}
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("keys hold %v domains, want %v", got, tt.want)
			}
			if !slices.Equal(all, tt.domains) {
				t.Error("the keys do not hold the domains in order")
			}
			wantSets := make([]string, len(tt.want))
			for i := range wantSets {
				wantSets[i] = fmt.Sprintf("State:/Network/Service/plexd-meshdns-match-%d/DNS", i)
			}
			if got := setsIn(script); !slices.Equal(got, wantSets) {
				t.Errorf("set %q, want %q", got, wantSets)
			}
			if got := removesIn(script); !slices.Equal(got, []string{keyMatch3}) {
				t.Errorf("removed %q, want %q", got, []string{keyMatch3})
			}
		})
	}
}

// Only lines that name a plexd DNS key count: the empty answer, other
// owners' keys and other dictionaries are never removed.
func TestScutilApply_ListParsing(t *testing.T) {
	tests := []struct {
		name string
		out  string
	}{
		{"no keys", "  no subKey(s).\n"},
		{"empty output", ""},
		{"other keys", "  subKey [0] = State:/Network/Service/NetBird-Match-0/DNS\n" +
			"  subKey [1] = State:/Network/Service/plexd-meshdns-match-0/IPv4\n" +
			"  subKey [2] = State:/Network/Service/plexd-meshdns-/DNS\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeScutil{replies: []scutilReply{{out: tt.out}}}
			r, _ := newScutilTest(f)
			if err := r.Apply(context.Background(), mockRegistration()); err != nil {
				t.Fatalf("Apply() = %v, want nil", err)
			}
			if got := removesIn(f.ran()[1]); len(got) != 0 {
				t.Errorf("removed %q, want nothing", got)
			}
		})
	}
	if got := parseScutilList([]byte(listOf(keySearch, keyMatch0).out)); !slices.Equal(got, []string{keySearch, keyMatch0}) {
		t.Errorf("parseScutilList = %q, want %q", got, []string{keySearch, keyMatch0})
	}
}

// A registration that writes no key removes what plexd holds, and does
// nothing at all when it holds nothing.
func TestScutilApply_EmptyRegistration(t *testing.T) {
	empty := Registration{Interface: "utun7", Server: netip.MustParseAddrPort("127.0.0.1:5354")}

	f := &fakeScutil{replies: []scutilReply{listOf(keySearch, keyMatch0)}}
	r, _ := newScutilTest(f)
	if err := r.Apply(context.Background(), empty); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantScripts(t, f, scutilList, "open\nremove "+keySearch+"\nremove "+keyMatch0+"\nquit\n")
	wantFlushes(t, f, 1)

	f = &fakeScutil{replies: []scutilReply{listOf()}}
	r, _ = newScutilTest(f)
	if err := r.Apply(context.Background(), empty); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantScripts(t, f, scutilList)
	wantFlushes(t, f, 0)
}

// A domain that is not a plain DNS name never reaches a script, which root
// runs: a newline would start a command of its own.
func TestScutilApply_RefusesDomain(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Registration, string)
		bad  string
	}{
		{"space", func(r *Registration, d string) { r.RoutingDomains = append(r.RoutingDomains, d) }, "a b"},
		{"newline", func(r *Registration, d string) { r.RoutingDomains = append(r.RoutingDomains, d) }, "x\nremove State:/Network/Global/DNS"},
		{"quote", func(r *Registration, d string) { r.RoutingDomains = append(r.RoutingDomains, d) }, `"`},
		{"254 bytes", func(r *Registration, d string) { r.RoutingDomains = append(r.RoutingDomains, d) }, strings.Repeat("a", 254)},
		{"empty", func(r *Registration, d string) { r.RoutingDomains = append(r.RoutingDomains, d) }, ""},
		{"search domain", func(r *Registration, d string) { r.SearchDomain = d }, "app e2e"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeScutil{}
			r, _ := newScutilTest(f)
			reg := mockRegistration()
			tt.edit(&reg, tt.bad)

			err := r.Apply(context.Background(), reg)
			want := fmt.Sprintf("meshdns: scutil: domain %q cannot be written to the dynamic store", tt.bad)
			if err == nil || err.Error() != want {
				t.Errorf("Apply() = %v, want %s", err, want)
			}
			wantScripts(t, f)
			wantFlushes(t, f, 0)
		})
	}
}

// A missing scutil counts as no usable system resolver for Apply, and as
// nothing to remove for Revert.
func TestScutil_Missing(t *testing.T) {
	missing := []error{
		&fs.PathError{Op: "fork/exec", Path: scutilPath, Err: fs.ErrNotExist},
		&exec.Error{Name: scutilPath, Err: exec.ErrNotFound},
	}
	for _, runErr := range missing {
		t.Run(runErr.Error(), func(t *testing.T) {
			f := &fakeScutil{replies: []scutilReply{{err: runErr}}}
			r, logs := newScutilTest(f)
			err := r.Apply(context.Background(), mockRegistration())
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("Apply() = %v, want an error wrapping ErrUnavailable", err)
			}
			if want := "meshdns: scutil: /usr/sbin/scutil is missing: meshdns: no usable system resolver"; err == nil || err.Error() != want {
				t.Errorf("Apply() = %v, want %s", err, want)
			}
			wantScripts(t, f, scutilList)
			wantFlushes(t, f, 0)
			wantLine(t, logs, slog.LevelDebug, "scutil not usable", map[string]string{"op": "list"})

			f = &fakeScutil{replies: []scutilReply{{err: runErr}}}
			r, logs = newScutilTest(f)
			if err := r.Revert(context.Background(), "utun7"); err != nil {
				t.Errorf("Revert() = %v, want nil", err)
			}
			wantScripts(t, f, scutilList)
			wantFlushes(t, f, 0)
			wantLine(t, logs, slog.LevelDebug, "scutil not usable", map[string]string{"op": "list"})
		})
	}
}

// A scutil that outlives the context fails with the context's error.
func TestScutilApply_Deadline(t *testing.T) {
	f := &fakeScutil{block: true}
	r, _ := newScutilTest(f)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := r.Apply(ctx, mockRegistration())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Apply() = %v, want an error wrapping context.DeadlineExceeded", err)
	}
	if want := "meshdns: scutil: list: context deadline exceeded"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	wantScripts(t, f, scutilList)
}

// A list that fails ends Apply before any script that changes something. The
// error carries scutil's output when it printed any.
func TestScutilApply_ListFails(t *testing.T) {
	tests := []struct {
		out  string
		want string
	}{
		{"boom\n", "meshdns: scutil: list: exit status 1: boom"},
		{"first\n\nsecond\n", "meshdns: scutil: list: exit status 1: first; second"},
		{"", "meshdns: scutil: list: exit status 1"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			f := &fakeScutil{replies: []scutilReply{{out: tt.out, err: errors.New("exit status 1")}}}
			r, _ := newScutilTest(f)

			err := r.Apply(context.Background(), mockRegistration())
			if err == nil || err.Error() != tt.want {
				t.Errorf("Apply() = %v, want %s", err, tt.want)
			}
			if errors.Is(err, ErrUnavailable) {
				t.Errorf("Apply() = %v wraps ErrUnavailable, want it not to", err)
			}
			wantScripts(t, f, scutilList)
			wantFlushes(t, f, 0)
		})
	}
}

// A script that runs out the step deadline still leaves the removal its
// share of the time: the removal runs under Apply's own context.
func TestScutilApply_RevertAfterDeadline(t *testing.T) {
	f := &fakeScutil{
		replies:  []scutilReply{listOf(keyMatch1), {}, listOf(keyMatch0, keyMatch1), {}},
		blockRun: 2,
	}
	r, _ := newScutilTest(f)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := r.Apply(ctx, mockRegistration())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Apply() = %v, want an error wrapping context.DeadlineExceeded", err)
	}
	if want := "meshdns: scutil: apply: context deadline exceeded"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	scripts := f.ran()
	if len(scripts) != 4 {
		t.Fatalf("scutil ran %d scripts, want list, apply, list, remove", len(scripts))
	}
	if want := "open\nremove " + keyMatch0 + "\nremove " + keyMatch1 + "\nquit\n"; scripts[3] != want {
		t.Errorf("removal = %q, want %q", scripts[3], want)
	}
	wantFlushes(t, f, 0)
}

// scutil exits 0 after a command fails, so output is a failure, which a
// revert of every plexd key follows. "No such key" alone is not one.
func TestScutilApply_ScriptOutput(t *testing.T) {
	f := &fakeScutil{replies: []scutilReply{
		listOf(keyMatch1),
		{out: "failed to set key\n"},
		listOf(keyMatch0, keyMatch1),
		{},
	}}
	r, logs := newScutilTest(f)

	err := r.Apply(context.Background(), mockRegistration())
	if want := "meshdns: scutil: apply: failed to set key"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Errorf("Apply() = %v wraps ErrUnavailable, want it not to", err)
	}
	scripts := f.ran()
	if len(scripts) != 4 {
		t.Fatalf("scutil ran %d scripts, want list, apply, list, remove", len(scripts))
	}
	if scripts[2] != scutilList || scripts[3] != "open\nremove "+keyMatch0+"\nremove "+keyMatch1+"\nquit\n" {
		t.Errorf("after the failure scutil ran %q and %q, want the list and the removal of both keys", scripts[2], scripts[3])
	}
	wantFlushes(t, f, 0)
	wantCount(t, logs, "revert after a failed registration failed", 0)

	// The revert after the failure fails too, which is logged at Debug.
	f = &fakeScutil{replies: []scutilReply{
		listOf(),
		{out: "failed to set key\n"},
		{out: "boom\n", err: errors.New("exit status 1")},
	}}
	r, logs = newScutilTest(f)
	if err := r.Apply(context.Background(), mockRegistration()); err == nil {
		t.Error("Apply() = nil, want the script's error")
	}
	wantLine(t, logs, slog.LevelDebug, "revert after a failed registration failed", map[string]string{
		"interface": "utun7",
		"error":     "meshdns: scutil: list: exit status 1: boom",
	})

	// A remove of a key that is already gone prints "No such key".
	f = &fakeScutil{replies: []scutilReply{listOf(keyMatch1), {out: "No such key\n\nNo such key\n"}}}
	r, _ = newScutilTest(f)
	if err := r.Apply(context.Background(), mockRegistration()); err != nil {
		t.Errorf("Apply() = %v, want nil", err)
	}
	wantFlushes(t, f, 1)
}

// A cache that will not flush leaves the registration in place.
func TestScutilApply_FlushFails(t *testing.T) {
	f := &fakeScutil{replies: []scutilReply{listOf()}, flushErr: errors.New("killall -HUP mDNSResponder: exit status 1")}
	r, logs := newScutilTest(f)

	if err := r.Apply(context.Background(), mockRegistration()); err != nil {
		t.Errorf("Apply() = %v, want nil", err)
	}
	wantFlushes(t, f, 1)
	wantLine(t, logs, slog.LevelDebug, "mesh dns cache flush failed", map[string]string{
		"error": "killall -HUP mDNSResponder: exit status 1",
	})
}

func TestScutilRevert(t *testing.T) {
	t.Run("removes every key", func(t *testing.T) {
		f := &fakeScutil{replies: []scutilReply{listOf(keySearch, keyMatch0, keyDefault)}}
		r, _ := newScutilTest(f)
		// The keys do not name the interface, so any interface finds them.
		if err := r.Revert(context.Background(), "utun9"); err != nil {
			t.Fatalf("Revert() = %v, want nil", err)
		}
		wantScripts(t, f, scutilList, "open\nremove "+keySearch+"\nremove "+keyMatch0+"\nremove "+keyDefault+"\nquit\n")
		wantFlushes(t, f, 1)
	})
	t.Run("nothing to remove", func(t *testing.T) {
		f := &fakeScutil{replies: []scutilReply{listOf()}}
		r, _ := newScutilTest(f)
		if err := r.Revert(context.Background(), "utun9"); err != nil {
			t.Fatalf("Revert() = %v, want nil", err)
		}
		wantScripts(t, f, scutilList)
		wantFlushes(t, f, 0)
	})
	t.Run("remove fails", func(t *testing.T) {
		f := &fakeScutil{replies: []scutilReply{listOf(keySearch), {out: "denied\n"}}}
		r, _ := newScutilTest(f)
		err := r.Revert(context.Background(), "utun9")
		if want := "meshdns: scutil: revert: denied"; err == nil || err.Error() != want {
			t.Errorf("Revert() = %v, want %s", err, want)
		}
		wantFlushes(t, f, 0)
	})
	t.Run("list fails", func(t *testing.T) {
		f := &fakeScutil{replies: []scutilReply{{out: "boom\n", err: errors.New("exit status 1")}}}
		r, _ := newScutilTest(f)
		err := r.Revert(context.Background(), "utun9")
		if want := "meshdns: scutil: list: exit status 1: boom"; err == nil || err.Error() != want {
			t.Errorf("Revert() = %v, want %s", err, want)
		}
		wantScripts(t, f, scutilList)
		wantFlushes(t, f, 0)
	})
}
