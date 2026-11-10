package meshdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	_ Registrar = (*NRPTRegistrar)(nil)
	_ nrptHost  = (*fakeNRPTHost)(nil)
)

// The rule keys plexd writes, spelled out rather than built from the
// constants, so a test pins the names an operator finds in the registry.
const (
	ruleMatch0  = "plexd-meshdns-match-0"
	ruleMatch1  = "plexd-meshdns-match-1"
	ruleMatch3  = "plexd-meshdns-match-3"
	ruleExempt  = "plexd-meshdns-exempt-local"
	ruleDefault = "plexd-meshdns-default"
)

// The keys of other owners, which plexd never touches: NetBird's, and one
// named by a GUID, as Windows names the rules that Add-DnsClientNrptRule and
// Group Policy write.
const (
	ruleNetBird = "NetBird-Match-0"
	ruleGUID    = "{5abe529b-675b-4486-8459-25a634dacc23}"
)

// The calls the mock control plane's registration records on an empty host,
// as the issue and the docs show them, and the search list a registration
// without a search domain sets.
const (
	writeMatch0  = "write local plexd-meshdns-match-0 [.app.e2e.internal .e2e.internal .0.99.10.in-addr.arpa] 127.0.0.1"
	writeExempt  = `write local plexd-meshdns-exempt-local [.local] ""`
	writeDefault = "write local plexd-meshdns-default [.] 127.0.0.1"
	searchMock   = "search list plexd0 [app.e2e.internal]"
	searchClear  = "search list plexd0 []"
)

// hostError is an error with a fixed text, so a test spells out what Windows
// says without the windows package, and the file builds on every runner.
type hostError string

func (e hostError) Error() string { return string(e) }

const (
	// errDenied is the text of ERROR_ACCESS_DENIED, which
	// GenerateGPNotification returns to a caller that is not LocalSystem.
	errDenied hostError = "Access is denied."
	// errNoKey is the text of ERROR_FILE_NOT_FOUND, which the real host
	// returns for a write into a Group Policy store whose key is gone.
	errNoKey hostError = "The system cannot find the file specified."
)

// nrptEntry is one key of a fake store. stale makes readRule report ok
// false, as for a key whose values are missing or not the ones plexd writes.
type nrptEntry struct {
	name       string
	namespaces []string
	servers    string
	stale      bool
}

// fakeNRPTHost stands in for the registry, IP Helper, userenv.dll and
// dnsapi.dll. It records every call that changes something, a failed one
// too, and holds the keys of each store in listed order. Key names match
// without regard to case, as in the registry.
type fakeNRPTHost struct {
	mu    sync.Mutex
	calls []string
	// touches counts every call, the ones that change nothing too.
	touches int
	stores  map[nrptStore][]nrptEntry
	// policyStore is whether the Group Policy store's key exists, and
	// policyValues whether that key holds values of its own.
	policyStore  bool
	policyValues bool
	// fail makes the call it names return the error every time, and
	// failOnce the next time only. A name is the method, followed for
	// listRules by the store and for readRule, writeRule and deleteRule by
	// the store and the key, as in "writeRule local plexd-meshdns-match-0".
	fail     map[string]error
	failOnce map[string]error
	// onChange is the handler the last watchPolicy received.
	onChange func()
}

func newFakeNRPTHost() *fakeNRPTHost {
	return &fakeNRPTHost{
		stores:   map[nrptStore][]nrptEntry{},
		fail:     map[string]error{},
		failOnce: map[string]error{},
	}
}

// failure counts a call and returns the error injected for op. It runs with
// mu held.
func (h *fakeNRPTHost) failure(op string) error {
	h.touches++
	if err, ok := h.failOnce[op]; ok {
		delete(h.failOnce, op)
		return err
	}
	return h.fail[op]
}

// record keeps a call that changes something. It runs with mu held.
func (h *fakeNRPTHost) record(format string, args ...any) {
	h.calls = append(h.calls, fmt.Sprintf(format, args...))
}

// index returns the position of the key name in store, or -1. It runs with
// mu held.
func (h *fakeNRPTHost) index(store nrptStore, name string) int {
	if store == nrptPolicy && !h.policyStore {
		return -1
	}
	return slices.IndexFunc(h.stores[store], func(e nrptEntry) bool { return strings.EqualFold(e.name, name) })
}

func (h *fakeNRPTHost) policyStoreExists() (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failure("policyStoreExists"); err != nil {
		return false, err
	}
	return h.policyStore, nil
}

func (h *fakeNRPTHost) listRules(store nrptStore) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failure("listRules " + string(store)); err != nil {
		return nil, err
	}
	if store == nrptPolicy && !h.policyStore {
		return nil, nil
	}
	var names []string
	for _, e := range h.stores[store] {
		names = append(names, e.name)
	}
	return names, nil
}

func (h *fakeNRPTHost) readRule(store nrptStore, name string) ([]string, string, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failure("readRule " + string(store) + " " + name); err != nil {
		return nil, "", false, err
	}
	i := h.index(store, name)
	if i < 0 || h.stores[store][i].stale {
		return nil, "", false, nil
	}
	e := h.stores[store][i]
	return slices.Clone(e.namespaces), e.servers, true, nil
}

func (h *fakeNRPTHost) writeRule(store nrptStore, rule nrptRule) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	servers := rule.servers
	if servers == "" {
		servers = `""`
	}
	h.record("write %s %s %v %s", store, rule.name, rule.namespaces, servers)
	if err := h.failure("writeRule " + string(store) + " " + rule.name); err != nil {
		return err
	}
	if store == nrptPolicy && !h.policyStore {
		return errNoKey
	}
	e := nrptEntry{name: rule.name, namespaces: slices.Clone(rule.namespaces), servers: rule.servers}
	if i := h.index(store, rule.name); i >= 0 {
		h.stores[store][i] = e
	} else {
		h.stores[store] = append(h.stores[store], e)
	}
	return nil
}

func (h *fakeNRPTHost) deleteRule(store nrptStore, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("delete %s %s", store, name)
	if err := h.failure("deleteRule " + string(store) + " " + name); err != nil {
		return err
	}
	h.drop(store, name)
	return nil
}

func (h *fakeNRPTHost) policyStoreEmpty() (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.failure("policyStoreEmpty"); err != nil {
		return false, err
	}
	return h.policyStore && len(h.stores[nrptPolicy]) == 0 && !h.policyValues, nil
}

func (h *fakeNRPTHost) deletePolicyStore() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("delete policy store")
	if err := h.failure("deletePolicyStore"); err != nil {
		return err
	}
	h.policyStore, h.policyValues = false, false
	delete(h.stores, nrptPolicy)
	return nil
}

func (h *fakeNRPTHost) setSearchList(iface string, domains []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("search list %s %v", iface, domains)
	return h.failure("setSearchList")
}

func (h *fakeNRPTHost) generateGPNotification() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("notify")
	return h.failure("generateGPNotification")
}

func (h *fakeNRPTHost) refreshPolicy() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("refresh")
	return h.failure("refreshPolicy")
}

func (h *fakeNRPTHost) flush() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("flush")
	return h.failure("flush")
}

// watchPolicy keeps onChange and never calls it: a test calls the handler
// watched returns to stand in for a Group Policy change. Unlike the real
// stop, the fake's does not wait for a running handler, so a handler may run
// after Revert, as a late notification would.
func (h *fakeNRPTHost) watchPolicy(onChange func()) (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record("watch")
	if err := h.failure("watchPolicy"); err != nil {
		return nil, err
	}
	h.onChange = onChange
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.record("stop")
	}, nil
}

// drop deletes the key name from store without recording a call, as an
// operator or a policy refresh would. It runs with mu held.
func (h *fakeNRPTHost) drop(store nrptStore, name string) {
	if i := h.index(store, name); i >= 0 {
		h.stores[store] = slices.Delete(h.stores[store], i, i+1)
	}
}

// update runs f with mu held, for a change of the host while the registrar
// may run.
func (h *fakeNRPTHost) update(f func(h *fakeNRPTHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f(h)
}

// recorded returns the changing calls so far.
func (h *fakeNRPTHost) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

// reset forgets the calls so far.
func (h *fakeNRPTHost) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls, h.touches = nil, 0
}

// watched returns the handler the last watchPolicy received, or nil.
func (h *fakeNRPTHost) watched() func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.onChange
}

// keys returns the names of the keys in store, in listed order.
func (h *fakeNRPTHost) keys(store nrptStore) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var names []string
	for _, e := range h.stores[store] {
		names = append(names, e.name)
	}
	return names
}

// newNRPTTest returns a registrar on h that logs to the returned recorder.
func newNRPTTest(h *fakeNRPTHost) (*NRPTRegistrar, *logRecorder) {
	logs := &logRecorder{}
	return &NRPTRegistrar{logger: slog.New(&recordingHandler{rec: logs}), host: h}, logs
}

// nrptRegistration is the registration of the mock control plane's block on
// Windows, where the resolver listens on 127.0.0.1:53, with a catch-all.
func nrptRegistration() Registration {
	return Registration{
		Interface:      "plexd0",
		Server:         netip.MustParseAddrPort("127.0.0.1:53"),
		SearchDomain:   "app.e2e.internal",
		RoutingDomains: []string{"e2e.internal", "0.99.10.in-addr.arpa"},
		DefaultRoute:   true,
	}
}

// mockEntries are the keys nrptRegistration writes, as a store holds them.
func mockEntries() []nrptEntry {
	return []nrptEntry{
		{name: ruleMatch0, namespaces: []string{".app.e2e.internal", ".e2e.internal", ".0.99.10.in-addr.arpa"}, servers: "127.0.0.1"},
		{name: ruleExempt, namespaces: []string{".local"}},
		{name: ruleDefault, namespaces: []string{"."}, servers: "127.0.0.1"},
	}
}

// mockWrites returns the writes of nrptRegistration into store, in order.
func mockWrites(store nrptStore) []string {
	writes := []string{writeMatch0, writeExempt, writeDefault}
	for i, w := range writes {
		writes[i] = strings.Replace(w, "write local ", "write "+string(store)+" ", 1)
	}
	return writes
}

// wantHostCalls fails the test unless the host recorded exactly want, in
// order.
func wantHostCalls(t *testing.T, h *fakeNRPTHost, want ...string) {
	t.Helper()
	got := h.recorded()
	if slices.Equal(got, want) {
		return
	}
	t.Errorf("host recorded %d calls, want %d", len(got), len(want))
	for i := range max(len(got), len(want)) {
		var g, w string
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g != w {
			t.Errorf("call %d:\n got: %q\nwant: %q", i, g, w)
		}
	}
}

// wantUntouched fails the test unless the registrar called nothing on the
// host, not even a call that changes nothing.
func wantUntouched(t *testing.T, h *fakeNRPTHost) {
	t.Helper()
	wantHostCalls(t, h)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.touches != 0 {
		t.Errorf("host saw %d calls, want none", h.touches)
	}
}

// wantStoreKeys fails the test unless store lists exactly want, in order.
func wantStoreKeys(t *testing.T, h *fakeNRPTHost, store nrptStore, want ...string) {
	t.Helper()
	if got := h.keys(store); !slices.Equal(got, want) {
		t.Errorf("%s store lists %q, want %q", store, got, want)
	}
}

// withSuffix returns the calls with suffix appended.
func withSuffix(calls []string, suffix ...string) []string {
	return append(slices.Clone(calls), suffix...)
}

func TestNRPTRegistrar_Name(t *testing.T) {
	r, _ := newNRPTTest(newFakeNRPTHost())
	if got := r.Name(); got != "Dnscache" {
		t.Errorf("Name() = %q, want %q", got, "Dnscache")
	}
}

// The calls for the mock control plane's registration on an empty host are
// the ones the issue and the docs show, in order.
func TestNRPTApply_ExampleCalls(t *testing.T) {
	h := newFakeNRPTHost()
	r, _ := newNRPTTest(h)

	if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h, writeMatch0, writeExempt, writeDefault, searchMock, "flush", "watch")
	wantStoreKeys(t, h, nrptLocal, ruleMatch0, ruleExempt, ruleDefault)
}

// A catch-all that ends stops taking every name before anything is written:
// the rule for every name goes first, whatever the listed order.
func TestNRPTApply_RemovesStaleKeysFirst(t *testing.T) {
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = []nrptEntry{
		{name: ruleMatch1, namespaces: []string{".old.internal"}, servers: "127.0.0.1"},
		{name: ruleDefault, namespaces: []string{"."}, servers: "127.0.0.1"},
	}
	r, _ := newNRPTTest(h)
	reg := nrptRegistration()
	reg.DefaultRoute = false

	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h,
		"delete local "+ruleDefault,
		"delete local "+ruleMatch1,
		writeMatch0,
		searchMock, "flush", "watch",
	)
	wantStoreKeys(t, h, nrptLocal, ruleMatch0)
}

// A pull that changes nothing writes no key, but the search list and the
// flush follow every Apply, and the watcher starts once.
func TestNRPTApply_SameRegistrationTwice(t *testing.T) {
	h := newFakeNRPTHost()
	r, _ := newNRPTTest(h)
	ctx := context.Background()

	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}
	h.reset()
	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h, searchMock, "flush")
}

// A key that reads otherwise than plexd would write it is written again.
func TestNRPTApply_RewritesDifferingKey(t *testing.T) {
	tests := []struct {
		name string
		edit func(*nrptEntry)
	}{
		{"other server", func(e *nrptEntry) { e.servers = "10.0.0.1" }},
		{"not ok", func(e *nrptEntry) { e.stale = true }},
		{"other namespaces", func(e *nrptEntry) { e.namespaces = e.namespaces[:2] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeNRPTHost()
			h.stores[nrptLocal] = mockEntries()
			tt.edit(&h.stores[nrptLocal][0])
			r, _ := newNRPTTest(h)

			if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
				t.Fatalf("Apply() = %v, want nil", err)
			}
			wantHostCalls(t, h, writeMatch0, searchMock, "flush", "watch")
		})
	}
}

// Only keys that carry plexd's prefix, in any case, are plexd's: other
// owners' keys stay through an Apply and a Revert.
func TestNRPTRegistrar_OwnsOnlyItsKeys(t *testing.T) {
	h := newFakeNRPTHost()
	upper := mockEntries()[0]
	upper.name = strings.ToUpper(ruleMatch0)
	h.stores[nrptLocal] = []nrptEntry{
		{name: ruleNetBird, namespaces: []string{".netbird.cloud"}, servers: "100.64.0.1"},
		{name: ruleGUID, namespaces: []string{".corp.example"}, servers: "192.0.2.1"},
		upper,
	}
	r, _ := newNRPTTest(h)
	ctx := context.Background()

	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	// The upper-case key is the match key plexd wants, so it is neither
	// deleted nor written again.
	wantHostCalls(t, h, writeExempt, writeDefault, searchMock, "flush", "watch")

	h.reset()
	if err := r.Revert(ctx, "plexd0"); err != nil {
		t.Fatalf("Revert() = %v, want nil", err)
	}
	wantHostCalls(t, h,
		"stop",
		searchClear,
		"delete local "+ruleDefault,
		"delete local PLEXD-MESHDNS-MATCH-0",
		"delete local "+ruleExempt,
		"flush",
	)
	wantStoreKeys(t, h, nrptLocal, ruleNetBird, ruleGUID)
}

// The domains go into match keys of at most 50 namespaces, the search domain
// first, and a match key the registration no longer fills goes.
func TestNRPTApply_Batches(t *testing.T) {
	search := "search.tst"
	routing := make([]string, 119)
	for i := range routing {
		routing[i] = fmt.Sprintf("d%03d.e.tst", i)
	}
	all := append([]string{search}, routing...)
	for _, d := range all {
		if len(d) != 10 {
			t.Fatalf("test domain %q has %d bytes, want 10", d, len(d))
		}
	}
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = []nrptEntry{{name: ruleMatch3, namespaces: []string{".old.tst"}, servers: "127.0.0.1"}}
	r, _ := newNRPTTest(h)
	reg := Registration{
		Interface:      "plexd0",
		Server:         netip.MustParseAddrPort("127.0.0.1:53"),
		SearchDomain:   search,
		RoutingDomains: routing,
	}

	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	want := []string{"delete local " + ruleMatch3}
	for i, batch := range [][]string{all[:50], all[50:100], all[100:]} {
		namespaces := make([]string, len(batch))
		for j, d := range batch {
			namespaces[j] = "." + d
		}
		want = append(want, fmt.Sprintf("write local plexd-meshdns-match-%d %v 127.0.0.1", i, namespaces))
	}
	want = append(want, "search list plexd0 [search.tst]", "flush", "watch")
	wantHostCalls(t, h, want...)

	h.mu.Lock()
	defer h.mu.Unlock()
	var sizes []int
	for _, e := range h.stores[nrptLocal] {
		sizes = append(sizes, len(e.namespaces))
	}
	if !slices.Equal(sizes, []int{50, 50, 20}) {
		t.Errorf("match keys hold %v namespaces, want [50 50 20]", sizes)
	}
	if first := h.stores[nrptLocal][0].namespaces[0]; first != ".search.tst" {
		t.Errorf("match-0 starts with %q, want the search domain .search.tst", first)
	}
}

// Without a search domain the adapter's search list is emptied.
func TestNRPTApply_NoSearchDomain(t *testing.T) {
	h := newFakeNRPTHost()
	r, _ := newNRPTTest(h)
	reg := nrptRegistration()
	reg.SearchDomain = ""

	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h,
		"write local plexd-meshdns-match-0 [.e2e.internal .0.99.10.in-addr.arpa] 127.0.0.1",
		writeExempt, writeDefault,
		searchClear, "flush", "watch",
	)
}

// A registration that writes no key removes every plexd key and empties the
// search list.
func TestNRPTApply_EmptyRegistration(t *testing.T) {
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = append(mockEntries(), nrptEntry{name: ruleNetBird, namespaces: []string{".netbird.cloud"}, servers: "100.64.0.1"})
	r, _ := newNRPTTest(h)
	empty := Registration{Interface: "plexd0", Server: netip.MustParseAddrPort("127.0.0.1:53")}

	if err := r.Apply(context.Background(), empty); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h,
		"delete local "+ruleDefault,
		"delete local "+ruleMatch0,
		"delete local "+ruleExempt,
		searchClear, "flush", "watch",
	)
	wantStoreKeys(t, h, nrptLocal, ruleNetBird)
}

// A domain that is not a plain DNS name never reaches the registry, which
// plexd writes as LocalSystem: a comma would split the search list.
func TestNRPTApply_RefusesDomain(t *testing.T) {
	routing := func(r *Registration, d string) { r.RoutingDomains = append(r.RoutingDomains, d) }
	tests := []struct {
		name string
		edit func(*Registration, string)
		bad  string
	}{
		{"space", routing, "a b"},
		{"comma", routing, "a,b"},
		{"newline", routing, "x\n"},
		{"quote", routing, `"`},
		{"254 bytes", routing, strings.Repeat("a", 254)},
		{"search domain", func(r *Registration, d string) { r.SearchDomain = d }, "a,b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeNRPTHost()
			r, _ := newNRPTTest(h)
			reg := nrptRegistration()
			tt.edit(&reg, tt.bad)

			err := r.Apply(context.Background(), reg)
			want := fmt.Sprintf("meshdns: nrpt: domain %q cannot be written to the Name Resolution Policy Table", tt.bad)
			if err == nil || err.Error() != want {
				t.Errorf("Apply() = %v, want %s", err, want)
			}
			wantUntouched(t, h)
		})
	}
}

// The table names a server by address alone, so a resolver on another port
// counts as no usable system resolver.
func TestNRPTApply_PortNot53(t *testing.T) {
	h := newFakeNRPTHost()
	r, _ := newNRPTTest(h)
	reg := nrptRegistration()
	reg.Server = netip.MustParseAddrPort("127.0.0.1:5354")

	err := r.Apply(context.Background(), reg)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("Apply() = %v, want an error wrapping ErrUnavailable", err)
	}
	want := "meshdns: nrpt: the Name Resolution Policy Table sends queries to port 53 only, and the resolver listens on 127.0.0.1:5354: meshdns: no usable system resolver"
	if err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	wantUntouched(t, h)
}

// An IPv4-mapped server is written as the IPv4 address the DNS Client sends
// to.
func TestNRPTApply_UnmapsServer(t *testing.T) {
	h := newFakeNRPTHost()
	r, _ := newNRPTTest(h)
	reg := nrptRegistration()
	reg.Server = netip.MustParseAddrPort("[::ffff:127.0.0.1]:53")

	if err := r.Apply(context.Background(), reg); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h, writeMatch0, writeExempt, writeDefault, searchMock, "flush", "watch")
}

// A context that is done stops Apply and Revert before the first host call.
func TestNRPTRegistrar_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = mockEntries()
	r, _ := newNRPTTest(h)

	err := r.Apply(ctx, nrptRegistration())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Apply() = %v, want an error wrapping context.Canceled", err)
	}
	if want := "meshdns: nrpt: context canceled"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	err = r.Revert(ctx, "plexd0")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Revert() = %v, want an error wrapping context.Canceled", err)
	}
	if want := "meshdns: nrpt: context canceled"; err == nil || err.Error() != want {
		t.Errorf("Revert() = %v, want %s", err, want)
	}
	wantUntouched(t, h)
	wantStoreKeys(t, h, nrptLocal, ruleMatch0, ruleExempt, ruleDefault)
}

// While Group Policy configures the table, every rule goes into the local
// store and then into the Group Policy store, and the DNS Client hears of it
// through GenerateGPNotification.
func TestNRPTApply_PolicyStore(t *testing.T) {
	h := newFakeNRPTHost()
	h.policyStore = true
	r, logs := newNRPTTest(h)

	if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	want := withSuffix(mockWrites(nrptLocal), mockWrites(nrptPolicy)...)
	wantHostCalls(t, h, withSuffix(want, searchMock, "notify", "flush", "watch")...)
	wantStoreKeys(t, h, nrptPolicy, ruleMatch0, ruleExempt, ruleDefault)
	wantLine(t, logs, slog.LevelDebug, "group policy notified", map[string]string{"via": "GenerateGPNotification"})
	wantCount(t, logs, "mesh dns group policy notification failed", 0)
}

// GenerateGPNotification refuses a caller that is not LocalSystem; Apply then
// runs the machine policy engine, and a failure of both is a warning only.
func TestNRPTApply_PolicyNotificationFallback(t *testing.T) {
	writes := withSuffix(mockWrites(nrptLocal), mockWrites(nrptPolicy)...)

	t.Run("refresh", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore = true
		h.fail["generateGPNotification"] = errDenied
		r, logs := newNRPTTest(h)

		if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
			t.Fatalf("Apply() = %v, want nil", err)
		}
		wantHostCalls(t, h, withSuffix(writes, searchMock, "notify", "refresh", "flush", "watch")...)
		wantLine(t, logs, slog.LevelDebug, "group policy notified", map[string]string{"via": "RefreshPolicyEx"})
		wantCount(t, logs, "mesh dns group policy notification failed", 0)
	})
	t.Run("both fail", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore = true
		h.fail["generateGPNotification"] = errDenied
		h.fail["refreshPolicy"] = errors.New("RefreshPolicyEx returned FALSE")
		r, logs := newNRPTTest(h)

		if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
			t.Fatalf("Apply() = %v, want nil", err)
		}
		wantHostCalls(t, h, withSuffix(writes, searchMock, "notify", "refresh", "flush", "watch")...)
		wantLine(t, logs, slog.LevelWarn, "mesh dns group policy notification failed", map[string]string{
			"error": "GenerateGPNotification: Access is denied.; RefreshPolicyEx: RefreshPolicyEx returned FALSE",
		})
		wantCount(t, logs, "group policy notified", 0)
	})
}

// Without the Group Policy store there is nothing to notify.
func TestNRPTApply_NoPolicyStoreNoNotification(t *testing.T) {
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = []nrptEntry{{name: ruleMatch1, namespaces: []string{".old.internal"}, servers: "127.0.0.1"}}
	r, logs := newNRPTTest(h)

	if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	for _, c := range h.recorded() {
		if c == "notify" || c == "refresh" {
			t.Errorf("Apply recorded %q, want no notification without the policy store", c)
		}
	}
	wantCount(t, logs, "group policy notified", 0)
}

// A write that fails ends Apply, which then empties the search list and
// removes every plexd key, and neither flushes nor watches.
func TestNRPTApply_WriteFails(t *testing.T) {
	boom := errors.New("boom")
	h := newFakeNRPTHost()
	stale := mockEntries()[0]
	stale.servers = "10.0.0.1"
	h.stores[nrptLocal] = []nrptEntry{
		stale,
		{name: ruleNetBird, namespaces: []string{".netbird.cloud"}, servers: "100.64.0.1"},
		{name: ruleDefault, namespaces: []string{"."}, servers: "127.0.0.1"},
	}
	h.fail["writeRule local "+ruleMatch0] = boom
	r, logs := newNRPTTest(h)

	err := r.Apply(context.Background(), nrptRegistration())
	if !errors.Is(err, boom) {
		t.Errorf("Apply() = %v, want an error wrapping %v", err, boom)
	}
	if want := "meshdns: nrpt: write local plexd-meshdns-match-0: boom"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	wantHostCalls(t, h,
		writeMatch0,
		searchClear,
		"delete local "+ruleDefault,
		"delete local "+ruleMatch0,
	)
	wantStoreKeys(t, h, nrptLocal, ruleNetBird)
	wantCount(t, logs, "revert after a failed registration failed", 0)
}

// A read that fails ends Apply before any write, and the removal of every
// plexd key follows as after any failed Apply.
func TestNRPTApply_ReadFails(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name string
		op   string
		want string
	}{
		{"list", "listRules local", "meshdns: nrpt: list local: boom"},
		{"read", "readRule local " + ruleMatch0, "meshdns: nrpt: read local plexd-meshdns-match-0: boom"},
		{"policy store", "policyStoreExists", "meshdns: nrpt: open policy store: boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeNRPTHost()
			h.stores[nrptLocal] = []nrptEntry{mockEntries()[0]}
			h.failOnce[tt.op] = boom
			r, logs := newNRPTTest(h)

			err := r.Apply(context.Background(), nrptRegistration())
			if !errors.Is(err, boom) {
				t.Errorf("Apply() = %v, want an error wrapping %v", err, boom)
			}
			if err == nil || err.Error() != tt.want {
				t.Errorf("Apply() = %v, want %s", err, tt.want)
			}
			wantHostCalls(t, h, searchClear, "delete local "+ruleMatch0)
			wantStoreKeys(t, h, nrptLocal)
			wantCount(t, logs, "revert after a failed registration failed", 0)
		})
	}
}

// A failed Apply that touched the Group Policy store notifies the DNS Client
// after the removal, also when the removal itself found nothing there.
func TestNRPTApply_FailureNotifiesPolicy(t *testing.T) {
	boom := errors.New("boom")
	writes := mockWrites(nrptPolicy)

	t.Run("pass wrote keys", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore = true
		h.fail["writeRule policy "+ruleDefault] = boom
		r, logs := newNRPTTest(h)

		err := r.Apply(context.Background(), nrptRegistration())
		if want := "meshdns: nrpt: write policy plexd-meshdns-default: boom"; err == nil || err.Error() != want {
			t.Errorf("Apply() = %v, want %s", err, want)
		}
		want := withSuffix(mockWrites(nrptLocal), writes...)
		wantHostCalls(t, h, withSuffix(want,
			searchClear,
			"delete local "+ruleDefault,
			"delete local "+ruleMatch0,
			"delete local "+ruleExempt,
			"delete policy "+ruleMatch0,
			"delete policy "+ruleExempt,
			"delete policy store",
			"notify",
		)...)
		wantLine(t, logs, slog.LevelDebug, "group policy notified", map[string]string{"via": "GenerateGPNotification"})
	})
	t.Run("pass only deleted", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore = true
		h.stores[nrptPolicy] = []nrptEntry{{name: ruleMatch1, namespaces: []string{".old.internal"}, servers: "127.0.0.1"}}
		h.fail["writeRule policy "+ruleMatch0] = boom
		r, _ := newNRPTTest(h)

		err := r.Apply(context.Background(), nrptRegistration())
		if want := "meshdns: nrpt: write policy plexd-meshdns-match-0: boom"; err == nil || err.Error() != want {
			t.Errorf("Apply() = %v, want %s", err, want)
		}
		wantHostCalls(t, h, withSuffix(mockWrites(nrptLocal),
			"delete policy "+ruleMatch1,
			writes[0],
			searchClear,
			"delete local "+ruleDefault,
			"delete local "+ruleMatch0,
			"delete local "+ruleExempt,
			"notify",
		)...)
	})
}

// An adapter that is gone fails Apply, which removes every rule it wrote.
func TestNRPTApply_AdapterGone(t *testing.T) {
	h := newFakeNRPTHost()
	h.fail["setSearchList"] = errAdapterGone
	r, logs := newNRPTTest(h)

	err := r.Apply(context.Background(), nrptRegistration())
	if !errors.Is(err, errAdapterGone) {
		t.Errorf("Apply() = %v, want an error wrapping errAdapterGone", err)
	}
	if want := "meshdns: nrpt: search list plexd0: no such adapter"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	wantHostCalls(t, h,
		writeMatch0, writeExempt, writeDefault,
		searchMock,
		searchClear,
		"delete local "+ruleDefault,
		"delete local "+ruleMatch0,
		"delete local "+ruleExempt,
	)
	wantStoreKeys(t, h, nrptLocal)
	// The rollback counts a missing adapter as nothing to clear.
	wantCount(t, logs, "revert after a failed registration failed", 0)
}

// A rollback that fails too is logged at Debug, with the Linux and macOS
// text, and Apply returns the error that started it.
func TestNRPTApply_RollbackFails(t *testing.T) {
	errWrite := errors.New("write denied")
	errDelete := errors.New("delete denied")
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = []nrptEntry{{name: ruleDefault, namespaces: []string{"."}, servers: "127.0.0.1"}}
	h.fail["writeRule local "+ruleMatch0] = errWrite
	h.fail["deleteRule local "+ruleDefault] = errDelete
	r, logs := newNRPTTest(h)

	err := r.Apply(context.Background(), nrptRegistration())
	if want := "meshdns: nrpt: write local plexd-meshdns-match-0: write denied"; err == nil || err.Error() != want {
		t.Errorf("Apply() = %v, want %s", err, want)
	}
	if errors.Is(err, errDelete) {
		t.Errorf("Apply() = %v wraps the rollback's error, want only the write's", err)
	}
	wantLine(t, logs, slog.LevelDebug, "revert after a failed registration failed", map[string]string{
		"interface": "plexd0",
		"error":     "meshdns: nrpt: delete local plexd-meshdns-default: delete denied",
	})
}

// A cache that will not flush leaves the registration in place.
func TestNRPTApply_FlushFails(t *testing.T) {
	h := newFakeNRPTHost()
	h.fail["flush"] = errors.New("DnsFlushResolverCache returned FALSE")
	r, logs := newNRPTTest(h)

	if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
		t.Errorf("Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h, writeMatch0, writeExempt, writeDefault, searchMock, "flush", "watch")
	wantLine(t, logs, slog.LevelDebug, "mesh dns cache flush failed", map[string]string{
		"error": "DnsFlushResolverCache returned FALSE",
	})
}

// A watcher that does not start leaves the registration in place, and the
// next Apply starts it.
func TestNRPTApply_WatchFails(t *testing.T) {
	h := newFakeNRPTHost()
	h.failOnce["watchPolicy"] = errors.New("RegisterGPNotification returned FALSE")
	r, logs := newNRPTTest(h)
	ctx := context.Background()

	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Errorf("Apply() = %v, want nil", err)
	}
	wantLine(t, logs, slog.LevelDebug, "group policy watch failed", map[string]string{
		"error": "RegisterGPNotification returned FALSE",
	})
	if h.watched() != nil {
		t.Error("the failed watch kept a handler")
	}

	h.reset()
	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Errorf("second Apply() = %v, want nil", err)
	}
	wantHostCalls(t, h, searchMock, "flush", "watch")
	if h.watched() == nil {
		t.Error("the second Apply started no watch")
	}
}

// Revert stops the watcher before it touches the host, empties the search
// list and removes plexd's keys, the rule for every name first, from the
// local store and then the Group Policy store, whose key goes when that
// leaves it empty.
func TestNRPTRevert_AfterApply(t *testing.T) {
	h := newFakeNRPTHost()
	h.policyStore = true
	r, logs := newNRPTTest(h)
	ctx := context.Background()

	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	h.reset()
	if err := r.Revert(ctx, "plexd0"); err != nil {
		t.Fatalf("Revert() = %v, want nil", err)
	}
	wantHostCalls(t, h,
		"stop",
		searchClear,
		"delete local "+ruleDefault,
		"delete local "+ruleMatch0,
		"delete local "+ruleExempt,
		"delete policy "+ruleDefault,
		"delete policy "+ruleMatch0,
		"delete policy "+ruleExempt,
		"delete policy store",
		"notify",
		"flush",
	)
	wantStoreKeys(t, h, nrptLocal)
	if h.policyStore {
		t.Error("the policy store's key is still there, want it deleted")
	}
	wantCount(t, logs, "group policy notified", 2)
}

// The Group Policy store's key stays while it holds something plexd did not
// write, or when plexd removed nothing from it.
func TestNRPTRevert_KeepsPolicyStore(t *testing.T) {
	plexdKeys := []string{"delete policy " + ruleDefault, "delete policy " + ruleMatch0, "delete policy " + ruleExempt}

	t.Run("foreign key", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore = true
		h.stores[nrptPolicy] = append([]nrptEntry{{name: ruleNetBird, namespaces: []string{".netbird.cloud"}, servers: "100.64.0.1"}}, mockEntries()...)
		r, _ := newNRPTTest(h)

		if err := r.Revert(context.Background(), "plexd0"); err != nil {
			t.Fatalf("Revert() = %v, want nil", err)
		}
		wantHostCalls(t, h, withSuffix(append([]string{searchClear}, plexdKeys...), "notify", "flush")...)
		wantStoreKeys(t, h, nrptPolicy, ruleNetBird)
	})
	t.Run("value of its own", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore, h.policyValues = true, true
		h.stores[nrptPolicy] = mockEntries()
		r, _ := newNRPTTest(h)

		if err := r.Revert(context.Background(), "plexd0"); err != nil {
			t.Fatalf("Revert() = %v, want nil", err)
		}
		wantHostCalls(t, h, withSuffix(append([]string{searchClear}, plexdKeys...), "notify", "flush")...)
		if !h.policyStore {
			t.Error("the policy store's key is gone, want it kept")
		}
	})
	t.Run("removed nothing", func(t *testing.T) {
		h := newFakeNRPTHost()
		h.policyStore = true
		h.stores[nrptLocal] = mockEntries()
		r, _ := newNRPTTest(h)

		if err := r.Revert(context.Background(), "plexd0"); err != nil {
			t.Fatalf("Revert() = %v, want nil", err)
		}
		wantHostCalls(t, h,
			searchClear,
			"delete local "+ruleDefault,
			"delete local "+ruleMatch0,
			"delete local "+ruleExempt,
			"flush",
		)
		if !h.policyStore {
			t.Error("the empty policy store's key is gone, want it kept")
		}
	})
}

// A Revert with nothing to remove on a host whose adapter is gone succeeds
// and neither flushes nor notifies.
func TestNRPTRevert_NothingToRemove(t *testing.T) {
	h := newFakeNRPTHost()
	h.fail["setSearchList"] = errAdapterGone
	r, _ := newNRPTTest(h)

	if err := r.Revert(context.Background(), "plexd0"); err != nil {
		t.Fatalf("Revert() = %v, want nil", err)
	}
	wantHostCalls(t, h, searchClear)
}

// A delete that fails leaves the other keys to go, and Revert reports it.
func TestNRPTRevert_DeleteFails(t *testing.T) {
	boom := errors.New("boom")
	h := newFakeNRPTHost()
	h.stores[nrptLocal] = []nrptEntry{
		mockEntries()[0],
		{name: ruleMatch1, namespaces: []string{".lab.internal"}, servers: "127.0.0.1"},
		{name: ruleDefault, namespaces: []string{"."}, servers: "127.0.0.1"},
	}
	h.fail["deleteRule local "+ruleMatch0] = boom
	r, _ := newNRPTTest(h)

	err := r.Revert(context.Background(), "plexd0")
	if !errors.Is(err, boom) {
		t.Errorf("Revert() = %v, want an error wrapping %v", err, boom)
	}
	if want := "meshdns: nrpt: delete local plexd-meshdns-match-0: boom"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Revert() = %v, want an error containing %s", err, want)
	}
	wantHostCalls(t, h,
		searchClear,
		"delete local "+ruleDefault,
		"delete local "+ruleMatch0,
		"delete local "+ruleMatch1,
		"flush",
	)
	wantStoreKeys(t, h, nrptLocal, ruleMatch0)
}

// A Group Policy store that appears after Apply receives every rule from the
// watcher, which notifies the DNS Client but never runs the policy engine: a
// refresh would signal the watcher again.
func TestNRPTPolicyChanged_PolicyStoreAppears(t *testing.T) {
	tests := []struct {
		name      string
		notifyErr error
	}{
		{"notify succeeds", nil},
		{"notify fails", errDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeNRPTHost()
			r, logs := newNRPTTest(h)
			if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
				t.Fatalf("Apply() = %v, want nil", err)
			}
			h.reset()
			h.update(func(h *fakeNRPTHost) {
				h.policyStore = true
				if tt.notifyErr != nil {
					h.fail["generateGPNotification"] = tt.notifyErr
				}
			})

			h.watched()()

			wantHostCalls(t, h, withSuffix(mockWrites(nrptPolicy), "notify", "flush")...)
			wantStoreKeys(t, h, nrptPolicy, ruleMatch0, ruleExempt, ruleDefault)
			wantLine(t, logs, slog.LevelInfo, "mesh dns registration re-applied after a group policy change", map[string]string{
				"group_policy": "true",
				"rules":        "3",
			})
			if tt.notifyErr == nil {
				wantLine(t, logs, slog.LevelDebug, "group policy notified", map[string]string{"via": "GenerateGPNotification"})
			} else {
				wantLine(t, logs, slog.LevelWarn, "mesh dns group policy notification failed", map[string]string{
					"error": "GenerateGPNotification: Access is denied.",
				})
			}
		})
	}
}

// A change that leaves both stores in step costs nothing, and a local key an
// operator deleted is written again.
func TestNRPTPolicyChanged_InStep(t *testing.T) {
	h := newFakeNRPTHost()
	h.policyStore = true
	r, logs := newNRPTTest(h)
	if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	onChange := h.watched()
	h.reset()
	before := len(logs.all())

	onChange()
	wantHostCalls(t, h)
	if got := logs.all()[before:]; len(got) != 0 {
		t.Errorf("a change in step logged %d lines, want none: first %q", len(got), got[0].msg)
	}

	h.update(func(h *fakeNRPTHost) { h.drop(nrptLocal, ruleMatch0) })
	onChange()
	wantHostCalls(t, h, writeMatch0, "flush")
	wantLine(t, logs, slog.LevelInfo, "mesh dns registration re-applied after a group policy change", map[string]string{
		"group_policy": "true",
		"rules":        "3",
	})
}

// A change after Revert, or after a failed Apply, finds no registration to
// write again, so it touches no key, not even a plexd key that appeared
// since.
func TestNRPTPolicyChanged_NoRegistration(t *testing.T) {
	tests := []struct {
		name string
		end  func(*testing.T, *NRPTRegistrar, *fakeNRPTHost)
	}{
		{"after revert", func(t *testing.T, r *NRPTRegistrar, _ *fakeNRPTHost) {
			if err := r.Revert(context.Background(), "plexd0"); err != nil {
				t.Fatalf("Revert() = %v, want nil", err)
			}
		}},
		{"after failed apply", func(t *testing.T, r *NRPTRegistrar, h *fakeNRPTHost) {
			h.fail["setSearchList"] = errors.New("boom")
			if err := r.Apply(context.Background(), nrptRegistration()); err == nil {
				t.Fatal("second Apply() = nil, want the search list's error")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFakeNRPTHost()
			r, logs := newNRPTTest(h)
			if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
				t.Fatalf("Apply() = %v, want nil", err)
			}
			onChange := h.watched()
			tt.end(t, r, h)
			h.reset()
			h.update(func(h *fakeNRPTHost) {
				h.stores[nrptLocal] = []nrptEntry{{name: ruleMatch1, namespaces: []string{".old.internal"}, servers: "127.0.0.1"}}
			})

			onChange()
			wantHostCalls(t, h)
			wantStoreKeys(t, h, nrptLocal, ruleMatch1)
			wantCount(t, logs, "mesh dns registration re-applied after a group policy change", 0)
		})
	}
}

// A change whose write fails removes nothing, and the next change writes
// again.
func TestNRPTPolicyChanged_WriteFails(t *testing.T) {
	boom := errors.New("boom")
	h := newFakeNRPTHost()
	r, logs := newNRPTTest(h)
	if err := r.Apply(context.Background(), nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	onChange := h.watched()
	h.reset()
	h.update(func(h *fakeNRPTHost) {
		h.policyStore = true
		h.fail["writeRule policy "+ruleMatch0] = boom
	})

	onChange()
	wantHostCalls(t, h, mockWrites(nrptPolicy)[0])
	wantLine(t, logs, slog.LevelWarn, "mesh dns re-apply after a group policy change failed", map[string]string{
		"error": "meshdns: nrpt: write policy plexd-meshdns-match-0: boom",
	})
	wantStoreKeys(t, h, nrptLocal, ruleMatch0, ruleExempt, ruleDefault)

	h.reset()
	h.update(func(h *fakeNRPTHost) { delete(h.fail, "writeRule policy "+ruleMatch0) })
	onChange()
	wantHostCalls(t, h, withSuffix(mockWrites(nrptPolicy), "notify", "flush")...)
}

// The watcher's handler runs on its own goroutine, so it may run while Apply
// and Revert do. The race detector checks the locking, and a handler that
// runs after the last Revert writes nothing.
func TestNRPTPolicyChanged_ConcurrentWithApplyAndRevert(t *testing.T) {
	h := newFakeNRPTHost()
	r, _ := newNRPTTest(h)
	ctx := context.Background()
	if err := r.Apply(ctx, nrptRegistration()); err != nil {
		t.Fatalf("Apply() = %v, want nil", err)
	}
	onChange := h.watched()

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			h.update(func(h *fakeNRPTHost) { h.drop(nrptLocal, ruleMatch0) })
			onChange()
		}
	})
	for range 50 {
		if err := r.Apply(ctx, nrptRegistration()); err != nil {
			t.Errorf("Apply() = %v, want nil", err)
		}
		if err := r.Revert(ctx, "plexd0"); err != nil {
			t.Errorf("Revert() = %v, want nil", err)
		}
	}
	wg.Wait()

	wantStoreKeys(t, h, nrptLocal)
	h.reset()
	onChange()
	wantHostCalls(t, h)
}
