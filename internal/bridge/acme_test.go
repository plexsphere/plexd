package bridge

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// ACMEManager tests
// ---------------------------------------------------------------------------

// newTestACMEManager returns an ACMEManager over a temporary cache whose
// requests go to a recording transport that answers none. It is torn down
// when the test ends.
func newTestACMEManager(t *testing.T) (*ACMEManager, *acmeTestTransport, *relayLog) {
	t.Helper()
	logger, logs := newRelayLogger()
	transport := &acmeTestTransport{}
	mgr := NewACMEManager(ACMEConfig{CacheDir: t.TempDir(), HTTPTransport: transport}, logger)
	t.Cleanup(func() { _ = mgr.Teardown() })
	return mgr, transport, logs
}

// activeAccount returns the account the manager uses now, or nil.
func activeAccount(m *ACMEManager) *acmeAccount {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.account
}

func TestACMEManager_InactiveWithoutAccount(t *testing.T) {
	mgr, transport, _ := newTestACMEManager(t)
	settings := &api.IngressACME{DirectoryURL: "https://ca.example/dir"}

	for _, tc := range []struct {
		name      string
		configure func()
	}{
		{name: "new"},
		{name: "nil settings and no hosts", configure: func() { mgr.Configure(nil, nil) }},
		{name: "settings and no hosts", configure: func() { mgr.Configure(settings, nil) }},
		{name: "nil settings and a host", configure: func() { mgr.Configure(nil, []string{"api.example.com"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.configure != nil {
				tc.configure()
			}
			if mgr.Active() {
				t.Error("Active = true, want false")
			}
			_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
			if err == nil || err.Error() != "bridge: acme: no account is configured" {
				t.Errorf("GetCertificate = %v, want %q", err, "bridge: acme: no account is configured")
			}
			for _, name := range []string{"api.example.com", "API.example.com", "", "x"} {
				if mgr.HasHost(name) {
					t.Errorf("HasHost(%q) = true, want false", name)
				}
			}
		})
	}
	if got := transport.requests(); len(got) != 0 {
		t.Errorf("requests = %v, want none", got)
	}
}

func TestACMEManager_ConfigureNoHostsRetiresTheAccount(t *testing.T) {
	mgr, _, _ := newTestACMEManager(t)
	settings := &api.IngressACME{DirectoryURL: "https://ca.example/dir"}
	mgr.Configure(settings, []string{"api.example.com"})
	acct := activeAccount(mgr)
	if !mgr.Active() || acct == nil {
		t.Fatal("Active = false after Configure with a host, want true")
	}

	mgr.Configure(settings, nil)
	if mgr.Active() || mgr.HasHost("api.example.com") {
		t.Error("the account is still active without hosts")
	}
	if !acct.gate.retired() {
		t.Error("the replaced account's gate is open, want it retired")
	}
}

func TestACMEManager_HostPolicy(t *testing.T) {
	mgr, _, _ := newTestACMEManager(t)
	mgr.Configure(&api.IngressACME{DirectoryURL: "https://ca.example/dir"}, []string{"api.example.com"})
	policy := activeAccount(mgr).manager.HostPolicy

	if err := policy(t.Context(), "API.Example.COM"); err != nil {
		t.Errorf("HostPolicy(API.Example.COM) = %v, want nil", err)
	}
	const want = `bridge: acme: "x.example.com" is not the sni_host of an acme rule`
	if err := policy(t.Context(), "x.example.com"); err == nil || err.Error() != want {
		t.Errorf("HostPolicy(x.example.com) = %v, want %q", err, want)
	}
	// autocert returns the policy's error unchanged and asks no CA.
	if _, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "x.example.com"}); err == nil || err.Error() != want {
		t.Errorf("GetCertificate(x.example.com) = %v, want %q", err, want)
	}
	if !mgr.HasHost("API.example.com") || mgr.HasHost("x.example.com") {
		t.Errorf("HasHost(API.example.com), HasHost(x.example.com) = %v, %v, want true, false",
			mgr.HasHost("API.example.com"), mgr.HasHost("x.example.com"))
	}
}

func TestACMEManager_ConfigureReplacesTheManager(t *testing.T) {
	mgr, _, logs := newTestACMEManager(t)
	const configured = `msg="acme account configured"`
	settings := api.IngressACME{DirectoryURL: "https://ca.example/dir", ContactEmail: "ops@example.com"}
	mgr.Configure(&settings, []string{"a.example.com"})
	first := activeAccount(mgr)
	if got := logLines(logs, configured, "directory_url=https://ca.example/dir", "contact=true", "hosts=1"); got != 1 {
		t.Fatalf("%d 'acme account configured' lines, want 1:\n%s", got, logs.String())
	}

	mgr.Configure(&settings, []string{"a.example.com", "b.example.com"})
	if activeAccount(mgr) != first {
		t.Fatal("a joining host replaced the manager, want it kept")
	}
	if got := logLines(logs, configured); got != 1 {
		t.Errorf("%d 'acme account configured' lines after a joining host, want 1", got)
	}

	prev := first
	for i, tc := range []struct {
		name     string
		settings api.IngressACME
		hosts    []string
	}{
		{name: "changed directory_url", settings: api.IngressACME{DirectoryURL: "https://other.example/dir", ContactEmail: "ops@example.com"}, hosts: []string{"a.example.com", "b.example.com"}},
		{name: "changed contact_email", settings: api.IngressACME{DirectoryURL: "https://other.example/dir", ContactEmail: "admin@example.com"}, hosts: []string{"a.example.com", "b.example.com"}},
		{name: "removed host", settings: api.IngressACME{DirectoryURL: "https://other.example/dir", ContactEmail: "admin@example.com"}, hosts: []string{"a.example.com"}},
	} {
		mgr.Configure(&tc.settings, tc.hosts)
		cur := activeAccount(mgr)
		if cur == nil || cur == prev {
			t.Fatalf("%s kept the manager, want it replaced", tc.name)
		}
		if !prev.gate.retired() {
			t.Errorf("%s: the replaced manager's gate is open, want it retired", tc.name)
		}
		if got := logLines(logs, configured, "contact=true"); got != i+2 {
			t.Errorf("%s: %d 'acme account configured' lines with contact=true, want %d:\n%s", tc.name, got, i+2, logs.String())
		}
		prev = cur
	}
	if s := logs.String(); strings.Contains(s, "ops@example.com") || strings.Contains(s, "admin@example.com") {
		t.Errorf("the log carries a contact address:\n%s", s)
	}
}

func TestACMEManager_RetiredManagerIsCutOff(t *testing.T) {
	mgr, transport, logs := newTestACMEManager(t)
	const failed = `msg="bridge: acme: obtain certificate failed"`
	const one, two = "https://one.example/dir", "https://two.example/dir"
	countOf := func(url string) int {
		n := 0
		for _, u := range transport.requests() {
			if u == url {
				n++
			}
		}
		return n
	}

	mgr.Configure(&api.IngressACME{DirectoryURL: one}, []string{"a.example.com"})
	logs.waitFor(t, failed, 1)
	if got := transport.requests(); len(got) == 0 || got[0] != one {
		t.Fatalf("requests = %v, want the first to the directory %s", got, one)
	}
	old := activeAccount(mgr)

	mgr.Configure(&api.IngressACME{DirectoryURL: two}, []string{"a.example.com"})
	logs.waitFor(t, failed, 2)
	before := countOf(one)

	_, err := old.client.Discover(t.Context())
	if !errors.Is(err, errACMERetired) {
		t.Errorf("Discover through the retired manager's client = %v, want errACMERetired", err)
	}
	if _, err := old.client.HTTPClient.Get(one); !errors.Is(err, errACMERetired) {
		t.Errorf("GET through the retired manager's client = %v, want errACMERetired", err)
	}
	if got := countOf(one); got != before {
		t.Errorf("%d requests reached the transport for %s, want still %d", got, one, before)
	}
	for _, u := range transport.requests() {
		if u != one {
			if u != two {
				t.Errorf("the active manager's first request went to %s, want %s", u, two)
			}
			break
		}
	}
	if countOf(two) == 0 {
		t.Errorf("no request reached %s, the active manager's directory", two)
	}
}

func TestACMEManager_ObtainFailureIsLogged(t *testing.T) {
	mgr, _, logs := newTestACMEManager(t)
	const failed = `msg="bridge: acme: obtain certificate failed"`
	settings := &api.IngressACME{DirectoryURL: "https://ca.example/dir"}
	failedFor := func(host string) int {
		return logLines(logs, `level=ERROR`, failed, "sni_host="+host, errNoNetwork.Error())
	}

	mgr.Configure(settings, []string{"a.example.com", "b.example.com"})
	logs.waitFor(t, failed, 2)
	mgr.Configure(settings, []string{"a.example.com", "b.example.com"})
	mgr.Configure(settings, []string{"a.example.com", "b.example.com", "c.example.com"})
	logs.waitFor(t, failed, 3)
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if got := failedFor(host); got != 1 {
			t.Errorf("%d 'obtain certificate failed' lines for %s, want 1:\n%s", got, host, logs.String())
		}
	}

	mgr.Configure(settings, []string{"a.example.com"})
	logs.waitFor(t, failed, 4)
	if got := failedFor("a.example.com"); got != 2 {
		t.Errorf("%d 'obtain certificate failed' lines for a.example.com after a new Configure, want 2", got)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func TestACMEManager_CacheDir(t *testing.T) {
	dir := t.TempDir()
	settings := &api.IngressACME{DirectoryURL: "https://ca.example/dir"}
	for _, tc := range []struct {
		name string
		dir  string
		want autocert.Cache
	}{
		{name: "a directory", dir: dir, want: autocert.DirCache(dir)},
		{name: "memory only", dir: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewACMEManager(ACMEConfig{CacheDir: tc.dir, HTTPTransport: &acmeTestTransport{}}, discardLogger())
			t.Cleanup(func() { _ = mgr.Teardown() })
			mgr.getCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, errNoNetwork
			}
			mgr.Configure(settings, []string{"a.example.com"})
			if got := activeAccount(mgr).manager.Cache; got != tc.want {
				t.Errorf("Cache = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestACMEManager_Teardown_Idempotent(t *testing.T) {
	mgr, _, _ := newTestACMEManager(t)
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func TestACMERetryBackoff(t *testing.T) {
	gate := newACMEGate(&acmeTestTransport{})
	t.Cleanup(gate.retire)
	backoff := acmeRetryBackoff(gate)
	req := httptest.NewRequest(http.MethodGet, "https://ca.example/dir", nil)
	answer := func(retryAfter string) *http.Response {
		resp := &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header)}
		if retryAfter != "" {
			resp.Header.Set("Retry-After", retryAfter)
		}
		return resp
	}

	for _, tc := range []struct {
		name       string
		n          int
		retryAfter string
		want       time.Duration
	}{
		{name: "Retry-After 3600", n: 1, retryAfter: "3600", want: -1},
		{name: "an HTTP date an hour ahead", n: 1, retryAfter: time.Now().Add(time.Hour).UTC().Format(http.TimeFormat), want: -1},
		{name: "Retry-After 3", n: 1, retryAfter: "3", want: 3 * time.Second},
		{name: "Retry-After 3 on the fifth retry", n: 5, retryAfter: "3", want: 3 * time.Second},
		{name: "Retry-After 0 counts as absent", n: 2, retryAfter: "0", want: 2 * time.Second},
		{name: "a Retry-After that does not parse counts as absent", n: 3, retryAfter: "soon", want: 4 * time.Second},
	} {
		if got := backoff(tc.n, req, answer(tc.retryAfter)); got != tc.want {
			t.Errorf("%s: backoff(%d) = %v, want %v", tc.name, tc.n, got, tc.want)
		}
	}
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second} {
		if got := backoff(i+1, req, answer("")); got != want {
			t.Errorf("without Retry-After: backoff(%d) = %v, want %v", i+1, got, want)
		}
	}

	gate.retire()
	for _, retryAfter := range []string{"", "3"} {
		if got := backoff(1, req, answer(retryAfter)); got != -1 {
			t.Errorf("after retire, Retry-After %q: backoff(1) = %v, want -1", retryAfter, got)
		}
	}
}

// acmeUnavailableTransport answers every request 503 with Retry-After: 3600
// and a problem document, counts the requests, and closes first on the first.
type acmeUnavailableTransport struct {
	first    chan struct{}
	once     sync.Once
	requests atomic.Int64
}

func (t *acmeUnavailableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	t.requests.Add(1)
	t.once.Do(func() { close(t.first) })
	const body = `{"type":"urn:ietf:params:acme:error:serverInternal","detail":"come back in an hour"}`
	return &http.Response{
		Status:        "503 Service Unavailable",
		StatusCode:    http.StatusServiceUnavailable,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/problem+json"}, "Retry-After": {"3600"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}

// TestACMEManager_TeardownDoesNotWaitOutRetryAfter has the CA answer 503 with
// a Retry-After of an hour: the account does not sleep it out, so Teardown
// returns at once and the CA was asked once.
func TestACMEManager_TeardownDoesNotWaitOutRetryAfter(t *testing.T) {
	logger, logs := newRelayLogger()
	transport := &acmeUnavailableTransport{first: make(chan struct{})}
	mgr := NewACMEManager(ACMEConfig{CacheDir: t.TempDir(), HTTPTransport: transport}, logger)
	t.Cleanup(func() { _ = mgr.Teardown() })

	mgr.Configure(&api.IngressACME{DirectoryURL: "https://ca.example/dir"}, []string{"a.example.com"})
	select {
	case <-transport.first:
	case <-time.After(2 * time.Second):
		t.Fatal("no request reached the transport within 2s")
	}

	start := time.Now()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Teardown returned after %v, want within 1s", elapsed)
	}
	if n := transport.requests.Load(); n != 1 {
		t.Errorf("the transport saw %d requests, want 1", n)
	}
	if got := logLines(logs, "still running after teardown"); got != 0 {
		t.Errorf("Teardown logged that requests are still running:\n%s", logs.String())
	}
}

// TestACMEManager_TeardownWaitIsBounded holds an obtaining goroutine past the
// teardown wait: Teardown returns at the bound, logs a warning and stays
// idempotent.
func TestACMEManager_TeardownWaitIsBounded(t *testing.T) {
	mgr, _, logs := newTestACMEManager(t)
	const wait = 100 * time.Millisecond
	mgr.teardownWait = wait
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	mgr.getCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		once.Do(func() { close(entered) })
		<-release
		return nil, errNoNetwork
	}
	// Registered after newTestACMEManager, so it runs before its Teardown.
	t.Cleanup(func() { close(release) })

	mgr.Configure(&api.IngressACME{DirectoryURL: "https://ca.example/dir"}, []string{"a.example.com"})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the certificate was not asked for within 2s")
	}

	start := time.Now()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if elapsed := time.Since(start); elapsed < wait || elapsed > time.Second {
		t.Errorf("Teardown returned after %v, want at the %v bound", elapsed, wait)
	}
	const warning = `level=WARN msg="bridge: acme: certificate requests still running after teardown" component=bridge`
	if got := logLines(logs, warning); got != 1 {
		t.Errorf("%d warnings that requests are still running, want 1:\n%s", got, logs.String())
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
	if mgr.Active() {
		t.Error("Active = true after Teardown, want false")
	}
}
