// Integration tests — ACME with Ingress

package bridge

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// ---------------------------------------------------------------------------
// Integration tests — ACME with Ingress
// ---------------------------------------------------------------------------

// TestACMEIntegration_ApplyConfiguresTheAccount applies a block with an acme
// rule: the account becomes active for the rule's host, asks the block's
// directory for the host's certificate ahead of a client, and keeps its key
// in the cache directory. A block without the rule retires the account.
func TestACMEIntegration_ApplyConfiguresTheAccount(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	block := api.IngressConfig{
		Rules: []api.IngressRule{acmeRule("acme", 8443, "acme.example.com", 9000)},
		ACME:  testACME,
	}
	if err := fx.mgr.Apply(t.Context(), block); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !fx.acme.Active() || !fx.acme.HasHost("acme.example.com") {
		t.Fatalf("ACME account active, has the host = %v, %v, want true, true", fx.acme.Active(), fx.acme.HasHost("acme.example.com"))
	}
	if s := fx.mgr.IngressStatus(); !s.ACMEEnabled {
		t.Errorf("IngressStatus = %+v, want ACMEEnabled", s)
	}
	fx.logs.waitFor(t, `msg="bridge: acme: obtain certificate failed" component=bridge sni_host=acme.example.com`, 1)
	if fx.acme.Issued("acme.example.com") {
		t.Error("Issued after autocert's obtain failed against the CA = true, want false")
	}
	if got := fx.transport.requests(); len(got) == 0 || got[0] != testACME.DirectoryURL {
		t.Errorf("requests = %v, want the first to %s", got, testACME.DirectoryURL)
	}
	if _, err := os.Stat(filepath.Join(fx.acme.cfg.CacheDir, "acme_account+key")); err != nil {
		t.Errorf("account key in the cache directory: %v", err)
	}
	if got := logLines(fx.logs, `msg="acme account configured"`, "directory_url="+testACME.DirectoryURL, "contact=true", "hosts=1"); got != 1 {
		t.Errorf("%d 'acme account configured' lines, want 1:\n%s", got, fx.logs.String())
	}

	if err := fx.mgr.Apply(t.Context(), rulesBlock()); err != nil {
		t.Fatalf("Apply without the acme rule: %v", err)
	}
	if fx.acme.Active() || fx.acme.HasHost("acme.example.com") {
		t.Error("the ACME account is active without an acme rule, want it retired")
	}
	if s := fx.mgr.IngressStatus(); s.ACMEEnabled {
		t.Errorf("IngressStatus = %+v, want ACMEEnabled false", s)
	}
}

// TestACMEIntegration_DirectoryNotAllowed refuses a directory that
// bridge.acme_directory_urls does not list: the acme rule is held and not
// served, no account is configured and port 443 does not open.
func TestACMEIntegration_DirectoryNotAllowed(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	cfg := ingressTestConfig(true)
	cfg.ACMEDirectoryURLs = []string{"https://ca.example/dir"}
	fx := buildIngressFixture(t, ctrl, cfg)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	const other = "https://other.invalid/dir"
	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{
		Rules: []api.IngressRule{acmeRule("acme", 8443, "acme.example.com", 9000)},
		ACME:  &api.IngressACME{DirectoryURL: other},
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if st := stateOf(t, fx.mgr, "acme"); st.Served || st.Reason != IngressReasonACMEDirectoryNotAllowed || st.Detail != other {
		t.Errorf("acme rule = %+v, want %q with the URL", st, IngressReasonACMEDirectoryNotAllowed)
	}
	if fx.acme.Active() {
		t.Error("the ACME account is active for a directory the bridge does not accept")
	}
	if got := ctrl.listenAddrs(); len(got) != 1 || got[0] != ":8443" {
		t.Errorf("Listen addresses = %v, want [:8443]", got)
	}
	if got := fx.transport.requests(); len(got) != 0 {
		t.Errorf("requests = %v, want none", got)
	}
	if got := logLines(fx.logs, `msg="ingress rule not served"`, "slug=acme", "reason=acme_directory_not_allowed"); got != 1 {
		t.Errorf("%d 'ingress rule not served' lines, want 1:\n%s", got, fx.logs.String())
	}
}

// TestACMEIntegration_ConcurrentAccess reads the manager from several
// goroutines while the account is configured and retired, to catch data races.
// Run with -race.
func TestACMEIntegration_ConcurrentAccess(t *testing.T) {
	mgr, _, _ := newTestACMEManager(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = mgr.HasHost("a.example.com")
				_ = mgr.Active()
				// The hello carries no server name, so autocert refuses it
				// before it reads its cache or the network. Never pass a nil
				// hello: autocert dereferences it, and on windows/amd64 the
				// access violation that raises can corrupt the heap
				// (golang/go#81238).
				cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{})
				if cert != nil || err == nil ||
					(err.Error() != "bridge: acme: no account is configured" && !strings.HasPrefix(err.Error(), "acme/autocert: ")) {
					t.Errorf("GetCertificate(empty hello) = %v, %v; want nil and a bridge or autocert error", cert, err)
					return
				}
			}
		})
	}

	settings := []*api.IngressACME{
		{DirectoryURL: "https://one.example/dir"},
		{DirectoryURL: "https://two.example/dir", ContactEmail: "ops@example.com"},
	}
	for i := range 20 {
		switch i % 3 {
		case 0:
			mgr.Configure(settings[i%2], []string{"a.example.com", "b.example.com"})
		case 1:
			mgr.Configure(settings[i%2], []string{"a.example.com"})
		default:
			mgr.Configure(nil, nil)
		}
	}
	close(stop)
	wg.Wait()
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
}
