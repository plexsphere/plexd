package bridge

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// ---------------------------------------------------------------------------
// IngressManager tests
// ---------------------------------------------------------------------------

// ingressTestConfig returns a bridge config whose ingress_enabled is set to
// enabled, so ingressTestConfig(false) is the opted-out bridge.
func ingressTestConfig(enabled bool) Config {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		IngressEnabled:  BoolPtr(enabled),
	}
	cfg.ApplyDefaults()
	return cfg
}

// newActiveIngressManager returns a set-up manager whose teardown runs when the
// test ends. Its ACME account and certificate fetch never leave the test.
func newActiveIngressManager(t *testing.T, ctrl IngressController) (*IngressManager, *relayLog) {
	t.Helper()
	fx := newIngressFixture(t, ctrl)
	return fx.mgr, fx.logs
}

// rulesBlock returns a block of rules without an acme member.
func rulesBlock(rules ...api.IngressRule) api.IngressConfig {
	return api.IngressConfig{Rules: rules}
}

// testACME is the acme member of the tests' blocks.
var testACME = &api.IngressACME{DirectoryURL: "https://ca.example/dir", ContactEmail: "ops@example.com"}

// terminateRule returns a terminate rule for host that names the Secret
// secret.
func terminateRule(slug string, port int, host, secret string, targetPort int) api.IngressRule {
	r := ingressRule(slug, port, host, targetPort)
	r.Mode = api.IngressModeTerminate
	r.CertificateSecretName = secret
	return r
}

// acmeRule returns an acme rule for host.
func acmeRule(slug string, port int, host string, targetPort int) api.IngressRule {
	r := ingressRule(slug, port, host, targetPort)
	r.Mode = api.IngressModeACME
	return r
}

// ingressRule returns a passthrough rule to 127.0.0.1 on targetPort.
func ingressRule(slug string, port int, host string, targetPort int) api.IngressRule {
	return api.IngressRule{
		ID:            "id-" + slug,
		Slug:          slug,
		ListenPort:    port,
		Mode:          api.IngressModePassthrough,
		SNIHost:       host,
		TargetNodeID:  "node-" + slug,
		TargetAddress: "127.0.0.1",
		TargetPort:    targetPort,
	}
}

// fourRules returns three SNI rules on 443 and a plain rule on 7022.
func fourRules() []api.IngressRule {
	return []api.IngressRule{
		ingressRule("a", 443, "a.example.com", 9441),
		ingressRule("b", 443, "b.example.com", 9442),
		ingressRule("wild", 443, "*.apps.example.com", 9443),
		ingressRule("plain", 7022, "", 9022),
	}
}

// logLines counts the log lines that carry every needle.
func logLines(logs *relayLog, needles ...string) int {
	n := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		ok := true
		for _, needle := range needles {
			if !strings.Contains(line, needle) {
				ok = false
				break
			}
		}
		if ok && line != "" {
			n++
		}
	}
	return n
}

// stateOf returns the state of the rule with the given slug.
func stateOf(t *testing.T, mgr *IngressManager, slug string) IngressRuleState {
	t.Helper()
	for _, st := range mgr.RuleStates() {
		if st.Rule.Slug == slug {
			return st
		}
	}
	t.Fatalf("no state for rule %s in %+v", slug, mgr.RuleStates())
	return IngressRuleState{}
}

func TestIngressManager_Setup_Disabled(t *testing.T) {
	mgr := buildIngressFixture(t, &mockIngressController{}, ingressTestConfig(false)).mgr

	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if mgr.IngressStatus() != nil {
		t.Error("IngressStatus should be nil when disabled")
	}
}

func TestIngressManager_Setup_Enabled(t *testing.T) {
	mgr, _ := newActiveIngressManager(t, &mockIngressController{})

	status := mgr.IngressStatus()
	if status == nil {
		t.Fatal("IngressStatus should not be nil when active")
	}
	if !status.Enabled || status.RuleCount != 0 || status.ConnectionCount != 0 {
		t.Errorf("IngressStatus = %+v, want enabled with no rules and no connections", status)
	}
}

func TestIngressManager_Apply_OneListenerPerPort(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)

	if err := mgr.Apply(t.Context(), rulesBlock(fourRules()...)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := ctrl.ingressCallsFor("Listen")
	if got := ctrl.listenAddrs(); len(got) != 2 || got[0] != ":443" || got[1] != ":7022" {
		t.Fatalf("Listen addresses = %v, want [:443 :7022]", got)
	}
	for _, c := range calls {
		if cfg, _ := c.Args[1].(*tls.Config); cfg != nil {
			t.Errorf("Listen(%v) got a tls.Config, want nil", c.Args[0])
		}
	}
	if got := mgr.IngressStatus().RuleCount; got != 4 {
		t.Errorf("RuleCount = %d, want 4", got)
	}

	rules := fourRules()
	rules[1].Mode = api.IngressModeTerminate
	rules[1].CertificateSecretName = "tls-b"
	if err := mgr.Apply(t.Context(), rulesBlock(rules...)); err != nil {
		t.Fatalf("Apply with a terminate rule: %v", err)
	}
	if got := mgr.IngressStatus().RuleCount; got != 3 {
		t.Errorf("RuleCount with a terminate rule without a certificate = %d, want 3", got)
	}
	if got := len(ctrl.ingressCallsFor("Listen")); got != 2 {
		t.Errorf("Listen calls = %d, want still 2", got)
	}
}

func TestIngressManager_Apply_Idempotent(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	mgr, logs := newActiveIngressManager(t, ctrl)

	rules := fourRules()
	rules[1].Mode = api.IngressModeTerminate
	rules[1].CertificateSecretName = "tls-b"
	invalid := ingressRule("bad", 443, "bad.example.com", 9444)
	invalid.Mode = "tcp"
	rules = append(rules, invalid)
	if err := mgr.Apply(t.Context(), rulesBlock(rules...)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := mgr.Apply(t.Context(), rulesBlock(rules...)); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	if got := len(ctrl.ingressCallsFor("Listen")); got != 2 {
		t.Errorf("Listen calls = %d, want 2", got)
	}
	if got := len(ctrl.ingressCallsFor("Close")); got != 0 {
		t.Errorf("Close calls = %d, want 0", got)
	}
	if got := logLines(logs, `msg="ingress rule not served"`); got != 1 {
		t.Errorf("%d 'ingress rule not served' lines, want 1:\n%s", got, logs.String())
	}
	if got := logLines(logs, `msg="ingress certificate not loaded"`, "secret=tls-b", "reason=certificate_secret_not_listed"); got != 1 {
		t.Errorf("%d 'ingress certificate not loaded' lines, want 1:\n%s", got, logs.String())
	}
	if got := logLines(logs, `msg="ingress rule added"`); got != 4 {
		t.Errorf("%d 'ingress rule added' lines, want 4:\n%s", got, logs.String())
	}
}

func TestIngressManager_Apply_EmptyClosesEverything(t *testing.T) {
	for name, empty := range map[string][]api.IngressRule{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			ctrl := newLoopbackIngressController(t)
			mgr, logs := newActiveIngressManager(t, ctrl)

			if err := mgr.Apply(t.Context(), rulesBlock(fourRules()...)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			addr := ctrl.addr(443)
			if err := mgr.Apply(t.Context(), rulesBlock(empty...)); err != nil {
				t.Fatalf("Apply(%s): %v", name, err)
			}

			if got := len(ctrl.ingressCallsFor("Close")); got != 2 {
				t.Errorf("Close calls = %d, want 2", got)
			}
			if states := mgr.RuleStates(); len(states) != 0 {
				t.Errorf("RuleStates = %+v, want empty", states)
			}
			if got := mgr.IngressStatus().RuleCount; got != 0 {
				t.Errorf("RuleCount = %d, want 0", got)
			}
			if conn, err := net.Dial("tcp", addr); err == nil {
				_ = conn.Close()
				t.Errorf("dial %s succeeded after the listener closed", addr)
			}
			if got := logLines(logs, `msg="ingress rule removed"`); got != 4 {
				t.Errorf("%d 'ingress rule removed' lines, want 4:\n%s", got, logs.String())
			}
			for _, port := range []string{"443", "7022"} {
				if got := logLines(logs, `msg="ingress listener closed"`, "listen_port="+port); got != 1 {
					t.Errorf("%d 'ingress listener closed' lines for %s, want 1", got, port)
				}
			}
		})
	}
}

func TestIngressManager_Apply_NotActive(t *testing.T) {
	mgr := buildIngressFixture(t, newLoopbackIngressController(t), ingressTestConfig(true)).mgr

	const want = "bridge: ingress: manager is not active"
	if err := mgr.Apply(t.Context(), rulesBlock(fourRules()...)); err == nil || err.Error() != want {
		t.Errorf("Apply before Setup = %v, want %q", err, want)
	}
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := mgr.Apply(t.Context(), rulesBlock(fourRules()...)); err == nil || err.Error() != want {
		t.Errorf("Apply after Teardown = %v, want %q", err, want)
	}
}

func TestIngressManager_Apply_ListenFailureIsRetried(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	ctrl.failListen(443, syscall.EADDRINUSE)
	mgr, logs := newActiveIngressManager(t, ctrl)

	err := mgr.Apply(t.Context(), rulesBlock(fourRules()...))
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want an error that wraps EADDRINUSE", err)
	}
	if !strings.HasPrefix(err.Error(), "bridge: ingress: listen on :443:") {
		t.Errorf("Apply = %q, want the prefix %q", err, "bridge: ingress: listen on :443:")
	}
	for _, slug := range []string{"a", "b", "wild"} {
		if st := stateOf(t, mgr, slug); st.Served || st.Reason != IngressReasonListenFailed {
			t.Errorf("rule %s: served, reason = %v, %q, want false, %q", slug, st.Served, st.Reason, IngressReasonListenFailed)
		}
	}
	if st := stateOf(t, mgr, "plain"); !st.Served {
		t.Errorf("rule plain = %+v, want served", st)
	}
	if got := logLines(logs, `msg="bridge: ingress: listen failed"`, "listen_port=443"); got != 1 {
		t.Errorf("%d 'listen failed' lines for 443, want 1:\n%s", got, logs.String())
	}

	ctrl.failListen(443, nil)
	if err := mgr.Apply(t.Context(), rulesBlock(fourRules()...)); err != nil {
		t.Fatalf("Apply after the port freed up: %v", err)
	}
	if got := ctrl.listenAddrs(); len(got) != 3 || got[2] != ":443" {
		t.Errorf("Listen addresses = %v, want a third call for :443", got)
	}
	for _, slug := range []string{"a", "b", "wild", "plain"} {
		if st := stateOf(t, mgr, slug); !st.Served {
			t.Errorf("rule %s = %+v, want served", slug, st)
		}
	}
}

func TestIngressManager_Apply_ListenPermissionHint(t *testing.T) {
	permErr := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EACCES)}
	for _, tc := range []struct {
		port     int
		wantHint bool
	}{
		{port: 443, wantHint: true},
		{port: 8443, wantHint: false},
	} {
		t.Run(strconv.Itoa(tc.port), func(t *testing.T) {
			ctrl := newLoopbackIngressController(t)
			ctrl.failListen(tc.port, permErr)
			mgr, logs := newActiveIngressManager(t, ctrl)

			if err := mgr.Apply(t.Context(), rulesBlock(ingressRule("web", tc.port, "", 9000))); err == nil {
				t.Fatal("Apply = nil, want the listen error")
			}
			port := "listen_port=" + strconv.Itoa(tc.port)
			if got := logLines(logs, `msg="bridge: ingress: listen failed"`, port); got != 1 {
				t.Fatalf("%d 'listen failed' lines, want 1:\n%s", got, logs.String())
			}
			hint := logLines(logs, `msg="bridge: ingress: listen failed"`, port, `hint="ports below 1024 need CAP_NET_BIND_SERVICE"`)
			if (hint == 1) != tc.wantHint {
				t.Errorf("hint on the line = %v, want %v:\n%s", hint == 1, tc.wantHint, logs.String())
			}
		})
	}
}

func TestIngressManager_CloseErrorDropsThePort(t *testing.T) {
	closeErr := errors.New("close failed")

	t.Run("Apply", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		mgr, logs := newActiveIngressManager(t, ctrl)
		if err := mgr.Apply(t.Context(), rulesBlock(ingressRule("web", 443, "", 9000))); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		addr := ctrl.addr(443)

		ctrl.setCloseErr(closeErr)
		if err := mgr.Apply(t.Context(), api.IngressConfig{}); err != nil {
			t.Fatalf("Apply(nil): %v", err)
		}
		if got := logLines(logs, `msg="bridge: ingress: close listener failed"`, "listen_port=443", "error="); got != 1 {
			t.Errorf("%d 'close listener failed' lines, want 1:\n%s", got, logs.String())
		}
		if conn, err := net.Dial("tcp", addr); err == nil {
			_ = conn.Close()
			t.Errorf("dial %s succeeded, want the port dropped", addr)
		}
		ctrl.setCloseErr(nil)
		if err := mgr.Apply(t.Context(), rulesBlock(ingressRule("web", 443, "", 9000))); err != nil {
			t.Fatalf("Apply again: %v", err)
		}
		if got := len(ctrl.ingressCallsFor("Listen")); got != 2 {
			t.Errorf("Listen calls = %d, want 2: the dropped port binds again", got)
		}
	})

	t.Run("Teardown", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		mgr, _ := newActiveIngressManager(t, ctrl)
		if err := mgr.Apply(t.Context(), rulesBlock(ingressRule("web", 443, "", 9000))); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		ctrl.setCloseErr(closeErr)

		err := mgr.Teardown()
		if !errors.Is(err, closeErr) {
			t.Fatalf("Teardown = %v, want it to wrap the close error", err)
		}
		if !strings.HasPrefix(err.Error(), "bridge: ingress: close listener 443:") {
			t.Errorf("Teardown = %q, want the prefix %q", err, "bridge: ingress: close listener 443:")
		}
		if mgr.IngressStatus() != nil {
			t.Error("IngressStatus should be nil after Teardown")
		}
	})
}

func TestIngressManager_Apply_PlainToSNIAndBack(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	mgr, _ := newActiveIngressManager(t, ctrl)

	plain := []api.IngressRule{ingressRule("plain", 443, "", 9000)}
	sni := []api.IngressRule{
		ingressRule("a", 443, "a.example.com", 9441),
		ingressRule("b", 443, "b.example.com", 9442),
	}
	for i, rules := range [][]api.IngressRule{plain, sni, plain} {
		if err := mgr.Apply(t.Context(), rulesBlock(rules...)); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}
	if got := len(ctrl.ingressCallsFor("Listen")); got != 1 {
		t.Errorf("Listen calls = %d, want 1", got)
	}
	if got := len(ctrl.ingressCallsFor("Close")); got != 0 {
		t.Errorf("Close calls = %d, want 0", got)
	}
	if st := stateOf(t, mgr, "plain"); !st.Served {
		t.Errorf("rule plain = %+v, want served", st)
	}
}

func TestIngressManager_Teardown_Idempotent(t *testing.T) {
	mgr, _ := newActiveIngressManager(t, newLoopbackIngressController(t))
	if err := mgr.Apply(t.Context(), rulesBlock(fourRules()...)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func TestIngressManager_IngressStatus_Inactive(t *testing.T) {
	mgr := buildIngressFixture(t, &mockIngressController{}, ingressTestConfig(false)).mgr

	if status := mgr.IngressStatus(); status != nil {
		t.Errorf("IngressStatus should be nil when not active, got %+v", status)
	}
}

func TestIngressManager_IngressCapabilities(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		mgr := buildIngressFixture(t, &mockIngressController{}, ingressTestConfig(true)).mgr

		caps := mgr.IngressCapabilities()
		if caps == nil {
			t.Fatal("IngressCapabilities should not be nil when enabled")
		}
		if caps["ingress"] != "true" {
			t.Errorf("ingress = %q, want %q", caps["ingress"], "true")
		}
		if caps["max_ingress_rules"] != "20" {
			t.Errorf("max_ingress_rules = %q, want %q", caps["max_ingress_rules"], "20")
		}
	})

	// A bridge that sets no ingress_enabled serves public ingress.
	t.Run("unset", func(t *testing.T) {
		cfg := ingressTestConfig(true)
		cfg.IngressEnabled = nil
		mgr := buildIngressFixture(t, &mockIngressController{}, cfg).mgr

		caps := mgr.IngressCapabilities()
		if caps["ingress"] != "true" {
			t.Errorf("ingress = %q with ingress_enabled unset, want %q", caps["ingress"], "true")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		mgr := buildIngressFixture(t, &mockIngressController{}, ingressTestConfig(false)).mgr

		if caps := mgr.IngressCapabilities(); caps != nil {
			t.Errorf("IngressCapabilities should be nil when disabled, got %v", caps)
		}
	})
}

// ---------------------------------------------------------------------------
// IngressReconcileHandler tests
// ---------------------------------------------------------------------------

func TestIngressReconcileHandler(t *testing.T) {
	withRules := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Enabled: true, Rules: fourRules()}}}

	t.Run("nil snapshot", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		mgr, _ := newActiveIngressManager(t, ctrl)
		handler := IngressReconcileHandler(mgr, discardLogger())
		if err := handler(t.Context(), withRules, reconcile.StateDiff{}); err != nil {
			t.Fatalf("handler: %v", err)
		}
		if err := handler(t.Context(), nil, reconcile.StateDiff{}); err != nil {
			t.Fatalf("handler(nil) = %v, want nil", err)
		}
		if got := len(mgr.RuleStates()); got != 4 {
			t.Errorf("%d rule states after a nil snapshot, want the 4 kept", got)
		}
	})

	withACME := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{
		Enabled: true,
		Rules:   append(fourRules(), acmeRule("acme", 8443, "acme.example.com", 9445)),
		ACME:    testACME,
	}}}
	for name, desired := range map[string]*api.NodeStateSnapshot{
		"nil Bridge":  {},
		"nil Ingress": {Bridge: &api.BridgeSnapshot{}},
	} {
		t.Run(name, func(t *testing.T) {
			ctrl := newLoopbackIngressController(t)
			fx := newIngressFixture(t, ctrl)
			handler := IngressReconcileHandler(fx.mgr, discardLogger())
			if err := handler(t.Context(), withACME, reconcile.StateDiff{}); err != nil {
				t.Fatalf("handler: %v", err)
			}
			if err := handler(t.Context(), desired, reconcile.StateDiff{}); err != nil {
				t.Fatalf("handler(%s): %v", name, err)
			}
			if got := len(fx.mgr.RuleStates()); got != 0 {
				t.Errorf("%d rule states, want none", got)
			}
			if got := len(ctrl.ingressCallsFor("Close")); got != 3 {
				t.Errorf("Close calls = %d, want 3", got)
			}
			if fx.acme.Active() {
				t.Error("the ACME account is active after the zero block, want it retired")
			}
		})
	}

	t.Run("acme member", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		fx := newIngressFixture(t, ctrl)
		handler := IngressReconcileHandler(fx.mgr, discardLogger())

		invalid := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{
			Enabled: true,
			Rules:   withACME.Bridge.Ingress.Rules,
			ACME:    &api.IngressACME{DirectoryURL: "http://ca.example/dir"},
		}}}
		if err := handler(t.Context(), invalid, reconcile.StateDiff{}); err != nil {
			t.Fatalf("handler: %v", err)
		}
		if st := stateOf(t, fx.mgr, "acme"); st.Reason != IngressReasonACMEDirectoryInvalid || st.Detail != "http://ca.example/dir" {
			t.Errorf("acme rule with an http directory = %+v, want %q with the URL", st, IngressReasonACMEDirectoryInvalid)
		}

		if err := handler(t.Context(), withACME, reconcile.StateDiff{}); err != nil {
			t.Fatalf("handler: %v", err)
		}
		if st := stateOf(t, fx.mgr, "acme"); !st.Served {
			t.Errorf("acme rule = %+v, want served", st)
		}
		if !fx.acme.Active() || !fx.acme.HasHost("acme.example.com") {
			t.Errorf("ACME account active, has the host = %v, %v, want true, true", fx.acme.Active(), fx.acme.HasHost("acme.example.com"))
		}
	})

	t.Run("failed bind", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		ctrl.failListen(443, syscall.EADDRINUSE)
		mgr, _ := newActiveIngressManager(t, ctrl)
		logger, logs := newRelayLogger()
		handler := IngressReconcileHandler(mgr, logger)

		if err := handler(t.Context(), withRules, reconcile.StateDiff{}); !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("handler = %v, want the bind error", err)
		}
		if got := logLines(logs, `msg="ingress reconcile: apply failed"`); got != 1 {
			t.Errorf("%d 'apply failed' lines, want 1:\n%s", got, logs.String())
		}
	})

	notEnabled := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Rules: fourRules()}}}
	bridgeChanged := reconcile.StateDiff{BridgeChanged: true}

	t.Run("not enabled", func(t *testing.T) {
		const warn = `msg="ingress: the state pull carries rules but does not enable public ingress, closing every listener"`
		ctrl := newLoopbackIngressController(t)
		mgr, _ := newActiveIngressManager(t, ctrl)
		logger, logs := newRelayLogger()
		handler := IngressReconcileHandler(mgr, logger)

		if err := handler(t.Context(), withRules, bridgeChanged); err != nil {
			t.Fatalf("handler: %v", err)
		}
		if got := len(mgr.RuleStates()); got != 4 {
			t.Fatalf("%d rule states after the enabled block, want 4", got)
		}
		addrs := []string{ctrl.addr(443), ctrl.addr(7022)}

		if err := handler(t.Context(), notEnabled, bridgeChanged); err != nil {
			t.Fatalf("handler(not enabled): %v", err)
		}
		if got := len(mgr.RuleStates()); got != 0 {
			t.Errorf("%d rule states after the block that does not enable ingress, want 0", got)
		}
		if got := len(ctrl.ingressCallsFor("Close")); got != 2 {
			t.Errorf("Close calls = %d, want 2", got)
		}
		for _, addr := range addrs {
			if conn, err := net.Dial("tcp", addr); err == nil {
				_ = conn.Close()
				t.Errorf("dial %s succeeded after the block that does not enable ingress", addr)
			}
		}
		if got := logLines(logs, "level=WARN", warn, "component=bridge", "rules=4"); got != 1 {
			t.Errorf("%d not-enabled Warn lines with rules=4, want 1:\n%s", got, logs.String())
		}

		// A cycle without bridge drift, run for a peer or policy change,
		// applies the block again without another Warn.
		if err := handler(t.Context(), notEnabled, reconcile.StateDiff{}); err != nil {
			t.Fatalf("handler(not enabled, no bridge drift): %v", err)
		}
		if got := logLines(logs, warn); got != 1 {
			t.Errorf("%d not-enabled Warn lines after a cycle without bridge drift, want still 1:\n%s", got, logs.String())
		}
	})

	t.Run("not enabled, no rules", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		mgr, _ := newActiveIngressManager(t, ctrl)
		logger, logs := newRelayLogger()
		handler := IngressReconcileHandler(mgr, logger)

		if err := handler(t.Context(), withRules, bridgeChanged); err != nil {
			t.Fatalf("handler: %v", err)
		}
		empty := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Rules: []api.IngressRule{}}}}
		if err := handler(t.Context(), empty, bridgeChanged); err != nil {
			t.Fatalf("handler(not enabled, no rules): %v", err)
		}
		if got := len(mgr.RuleStates()); got != 0 {
			t.Errorf("%d rule states, want none", got)
		}
		if got := len(ctrl.ingressCallsFor("Close")); got != 2 {
			t.Errorf("Close calls = %d, want 2: the zero block closes every listener", got)
		}
		if got := logLines(logs, "level=WARN"); got != 0 {
			t.Errorf("%d Warn lines for a block without rules, want 0:\n%s", got, logs.String())
		}
	})

	t.Run("opted out", func(t *testing.T) {
		logger, logs := newRelayLogger()
		handler := IngressReconcileHandler(nil, logger)

		if err := handler(t.Context(), withRules, bridgeChanged); err != nil {
			t.Fatalf("handler = %v, want nil", err)
		}
		const warn = `msg="ingress: the control plane enables public ingress, but bridge.ingress_enabled is false"`
		if got := logLines(logs, "level=WARN", warn, "component=bridge", "rules=4"); got != 1 {
			t.Errorf("%d opted-out Warn lines with rules=4, want 1:\n%s", got, logs.String())
		}
		if got := logLines(logs); got != 1 {
			t.Errorf("%d log lines, want only the Warn:\n%s", got, logs.String())
		}

		for _, tc := range []struct {
			name    string
			desired *api.NodeStateSnapshot
			diff    reconcile.StateDiff
		}{
			{"nil snapshot", nil, bridgeChanged},
			{"nil Bridge", &api.NodeStateSnapshot{}, bridgeChanged},
			{"nil Ingress", &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{}}, bridgeChanged},
			{"not enabled with rules", notEnabled, bridgeChanged},
			{"enabled without rules", &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Enabled: true}}}, bridgeChanged},
			{"enabled with rules, no bridge drift", withRules, reconcile.StateDiff{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				logger, logs := newRelayLogger()
				handler := IngressReconcileHandler(nil, logger)
				if err := handler(t.Context(), tc.desired, tc.diff); err != nil {
					t.Errorf("handler = %v, want nil", err)
				}
				if got := logs.String(); got != "" {
					t.Errorf("logs = %q, want none", got)
				}
			})
		}
	})
}

// TestIngressManager_Apply_ChallengePortListenFailure fails the bind of the
// challenge-only port 443: Apply returns the bind error, the acme rule on
// 8443 stays served, and the next Apply binds 443 again.
func TestIngressManager_Apply_ChallengePortListenFailure(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	ctrl.failListen(443, syscall.EADDRINUSE)
	fx := newIngressFixture(t, ctrl)
	block := api.IngressConfig{Rules: []api.IngressRule{acmeRule("acme", 8443, "acme.example.com", 9445)}, ACME: testACME}

	err := fx.mgr.Apply(t.Context(), block)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want an error that wraps EADDRINUSE", err)
	}
	if !strings.HasPrefix(err.Error(), "bridge: ingress: listen on :443:") {
		t.Errorf("Apply = %q, want the prefix %q", err, "bridge: ingress: listen on :443:")
	}
	if st := stateOf(t, fx.mgr, "acme"); !st.Served || st.Reason != "" {
		t.Errorf("acme rule on 8443 = %+v, want served", st)
	}
	if got := ctrl.listenAddrs(); len(got) != 2 || got[0] != ":443" || got[1] != ":8443" {
		t.Fatalf("Listen addresses = %v, want [:443 :8443]", got)
	}

	ctrl.failListen(443, nil)
	if err := fx.mgr.Apply(t.Context(), block); err != nil {
		t.Fatalf("Apply after the port freed up: %v", err)
	}
	if got := ctrl.listenAddrs(); len(got) != 3 || got[2] != ":443" {
		t.Errorf("Listen addresses = %v, want a third call for :443", got)
	}
}

// TestIngressManager_Apply_ACMERuleListenFailure fails the bind of an acme
// rule's own port: the rule reads listen_failed and the account stays
// inactive, so the CA is not asked for its host. Once the port binds, the next
// Apply serves the rule and configures the account.
func TestIngressManager_Apply_ACMERuleListenFailure(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	ctrl.failListen(8443, syscall.EADDRINUSE)
	fx := newIngressFixture(t, ctrl)
	block := api.IngressConfig{Rules: []api.IngressRule{acmeRule("acme", 8443, "acme.example.com", 9445)}, ACME: testACME}

	if err := fx.mgr.Apply(t.Context(), block); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Apply = %v, want an error that wraps EADDRINUSE", err)
	}
	if st := stateOf(t, fx.mgr, "acme"); st.Served || st.Reason != IngressReasonListenFailed {
		t.Errorf("acme rule on 8443 = %+v, want %q", st, IngressReasonListenFailed)
	}
	if s := fx.mgr.IngressStatus(); s.ACMEEnabled {
		t.Errorf("IngressStatus = %+v, want ACMEEnabled false", s)
	}
	if fx.acme.Active() || fx.acme.HasHost("acme.example.com") {
		t.Errorf("ACME account active, has the host = %v, %v, want false, false", fx.acme.Active(), fx.acme.HasHost("acme.example.com"))
	}

	ctrl.failListen(8443, nil)
	if err := fx.mgr.Apply(t.Context(), block); err != nil {
		t.Fatalf("Apply after the port freed up: %v", err)
	}
	if st := stateOf(t, fx.mgr, "acme"); !st.Served || st.Reason != "" {
		t.Errorf("acme rule on 8443 = %+v, want served", st)
	}
	if !fx.acme.Active() || !fx.acme.HasHost("acme.example.com") {
		t.Errorf("ACME account active, has the host = %v, %v, want true, true", fx.acme.Active(), fx.acme.HasHost("acme.example.com"))
	}
	if s := fx.mgr.IngressStatus(); !s.ACMEEnabled {
		t.Errorf("IngressStatus = %+v, want ACMEEnabled", s)
	}
}

// TestIngressManager_IngressStatus_CertificatesAndACME counts a terminate rule
// only while its certificate is loaded, and reads ACMEEnabled exactly while
// the last block held an acme rule without a reason.
func TestIngressManager_IngressStatus_CertificatesAndACME(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	fx := newIngressFixture(t, ctrl)
	fx.certs.set("tls", 1, certPEM(t, "t.example.com", "v1"))
	pass := ingressRule("pass", 443, "p.example.com", 9441)
	term := terminateRule("term", 443, "t.example.com", "tls", 9442)
	acme := acmeRule("acme", 8443, "acme.example.com", 9443)

	status := func() *api.IngressInfo {
		t.Helper()
		s := fx.mgr.IngressStatus()
		if s == nil {
			t.Fatal("IngressStatus = nil, want the status of an active manager")
		}
		return s
	}

	if err := fx.mgr.Apply(t.Context(), rulesBlock(pass, term)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if s := status(); s.RuleCount != 1 || s.ACMEEnabled {
		t.Errorf("without a certificate: RuleCount, ACMEEnabled = %d, %v, want 1, false", s.RuleCount, s.ACMEEnabled)
	}

	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{{Name: "tls", Version: 1}})
	if s := status(); s.RuleCount != 2 {
		t.Errorf("with the certificate: RuleCount = %d, want 2", s.RuleCount)
	}

	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{pass, term, acme}, ACME: testACME}); err != nil {
		t.Fatalf("Apply with an acme rule: %v", err)
	}
	if s := status(); s.RuleCount != 3 || !s.ACMEEnabled {
		t.Errorf("with an acme rule: RuleCount, ACMEEnabled = %d, %v, want 3, true", s.RuleCount, s.ACMEEnabled)
	}

	if err := fx.mgr.Apply(t.Context(), api.IngressConfig{Rules: []api.IngressRule{pass, term, acme}}); err != nil {
		t.Fatalf("Apply without the acme member: %v", err)
	}
	if s := status(); s.RuleCount != 2 || s.ACMEEnabled {
		t.Errorf("with an acme rule that has a reason: RuleCount, ACMEEnabled = %d, %v, want 2, false", s.RuleCount, s.ACMEEnabled)
	}

	fx.mgr.SyncSecretInventory(t.Context(), []api.NodeStateSecret{})
	if s := status(); s.RuleCount != 1 {
		t.Errorf("after the Secret left the inventory: RuleCount = %d, want 1", s.RuleCount)
	}
}
