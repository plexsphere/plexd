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

func ingressTestConfig(enabled bool) Config {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		IngressEnabled:  enabled,
	}
	cfg.ApplyDefaults()
	return cfg
}

// newActiveIngressManager returns a set-up manager whose teardown runs when the
// test ends.
func newActiveIngressManager(t *testing.T, ctrl IngressController) (*IngressManager, *relayLog) {
	t.Helper()
	logger, logs := newRelayLogger()
	mgr := NewIngressManager(ctrl, ingressTestConfig(true), logger, nil)
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Teardown() })
	return mgr, logs
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
	mgr := NewIngressManager(&mockIngressController{}, ingressTestConfig(false), discardLogger(), nil)

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

	if err := mgr.Apply(fourRules()); err != nil {
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
	if err := mgr.Apply(rules); err != nil {
		t.Fatalf("Apply with a terminate rule: %v", err)
	}
	if got := mgr.IngressStatus().RuleCount; got != 3 {
		t.Errorf("RuleCount with a terminate rule = %d, want 3", got)
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
	if err := mgr.Apply(rules); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := mgr.Apply(rules); err != nil {
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
	if got := logLines(logs, `msg="ingress rule added"`); got != 4 {
		t.Errorf("%d 'ingress rule added' lines, want 4:\n%s", got, logs.String())
	}
}

func TestIngressManager_Apply_EmptyClosesEverything(t *testing.T) {
	for name, empty := range map[string][]api.IngressRule{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			ctrl := newLoopbackIngressController(t)
			mgr, logs := newActiveIngressManager(t, ctrl)

			if err := mgr.Apply(fourRules()); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			addr := ctrl.addr(443)
			if err := mgr.Apply(empty); err != nil {
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
	mgr := NewIngressManager(newLoopbackIngressController(t), ingressTestConfig(true), discardLogger(), nil)

	const want = "bridge: ingress: manager is not active"
	if err := mgr.Apply(fourRules()); err == nil || err.Error() != want {
		t.Errorf("Apply before Setup = %v, want %q", err, want)
	}
	if err := mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := mgr.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := mgr.Apply(fourRules()); err == nil || err.Error() != want {
		t.Errorf("Apply after Teardown = %v, want %q", err, want)
	}
}

func TestIngressManager_Apply_ListenFailureIsRetried(t *testing.T) {
	ctrl := newLoopbackIngressController(t)
	ctrl.failListen(443, syscall.EADDRINUSE)
	mgr, logs := newActiveIngressManager(t, ctrl)

	err := mgr.Apply(fourRules())
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
	if err := mgr.Apply(fourRules()); err != nil {
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

			if err := mgr.Apply([]api.IngressRule{ingressRule("web", tc.port, "", 9000)}); err == nil {
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
		if err := mgr.Apply([]api.IngressRule{ingressRule("web", 443, "", 9000)}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		addr := ctrl.addr(443)

		ctrl.setCloseErr(closeErr)
		if err := mgr.Apply(nil); err != nil {
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
		if err := mgr.Apply([]api.IngressRule{ingressRule("web", 443, "", 9000)}); err != nil {
			t.Fatalf("Apply again: %v", err)
		}
		if got := len(ctrl.ingressCallsFor("Listen")); got != 2 {
			t.Errorf("Listen calls = %d, want 2: the dropped port binds again", got)
		}
	})

	t.Run("Teardown", func(t *testing.T) {
		ctrl := newLoopbackIngressController(t)
		mgr, _ := newActiveIngressManager(t, ctrl)
		if err := mgr.Apply([]api.IngressRule{ingressRule("web", 443, "", 9000)}); err != nil {
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
		if err := mgr.Apply(rules); err != nil {
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
	if err := mgr.Apply(fourRules()); err != nil {
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
	mgr := NewIngressManager(&mockIngressController{}, ingressTestConfig(false), discardLogger(), nil)

	if status := mgr.IngressStatus(); status != nil {
		t.Errorf("IngressStatus should be nil when not active, got %+v", status)
	}
}

func TestIngressManager_IngressCapabilities(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		mgr := NewIngressManager(&mockIngressController{}, ingressTestConfig(true), discardLogger(), nil)

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

	t.Run("disabled", func(t *testing.T) {
		mgr := NewIngressManager(&mockIngressController{}, ingressTestConfig(false), discardLogger(), nil)

		if caps := mgr.IngressCapabilities(); caps != nil {
			t.Errorf("IngressCapabilities should be nil when disabled, got %v", caps)
		}
	})
}

// ---------------------------------------------------------------------------
// IngressReconcileHandler tests
// ---------------------------------------------------------------------------

func TestIngressReconcileHandler(t *testing.T) {
	withRules := &api.NodeStateSnapshot{Bridge: &api.BridgeSnapshot{Ingress: &api.IngressConfig{Rules: fourRules()}}}

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

	for name, desired := range map[string]*api.NodeStateSnapshot{
		"nil Bridge":  {},
		"nil Ingress": {Bridge: &api.BridgeSnapshot{}},
	} {
		t.Run(name, func(t *testing.T) {
			ctrl := newLoopbackIngressController(t)
			mgr, _ := newActiveIngressManager(t, ctrl)
			handler := IngressReconcileHandler(mgr, discardLogger())
			if err := handler(t.Context(), withRules, reconcile.StateDiff{}); err != nil {
				t.Fatalf("handler: %v", err)
			}
			if err := handler(t.Context(), desired, reconcile.StateDiff{}); err != nil {
				t.Fatalf("handler(%s): %v", name, err)
			}
			if got := len(mgr.RuleStates()); got != 0 {
				t.Errorf("%d rule states, want none", got)
			}
			if got := len(ctrl.ingressCallsFor("Close")); got != 2 {
				t.Errorf("Close calls = %d, want 2", got)
			}
		})
	}

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
}
