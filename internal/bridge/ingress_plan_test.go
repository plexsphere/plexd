package bridge

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// planRule returns a valid passthrough rule; each test changes what it checks.
func planRule(slug string, port int, host string) api.IngressRule {
	return api.IngressRule{
		ID:            "id-" + slug,
		Slug:          slug,
		ListenPort:    port,
		Mode:          api.IngressModePassthrough,
		SNIHost:       host,
		TargetNodeID:  "node-" + slug,
		TargetAddress: "10.0.0.5",
		TargetPort:    8443,
	}
}

// hostOfLen returns a host name of n bytes made of labels of at most 63 bytes.
func hostOfLen(n int) string {
	var labels []string
	for n > 0 {
		k := min(63, n)
		labels = append(labels, strings.Repeat("a", k))
		n -= k + 1 // the label and the dot before the next one
	}
	return strings.Join(labels, ".")
}

func TestPlanIngress_ReasonPerCheck(t *testing.T) {
	if got := len(hostOfLen(254)); got != 254 {
		t.Fatalf("hostOfLen(254) is %d bytes", got)
	}

	for _, tc := range []struct {
		name   string
		before []api.IngressRule // rules ahead of the one checked
		edit   func(*api.IngressRule)
		reason string
		detail string
	}{
		{name: "empty id", edit: func(r *api.IngressRule) { r.ID = "" }, reason: IngressReasonInvalid, detail: "id"},
		{name: "duplicate id", before: []api.IngressRule{planRule("first", 443, "first.example.com")}, edit: func(r *api.IngressRule) { r.ID = "id-first" }, reason: IngressReasonDuplicateID},
		{name: "mode tcp", edit: func(r *api.IngressRule) { r.Mode = "tcp" }, reason: IngressReasonInvalid, detail: "mode"},
		{name: "listen port 0", edit: func(r *api.IngressRule) { r.ListenPort = 0 }, reason: IngressReasonInvalid, detail: "listen_port"},
		{name: "listen port 65536", edit: func(r *api.IngressRule) { r.ListenPort = 65536 }, reason: IngressReasonInvalid, detail: "listen_port"},
		{name: "sni host *", edit: func(r *api.IngressRule) { r.SNIHost = "*" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "sni host *.", edit: func(r *api.IngressRule) { r.SNIHost = "*." }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "sni host a.*.example.com", edit: func(r *api.IngressRule) { r.SNIHost = "a.*.example.com" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "sni host a..example.com", edit: func(r *api.IngressRule) { r.SNIHost = "a..example.com" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "sni host of 254 bytes", edit: func(r *api.IngressRule) { r.SNIHost = hostOfLen(254) }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "terminate without a host", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeTerminate; r.SNIHost = "" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "acme without a host", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeACME; r.SNIHost = "" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "empty target address", edit: func(r *api.IngressRule) { r.TargetAddress = "" }, reason: IngressReasonInvalid, detail: "target_address"},
		{name: "target address with a port", edit: func(r *api.IngressRule) { r.TargetAddress = "10.0.0.5:80" }, reason: IngressReasonInvalid, detail: "target_address"},
		{name: "target address in brackets", edit: func(r *api.IngressRule) { r.TargetAddress = "[fd00::1]" }, reason: IngressReasonInvalid, detail: "target_address"},
		{name: "target address with a zone", edit: func(r *api.IngressRule) { r.TargetAddress = "fe80::1%eth0" }, reason: IngressReasonInvalid, detail: "target_address"},
		{name: "target port 0", edit: func(r *api.IngressRule) { r.TargetPort = 0 }, reason: IngressReasonInvalid, detail: "target_port"},
		{name: "target port 65536", edit: func(r *api.IngressRule) { r.TargetPort = 65536 }, reason: IngressReasonInvalid, detail: "target_port"},
		{name: "listener conflict", before: []api.IngressRule{planRule("holder", 443, "web.example.com")}, edit: func(*api.IngressRule) {}, reason: IngressReasonListenerConflict, detail: "holder"},
		{name: "max rules", before: []api.IngressRule{planRule("r1", 443, "r1.example.com"), planRule("r2", 443, "r2.example.com")}, edit: func(*api.IngressRule) {}, reason: IngressReasonMaxRules},
		{name: "terminate is held, not served", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeTerminate }, reason: IngressReasonModeNotServed},
		{name: "acme is held, not served", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeACME }, reason: IngressReasonModeNotServed},
		{name: "sni host of 253 bytes is served", edit: func(r *api.IngressRule) { r.SNIHost = hostOfLen(253) }},
		{name: "wildcard host is served", edit: func(r *api.IngressRule) { r.SNIHost = "*.example.com" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := planRule("web", 443, "web.example.com")
			tc.edit(&r)
			maxRules := 20
			if tc.reason == IngressReasonMaxRules {
				maxRules = 2
			}
			plan := planIngress(append(append([]api.IngressRule{}, tc.before...), r), maxRules)
			if len(plan.states) != len(tc.before)+1 {
				t.Fatalf("%d states, want %d", len(plan.states), len(tc.before)+1)
			}
			st := plan.states[len(plan.states)-1]
			if st.Rule != r {
				t.Errorf("state rule = %+v, want %+v", st.Rule, r)
			}
			if st.Reason != tc.reason || st.Detail != tc.detail {
				t.Errorf("reason, detail = %q, %q, want %q, %q", st.Reason, st.Detail, tc.reason, tc.detail)
			}
			if wantServed := tc.reason == ""; st.Served != wantServed {
				t.Errorf("Served = %v, want %v", st.Served, wantServed)
			}
		})
	}
}

func TestPlanIngress_ListenerConflict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []api.IngressRule
		want  []IngressRuleState // Reason and Detail per rule
	}{
		{
			name:  "same port and host",
			rules: []api.IngressRule{planRule("a", 443, "web.example.com"), planRule("b", 443, "WEB.example.com")},
			want:  []IngressRuleState{{Served: true}, {Reason: IngressReasonListenerConflict, Detail: "a"}},
		},
		{
			name:  "plain rule on an SNI port",
			rules: []api.IngressRule{planRule("tls", 443, "web.example.com"), planRule("plain", 443, "")},
			want:  []IngressRuleState{{Served: true}, {Reason: IngressReasonListenerConflict, Detail: "tls"}},
		},
		{
			name:  "SNI rule on a plain port",
			rules: []api.IngressRule{planRule("plain", 443, ""), planRule("tls", 443, "web.example.com")},
			want:  []IngressRuleState{{Served: true}, {Reason: IngressReasonListenerConflict, Detail: "plain"}},
		},
		{
			name:  "two hosts on one port",
			rules: []api.IngressRule{planRule("a", 443, "a.example.com"), planRule("b", 443, "b.example.com")},
			want:  []IngressRuleState{{Served: true}, {Served: true}},
		},
		{
			name:  "one host on two ports",
			rules: []api.IngressRule{planRule("a", 443, "web.example.com"), planRule("b", 8443, "web.example.com")},
			want:  []IngressRuleState{{Served: true}, {Served: true}},
		},
		{
			name:  "exact host beside a wildcard",
			rules: []api.IngressRule{planRule("api", 443, "api.example.com"), planRule("wild", 443, "*.example.com")},
			want:  []IngressRuleState{{Served: true}, {Served: true}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planIngress(tc.rules, 20)
			if len(plan.states) != len(tc.want) {
				t.Fatalf("%d states, want %d", len(plan.states), len(tc.want))
			}
			for i, want := range tc.want {
				got := plan.states[i]
				if got.Served != want.Served || got.Reason != want.Reason || got.Detail != want.Detail {
					t.Errorf("rule %s: served, reason, detail = %v, %q, %q, want %v, %q, %q",
						got.Rule.Slug, got.Served, got.Reason, got.Detail, want.Served, want.Reason, want.Detail)
				}
			}
		})
	}
}

func TestPlanIngress_MaxRules(t *testing.T) {
	invalid := planRule("bad", 443, "bad.example.com")
	invalid.Mode = "tcp"
	rules := []api.IngressRule{
		invalid,
		planRule("r1", 443, "r1.example.com"),
		planRule("r2", 443, "r2.example.com"),
		planRule("r3", 443, "r3.example.com"),
		planRule("r4", 8443, ""),
	}
	plan := planIngress(rules, 2)

	want := []string{IngressReasonInvalid, "", "", IngressReasonMaxRules, IngressReasonMaxRules}
	for i, st := range plan.states {
		if st.Reason != want[i] {
			t.Errorf("rule %s: reason = %q, want %q", st.Rule.Slug, st.Reason, want[i])
		}
	}
	if _, ok := plan.tables[8443]; ok {
		t.Error("port 8443 has a table, want none: its only rule is past the bound")
	}
	if tbl := plan.tables[443]; tbl == nil || len(tbl.exact) != 2 {
		t.Errorf("table of 443 = %+v, want the two held hosts", tbl)
	}
}

func TestPlanIngress_EmptyAndUnservedBlocks(t *testing.T) {
	for name, rules := range map[string][]api.IngressRule{"nil": nil, "empty": {}} {
		plan := planIngress(rules, 20)
		if len(plan.tables) != 0 || len(plan.states) != 0 {
			t.Errorf("%s: %d tables and %d states, want none", name, len(plan.tables), len(plan.states))
		}
	}

	term := planRule("term", 443, "term.example.com")
	term.Mode = api.IngressModeTerminate
	acme := planRule("acme", 443, "acme.example.com")
	acme.Mode = api.IngressModeACME
	plan := planIngress([]api.IngressRule{term, acme}, 20)
	if len(plan.tables) != 0 {
		t.Errorf("%d tables, want none for a block without a passthrough rule", len(plan.tables))
	}
	for _, st := range plan.states {
		if st.Served || st.Reason != IngressReasonModeNotServed {
			t.Errorf("rule %s: served, reason = %v, %q, want false, %q", st.Rule.Slug, st.Served, st.Reason, IngressReasonModeNotServed)
		}
	}
}

func TestPlanIngress_HostCaseAndIPv6Target(t *testing.T) {
	r := planRule("api", 443, "API.Example.COM")
	r.TargetAddress = "fd00::7"
	r.TargetPort = 8443
	plan := planIngress([]api.IngressRule{r}, 20)

	route := plan.tables[443].exact["api.example.com"]
	if route == nil {
		t.Fatalf("no route under api.example.com, table = %+v", plan.tables[443])
	}
	if route.target != "[fd00::7]:8443" {
		t.Errorf("target = %q, want %q", route.target, "[fd00::7]:8443")
	}
	if route.rule != r {
		t.Errorf("route rule = %+v, want the rule as pulled", route.rule)
	}
}

func TestIngressTable_Match(t *testing.T) {
	plan := planIngress([]api.IngressRule{
		planRule("api", 443, "api.example.com"),
		planRule("wild", 443, "*.example.com"),
	}, 20)
	tbl := plan.tables[443]

	for _, tc := range []struct {
		name string
		want string // slug, or empty for no route
	}{
		{name: "api.example.com", want: "api"},
		{name: "API.example.com", want: "api"},
		{name: "a.example.com", want: "wild"},
		{name: "A.EXAMPLE.COM", want: "wild"},
		{name: "example.com"},
		{name: "a.b.example.com"},
		{name: ".example.com"},
		{name: ""},
	} {
		var got string
		if r := tbl.match(tc.name); r != nil {
			got = r.rule.Slug
		}
		if got != tc.want {
			t.Errorf("match(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
