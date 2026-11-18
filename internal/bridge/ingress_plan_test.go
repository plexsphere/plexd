package bridge

import (
	"strings"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

// planRule returns a valid tcp passthrough rule; each test changes what it
// checks.
func planRule(slug string, port int, host string) api.IngressRule {
	return api.IngressRule{
		ID:            "id-" + slug,
		Slug:          slug,
		Protocol:      api.IngressProtocolTCP,
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
		{name: "terminate without a secret name", edit: terminateNamed(""), reason: IngressReasonInvalid, detail: "certificate_secret_name"},
		{name: "terminate with the secret name Tls", edit: terminateNamed("Tls"), reason: IngressReasonInvalid, detail: "certificate_secret_name"},
		{name: "terminate with the secret name 1cert", edit: terminateNamed("1cert"), reason: IngressReasonInvalid, detail: "certificate_secret_name"},
		{name: "terminate with a secret name of 64 characters", edit: terminateNamed("t" + strings.Repeat("a", 63)), reason: IngressReasonInvalid, detail: "certificate_secret_name"},
		{name: "acme with a wildcard host", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeACME; r.SNIHost = "*.example.com" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "acme with a host of one label", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeACME; r.SNIHost = "localhost" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "passthrough ignores the secret name", edit: func(r *api.IngressRule) { r.CertificateSecretName = "Tls" }},
		{name: "terminate is held", edit: terminateNamed("tls")},
		{name: "terminate with a secret name of 63 characters is held", edit: terminateNamed("t" + strings.Repeat("a", 62))},
		{name: "acme is held", edit: func(r *api.IngressRule) { r.Mode = api.IngressModeACME }},
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
			plan := planIngress(append(append([]api.IngressRule{}, tc.before...), r), maxRules, acmeAvailability{})
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
			if wantServed := tc.reason == ""; st.Served != wantServed || st.held != wantServed {
				t.Errorf("Served, held = %v, %v, want %v, %v", st.Served, st.held, wantServed, wantServed)
			}
		})
	}
}

// terminateNamed makes a rule a terminate rule that names the Secret name.
func terminateNamed(name string) func(*api.IngressRule) {
	return func(r *api.IngressRule) {
		r.Mode = api.IngressModeTerminate
		r.CertificateSecretName = name
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
			plan := planIngress(tc.rules, 20, acmeAvailability{})
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

// udpPlanRule returns a valid udp rule on port.
func udpPlanRule(slug string, port int) api.IngressRule {
	r := planRule(slug, port, "")
	r.Protocol = api.IngressProtocolUDP
	return r
}

// routesOf returns the slugs of every route in the plan's tables.
func routesOf(plan ingressPlan) []string {
	var slugs []string
	for _, tbl := range plan.tables {
		for _, r := range tbl.routes() {
			slugs = append(slugs, r.rule.Slug)
		}
	}
	return slugs
}

func TestPlanIngress_Protocol(t *testing.T) {
	t.Run("an empty protocol is tcp", func(t *testing.T) {
		r := planRule("web", 443, "web.example.com")
		r.Protocol = ""
		plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
		st := plan.states[0]
		if !st.held || !st.Served || st.Reason != "" {
			t.Errorf("rule without a protocol = %+v, want held and served", st)
		}
		if st.Rule.Protocol != api.IngressProtocolTCP {
			t.Errorf("state Rule.Protocol = %q, want %q", st.Rule.Protocol, api.IngressProtocolTCP)
		}
		route := plan.tables[443].exact["web.example.com"]
		if route == nil || route.rule.Protocol != api.IngressProtocolTCP {
			t.Errorf("route = %+v, want one under web.example.com whose rule reads %q", route, api.IngressProtocolTCP)
		}
		if len(plan.udp) != 0 {
			t.Errorf("plan.udp = %+v, want empty", plan.udp)
		}
	})

	for _, tc := range []struct {
		name   string
		rule   api.IngressRule // the rule before edit
		edit   func(*api.IngressRule)
		reason string
		detail string
	}{
		{name: "protocol sctp", rule: planRule("web", 443, ""), edit: func(r *api.IngressRule) { r.Protocol = "sctp" }, reason: IngressReasonInvalid, detail: "protocol"},
		{name: "protocol UDP", rule: planRule("web", 443, ""), edit: func(r *api.IngressRule) { r.Protocol = "UDP" }, reason: IngressReasonInvalid, detail: "protocol"},
		{name: "unknown protocol and unknown mode", rule: planRule("web", 443, ""), edit: func(r *api.IngressRule) { r.Protocol = "sctp"; r.Mode = "tcp" }, reason: IngressReasonInvalid, detail: "protocol"},
		{name: "udp terminate", rule: udpPlanRule("dns", 53), edit: func(r *api.IngressRule) {
			r.Mode, r.SNIHost, r.CertificateSecretName = api.IngressModeTerminate, "dns.example.com", "tls"
		}, reason: IngressReasonInvalid, detail: "mode"},
		{name: "udp acme", rule: udpPlanRule("dns", 53), edit: func(r *api.IngressRule) { r.Mode, r.SNIHost = api.IngressModeACME, "dns.example.com" }, reason: IngressReasonInvalid, detail: "mode"},
		{name: "udp passthrough with an sni host", rule: udpPlanRule("dns", 53), edit: func(r *api.IngressRule) { r.SNIHost = "dns.example.com" }, reason: IngressReasonInvalid, detail: "sni_host"},
		{name: "udp passthrough with a secret name outside the grammar is held", rule: udpPlanRule("dns", 53), edit: func(r *api.IngressRule) { r.CertificateSecretName = "Tls" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			tc.edit(&r)
			plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
			st := plan.states[0]
			if st.Rule != r {
				t.Errorf("state rule = %+v, want %+v", st.Rule, r)
			}
			if st.Reason != tc.reason || st.Detail != tc.detail {
				t.Errorf("reason, detail = %q, %q, want %q, %q", st.Reason, st.Detail, tc.reason, tc.detail)
			}
			if wantServed := tc.reason == ""; st.Served != wantServed || st.held != wantServed {
				t.Errorf("Served, held = %v, %v, want %v, %v", st.Served, st.held, wantServed, wantServed)
			}
		})
	}

	t.Run("a udp passthrough rule is held in plan.udp", func(t *testing.T) {
		r := udpPlanRule("dns", 53)
		plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
		if st := plan.states[0]; !st.held || !st.Served || st.Reason != "" || st.Rule != r {
			t.Errorf("udp rule = %+v, want held and served as pulled", st)
		}
		route := plan.udp[53]
		if route == nil || route.rule != r || !route.served || route.target != "10.0.0.5:8443" {
			t.Errorf("plan.udp[53] = %+v, want the served route of the rule to 10.0.0.5:8443", route)
		}
		if len(plan.udp) != 1 {
			t.Errorf("plan.udp = %+v, want only port 53", plan.udp)
		}
		if slugs := routesOf(plan); len(slugs) != 0 || len(plan.tables) != 0 {
			t.Errorf("tables = %+v with routes %v, want no table for a udp rule", plan.tables, slugs)
		}
	})
}

func TestPlanIngress_UDPListenerConflict(t *testing.T) {
	t.Run("a plain tcp rule and a udp rule on 53", func(t *testing.T) {
		for name, rules := range map[string][]api.IngressRule{
			"tcp first": {planRule("tcp53", 53, ""), udpPlanRule("udp53", 53)},
			"udp first": {udpPlanRule("udp53", 53), planRule("tcp53", 53, "")},
		} {
			plan := planIngress(rules, 20, acmeAvailability{})
			for _, st := range plan.states {
				if !st.held || !st.Served || st.Reason != "" {
					t.Errorf("%s: rule %s = %+v, want held and served", name, st.Rule.Slug, st)
				}
			}
			if tbl := plan.tables[53]; tbl == nil || tbl.plain == nil || tbl.plain.rule.Slug != "tcp53" {
				t.Errorf("%s: table of 53 = %+v, want tcp53 as its plain rule", name, tbl)
			}
			if route := plan.udp[53]; route == nil || route.rule.Slug != "udp53" {
				t.Errorf("%s: plan.udp[53] = %+v, want udp53", name, route)
			}
		}
	})

	t.Run("a second udp rule on 53", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{
			planRule("tcp53", 53, ""),
			udpPlanRule("udp53", 53),
			udpPlanRule("udp53b", 53),
		}, 20, acmeAvailability{})
		if st := plan.states[2]; st.Served || st.held || st.Reason != IngressReasonListenerConflict || st.Detail != "udp53" {
			t.Errorf("second udp rule = %+v, want %q held by udp53", st, IngressReasonListenerConflict)
		}
		if route := plan.udp[53]; route == nil || route.rule.Slug != "udp53" {
			t.Errorf("plan.udp[53] = %+v, want the first udp rule", route)
		}
	})

	t.Run("a udp rule on 443 beside an acme rule on 443", func(t *testing.T) {
		for name, rules := range map[string][]api.IngressRule{
			"acme first": {acmePlanRule("acme", 443, "acme.example.com"), udpPlanRule("quic", 443)},
			"udp first":  {udpPlanRule("quic", 443), acmePlanRule("acme", 443, "acme.example.com")},
		} {
			plan := planIngress(rules, 20, acmeAvailability{})
			for _, st := range plan.states {
				if !st.held || !st.Served || st.Reason != "" {
					t.Errorf("%s: rule %s = %+v, want held and served", name, st.Rule.Slug, st)
				}
			}
			if tbl := plan.tables[acmeChallengePort]; tbl == nil || len(tbl.routes()) != 1 || tbl.exact["acme.example.com"] == nil {
				t.Errorf("%s: table of 443 = %+v, want only the acme rule's", name, tbl)
			}
			if route := plan.udp[443]; route == nil || route.rule.Slug != "quic" {
				t.Errorf("%s: plan.udp[443] = %+v, want quic", name, route)
			}
		}
	})

	t.Run("a udp rule on 443 holds no challenge port", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{
			acmePlanRule("acme", 8443, "acme.example.com"),
			udpPlanRule("quic", 443),
		}, 20, acmeAvailability{})
		if st := plan.states[0]; !st.Served || st.Reason != "" {
			t.Errorf("acme rule = %+v, want served", st)
		}
		if tbl := plan.tables[acmeChallengePort]; tbl == nil || len(tbl.routes()) != 0 {
			t.Errorf("table of 443 = %+v, want the empty challenge table", tbl)
		}
	})
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
	plan := planIngress(rules, 2, acmeAvailability{})

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

	// The rules of both protocols count toward the bound.
	for _, third := range []api.IngressRule{planRule("tcp3", 8443, ""), udpPlanRule("udp3", 8053)} {
		plan := planIngress([]api.IngressRule{planRule("tcp1", 443, ""), udpPlanRule("udp1", 53), third}, 2, acmeAvailability{})
		want := []string{"", "", IngressReasonMaxRules}
		for i, st := range plan.states {
			if st.Reason != want[i] {
				t.Errorf("third rule %s: rule %s: reason = %q, want %q", third.Slug, st.Rule.Slug, st.Reason, want[i])
			}
		}
		if len(plan.tables) != 1 || plan.tables[443] == nil {
			t.Errorf("third rule %s: tables = %+v, want only 443's", third.Slug, plan.tables)
		}
		if len(plan.udp) != 1 || plan.udp[53] == nil {
			t.Errorf("third rule %s: plan.udp = %+v, want only 53's", third.Slug, plan.udp)
		}
	}
}

func TestPlanIngress_EmptyAndTerminateBlocks(t *testing.T) {
	for name, rules := range map[string][]api.IngressRule{"nil": nil, "empty": {}} {
		plan := planIngress(rules, 20, acmeAvailability{})
		if len(plan.tables) != 0 || len(plan.states) != 0 {
			t.Errorf("%s: %d tables and %d states, want none", name, len(plan.tables), len(plan.states))
		}
		if len(plan.udp) != 0 {
			t.Errorf("%s: plan.udp = %+v, want empty", name, plan.udp)
		}
	}

	term := planRule("term", 8443, "term.example.com")
	term.Mode = api.IngressModeTerminate
	term.CertificateSecretName = "tls"
	plan := planIngress([]api.IngressRule{term}, 20, acmeAvailability{})
	if len(plan.tables) != 1 || plan.tables[8443] == nil || plan.tables[8443].exact["term.example.com"] == nil {
		t.Fatalf("tables = %+v, want one for 8443 that routes term.example.com", plan.tables)
	}
	if st := plan.states[0]; !st.held || !st.Served || st.Reason != "" {
		t.Errorf("terminate rule = %+v, want held and served by the plan", st)
	}
	if route := plan.tables[8443].exact["term.example.com"]; !route.served {
		t.Error("the terminate rule's route is not served")
	}
}

func TestPlanIngress_HostCaseAndIPv6Target(t *testing.T) {
	r := planRule("api", 443, "API.Example.COM")
	r.TargetAddress = "fd00::7"
	r.TargetPort = 8443
	plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})

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
	}, 20, acmeAvailability{})
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

func TestCheckACMEDirectory(t *testing.T) {
	const dir = "https://ca.example/dir"
	for _, tc := range []struct {
		name     string
		settings *api.IngressACME
		allowed  []string
		reason   string
		detail   string
	}{
		{name: "no acme member", reason: IngressReasonACMEDirectoryInvalid},
		{name: "empty URL", settings: &api.IngressACME{}, reason: IngressReasonACMEDirectoryInvalid},
		{name: "http URL", settings: &api.IngressACME{DirectoryURL: "http://ca.example/dir"}, reason: IngressReasonACMEDirectoryInvalid, detail: "http://ca.example/dir"},
		{name: "URL without a scheme", settings: &api.IngressACME{DirectoryURL: "ca.example/dir"}, reason: IngressReasonACMEDirectoryInvalid, detail: "ca.example/dir"},
		{name: "URL with user information", settings: &api.IngressACME{DirectoryURL: "https://user@ca.example/dir"}, reason: IngressReasonACMEDirectoryInvalid, detail: "https://user@ca.example/dir"},
		{name: "nil allow-list", settings: &api.IngressACME{DirectoryURL: dir}},
		{name: "empty allow-list", settings: &api.IngressACME{DirectoryURL: dir}, allowed: []string{}},
		{name: "allow-list that holds it", settings: &api.IngressACME{DirectoryURL: dir}, allowed: []string{"https://other.example/dir", dir}},
		{name: "allow-list that holds it with spaces", settings: &api.IngressACME{DirectoryURL: dir}, allowed: []string{"  " + dir + " "}},
		{name: "allow-list of another URL", settings: &api.IngressACME{DirectoryURL: dir}, allowed: []string{"https://other.example/dir"}, reason: IngressReasonACMEDirectoryNotAllowed, detail: dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkACMEDirectory(tc.settings, tc.allowed)
			if got.Reason != tc.reason || got.Detail != tc.detail {
				t.Errorf("checkACMEDirectory = %+v, want reason %q, detail %q", got, tc.reason, tc.detail)
			}
		})
	}
}

// acmePlanRule returns an acme rule for host on port.
func acmePlanRule(slug string, port int, host string) api.IngressRule {
	r := planRule(slug, port, host)
	r.Mode = api.IngressModeACME
	return r
}

// TestPlanIngress_ACMERuleWithAReason holds an acme rule the availability
// gives a reason: it keeps its listener slot, is not served, and across two
// Apply calls it is added once and not served once.
func TestPlanIngress_ACMERuleWithAReason(t *testing.T) {
	const dir = "https://ca.example/dir"
	avail := acmeAvailability{Reason: IngressReasonACMEDirectoryNotAllowed, Detail: dir}
	acme := acmePlanRule("acme", 8443, "acme.example.com")
	pass := planRule("pass", 8443, "acme.example.com")

	plan := planIngress([]api.IngressRule{acme, pass}, 20, avail)
	if st := plan.states[0]; st.Served || !st.held || st.Reason != avail.Reason || st.Detail != dir {
		t.Errorf("acme rule = %+v, want held, not served, %q with the URL", st, avail.Reason)
	}
	if st := plan.states[1]; st.Reason != IngressReasonListenerConflict || st.Detail != "acme" {
		t.Errorf("passthrough rule on the acme rule's host = %+v, want %q held by acme", st, IngressReasonListenerConflict)
	}
	if route := plan.tables[8443].exact["acme.example.com"]; route == nil || route.served {
		t.Errorf("route of the acme rule = %+v, want one that is not served", route)
	}

	ctrl := newLoopbackIngressController(t)
	cfg := ingressTestConfig(true)
	cfg.ACMEDirectoryURLs = []string{"https://other.example/dir"}
	fx := buildIngressFixture(t, ctrl, cfg)
	if err := fx.mgr.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	block := api.IngressConfig{Rules: []api.IngressRule{acme}, ACME: &api.IngressACME{DirectoryURL: dir}}
	for i := range 2 {
		if err := fx.mgr.Apply(t.Context(), block); err != nil {
			t.Fatalf("Apply %d: %v", i, err)
		}
	}
	if st := stateOf(t, fx.mgr, "acme"); st.Served || st.Reason != avail.Reason || st.Detail != dir {
		t.Errorf("acme rule = %+v, want not served with %q and the URL", st, avail.Reason)
	}
	if got := logLines(fx.logs, `msg="ingress rule added"`, "slug=acme"); got != 1 {
		t.Errorf("%d 'ingress rule added' lines, want 1:\n%s", got, fx.logs.String())
	}
	if got := logLines(fx.logs, `msg="ingress rule not served"`, "slug=acme", "reason="+avail.Reason, "detail="+dir); got != 1 {
		t.Errorf("%d 'ingress rule not served' lines, want 1:\n%s", got, fx.logs.String())
	}
	if fx.acme.Active() {
		t.Error("the ACME account is active, want none for an acme rule with a reason")
	}
}

func TestPlanIngress_ChallengePort(t *testing.T) {
	acme := acmePlanRule("acme", 8443, "acme.example.com")

	t.Run("no rule on 443", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{acme}, 20, acmeAvailability{})
		tbl := plan.tables[acmeChallengePort]
		if tbl == nil || len(tbl.routes()) != 0 {
			t.Fatalf("table of 443 = %+v, want an empty one", tbl)
		}
		if plan.tables[8443] == nil {
			t.Error("no table for the acme rule's port 8443")
		}
		if st := plan.states[0]; !st.Served || st.Reason != "" {
			t.Errorf("acme rule = %+v, want served", st)
		}
	})

	t.Run("an SNI rule on 443 for another host", func(t *testing.T) {
		other := planRule("other", 443, "other.example.com")
		plan := planIngress([]api.IngressRule{acme, other}, 20, acmeAvailability{})
		tbl := plan.tables[acmeChallengePort]
		if tbl == nil || len(tbl.routes()) != 1 || tbl.exact["other.example.com"] == nil {
			t.Fatalf("table of 443 = %+v, want only the other rule's", tbl)
		}
		if st := plan.states[0]; !st.Served || st.Reason != "" {
			t.Errorf("acme rule = %+v, want served", st)
		}
	})

	plainRule := planRule("plain", 443, "")
	terminate := planRule("term", 443, "acme.example.com")
	terminate.Mode = api.IngressModeTerminate
	terminate.CertificateSecretName = "tls"
	for _, tc := range []struct {
		name   string
		holder api.IngressRule
	}{
		{name: "a plain rule on 443", holder: plainRule},
		{name: "a passthrough rule on 443 for its host", holder: planRule("pass", 443, "acme.example.com")},
		{name: "a passthrough wildcard on 443 that covers its host", holder: planRule("wild", 443, "*.example.com")},
		{name: "a terminate rule on 443 for its host", holder: terminate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planIngress([]api.IngressRule{acme, tc.holder}, 20, acmeAvailability{})
			st := plan.states[0]
			if st.Served || !st.held || st.Reason != IngressReasonACMEChallengePortTaken || st.Detail != tc.holder.Slug {
				t.Errorf("acme rule = %+v, want held, not served, %q by %s", st, IngressReasonACMEChallengePortTaken, tc.holder.Slug)
			}
			if route := plan.tables[8443].exact["acme.example.com"]; route == nil || route.served {
				t.Errorf("route of the acme rule = %+v, want one that is not served", route)
			}
			if !plan.states[1].Served {
				t.Errorf("rule %s = %+v, want served", tc.holder.Slug, plan.states[1])
			}
		})
	}

	t.Run("an acme rule on 443", func(t *testing.T) {
		on443 := acmePlanRule("acme443", 443, "acme.example.com")
		plan := planIngress([]api.IngressRule{on443}, 20, acmeAvailability{})
		if st := plan.states[0]; !st.Served || st.Reason != "" {
			t.Errorf("acme rule on 443 = %+v, want served", st)
		}
		if tbl := plan.tables[acmeChallengePort]; tbl == nil || tbl.exact["acme.example.com"] == nil {
			t.Errorf("table of 443 = %+v, want the acme rule's", tbl)
		}
	})

	t.Run("an acme rule with a reason", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{acme}, 20, acmeAvailability{Reason: IngressReasonACMEDirectoryInvalid})
		if _, ok := plan.tables[acmeChallengePort]; ok {
			t.Error("port 443 has a table, want none: no acme rule is served")
		}
		if plan.tables[8443] == nil {
			t.Error("no table for the held acme rule's port 8443")
		}
	})
}
