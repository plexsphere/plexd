package bridge

import (
	"fmt"
	"net/http"
	"slices"
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

// withOneTarget returns r with the one target the planner gives a rule
// without targets: its three deprecated members.
func withOneTarget(r api.IngressRule) api.IngressRule {
	r.Targets = []api.IngressTarget{{NodeID: r.TargetNodeID, Address: r.TargetAddress, Port: r.TargetPort}}
	return r
}

// firstTargetAddr returns the address a balancer of route's planned rule
// dials first.
func firstTargetAddr(route *ingressRoute) string {
	return newIngressBalancer(route.rule.Targets).targets[0].addr
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
		{name: "empty target address", edit: func(r *api.IngressRule) { r.TargetAddress = "" }, reason: IngressReasonInvalid, detail: "targets[0].address"},
		{name: "target address with a port", edit: func(r *api.IngressRule) { r.TargetAddress = "10.0.0.5:80" }, reason: IngressReasonInvalid, detail: "targets[0].address"},
		{name: "target address in brackets", edit: func(r *api.IngressRule) { r.TargetAddress = "[fd00::1]" }, reason: IngressReasonInvalid, detail: "targets[0].address"},
		{name: "target address with a zone", edit: func(r *api.IngressRule) { r.TargetAddress = "fe80::1%eth0" }, reason: IngressReasonInvalid, detail: "targets[0].address"},
		{name: "target port 0", edit: func(r *api.IngressRule) { r.TargetPort = 0 }, reason: IngressReasonInvalid, detail: "targets[0].port"},
		{name: "target port 65536", edit: func(r *api.IngressRule) { r.TargetPort = 65536 }, reason: IngressReasonInvalid, detail: "targets[0].port"},
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
		{name: "passthrough with conditions", edit: func(r *api.IngressRule) { r.Conditions.PathPrefix = "/api" }, reason: IngressReasonInvalid, detail: "conditions"},
		{name: "terminate with a path prefix api", edit: withConditions("api"), reason: IngressReasonInvalid, detail: "conditions.path_prefix"},
		{name: "terminate with the header name Host", edit: withConditions("/api", "Host", "x"), reason: IngressReasonInvalid, detail: "conditions.headers"},
		{name: "terminate with strip_path_prefix and no prefix", edit: func(r *api.IngressRule) { withConditions("")(r); r.StripPathPrefix = true }, reason: IngressReasonInvalid, detail: "strip_path_prefix"},
		{name: "terminate with conditions is held", edit: withConditions("/api", "x-a", "1")},
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
			if want := withOneTarget(r); !st.Rule.Equal(want) {
				t.Errorf("state rule = %+v, want %+v", st.Rule, want)
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

// planTargets returns n targets, the i-th, counted from 1, on node-i at
// 10.0.1.i and port 9000+i.
func planTargets(n int) []api.IngressTarget {
	targets := make([]api.IngressTarget, n)
	for i := range targets {
		targets[i] = api.IngressTarget{NodeID: fmt.Sprintf("node-%d", i+1), Address: fmt.Sprintf("10.0.1.%d", i+1), Port: 9001 + i}
	}
	return targets
}

func TestPlanIngress_Targets(t *testing.T) {
	t.Run("both pull shapes of one rule plan equal", func(t *testing.T) {
		legacy := planRule("web", 443, "web.example.com")
		current := withOneTarget(legacy)
		fromLegacy := planIngress([]api.IngressRule{legacy}, 20, acmeAvailability{}).states[0]
		fromCurrent := planIngress([]api.IngressRule{current}, 20, acmeAvailability{}).states[0]
		if !fromLegacy.held || !fromCurrent.held {
			t.Fatalf("states = %+v and %+v, want both held", fromLegacy, fromCurrent)
		}
		if !fromLegacy.Rule.Equal(fromCurrent.Rule) {
			t.Errorf("planned rules %+v and %+v, want them equal", fromLegacy.Rule, fromCurrent.Rule)
		}
		if !slices.Equal(fromLegacy.Rule.Targets, current.Targets) {
			t.Errorf("targets of the rule without targets = %+v, want %+v", fromLegacy.Rule.Targets, current.Targets)
		}
		if fromLegacy.reportsTargets || !fromCurrent.reportsTargets {
			t.Errorf("reportsTargets = %v without targets and %v with them, want false and true", fromLegacy.reportsTargets, fromCurrent.reportsTargets)
		}
	})

	t.Run("targets win over the deprecated members", func(t *testing.T) {
		targets := []api.IngressTarget{{NodeID: "node-a", Address: "10.0.0.7", Port: 9001}, {NodeID: "node-b", Address: "fd00::8", Port: 9002}}
		for name, edit := range map[string]func(*api.IngressRule){
			"another target":         func(*api.IngressRule) {},
			"members it cannot dial": func(r *api.IngressRule) { r.TargetNodeID, r.TargetAddress, r.TargetPort = "", "10.0.0.300", 0 },
		} {
			r := planRule("web", 443, "web.example.com")
			edit(&r)
			r.Targets = targets
			plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
			want := r
			want.TargetNodeID, want.TargetAddress, want.TargetPort = "node-a", "10.0.0.7", 9001
			if st := plan.states[0]; !st.held || !st.Served || !st.Rule.Equal(want) || !st.reportsTargets {
				t.Errorf("%s: state = %+v, want held and served with %+v", name, st, want)
			}
			route := plan.tables[443].exact["web.example.com"].lead()
			b := newIngressBalancer(route.rule.Targets)
			if got := []string{b.targets[0].addr, b.targets[1].addr}; !slices.Equal(got, []string{"10.0.0.7:9001", "[fd00::8]:9002"}) {
				t.Errorf("%s: the route's targets dial %v, want 10.0.0.7:9001 and [fd00::8]:9002", name, got)
			}
		}
	})

	withTargets := func(targets []api.IngressTarget) func(*api.IngressRule) {
		return func(r *api.IngressRule) { r.Targets = targets }
	}
	withSecond := func(address string) func(*api.IngressRule) {
		return withTargets([]api.IngressTarget{{NodeID: "node-a", Address: "10.0.0.7", Port: 9001}, {NodeID: "node-b", Address: address, Port: 9002}})
	}
	withFirstPort := func(port int) func(*api.IngressRule) {
		return withTargets([]api.IngressTarget{{NodeID: "node-a", Address: "10.0.0.7", Port: port}, {NodeID: "node-b", Address: "10.0.0.8", Port: 9002}})
	}
	for _, tc := range []struct {
		name   string
		edit   func(*api.IngressRule)
		detail string // empty when the rule is held
	}{
		{name: "nine targets", edit: withTargets(planTargets(9)), detail: "targets"},
		{name: "a second address 10.0.0.300", edit: withSecond("10.0.0.300"), detail: "targets[1].address"},
		{name: "a second address [fd00::1]", edit: withSecond("[fd00::1]"), detail: "targets[1].address"},
		{name: "a second address 10.0.0.1:80", edit: withSecond("10.0.0.1:80"), detail: "targets[1].address"},
		{name: "a first port 0", edit: withFirstPort(0), detail: "targets[0].port"},
		{name: "a first port 65536", edit: withFirstPort(65536), detail: "targets[0].port"},
		{name: "neither targets nor target_address", edit: func(r *api.IngressRule) { r.TargetAddress = "" }, detail: "targets[0].address"},
		{name: "an address ahead of its own port", edit: withTargets([]api.IngressTarget{{NodeID: "node-a", Address: "", Port: 0}}), detail: "targets[0].address"},
		{name: "a first port ahead of a second address", edit: withTargets([]api.IngressTarget{{NodeID: "node-a", Address: "10.0.0.7", Port: 0}, {NodeID: "node-b", Address: "", Port: 9002}}), detail: "targets[0].port"},
		{name: "eight targets", edit: withTargets(planTargets(8))},
		{name: "one node address with two ports", edit: withTargets([]api.IngressTarget{{NodeID: "node-a", Address: "10.0.0.7", Port: 9001}, {NodeID: "node-a", Address: "10.0.0.7", Port: 9002}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := planRule("web", 443, "web.example.com")
			tc.edit(&r)
			st := planIngress([]api.IngressRule{r}, 20, acmeAvailability{}).states[0]
			wantReason := ""
			if tc.detail != "" {
				wantReason = IngressReasonInvalid
			}
			if st.Reason != wantReason || st.Detail != tc.detail {
				t.Errorf("reason, detail = %q, %q, want %q, %q", st.Reason, st.Detail, wantReason, tc.detail)
			}
			if wantHeld := tc.detail == ""; st.held != wantHeld || st.Served != wantHeld {
				t.Errorf("held, Served = %v, %v, want %v, %v", st.held, st.Served, wantHeld, wantHeld)
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

// withConditions makes a rule a terminate rule of the Secret tls with the path
// prefix and the header conditions, given as name, value pairs.
func withConditions(prefix string, nameValues ...string) func(*api.IngressRule) {
	return func(r *api.IngressRule) {
		terminateNamed("tls")(r)
		r.Conditions = api.IngressConditions{PathPrefix: prefix}
		for i := 0; i+1 < len(nameValues); i += 2 {
			r.Conditions.Headers = append(r.Conditions.Headers, api.IngressHeaderCondition{Name: nameValues[i], Value: nameValues[i+1]})
		}
	}
}

// condRule returns a terminate rule of the Secret tls for host on port 443
// with the path prefix and the header conditions, given as name, value pairs.
func condRule(slug, host, prefix string, nameValues ...string) api.IngressRule {
	r := planRule(slug, 443, host)
	withConditions(prefix, nameValues...)(&r)
	return r
}

// headersOf returns n header conditions x-0: v to x-<n-1>: v.
func headersOf(n int) []api.IngressHeaderCondition {
	out := make([]api.IngressHeaderCondition, n)
	for i := range out {
		out[i] = api.IngressHeaderCondition{Name: "x-" + string(rune('a'+i)), Value: "v"}
	}
	return out
}

func TestPlanIngress_ConditionsGrammar(t *testing.T) {
	setHeaders := func(h ...api.IngressHeaderCondition) func(*api.IngressRule) {
		return func(r *api.IngressRule) { r.Conditions.Headers = h }
	}
	header := func(name, value string) api.IngressHeaderCondition {
		return api.IngressHeaderCondition{Name: name, Value: value}
	}
	setPrefix := func(p string) func(*api.IngressRule) {
		return func(r *api.IngressRule) { r.Conditions.PathPrefix = p }
	}
	for _, tc := range []struct {
		name   string
		rule   api.IngressRule
		edit   func(*api.IngressRule)
		detail string // empty for a rule that is held
	}{
		{name: "conditions on a tcp passthrough rule", rule: planRule("web", 443, "web.example.com"), edit: setPrefix("/api"), detail: "conditions"},
		{name: "a header condition on a tcp passthrough rule", rule: planRule("web", 443, "web.example.com"), edit: setHeaders(header("x-a", "1")), detail: "conditions"},
		{name: "conditions on a udp rule", rule: udpPlanRule("dns", 53), edit: setPrefix("/api"), detail: "conditions"},

		{name: "prefix api", rule: condRule("web", "web.example.com", ""), edit: setPrefix("api"), detail: "conditions.path_prefix"},
		{name: "prefix /api/", rule: condRule("web", "web.example.com", ""), edit: setPrefix("/api/"), detail: "conditions.path_prefix"},
		{name: "prefix //", rule: condRule("web", "web.example.com", ""), edit: setPrefix("//"), detail: "conditions.path_prefix"},
		{name: "prefix /a/../b", rule: condRule("web", "web.example.com", ""), edit: setPrefix("/a/../b"), detail: "conditions.path_prefix"},
		{name: "prefix /a b", rule: condRule("web", "web.example.com", ""), edit: setPrefix("/a b"), detail: "conditions.path_prefix"},
		{name: "prefix /a%20b", rule: condRule("web", "web.example.com", ""), edit: setPrefix("/a%20b"), detail: "conditions.path_prefix"},
		{name: "prefix /a?b", rule: condRule("web", "web.example.com", ""), edit: setPrefix("/a?b"), detail: "conditions.path_prefix"},
		{name: "prefix of 1025 bytes", rule: condRule("web", "web.example.com", ""), edit: setPrefix("/" + strings.Repeat("a", 1024)), detail: "conditions.path_prefix"},

		{name: "9 headers", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(headersOf(9)...), detail: "conditions.headers"},
		{name: "an empty header name", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("", "1")), detail: "conditions.headers"},
		{name: "the header name X-A", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("X-A", "1")), detail: "conditions.headers"},
		{name: "the header name host", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("host", "web.example.com")), detail: "conditions.headers"},
		{name: "the header name a b", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("a b", "1")), detail: "conditions.headers"},
		{name: "a header name of 65 characters", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header(strings.Repeat("x", 65), "1")), detail: "conditions.headers"},
		{name: "the header name x-a twice", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", "1"), header("x-a", "2")), detail: "conditions.headers"},
		{name: "an empty header value", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", "")), detail: "conditions.headers"},
		{name: "a header value with a leading space", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", " v")), detail: "conditions.headers"},
		{name: "a header value with a trailing space", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", "v ")), detail: "conditions.headers"},
		{name: "a header value of 257 bytes", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", strings.Repeat("v", 257))), detail: "conditions.headers"},
		{name: "a header value with 0x7F", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", "v\x7f")), detail: "conditions.headers"},

		{name: "strip without a prefix", rule: condRule("web", "web.example.com", ""), edit: func(r *api.IngressRule) { r.StripPathPrefix = true }, detail: "strip_path_prefix"},
		{name: "strip with headers only", rule: condRule("web", "web.example.com", "", "x-a", "1"), edit: func(r *api.IngressRule) { r.StripPathPrefix = true }, detail: "strip_path_prefix"},
		{name: "strip with the prefix /", rule: condRule("web", "web.example.com", "/"), edit: func(r *api.IngressRule) { r.StripPathPrefix = true }, detail: "strip_path_prefix"},

		{name: "the prefix / is held", rule: condRule("web", "web.example.com", "/"), edit: func(*api.IngressRule) {}},
		{name: "the prefix /api is held", rule: condRule("web", "web.example.com", "/api"), edit: func(*api.IngressRule) {}},
		{name: "the prefix /a.b/c~d is held", rule: condRule("web", "web.example.com", "/a.b/c~d"), edit: func(*api.IngressRule) {}},
		{name: "a prefix of 1024 bytes is held", rule: condRule("web", "web.example.com", "/"+strings.Repeat("a", 1023)), edit: func(*api.IngressRule) {}},
		{name: "8 headers are held", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(headersOf(8)...)},
		{name: "headers without a prefix are held", rule: condRule("web", "web.example.com", "", "x-a", "1"), edit: func(*api.IngressRule) {}},
		{name: "a header name of 64 token characters is held", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("!#$%&'*+-.^_`|~0"+strings.Repeat("z", 48), "1"))},
		{name: "a header value of 256 printable bytes is held", rule: condRule("web", "web.example.com", "/api"), edit: setHeaders(header("x-a", "!"+strings.Repeat(" ~", 127)+"!"))},
		{name: "strip with the prefix /api is held", rule: condRule("web", "web.example.com", "/api"), edit: func(r *api.IngressRule) { r.StripPathPrefix = true }},
		{name: "an empty header list is no condition", rule: planRule("web", 443, "web.example.com"), edit: setHeaders()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			tc.edit(&r)
			plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
			st := plan.states[0]
			if tc.detail == "" {
				if !st.held || !st.Served || st.Reason != "" {
					t.Errorf("state = %+v, want held and served", st)
				}
				return
			}
			if st.held || st.Reason != IngressReasonInvalid || st.Detail != tc.detail {
				t.Errorf("reason, detail = %q, %q, want %q, %q", st.Reason, st.Detail, IngressReasonInvalid, tc.detail)
			}
		})
	}

	t.Run("an empty header list reads nil in the state", func(t *testing.T) {
		r := condRule("web", "web.example.com", "/api")
		r.Conditions.Headers = []api.IngressHeaderCondition{}
		plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
		if got := plan.states[0].Rule.Conditions.Headers; got != nil {
			t.Errorf("state Headers = %#v, want nil", got)
		}
	})
}

// TestPlanIngress_SharedHost holds rules that share a port and host by their
// conditions and refuses the rules the control plane's terms leave out.
func TestPlanIngress_SharedHost(t *testing.T) {
	t.Run("three rules of one Secret on one host", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{
			condRule("web", "shop.example.com", "/"),
			condRule("api", "shop.example.com", "/api"),
			condRule("beta", "shop.example.com", "/api", "x-beta", "1"),
		}, 20, acmeAvailability{})
		for _, st := range plan.states {
			if !st.held || !st.Served || st.Reason != "" {
				t.Errorf("rule %s = %+v, want held and served", st.Rule.Slug, st)
			}
		}
		host := plan.tables[443].exact["shop.example.com"]
		if host == nil || !host.http || len(host.routes) != 3 {
			t.Fatalf("host = %+v, want an http host with three routes", host)
		}
		if got := len(plan.tables[443].routes()); got != 3 {
			t.Errorf("table routes = %d, want 3", got)
		}
	})

	t.Run("a rule with conditions alone is an http host", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{condRule("api", "shop.example.com", "/api")}, 20, acmeAvailability{})
		if host := plan.tables[443].exact["shop.example.com"]; host == nil || !host.http {
			t.Errorf("host = %+v, want an http host", host)
		}
	})

	t.Run("a rule without conditions is no http host", func(t *testing.T) {
		r := planRule("term", 443, "shop.example.com")
		terminateNamed("tls")(&r)
		plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})
		if host := plan.tables[443].exact["shop.example.com"]; host == nil || host.http {
			t.Errorf("host = %+v, want a host that forwards bytes", host)
		}
	})

	t.Run("a wildcard host shared by two rules", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{
			condRule("a", "*.example.com", "/a"),
			condRule("b", "*.example.com", "/b"),
		}, 20, acmeAvailability{})
		if host := plan.tables[443].wildcard["example.com"]; host == nil || !host.http || len(host.routes) != 2 {
			t.Errorf("wildcard host = %+v, want an http host with two routes", host)
		}
	})

	noConditions := planRule("plainhost", 443, "shop.example.com")
	terminateNamed("tls")(&noConditions)
	acmeWith := condRule("acmehost", "shop.example.com", "/acme")
	acmeWith.Mode, acmeWith.CertificateSecretName = api.IngressModeACME, ""
	otherSecret := condRule("other", "shop.example.com", "/other")
	otherSecret.CertificateSecretName = "tls-other"
	for _, tc := range []struct {
		name   string
		rules  []api.IngressRule // the last one is checked
		detail string
	}{
		{name: "a rule without conditions on a host a rule with conditions holds", rules: []api.IngressRule{condRule("first", "shop.example.com", "/api"), condRule("second", "shop.example.com", "/"), noConditions}, detail: "first"},
		{name: "a rule with conditions on a host a rule without conditions holds", rules: []api.IngressRule{noConditions, condRule("api", "shop.example.com", "/api")}, detail: "plainhost"},
		{name: "a passthrough rule on a host rules with conditions hold", rules: []api.IngressRule{condRule("first", "shop.example.com", "/api"), planRule("pass", 443, "shop.example.com")}, detail: "first"},
		{name: "a rule of another mode", rules: []api.IngressRule{condRule("first", "shop.example.com", "/api"), condRule("second", "shop.example.com", "/"), acmeWith}, detail: "first"},
		{name: "a terminate rule naming another Secret", rules: []api.IngressRule{condRule("first", "shop.example.com", "/api"), condRule("second", "shop.example.com", "/"), otherSecret}, detail: "first"},
		{name: "the same conditions", rules: []api.IngressRule{condRule("first", "shop.example.com", "/"), condRule("api", "shop.example.com", "/api", "x-a", "1"), condRule("dup", "shop.example.com", "/api", "x-a", "1")}, detail: "api"},
		{name: "the same headers in another order", rules: []api.IngressRule{condRule("first", "shop.example.com", "/"), condRule("api", "shop.example.com", "/api", "x-a", "1", "x-b", "2"), condRule("dup", "shop.example.com", "/api", "x-b", "2", "x-a", "1")}, detail: "api"},
		{name: "the prefix / against an empty prefix", rules: []api.IngressRule{condRule("api", "shop.example.com", "/api"), condRule("root", "shop.example.com", "/", "x-a", "1"), condRule("dup", "shop.example.com", "", "x-a", "1")}, detail: "root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planIngress(tc.rules, 20, acmeAvailability{})
			st := plan.states[len(plan.states)-1]
			if st.held || st.Reason != IngressReasonListenerConflict || st.Detail != tc.detail {
				t.Errorf("rule %s = %+v, want %q held by %s", st.Rule.Slug, st, IngressReasonListenerConflict, tc.detail)
			}
			for _, earlier := range plan.states[:len(plan.states)-1] {
				if !earlier.held {
					t.Errorf("rule %s = %+v, want held", earlier.Rule.Slug, earlier)
				}
			}
		})
	}

	t.Run("rules sharing a host count toward the bound", func(t *testing.T) {
		plan := planIngress([]api.IngressRule{
			condRule("a", "shop.example.com", "/a"),
			condRule("b", "shop.example.com", "/b"),
			condRule("c", "shop.example.com", "/c"),
		}, 2, acmeAvailability{})
		if st := plan.states[2]; st.Reason != IngressReasonMaxRules {
			t.Errorf("third rule = %+v, want %q", st, IngressReasonMaxRules)
		}
		if host := plan.tables[443].exact["shop.example.com"]; host == nil || len(host.routes) != 2 {
			t.Errorf("host = %+v, want two routes", host)
		}
	})
}

func TestPlanIngress_Precedence(t *testing.T) {
	rules := []api.IngressRule{
		condRule("z-root", "shop.example.com", "", "x-z", "1"),
		condRule("api", "shop.example.com", "/api"),
		condRule("api-one", "shop.example.com", "/api", "x-a", "1"),
		condRule("v1", "shop.example.com", "/api/v1"),
		condRule("a-root", "shop.example.com", "/", "x-y", "1"),
		condRule("api-two", "shop.example.com", "/api", "x-a", "1", "x-b", "2"),
	}
	plan := planIngress(rules, 20, acmeAvailability{})
	host := plan.tables[443].exact["shop.example.com"]
	if host == nil {
		t.Fatal("no host shop.example.com")
	}
	var got []string
	for _, r := range host.routes {
		got = append(got, r.rule.Slug)
	}
	want := []string{"v1", "api-two", "api-one", "api", "a-root", "z-root"}
	if !slices.Equal(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}
	if lead := host.lead().rule.Slug; lead != "v1" {
		t.Errorf("lead = %s, want v1", lead)
	}

	// Slugs are unique within a bridge; two equal ones fall back to the id.
	a, b := condRule("same", "shop.example.com", "/a"), condRule("same", "shop.example.com", "/b")
	a.ID, b.ID = "id-2", "id-1"
	ra, rb := &ingressRoute{rule: a}, &ingressRoute{rule: b}
	if comparePrecedence(rb, ra) >= 0 {
		t.Error("of two routes with one slug and prefixes of one length, the lower id does not come first")
	}
}

func TestIngressHost_Route(t *testing.T) {
	hostOf := func(rules ...api.IngressRule) *ingressHost {
		plan := planIngress(rules, 20, acmeAvailability{})
		return plan.tables[443].exact["shop.example.com"]
	}
	slugOf := func(r *ingressRoute) string {
		if r == nil {
			return ""
		}
		return r.rule.Slug
	}
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}

	prefix := hostOf(condRule("api", "shop.example.com", "/api"))
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/api", want: "api"},
		{path: "/api/users", want: "api"},
		{path: "/api/", want: "api"},
		{path: "/apix"},
		{path: "/API"},
		{path: "/"},
		{path: "/ap"},
	} {
		if got := slugOf(prefix.route(tc.path, http.Header{})); got != tc.want {
			t.Errorf("prefix /api: route(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}

	for _, p := range []string{"", "/"} {
		every := hostOf(condRule("all", "shop.example.com", p, "x-a", "1"))
		for _, path := range []string{"/", "/api", "/x/y/z", "*"} {
			if got := slugOf(every.route(path, hdr("X-A", "1"))); got != "all" {
				t.Errorf("prefix %q: route(%q) = %q, want all", p, path, got)
			}
		}
	}

	headers := hostOf(condRule("tenant", "shop.example.com", "/api", "x-tenant", "acme"))
	for _, tc := range []struct {
		name string
		hdr  http.Header
		want string
	}{
		{name: "the value", hdr: hdr("X-Tenant", "acme"), want: "tenant"},
		{name: "a second field line of the name", hdr: hdr("X-Tenant", "other", "X-Tenant", "acme"), want: "tenant"},
		{name: "a name in another case", hdr: http.Header{"X-TENANT": {"acme"}}, want: "tenant"},
		{name: "another value", hdr: hdr("X-Tenant", "other")},
		{name: "a value in another case", hdr: hdr("X-Tenant", "ACME")},
		{name: "a list a, b for a", hdr: hdr("X-Tenant", "acme, other")},
		{name: "no field", hdr: http.Header{}},
	} {
		h := tc.hdr
		// A server canonicalizes request field names; a test header built by
		// hand in another case stands for a client that sent that case.
		for k, v := range h {
			if c := http.CanonicalHeaderKey(k); c != k {
				delete(h, k)
				h[c] = v
			}
		}
		if got := slugOf(headers.route("/api", h)); got != tc.want {
			t.Errorf("header x-tenant: acme, %s: route = %q, want %q", tc.name, got, tc.want)
		}
	}

	none := hostOf(condRule("a", "shop.example.com", "/a"), condRule("b", "shop.example.com", "/b", "x-b", "1"))
	if got := none.route("/c", hdr("X-B", "1")); got != nil {
		t.Errorf("a host none of whose routes match: route = %q, want nil", slugOf(got))
	}
	if got := slugOf(none.route("/b/x", hdr("X-B", "1"))); got != "b" {
		t.Errorf("route(/b/x) = %q, want b", got)
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
		host := plan.tables[443].exact["web.example.com"]
		if host == nil || host.lead().rule.Protocol != api.IngressProtocolTCP {
			t.Errorf("host = %+v, want one under web.example.com whose rule reads %q", host, api.IngressProtocolTCP)
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
			if want := withOneTarget(r); !st.Rule.Equal(want) {
				t.Errorf("state rule = %+v, want %+v", st.Rule, want)
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
		if st := plan.states[0]; !st.held || !st.Served || st.Reason != "" || !st.Rule.Equal(withOneTarget(r)) {
			t.Errorf("udp rule = %+v, want held and served as pulled", st)
		}
		route := plan.udp[53]
		if route == nil || !route.rule.Equal(withOneTarget(r)) || !route.served || firstTargetAddr(route) != "10.0.0.5:8443" {
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
	if route := plan.tables[8443].exact["term.example.com"].lead(); !route.served {
		t.Error("the terminate rule's route is not served")
	}
}

func TestPlanIngress_HostCaseAndIPv6Target(t *testing.T) {
	r := planRule("api", 443, "API.Example.COM")
	r.TargetAddress = "fd00::7"
	r.TargetPort = 8443
	plan := planIngress([]api.IngressRule{r}, 20, acmeAvailability{})

	host := plan.tables[443].exact["api.example.com"]
	if host == nil {
		t.Fatalf("no host api.example.com, table = %+v", plan.tables[443])
	}
	route := host.lead()
	if got := firstTargetAddr(route); got != "[fd00::7]:8443" {
		t.Errorf("target = %q, want %q", got, "[fd00::7]:8443")
	}
	if !route.rule.Equal(withOneTarget(r)) {
		t.Errorf("route rule = %+v, want the rule as pulled", route.rule)
	}
}

func TestIngressTable_Match(t *testing.T) {
	plan := planIngress([]api.IngressRule{
		planRule("api", 443, "api.example.com"),
		planRule("wild", 443, "*.example.com"),
		condRule("shop-web", "shop.example.com", "/"),
		condRule("shop-api", "shop.example.com", "/api"),
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
		{name: "Shop.Example.Com", want: "shop-api"}, // the lead route of the shared host
		{name: "example.com"},
		{name: "a.b.example.com"},
		{name: ".example.com"},
		{name: ""},
	} {
		var got string
		if h := tbl.match(tc.name); h != nil {
			got = h.lead().rule.Slug
		}
		if got != tc.want {
			t.Errorf("match(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
	if h := tbl.match("shop.example.com"); h == nil || len(h.routes) != 2 || !h.http {
		t.Errorf("match(shop.example.com) = %+v, want the http host with both routes", h)
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
	if host := plan.tables[8443].exact["acme.example.com"]; host == nil || host.lead().served {
		t.Errorf("host of the acme rule = %+v, want one whose route is not served", host)
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
			if host := plan.tables[8443].exact["acme.example.com"]; host == nil || host.lead().served {
				t.Errorf("host of the acme rule = %+v, want one whose route is not served", host)
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

	t.Run("two acme rules with conditions on one host", func(t *testing.T) {
		withPrefix := func(slug, prefix string) api.IngressRule {
			r := acmePlanRule(slug, 8443, "acme.example.com")
			r.Conditions.PathPrefix = prefix
			return r
		}
		rules := []api.IngressRule{withPrefix("acme-api", "/api"), withPrefix("acme-web", "/")}
		plan := planIngress(rules, 20, acmeAvailability{})
		for _, st := range plan.states {
			if !st.held || !st.Served || st.Reason != "" {
				t.Errorf("rule %s = %+v, want held and served", st.Rule.Slug, st)
			}
		}
		if host := plan.tables[8443].exact["acme.example.com"]; host == nil || !host.http || len(host.routes) != 2 {
			t.Errorf("host = %+v, want an http host with two routes", host)
		}

		pass := planRule("pass", 443, "acme.example.com")
		plan = planIngress(append(rules, pass), 20, acmeAvailability{})
		for _, st := range plan.states[:2] {
			if st.Served || !st.held || st.Reason != IngressReasonACMEChallengePortTaken || st.Detail != "pass" {
				t.Errorf("rule %s = %+v, want held, not served, %q by pass", st.Rule.Slug, st, IngressReasonACMEChallengePortTaken)
			}
		}
		for _, r := range plan.tables[8443].exact["acme.example.com"].routes {
			if r.served {
				t.Errorf("route %s is served, want not", r.rule.Slug)
			}
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
