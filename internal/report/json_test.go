package report

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/MemorManeo/whyopen/internal/policy"
)

func decodeJSON(t *testing.T, vs []model.Verdict, opt JSONOptions) map[string]any {
	t.Helper()
	var sb strings.Builder
	if err := JSON(&sb, vs, opt); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, sb.String())
	}
	return doc
}

// The schema is a promise to whatever consumes it, so it says which
// version it is before it says anything else.
func TestJSONCarriesItsSchemaVersion(t *testing.T) {
	doc := decodeJSON(t, nil, JSONOptions{})
	if got := doc["schema_version"]; got != float64(SchemaVersion) {
		t.Fatalf("schema_version = %v, want %d", got, SchemaVersion)
	}
}

// Whatever the table shows, a machine reader must be able to get without
// parsing the table.
func TestJSONVerdictCarriesWhatTheTableShows(t *testing.T) {
	doc := decodeJSON(t, []model.Verdict{{
		Endpoint: model.Endpoint{Kind: "socket", Port: 443, Proto: "tcp", Owner: "nginx.service", BindIP: "0.0.0.0"},
		Family:   "ip",
		Result:   "reachable",
		Reason:   "delivered locally",
	}}, JSONOptions{})

	vs, ok := doc["verdicts"].([]any)
	if !ok || len(vs) != 1 {
		t.Fatalf("verdicts = %v, want one", doc["verdicts"])
	}
	v := vs[0].(map[string]any)
	for k, want := range map[string]any{
		"port": float64(443), "proto": "tcp", "family": "ip", "result": "reachable",
		"reason": "delivered locally", "owner": "nginx.service", "bind_ip": "0.0.0.0", "kind": "socket",
	} {
		if v[k] != want {
			t.Errorf("verdict[%q] = %v, want %v", k, v[k], want)
		}
	}
}

// The path is the expensive part of the document and only --explain asks
// for it, so it is absent otherwise rather than empty.
func TestJSONOmitsThePathUnlessAsked(t *testing.T) {
	v := model.Verdict{
		Endpoint: model.Endpoint{Port: 22, Proto: "tcp"}, Family: "ip", Result: "reachable",
		Path: []model.Hit{{Family: "ip", Table: "filter", Chain: "INPUT", Hook: "input", Handle: 12, Action: "accept",
			Rule: facts.Rule{Handle: 12, Exprs: []facts.Expr{
				{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}}}}}},
	}
	quiet := decodeJSON(t, []model.Verdict{v}, JSONOptions{})
	if _, present := quiet["verdicts"].([]any)[0].(map[string]any)["path"]; present {
		t.Error("path present without WithPath")
	}

	loud := decodeJSON(t, []model.Verdict{v}, JSONOptions{WithPath: true})
	path, ok := loud["verdicts"].([]any)[0].(map[string]any)["path"].([]any)
	if !ok || len(path) != 1 {
		t.Fatalf("path = %v, want one hit", loud["verdicts"].([]any)[0])
	}
	hit := path[0].(map[string]any)
	if hit["table"] != "filter" || hit["chain"] != "INPUT" || hit["handle"] != float64(12) {
		t.Errorf("hit = %v, missing what locates the rule", hit)
	}
	// The nft-like rendering, so a consumer does not have to reassemble
	// the rule from the facts document to show a human what matched.
	if hit["rule"] != "accept" {
		t.Errorf("hit[rule] = %v, want the rendered rule", hit["rule"])
	}
}

func TestJSONCarriesTheDNATRewrite(t *testing.T) {
	doc := decodeJSON(t, []model.Verdict{{
		Endpoint: model.Endpoint{Kind: "publish", Port: 5432, Proto: "tcp"},
		Family:   "ip", Result: "reachable",
		DNAT: &model.DNAT{IP: netip.MustParseAddr("172.20.0.2"), Port: 5432},
	}}, JSONOptions{})
	d, ok := doc["verdicts"].([]any)[0].(map[string]any)["dnat"].(map[string]any)
	if !ok {
		t.Fatalf("dnat missing from a verdict that was rewritten: %v", doc["verdicts"])
	}
	if d["ip"] != "172.20.0.2" || d["port"] != float64(5432) {
		t.Errorf("dnat = %v, want 172.20.0.2:5432", d)
	}
}

// A machine reader that gets the verdicts but not the judgement on them
// would have to re-implement the policy to know whether the run passed.
func TestJSONCarriesThePolicyResult(t *testing.T) {
	res := policy.Result{
		Violations: []model.Verdict{{Endpoint: model.Endpoint{Port: 8080, Proto: "tcp", Owner: "node"}, Family: "ip6", Result: "reachable"}},
		Stale:      []policy.Stale{{Entry: policy.Entry{Port: 9999, Proto: "tcp"}, Found: "filtered"}},
		Unknown:    []model.Verdict{{Endpoint: model.Endpoint{Port: 22, Proto: "tcp"}, Family: "ip", Result: "unknown"}},
	}
	doc := decodeJSON(t, nil, JSONOptions{Policy: &res, PolicySource: "whyopen.yaml"})
	p, ok := doc["policy"].(map[string]any)
	if !ok {
		t.Fatalf("policy missing: %v", doc)
	}
	if p["source"] != "whyopen.yaml" {
		t.Errorf("policy source = %v", p["source"])
	}
	if len(p["violations"].([]any)) != 1 || len(p["stale"].([]any)) != 1 || len(p["unknown"].([]any)) != 1 {
		t.Errorf("policy = %v, want one of each", p)
	}
	stale := p["stale"].([]any)[0].(map[string]any)
	if stale["port"] != float64(9999) || stale["found"] != "filtered" {
		t.Errorf("stale = %v", stale)
	}
}

// No policy was consulted is not the same as a policy that found nothing,
// so the key is absent rather than an empty object.
func TestJSONOmitsThePolicyWhenNoneWasGiven(t *testing.T) {
	doc := decodeJSON(t, nil, JSONOptions{})
	if _, present := doc["policy"]; present {
		t.Error("policy present although none was given")
	}
}

// Same order as the table: an open port is the first thing a reader sees,
// whether the reader is a person or a script.
func TestJSONSortsWorstFirst(t *testing.T) {
	doc := decodeJSON(t, []model.Verdict{
		{Endpoint: model.Endpoint{Port: 1, Proto: "tcp"}, Result: "filtered"},
		{Endpoint: model.Endpoint{Port: 2, Proto: "tcp"}, Result: "unknown"},
		{Endpoint: model.Endpoint{Port: 3, Proto: "tcp"}, Result: "reachable"},
	}, JSONOptions{})
	vs := doc["verdicts"].([]any)
	var got []any
	for _, v := range vs {
		got = append(got, v.(map[string]any)["result"])
	}
	if got[0] != "reachable" || got[1] != "unknown" || got[2] != "filtered" {
		t.Errorf("order = %v, want reachable, unknown, filtered", got)
	}
}

func TestJSONNamesTheBuildAndHost(t *testing.T) {
	doc := decodeJSON(t, nil, JSONOptions{Version: "0.4.0", Hostname: "gulfinson", Zone: "internet"})
	if doc["whyopen"] != "0.4.0" || doc["hostname"] != "gulfinson" || doc["zone"] != "internet" {
		t.Errorf("doc = %v, want the build, host and zone named", doc)
	}
}
