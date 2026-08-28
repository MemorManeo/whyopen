package report

import (
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

func TestRenderRule(t *testing.T) {
	r := facts.Rule{Handle: 21, Exprs: []facts.Expr{
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "iifname", Register: 1}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "neq", Register: 1, Data: "62722d6162630000000000000000000000"}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "1538"}},
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "DNAT", Decoded: true,
			DNAT: &facts.DNATInfo{MinIP: "172.20.0.2", MinPort: 5432}}},
	}}
	got := RenderRule(r)
	for _, want := range []string{`iifname != "br-abc"`, "dport 5432", "dnat to 172.20.0.2:5432"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RenderRule = %q, missing %q", got, want)
		}
	}
}

func TestTableGroupsWorstFirst(t *testing.T) {
	var sb strings.Builder
	Table(&sb, []model.Verdict{
		{Endpoint: model.Endpoint{Proto: "tcp", Port: 22, Owner: "ssh.service"}, Family: "ip", Result: "filtered"},
		{Endpoint: model.Endpoint{Proto: "tcp", Port: 5432, Owner: "db"}, Family: "ip", Result: "reachable"},
		{Endpoint: model.Endpoint{Proto: "tcp", Port: 9000, Owner: "x"}, Family: "ip", Result: "unknown"},
	}, nil)
	out := sb.String()
	iReach := strings.Index(out, "5432")
	iUnknown := strings.Index(out, "9000")
	iFiltered := strings.Index(out, "22")
	if !(iReach < iUnknown && iUnknown < iFiltered) {
		t.Fatalf("wrong ordering, want reachable then unknown then filtered:\n%s", out)
	}
}

func TestTableSurfacesWarnings(t *testing.T) {
	var sb strings.Builder
	Table(&sb, nil, []facts.Warning{{Source: "docker", Message: "daemon unreachable"}})
	if !strings.Contains(sb.String(), "daemon unreachable") {
		t.Fatalf("warnings must be visible in the report:\n%s", sb.String())
	}
}
