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

// RULING 21: the standard nft subnet-match shape is payload, bitwise, cmp.
// Ignoring the bitwise expression left the following cmp rendered as an
// exact address, which is confidently wrong for a rule scoped to a subnet
// (UFW private-subnet allows and Docker bridge-subnet matches both have this
// shape). A contiguous mask renders as CIDR; anything else renders as an
// explicit masked equality, never a false-precision exact match.
func TestRenderRuleWithBitwiseMask(t *testing.T) {
	prefixRule := facts.Rule{Handle: 30, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: "ffffff00", Xor: "00000000"}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "0a000000"}},
	}}
	if got := RenderRule(prefixRule); !strings.Contains(got, "daddr 10.0.0.0/24") {
		t.Fatalf("RenderRule = %q, want a CIDR rendering of the contiguous mask", got)
	}

	oddRule := facts.Rule{Handle: 31, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: "0f0f0f0f", Xor: "00000000"}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "01020304"}},
	}}
	got := RenderRule(oddRule)
	if !strings.Contains(got, "daddr & 0x0f0f0f0f == 0x01020304") {
		t.Fatalf("RenderRule = %q, want an explicit masked form for a non-contiguous mask", got)
	}
}

// C1: an expression whyopen could not decode must be visible in --explain.
// Omitting it made the rendered rule read as though it were fully
// understood, which is the opposite of what the reader needs from the very
// rule that produced an unknown verdict.
func TestRenderRuleShowsUnresolvedExpressions(t *testing.T) {
	r := facts.Rule{Handle: 40, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprUnknown, Note: "*expr.Lookup"},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "<unresolved: *expr.Lookup>") {
		t.Fatalf("RenderRule = %q, want the unresolved expression named", got)
	}
}
