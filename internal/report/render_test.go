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

// A decoded recent match renders with the iptables option spelling, so
// --explain shows exactly what decided port 22 on a stock UFW host.
func TestRenderRuleShowsDecodedRecentMatch(t *testing.T) {
	r := facts.Rule{Handle: 41, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
			Recent: &facts.RecentInfo{Mode: "update", Seconds: 30, HitCount: 6, Name: "SSH"}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "recent --update --seconds 30 --hitcount 6 --name SSH") {
		t.Fatalf("RenderRule = %q, want the recent match rendered", got)
	}
}

// A native ct state match renders through the same payload/bitwise/cmp
// path as a subnet match, with the field named "ct state" instead of
// "daddr". The mask (0x6, established|related) is not a contiguous prefix
// from the top bit, so it renders as an explicit masked equality rather
// than a false-precision CIDR-style form.
func TestRenderRuleShowsNativeCtState(t *testing.T) {
	r := facts.Rule{Handle: 43, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "state", Register: 1}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: "06000000", Xor: "00000000"}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "06000000"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "ct state & 0x06000000 == 0x06000000") {
		t.Fatalf("RenderRule = %q, want the ct state match rendered", got)
	}
}

// An undecoded recent match must still say so, not disappear or render as
// though it were fully understood.
func TestRenderRuleShowsUndecodedRecentMatch(t *testing.T) {
	r := facts.Rule{Handle: 42, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "match recent (undecoded)") {
		t.Fatalf("RenderRule = %q, want the undecoded recent match named", got)
	}
}

// The named-set form: "tcp dport @zone_public_ports accept".
func TestRenderRuleShowsNamedSetLookup(t *testing.T) {
	r := facts.Rule{Handle: 44, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "dport in @zone_public_ports") {
		t.Fatalf("RenderRule = %q, want the named set lookup rendered", got)
	}
}

// The anonymous-set form ("tcp dport { 22, 8080 } accept") carries no
// usable name (decision 0004's census), so it renders by ID.
func TestRenderRuleShowsAnonymousSetLookup(t *testing.T) {
	r := facts.Rule{Handle: 45, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, SetID: 7}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "dport in anonymous set 7") {
		t.Fatalf("RenderRule = %q, want the anonymous set lookup rendered by ID", got)
	}
}

// Invert ("tcp dport != @zone_public_ports") must be visible in --explain.
func TestRenderRuleShowsInvertedSetLookup(t *testing.T) {
	r := facts.Rule{Handle: 46, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports", Invert: true}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "dport not in @zone_public_ports") {
		t.Fatalf("RenderRule = %q, want the inverted set lookup rendered", got)
	}
}

// An IPv6 rule rendered as raw hex is unreadable exactly where --explain
// is meant to help: the rule that decided an IPv6 verdict.
func TestRenderRuleShowsIPv6AddressesAsAddresses(t *testing.T) {
	r := facts.Rule{Handle: 7, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 24, Len: 16}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "20010db8000004920000000000000010"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	got := RenderRule(r)
	if !strings.Contains(got, "2001:db8:0:492::10") {
		t.Fatalf("RenderRule = %q, want the IPv6 address rendered as an address", got)
	}
}
