package model

import (
	"net/netip"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

func testPacket() *Packet {
	return &Packet{
		Family: "ip", Proto: "tcp",
		Src:     netip.MustParseAddr("198.51.100.7"),
		Dst:     netip.MustParseAddr("203.0.113.10"),
		SrcPort: 41234, DstPort: 5432,
		InIface: "eth0", CtState: "new", DstIsLocal: true,
	}
}

// "ip daddr 203.0.113.10 tcp dport 5432" must match; the same rule with a
// different port must not.
func TestMatchPayloadAndPort(t *testing.T) {
	rule := facts.Rule{Handle: 1, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "cb00710a"}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "1538"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	out, act := MatchRule(testPacket(), rule)
	if out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept", out, act)
	}

	rule.Exprs[3].Cmp.Data = "0050" // port 80
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match on a different port", out)
	}
}

// meta iifname is compared against a NUL-terminated name.
func TestMatchIifnameNeq(t *testing.T) {
	rule := facts.Rule{Handle: 2, Exprs: []facts.Expr{
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "iifname", Register: 1}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "neq", Register: 1, Data: "62722d7800"}}, // "br-x\0"
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	// Packet arrives on eth0, which is not br-x, so the neq matches.
	if out, act := MatchRule(testPacket(), rule); out != OutcomeMatch || act.Kind != "drop" {
		t.Fatalf("out=%v act=%+v, want match/drop", out, act)
	}
}

// The single most important negative case in the whole tool: Docker and UFW
// both emit "ct state related,established accept", and a fresh inbound SYN
// is state new, so those rules must not match.
func TestConntrackEstablishedDoesNotMatchNewSYN(t *testing.T) {
	rule := facts.Rule{Handle: 3, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "conntrack", Decoded: true,
			Conntrack: &facts.ConntrackInfo{MatchesState: true, States: []string{"established", "related"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a new SYN is not established or related", out)
	}

	rule.Exprs[0].Xt.Conntrack.States = []string{"new"}
	if out, act := MatchRule(testPacket(), rule); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept for ct state new", out, act)
	}
}

func TestAddrTypeLocal(t *testing.T) {
	rule := facts.Rule{Handle: 4, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"local"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeMatch {
		t.Fatalf("want match when the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, rule); out != OutcomeNoMatch {
		t.Fatalf("want no match when the destination is not local")
	}
}

// An icmp match can never match a TCP packet, so it is resolvable by name.
func TestICMPMatchNeverMatchesTCP(t *testing.T) {
	rule := facts.Rule{Handle: 5, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "icmp"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("want no match: an icmp match cannot match tcp")
	}
}

// Anything not resolvable must be unknown, never an optimistic guess.
func TestUnresolvableExpressionIsUnknown(t *testing.T) {
	for _, e := range []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 4, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "gt", Register: 1, Data: "00"}},
	} {
		rule := facts.Rule{Handle: 6, Exprs: []facts.Expr{e,
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}}}}
		if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
			t.Fatalf("expr %+v gave %v, want unknown", e, out)
		}
	}
}

// A decoded DNAT target yields the rewrite the traversal will apply.
func TestDNATTargetAction(t *testing.T) {
	rule := facts.Rule{Handle: 7, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "DNAT", Decoded: true,
			DNAT: &facts.DNATInfo{MinIP: "172.20.0.2", MaxIP: "172.20.0.2", MinPort: 2222, MaxPort: 2222}}},
	}}
	out, act := MatchRule(testPacket(), rule)
	if out != OutcomeMatch || act.Kind != "dnat" || act.DNAT.MinPort != 2222 {
		t.Fatalf("out=%v act=%+v, want a dnat action", out, act)
	}
}
