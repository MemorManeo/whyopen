package model

import (
	"encoding/binary"
	"encoding/hex"
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

// The addrtype dest field is a bitmask: dst-type multicast can never match
// the synthetic packet, whose destination is always local or unicast. This
// is the case that would poison a real host if resolution were guarded to
// only DestTypes == ["local"], since Docker/ufw rulesets carry addrtype
// rules for multicast and broadcast on the input path.
func TestAddrTypeMulticastNoMatch(t *testing.T) {
	rule := facts.Rule{Handle: 8, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"multicast"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("want no match: the packet's destination is never multicast")
	}
}

// DestTypes is an OR-ed set: ["local","unicast"] matches whichever role the
// destination actually has.
func TestAddrTypeDestUnionMatchesEither(t *testing.T) {
	rule := facts.Rule{Handle: 9, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"local", "unicast"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeMatch {
		t.Fatalf("want match when the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, rule); out != OutcomeMatch {
		t.Fatalf("want match when the destination is unicast too")
	}
}

// SourceTypes constrains the source role independently of DestTypes. The
// synthetic packet's source is always unicast.
func TestAddrTypeSourceConstraint(t *testing.T) {
	excluding := facts.Rule{Handle: 10, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{SourceTypes: []string{"local"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), excluding); out != OutcomeNoMatch {
		t.Fatalf("want no match: source-type local excludes the packet's unicast source")
	}

	deciding := facts.Rule{Handle: 11, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{SourceTypes: []string{"unicast"}, DestTypes: []string{"local"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), deciding); out != OutcomeMatch {
		t.Fatalf("want match: source-type unicast passes, dest-type local decides and the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, deciding); out != OutcomeNoMatch {
		t.Fatalf("want no match: source-type unicast passes, but dest-type local decides and the destination is not local")
	}
}

// An addrtype name outside the six xt addrtype knows is unresolvable.
func TestAddrTypeUnrecognisedNameIsUnknown(t *testing.T) {
	rule := facts.Rule{Handle: 12, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"prohibit"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("want unknown: \"prohibit\" is not a modelled addrtype value")
	}
}

// A decoded addrtype match with no constraint at all is unresolvable, not an
// optimistic match.
func TestAddrTypeBothSetsEmptyIsUnknown(t *testing.T) {
	rule := facts.Rule{Handle: 13, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("want unknown: no dest or source constraint is modelled")
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
		// C1: an expression the collector had no decoder for. It is the
		// nft spelling of a port list ("tcp dport { 22, 80 }") among other
		// things, so treating it as transparent turned a set-scoped accept
		// into an unconditional one.
		{Kind: facts.ExprUnknown, Note: "*expr.Lookup"},
		{Kind: facts.ExprUnknown, Note: "*expr.Range"},
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
	if out != OutcomeMatch || act.Kind != "dnat" || act.DNAT.Port != 2222 {
		t.Fatalf("out=%v act=%+v, want a dnat action", out, act)
	}
}

// I2: an inverted dest-type match is the opposite of the plain one.
// UFW's ufw-not-local uses "! --dst-type LOCAL" to drop traffic aimed at
// addresses this host does not own.
func TestAddrTypeInvertedDest(t *testing.T) {
	rule := facts.Rule{Handle: 14, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"local"}, InvertDest: true}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("want no match: the destination is local and the match is inverted")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, act := MatchRule(p, rule); out != OutcomeMatch || act.Kind != "drop" {
		t.Fatalf("out=%v act=%+v, want match/drop: a non-local destination satisfies the inverted match", out, act)
	}
}

// The same for the source half.
func TestAddrTypeInvertedSource(t *testing.T) {
	rule := facts.Rule{Handle: 15, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{SourceTypes: []string{"unicast"}, InvertSource: true}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("want no match: the source is unicast and the match is inverted")
	}
}

// A conntrack match the collector could only partly decode must not be
// resolved on its state bits alone.
func TestConntrackNotFullyDecodedIsUnknown(t *testing.T) {
	rule := facts.Rule{Handle: 16, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "conntrack", Decoded: false,
			Conntrack: &facts.ConntrackInfo{MatchesState: true, States: []string{"new"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("want unknown: the match constrains something whyopen did not decode")
	}
}

// L1: "rt type 0 counter drop" is the second rule of ufw6-before-input on
// every UFW IPv6 installation. xt rt matches an IPv6 routing header, and the
// synthetic packet is a bare TCP or UDP segment with no extension headers,
// so it provably cannot match. Treating it as unresolvable made every IPv6
// verdict on a stock UFW host unknown.
func TestRTMatchCannotMatchAPlainSegment(t *testing.T) {
	rule := facts.Rule{Handle: 17, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "rt"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	p := testPacket()
	p.Family, p.Dst, p.Src = "ip6", netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8:ffff::7")
	if out, _ := MatchRule(p, rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: the packet carries no IPv6 routing header", out)
	}
}

// L1: UFW asserts an on-link hop limit (--hl-eq 255) for neighbour
// discovery. A packet from the internet zone has crossed at least one
// router, so it cannot have hop limit 255.
func TestHLMatchCannotMatchAnInternetSourcedPacket(t *testing.T) {
	rule := facts.Rule{Handle: 18, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "hl"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	p := testPacket()
	p.Family, p.Dst, p.Src = "ip6", netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8:ffff::7")
	if out, _ := MatchRule(p, rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: an internet-sourced packet cannot have hop limit 255", out)
	}
}

// L2: UFW's SSH rate limiter emits "tcp dport 22 ct state new xt match
// recent" with no verdict at all (the --set half of --update/--set),
// followed by a second rule carrying the jump. The first rule cannot change
// traversal whether it matches or not, so an unresolvable match inside it
// must not poison the verdict.
func TestUnresolvableMatchInAVerdictlessRuleIsSkipped(t *testing.T) {
	rule := facts.Rule{Handle: 19, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "0016"}},
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "conntrack", Decoded: true,
			Conntrack: &facts.ConntrackInfo{MatchesState: true, States: []string{"new"}}}},
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprOther, Note: "counter"},
	}}
	p := testPacket()
	p.DstPort = 22
	if out, act := MatchRule(p, rule); out != OutcomeNoMatch || act.Kind != "none" {
		t.Fatalf("out=%v act=%+v, want the rule skipped: it has no verdict to apply", out, act)
	}
}

// The same rule with a verdict is back to poisoning: now the outcome of the
// unresolvable match decides where the packet goes.
func TestUnresolvableMatchWithAVerdictStillPoisons(t *testing.T) {
	rule := facts.Rule{Handle: 20, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "jump", Chain: "ufw-user-limit"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: the match decides whether the jump is taken", out)
	}
}

// The shortcut must never cover a facts.ExprUnknown. An expression the
// collector had no decoder for can be terminal in its own right, so a rule
// carrying one is unresolvable whether it has a verdict or not.
func TestUnknownExprInAVerdictlessRuleStillPoisons(t *testing.T) {
	rule := facts.Rule{Handle: 21, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprUnknown, Note: "*expr.Reject"},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: an undecoded expression may itself be terminal", out)
	}
}

// Nor an xt target: REJECT is terminal, and a target whyopen cannot resolve
// may be too.
func TestUnresolvableTargetInAVerdictlessRuleStillPoisons(t *testing.T) {
	rule := facts.Rule{Handle: 22, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "TCPMSS"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: an unresolved target can be terminal", out)
	}
}

// Nor a rule whose other xt expression yields an action of its own, even
// though that one is resolvable.
func TestUnresolvableMatchAlongsideAnActionTargetStillPoisons(t *testing.T) {
	rule := facts.Rule{Handle: 23, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "REJECT"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: the REJECT target is terminal", out)
	}
}

// Ledger minor: no test exercised a successful bitwise resolution, so the
// payload/bitwise/cmp triple that every subnet match compiles to was
// unexercised. The packet's destination 203.0.113.10 is inside
// 203.0.113.0/24 and outside 10.0.0.0/8.
func TestMatchBitwiseSubnet(t *testing.T) {
	rule := facts.Rule{Handle: 24, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: "ffffff00", Xor: "00000000"}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "cb007100"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, act := MatchRule(testPacket(), rule); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: 203.0.113.10 is in 203.0.113.0/24", out, act)
	}

	rule.Exprs[1].Bitwise.Mask = "ff000000"
	rule.Exprs[2].Cmp.Data = "0a000000"
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: 203.0.113.10 is not in 10.0.0.0/8", out)
	}
}

// The two rules ufw limit ssh emits. A first packet from an unseen source
// matches the --set rule (which constrains nothing and carries no verdict)
// and does not match the --update rule, so the port resolves rather than
// poisoning the verdict.
func TestRecentSetMatchesAndUpdateDoesNot(t *testing.T) {
	set := facts.Rule{Handle: 1, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
			Recent: &facts.RecentInfo{Mode: "set", Name: "SSH"}}},
	}}
	if out, _ := MatchRule(testPacket(), set); out != OutcomeMatch {
		t.Fatalf("--set = %v, want match", out)
	}

	update := facts.Rule{Handle: 2, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
			Recent: &facts.RecentInfo{Mode: "update", Seconds: 30, HitCount: 6, Name: "SSH"}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	if out, _ := MatchRule(testPacket(), update); out != OutcomeNoMatch {
		t.Fatalf("--update = %v, want no match for a first packet from an unseen source", out)
	}
}

func TestRecentInvertFlips(t *testing.T) {
	r := facts.Rule{Handle: 3, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
			Recent: &facts.RecentInfo{Mode: "update", Invert: true, Name: "SSH"}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), r); out != OutcomeMatch {
		t.Fatalf("inverted --update = %v, want match", out)
	}
}

// An undecoded recent must still poison, so an unfamiliar revision cannot
// silently resolve.
func TestUndecodedRecentIsStillUnknown(t *testing.T) {
	r := facts.Rule{Handle: 4, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	if out, _ := MatchRule(testPacket(), r); out != OutcomeUnknown {
		t.Fatalf("undecoded recent = %v, want unknown", out)
	}
}

// A decoded recent whose mode this build does not model must poison rather
// than fall through to a silent no-match. The --facts path can hand a v0.1
// binary a document a later version wrote, so an unfamiliar mode name is a
// live possibility and not merely a typo guard.
func TestRecentUnrecognisedModeIsUnknown(t *testing.T) {
	for _, mode := range []string{"", "remoove", "reap", "SET"} {
		r := facts.Rule{Handle: 5, Exprs: []facts.Expr{
			{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
				Recent: &facts.RecentInfo{Mode: mode, Name: "SSH"}}},
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
		}}
		if out, _ := MatchRule(testPacket(), r); out != OutcomeUnknown {
			t.Fatalf("recent mode %q = %v, want unknown", mode, out)
		}
	}
}

// The three modes with no dedicated test above still resolve to a no-match
// for a first packet from an unseen source, so enumerating the modes did not
// turn a resolvable rule into an unknown one.
func TestRecentCheckingAndRemoveModesDoNotMatch(t *testing.T) {
	for _, mode := range []string{"check", "rcheck", "remove"} {
		r := facts.Rule{Handle: 6, Exprs: []facts.Expr{
			{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
				Recent: &facts.RecentInfo{Mode: mode, Name: "SSH"}}},
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
		}}
		if out, _ := MatchRule(testPacket(), r); out != OutcomeNoMatch {
			t.Fatalf("recent mode %q = %v, want no match", mode, out)
		}
	}
}

// ctBit mirrors the NF_CT_STATE_BIT values internal/collect/nftconv.go's
// ctStateNames already carries (provenance: docs/decisions/0001), which the
// kernel's native ct expression draws from the same enum, per this match.go
// package's ctStateNewBit comment.
const (
	ctBitInvalid     = 0x1
	ctBitEstablished = 0x2
	ctBitRelated     = 0x4
	ctBitNew         = 0x8
)

// natHex encodes v the way a real kernel lays out a ct-state register: 4
// bytes, native byte order. See ctBytes's doc comment in match.go for why
// that is the layout to match.
func natHex(v uint32) string {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return hex.EncodeToString(b)
}

// The comma-list form of "ct state established,related accept"
// (docs/decisions/0004) compiles to Ct, Bitwise, Cmp. A fresh SYN is state
// new, so it must not match, exactly like TestConntrackEstablishedDoesNotMatchNewSYN
// already protects for the xt shape.
func TestNativeCtStateCommaListDoesNotMatchNewSYN(t *testing.T) {
	rule := facts.Rule{Handle: 25, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "state", Register: 1}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: natHex(ctBitEstablished | ctBitRelated), Xor: natHex(0)}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: natHex(ctBitEstablished | ctBitRelated)}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a new SYN is not established or related", out)
	}
}

// "ct state invalid drop" (docs/decisions/0004) must likewise not match a
// fresh SYN.
func TestNativeCtStateInvalidDoesNotMatchNewSYN(t *testing.T) {
	rule := facts.Rule{Handle: 26, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "state", Register: 1}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: natHex(ctBitInvalid), Xor: natHex(0)}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: natHex(ctBitInvalid)}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a new SYN is not invalid", out)
	}
}

// The positive case: "ct state new accept" matches the flag the synthetic
// packet actually carries, proving the Ct/Bitwise/Cmp trio can resolve to a
// match, not just to no-match.
func TestNativeCtStateNewMatches(t *testing.T) {
	rule := facts.Rule{Handle: 27, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "state", Register: 1}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: natHex(ctBitNew), Xor: natHex(0)}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: natHex(ctBitNew)}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, act := MatchRule(testPacket(), rule); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: a new SYN is state new", out, act)
	}
}

// A ct key whyopen does not model must not be guessed at, even if it somehow
// reaches the evaluator: a hand-built or forward-compatible facts document
// can carry one even though internal/collect/nftconv.go's convertCt never
// produces one itself.
func TestNativeCtUnmodelledKeyIsUnknown(t *testing.T) {
	rule := facts.Rule{Handle: 28, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "mark", Register: 1}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: \"mark\" is not a modelled ct key", out)
	}
}
