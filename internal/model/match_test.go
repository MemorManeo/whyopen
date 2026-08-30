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
	out, act := MatchRule(testPacket(), rule, nil)
	if out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept", out, act)
	}

	rule.Exprs[3].Cmp.Data = "0050" // port 80
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
	if out, act := MatchRule(testPacket(), rule, nil); out != OutcomeMatch || act.Kind != "drop" {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a new SYN is not established or related", out)
	}

	rule.Exprs[0].Xt.Conntrack.States = []string{"new"}
	if out, act := MatchRule(testPacket(), rule, nil); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept for ct state new", out, act)
	}
}

func TestAddrTypeLocal(t *testing.T) {
	rule := facts.Rule{Handle: 4, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"local"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeMatch {
		t.Fatalf("want match when the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, rule, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeMatch {
		t.Fatalf("want match when the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, rule, nil); out != OutcomeMatch {
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
	if out, _ := MatchRule(testPacket(), excluding, nil); out != OutcomeNoMatch {
		t.Fatalf("want no match: source-type local excludes the packet's unicast source")
	}

	deciding := facts.Rule{Handle: 11, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{SourceTypes: []string{"unicast"}, DestTypes: []string{"local"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), deciding, nil); out != OutcomeMatch {
		t.Fatalf("want match: source-type unicast passes, dest-type local decides and the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, deciding, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
		t.Fatalf("want unknown: no dest or source constraint is modelled")
	}
}

// An icmp match can never match a TCP packet, so it is resolvable by name.
func TestICMPMatchNeverMatchesTCP(t *testing.T) {
	rule := facts.Rule{Handle: 5, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "icmp"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
		if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
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
	out, act := MatchRule(testPacket(), rule, nil)
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
		t.Fatalf("want no match: the destination is local and the match is inverted")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, act := MatchRule(p, rule, nil); out != OutcomeMatch || act.Kind != "drop" {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
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
	if out, _ := MatchRule(p, rule, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(p, rule, nil); out != OutcomeNoMatch {
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
	// OutcomeSkipped rather than OutcomeNoMatch: it steers traversal the
	// same way, and says the rule was stepped over rather than that the
	// packet failed to match it, so the path can still show it.
	if out, act := MatchRule(p, rule, nil); out != OutcomeSkipped || act.Kind != "none" {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: an undecoded expression may itself be terminal", out)
	}
}

// Nor an xt target: REJECT is terminal, and a target whyopen cannot resolve
// may be too.
func TestUnresolvableTargetInAVerdictlessRuleStillPoisons(t *testing.T) {
	rule := facts.Rule{Handle: 22, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "TCPMSS"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
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
	if out, act := MatchRule(testPacket(), rule, nil); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: 203.0.113.10 is in 203.0.113.0/24", out, act)
	}

	rule.Exprs[1].Bitwise.Mask = "ff000000"
	rule.Exprs[2].Cmp.Data = "0a000000"
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), set, nil); out != OutcomeMatch {
		t.Fatalf("--set = %v, want match", out)
	}

	update := facts.Rule{Handle: 2, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
			Recent: &facts.RecentInfo{Mode: "update", Seconds: 30, HitCount: 6, Name: "SSH"}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	if out, _ := MatchRule(testPacket(), update, nil); out != OutcomeNoMatch {
		t.Fatalf("--update = %v, want no match for a first packet from an unseen source", out)
	}
}

func TestRecentInvertFlips(t *testing.T) {
	r := facts.Rule{Handle: 3, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent", Decoded: true,
			Recent: &facts.RecentInfo{Mode: "update", Invert: true, Name: "SSH"}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), r, nil); out != OutcomeMatch {
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
	if out, _ := MatchRule(testPacket(), r, nil); out != OutcomeUnknown {
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
		if out, _ := MatchRule(testPacket(), r, nil); out != OutcomeUnknown {
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
		if out, _ := MatchRule(testPacket(), r, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeNoMatch {
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
	if out, act := MatchRule(testPacket(), rule, nil); out != OutcomeMatch || act.Kind != "accept" {
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
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: \"mark\" is not a modelled ct key", out)
	}
}

// dportLookupRule builds "tcp dport @<lk.Set|SetID> accept" the way
// docs/decisions/0004's census found it compiles: Payload loads the
// destination port into register 1, Lookup tests it, Verdict decides.
func dportLookupRule(lk facts.LookupExpr) facts.Rule {
	return facts.Rule{Handle: 100, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprLookup, Lookup: &lk},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
}

// portSet is a flat, named inet_service set, e.g. the named-set form of
// "tcp dport @zone_public_ports accept" (docs/decisions/0004).
func portSet(name string, id uint32, ports ...uint16) facts.Set {
	s := facts.Set{Name: name, ID: id}
	for _, p := range ports {
		s.Elements = append(s.Elements, facts.SetElement{
			Key: hex.EncodeToString([]byte{byte(p >> 8), byte(p)}),
		})
	}
	return s
}

// The named-set form: "tcp dport @zone_public_ports accept" with
// elements {22, 8080}. Port 22 is a member.
func TestLookupNamedSetMembership(t *testing.T) {
	sets := []facts.Set{portSet("zone_public_ports", 3, 22, 8080)}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports"})

	p := testPacket()
	p.DstPort = 22
	if out, act := MatchRule(p, rule, sets); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: 22 is in the set", out, act)
	}
}

// IsDestRegSet is the expression's own statement that this is a map lookup
// writing a value, not a plain membership test, and it must be refused
// independently of the named set's own IsMap flag: this set is flat,
// present, and would otherwise match (same set and port as
// TestLookupNamedSetMembership), so a wrongly-shared guard that only
// checked facts.Set.IsMap would let this resolve to a match. It must not.
func TestLookupRefusalIsDestRegSet(t *testing.T) {
	sets := []facts.Set{portSet("zone_public_ports", 3, 22, 8080)}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports", IsDestRegSet: true})

	p := testPacket()
	p.DstPort = 22
	if out, _ := MatchRule(p, rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: IsDestRegSet marks this a map lookup, not a membership test, even though the named set would otherwise match", out)
	}
}

// The same set and rule, a port that is not a member.
func TestLookupNamedSetNonMembership(t *testing.T) {
	sets := []facts.Set{portSet("zone_public_ports", 3, 22, 8080)}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports"})

	p := testPacket()
	p.DstPort = 5432
	if out, _ := MatchRule(p, rule, sets); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: 5432 is not in the set", out)
	}
}

// Invert ("tcp dport != @zone_public_ports") flips a member into a
// non-match and a non-member into a match.
func TestLookupInvertFlipsMembership(t *testing.T) {
	sets := []facts.Set{portSet("zone_public_ports", 3, 22, 8080)}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports", Invert: true})

	member := testPacket()
	member.DstPort = 22
	if out, _ := MatchRule(member, rule, sets); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: 22 is a member and the test is inverted", out)
	}

	nonMember := testPacket()
	nonMember.DstPort = 5432
	if out, act := MatchRule(nonMember, rule, sets); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: 5432 is not a member and the test is inverted", out, act)
	}
}

// The anonymous-set form ("tcp dport { 22, 8080 } accept") carries a SetID
// and no usable name (decision 0004's census), so it must resolve by ID.
func TestLookupAnonymousSetByID(t *testing.T) {
	sets := []facts.Set{{Anonymous: true, ID: 7, Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{0, 22})},
		{Key: hex.EncodeToString([]byte{0x1f, 0x90})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, SetID: 7})

	p := testPacket()
	p.DstPort = 8080
	if out, act := MatchRule(p, rule, sets); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: 8080 is in the anonymous set", out, act)
	}
}

// A Lookup naming a set that is not in the document (deleted mid-read, its
// elements failed to read, or simply absent) must not be guessed at.
func TestLookupRefusalSetNotInDocument(t *testing.T) {
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports"})
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: the named set is not in the document", out)
	}
}

// An interval set's elements are bounds, not members, and this is the test
// that keeps them from being read as members. It used to assert that such
// a set is refused outright, which was right while whyopen did not model
// ranges (v0.2) and stopped being right when decision 0011 captured what
// one contains.
//
// The set here holds a single element, a start at 22 with no end above it,
// which the capture says means "22 to the top of the range". Read as a
// flat membership list it would mean the set is exactly {22}. Port 23
// tells the two readings apart.
func TestIntervalSetElementsAreBoundsNotMembers(t *testing.T) {
	sets := []facts.Set{{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{0, 22})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "ports"})

	p := testPacket()
	p.DstPort = 23
	if out, _ := MatchRule(p, rule, sets); out != OutcomeMatch {
		t.Fatalf("out=%v, want match: 23 is inside [22, top], and only a flat reading would miss it", out)
	}
	p.DstPort = 21
	if out, _ := MatchRule(p, rule, sets); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: 21 is below the interval's start", out)
	}
}

// A map or verdict map carries a value alongside each key; whyopen only
// resolves a plain membership test.
func TestLookupRefusalMapSet(t *testing.T) {
	sets := []facts.Set{{Name: "ports", IsMap: true, Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{0, 22}), Val: hex.EncodeToString([]byte{1})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "ports"})
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: a map is not a plain membership test", out)
	}
}

// A concatenated key type (e.g. "ip saddr . tcp dport") is out of scope.
func TestLookupRefusalConcatenatedSet(t *testing.T) {
	sets := []facts.Set{{Name: "pairs", Concatenation: true, Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{203, 0, 113, 10, 0, 22, 0, 0})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "pairs"})
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: a concatenated key type is out of scope", out)
	}
}

// Elements of differing key lengths are not a flat set of comparable keys,
// whatever the set-level flags say.
func TestLookupRefusalUnequalKeyLengths(t *testing.T) {
	sets := []facts.Set{{Name: "mixed", Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{0, 22})},
		{Key: hex.EncodeToString([]byte{0, 0, 0, 80})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "mixed"})
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: elements are not all the same length", out)
	}
}

// A map element that slipped past a false IsMap flag must still be refused,
// the defence-in-depth check in lookupMatch.
func TestLookupRefusalElementCarriesValDespiteIsMapFalse(t *testing.T) {
	sets := []facts.Set{{Name: "ports", Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{0, 22}), Val: hex.EncodeToString([]byte{1})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "ports"})
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: an element carrying Val is a map element regardless of the set flag", out)
	}
}

// Likewise for an interval element that slipped past a false Interval flag.
func TestLookupRefusalElementCarriesKeyEndDespiteIntervalFalse(t *testing.T) {
	sets := []facts.Set{{Name: "ports", Elements: []facts.SetElement{
		{Key: hex.EncodeToString([]byte{0, 22}), KeyEnd: hex.EncodeToString([]byte{0, 80})},
	}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "ports"})
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: an element carrying KeyEnd is an interval element regardless of the set flag", out)
	}
}

// An element whose key is not valid hex cannot be decoded at all. A
// hand-built or corrupted facts document can carry one even though
// internal/collect never emits invalid hex itself.
func TestLookupRefusalUndecodableElementKey(t *testing.T) {
	sets := []facts.Set{{Name: "ports", Elements: []facts.SetElement{{Key: "not-hex"}}}}
	rule := dportLookupRule(facts.LookupExpr{SourceRegister: 1, Set: "ports"})
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: the element key does not decode as hex", out)
	}
}

// A Lookup whose source register was never loaded by an earlier expression
// (a hand-built facts document, or a shape whyopen's collector never
// produces) cannot be resolved.
func TestLookupRefusalRegisterNeverLoaded(t *testing.T) {
	sets := []facts.Set{portSet("zone_public_ports", 3, 22)}
	rule := facts.Rule{Handle: 101, Exprs: []facts.Expr{
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: register 1 was never loaded", out)
	}
}

// A register narrower than the set's key width cannot be compared to it,
// the same conservative call ExprCmp already makes for an undersized
// register rather than silently comparing a truncated prefix.
func TestLookupRefusalRegisterShorterThanKey(t *testing.T) {
	sets := []facts.Set{portSet("zone_public_ports", 3, 22)}
	rule := facts.Rule{Handle: 102, Exprs: []facts.Expr{
		// A one-byte meta field (l4proto) loaded where a two-byte port set
		// is then tested against it: shorter than the set's key width.
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "l4proto", Register: 1}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, Set: "zone_public_ports"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown: the register is narrower than the set's key width", out)
	}
}

// End to end: the brace-list form of "ct state { established, related }
// accept" (docs/decisions/0004) compiles to Ct then Lookup against an
// anonymous ct_state set, unlike the comma-list form's Ct/Bitwise/Cmp. A
// fresh SYN is state new, which is not in {established, related}, so it
// must not match, mirroring TestNativeCtStateCommaListDoesNotMatchNewSYN
// for the set-lookup idiom instead of the mask-and-compare one.
func TestNativeCtStateBraceListDoesNotMatchNewSYN(t *testing.T) {
	sets := []facts.Set{{Anonymous: true, ID: 9, Elements: []facts.SetElement{
		{Key: natHex(ctBitEstablished)},
		{Key: natHex(ctBitRelated)},
	}}}
	rule := facts.Rule{Handle: 29, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "state", Register: 1}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, SetID: 9}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, sets); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a new SYN is not established or related", out)
	}
}

// The positive case for the same brace-list idiom: "ct state { new }
// accept" matches the flag the synthetic packet actually carries.
func TestNativeCtStateBraceListNewMatches(t *testing.T) {
	sets := []facts.Set{{Anonymous: true, ID: 9, Elements: []facts.SetElement{
		{Key: natHex(ctBitNew)},
	}}}
	rule := facts.Rule{Handle: 30, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "state", Register: 1}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, SetID: 9}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, act := MatchRule(testPacket(), rule, sets); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept: a new SYN is state new", out, act)
	}
}

// A positive range is not a Range expression: the kernel compiles
// `tcp dport 1024-2048` to two ordered comparisons on the same register
// (docs/decisions/0011-ranges-and-interval-sets.md). whyopen decoded them
// as gte and lte from the start and then refused them in the evaluator,
// which is why the commonest range shape reported unknown.
func rangeRule(lo, hi string) facts.Rule {
	return facts.Rule{Handle: 31, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "gte", Register: 1, Data: lo}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "lte", Register: 1, Data: hi}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
}

func TestOrderedComparisonsResolveARange(t *testing.T) {
	const lo, hi = "0400", "0800" // 1024 and 2048
	cases := []struct {
		port uint16
		want Outcome
	}{
		{1023, OutcomeNoMatch},
		{1024, OutcomeMatch}, // inclusive at both ends
		{1500, OutcomeMatch},
		{2048, OutcomeMatch},
		{2049, OutcomeNoMatch},
	}
	for _, c := range cases {
		p := testPacket()
		p.DstPort = c.port
		out, act := MatchRule(p, rangeRule(lo, hi), nil)
		if out != c.want {
			t.Errorf("port %d: out = %v, want %v", c.port, out, c.want)
		}
		if c.want == OutcomeMatch && act.Kind != "accept" {
			t.Errorf("port %d: act = %+v, want accept", c.port, act)
		}
	}
}

// The register holds a big-endian value, so a byte-wise comparison is the
// numeric one only if it is done over the full width. A port above 255
// exercises that: 0x0100 is greater than 0x00ff, and a comparison that
// looked at one byte would get it backwards.
func TestOrderedComparisonIsWidthCorrect(t *testing.T) {
	p := testPacket()
	p.DstPort = 256 // 0x0100
	if out, _ := MatchRule(p, rangeRule("00ff", "0200"), nil); out != OutcomeMatch {
		t.Fatalf("out = %v, want match: 256 is between 255 and 512", out)
	}
	p.DstPort = 255 // 0x00ff
	if out, _ := MatchRule(p, rangeRule("0100", "0200"), nil); out != OutcomeNoMatch {
		t.Fatalf("out = %v, want no match: 255 is below 256", out)
	}
}

func TestStrictOrderedComparisons(t *testing.T) {
	rule := func(op, data string) facts.Rule {
		return facts.Rule{Handle: 32, Exprs: []facts.Expr{
			{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
			{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: op, Register: 1, Data: data}},
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
		}}
	}
	cases := []struct {
		op   string
		port uint16
		want Outcome
	}{
		{"gt", 1024, OutcomeNoMatch}, // not greater than itself
		{"gt", 1025, OutcomeMatch},
		{"lt", 1024, OutcomeNoMatch},
		{"lt", 1023, OutcomeMatch},
	}
	for _, c := range cases {
		p := testPacket()
		p.DstPort = c.port
		if out, _ := MatchRule(p, rule(c.op, "0400"), nil); out != c.want {
			t.Errorf("%s 1024 with port %d: out = %v, want %v", c.op, c.port, out, c.want)
		}
	}
}

func rangeExprRule(op, from, to string) facts.Rule {
	return facts.Rule{Handle: 33, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprRange, Range: &facts.RangeExpr{Op: op, Register: 1, From: from, To: to}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
}

// The bounds are inclusive, which is what `tcp dport != 3000-4000` means
// and what the capture in decision 0011 recorded.
func TestRangeExpressionNeq(t *testing.T) {
	cases := map[uint16]Outcome{
		2999: OutcomeMatch,   // outside, so a neq range matches
		3000: OutcomeNoMatch, // the lower bound is inside the range
		3500: OutcomeNoMatch,
		4000: OutcomeNoMatch, // and so is the upper
		4001: OutcomeMatch,
	}
	for port, want := range cases {
		p := testPacket()
		p.DstPort = port
		if out, _ := MatchRule(p, rangeExprRule("neq", "0bb8", "0fa0"), nil); out != want {
			t.Errorf("port %d: out = %v, want %v", port, out, want)
		}
	}
}

func TestRangeExpressionEq(t *testing.T) {
	cases := map[uint16]Outcome{
		21: OutcomeNoMatch,
		22: OutcomeMatch,
		60: OutcomeMatch,
		80: OutcomeMatch,
		81: OutcomeNoMatch,
	}
	for port, want := range cases {
		p := testPacket()
		p.DstPort = port
		if out, _ := MatchRule(p, rangeExprRule("eq", "0016", "0050"), nil); out != want {
			t.Errorf("port %d: out = %v, want %v", port, out, want)
		}
	}
}

// Anything about a range whyopen cannot read is refused, not approximated:
// a register narrower than the bounds, bounds of different widths, or an
// operator it has no name for.
func TestRangeExpressionRefusals(t *testing.T) {
	for _, r := range []*facts.RangeExpr{
		{Op: "eq", Register: 1, From: "0016", To: "50"},    // mismatched widths
		{Op: "gte", Register: 1, From: "0016", To: "0050"}, // not an operator a range carries
		{Op: "eq", Register: 1, From: "zz", To: "0050"},    // not hex
		{Op: "eq", Register: 9, From: "0016", To: "0050"},  // a register nothing wrote
	} {
		rule := facts.Rule{Handle: 34, Exprs: []facts.Expr{
			{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
			{Kind: facts.ExprRange, Range: r},
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
		}}
		p := testPacket()
		p.DstPort = 22
		if out, _ := MatchRule(p, rule, nil); out != OutcomeUnknown {
			t.Errorf("range %+v: out = %v, want unknown", r, out)
		}
	}
}

// intervalSet is what the kernel returns for `elements = { 100-200, 8080 }`,
// in the shape decision 0011 captured: a start element and an exclusive
// end element flagged IntervalEnd, a single value stored as an interval one
// wide, a zero sentinel closing the region below the first interval, and
// all of it in descending order, because the order is not something to
// rely on.
func intervalSet() facts.Set {
	return facts.Set{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: "1f91", IntervalEnd: true}, // 8081
		{Key: "1f90"},                    // 8080
		{Key: "00c9", IntervalEnd: true}, // 201
		{Key: "0064"},                    // 100
		{Key: "0000", IntervalEnd: true}, // the sentinel
	}}
}

func lookupRule(set string) facts.Rule {
	return facts.Rule{Handle: 51, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{SourceRegister: 1, Set: set}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
}

func TestIntervalSetMembership(t *testing.T) {
	cases := map[uint16]Outcome{
		99:   OutcomeNoMatch,
		100:  OutcomeMatch, // the start is inclusive
		150:  OutcomeMatch,
		200:  OutcomeMatch, // and the end element is exclusive, so 200 is in
		201:  OutcomeNoMatch,
		8079: OutcomeNoMatch,
		8080: OutcomeMatch, // a single value is an interval one wide
		8081: OutcomeNoMatch,
	}
	for port, want := range cases {
		p := testPacket()
		p.DstPort = port
		if out, _ := MatchRule(p, lookupRule("ports"), []facts.Set{intervalSet()}); out != want {
			t.Errorf("port %d: out = %v, want %v", port, out, want)
		}
	}
}

// An interval reaching the top of the key type's range has no end element
// at all: its exclusive end would be one past the maximum. It is the last
// start, left dangling, which decision 0011's v1.2 update captured. This
// used to be refused, on a guess about what such a set would look like
// that the capture then contradicted.
//
// These are the exact element lists the kernel returned for
// `{ 1024-65535 }`, for `{ 100-200, 1024-65535 }`, and for
// `{ 0-100, 1024-65535 }`. The third carries no zero sentinel at all,
// because key 0 is the start of its first interval, and it is the one that
// shows a dangling start means "to the top" on its own.
func TestIntervalSetReadsATopOfRangeInterval(t *testing.T) {
	toTheTop := facts.Set{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: "0000", IntervalEnd: true},
		{Key: "0400"},
	}}
	topAndMiddle := facts.Set{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: "0400"},
		{Key: "00c9", IntervalEnd: true},
		{Key: "0064"},
		{Key: "0000", IntervalEnd: true},
	}}
	bottomAndTop := facts.Set{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: "0400"},
		{Key: "0065", IntervalEnd: true},
		{Key: "0000"},
	}}

	for name, c := range map[string]struct {
		set  facts.Set
		want map[uint16]Outcome
	}{
		"1024-65535":       {toTheTop, map[uint16]Outcome{1023: OutcomeNoMatch, 1024: OutcomeMatch, 40000: OutcomeMatch, 65535: OutcomeMatch}},
		"100-200,1024-":    {topAndMiddle, map[uint16]Outcome{99: OutcomeNoMatch, 150: OutcomeMatch, 300: OutcomeNoMatch, 65535: OutcomeMatch}},
		"0-100,1024-65535": {bottomAndTop, map[uint16]Outcome{0: OutcomeMatch, 100: OutcomeMatch, 101: OutcomeNoMatch, 65535: OutcomeMatch}},
	} {
		for port, want := range c.want {
			p := testPacket()
			p.DstPort = port
			if out, _ := MatchRule(p, lookupRule("ports"), []facts.Set{c.set}); out != want {
				t.Errorf("%s port %d: out = %v, want %v", name, port, out, want)
			}
		}
	}
}

// Two starts with nothing between them is a shape none of the five
// captured sets produced, and the pairing cannot mean anything by it.
func TestIntervalSetRefusesTwoConsecutiveStarts(t *testing.T) {
	s := facts.Set{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: "0064"}, {Key: "0400"}, {Key: "1000", IntervalEnd: true},
	}}
	p := testPacket()
	p.DstPort = 2000
	if out, _ := MatchRule(p, lookupRule("ports"), []facts.Set{s}); out != OutcomeUnknown {
		t.Fatalf("out = %v, want unknown", out)
	}
}

// The other representation the kernel has for an interval, a key with an
// explicit end, was not observed and is not guessed at.
func TestIntervalSetRefusesAKeyEndRepresentation(t *testing.T) {
	s := facts.Set{Name: "ports", Interval: true, Elements: []facts.SetElement{
		{Key: "0064", KeyEnd: "00c8"},
	}}
	p := testPacket()
	p.DstPort = 150
	if out, _ := MatchRule(p, lookupRule("ports"), []facts.Set{s}); out != OutcomeUnknown {
		t.Fatalf("out = %v, want unknown", out)
	}
}

// A flat set is still a flat set: adding intervals must not change how the
// membership test whyopen already had behaves.
func TestFlatSetStillMatchesExactly(t *testing.T) {
	s := facts.Set{Name: "ports", Elements: []facts.SetElement{{Key: "0016"}, {Key: "0050"}}}
	for port, want := range map[uint16]Outcome{22: OutcomeMatch, 80: OutcomeMatch, 443: OutcomeNoMatch} {
		p := testPacket()
		p.DstPort = port
		if out, _ := MatchRule(p, lookupRule("ports"), []facts.Set{s}); out != want {
			t.Errorf("port %d: out = %v, want %v", port, out, want)
		}
	}
}

// IPS_DST_NAT, bit 5 of the kernel's ip_conntrack_status enum.
const ctStatusDstNat = 0x20

// `ct status dnat accept` is what a real firewalld emits in both
// filter_INPUT and filter_FORWARD, and it made every port on such a host
// unknown. whyopen can answer it exactly, because it is the one deciding
// whether this packet was DNAT'd: it applied the rewrite itself.
func ctStatusRule(bit uint32) facts.Rule {
	return facts.Rule{Handle: 61, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "status", Register: 1}},
		{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: natHex(bit), Xor: natHex(0)}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "neq", Register: 1, Data: natHex(0)}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
}

func TestCtStatusDnatMatchesOnlyARewrittenPacket(t *testing.T) {
	rewritten := testPacket()
	rewritten.DNATApplied = true
	if out, act := MatchRule(rewritten, ctStatusRule(ctStatusDstNat), nil); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want a match: this packet was DNAT'd", out, act)
	}

	if out, _ := MatchRule(testPacket(), ctStatusRule(ctStatusDstNat), nil); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: nothing rewrote this packet", out)
	}
}

// Every other status bit is determinate for whyopen's packet and clear:
// it is the first packet of a connection, so nothing has been confirmed,
// replied to or expected. A rule asking about one of those resolves to
// "not set" rather than poisoning the verdict.
func TestCtStatusOtherBitsAreClear(t *testing.T) {
	const ctStatusAssured = 0x4
	p := testPacket()
	p.DNATApplied = true
	if out, _ := MatchRule(p, ctStatusRule(ctStatusAssured), nil); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a first packet is not assured", out)
	}
}

// A ct key whyopen does not model still refuses, which is the posture the
// status key just joined rather than replaced.
func TestUnmodelledCtKeyStillRefuses(t *testing.T) {
	rule := facts.Rule{Handle: 62, Exprs: []facts.Expr{
		{Kind: facts.ExprCt, Ct: &facts.CtExpr{Key: "mark", Register: 1}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: natHex(1)}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule, nil); out != OutcomeUnknown {
		t.Fatalf("out=%v, want unknown for a ct key whyopen does not model", out)
	}
}
