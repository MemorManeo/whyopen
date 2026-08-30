//go:build linux

package collect

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/MemorManeo/whyopen/internal/facts"
)

func mustMarshal(t *testing.T, attrs []netlink.Attribute) []byte {
	t.Helper()
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// xtExprAttr builds one NFTA_LIST_ELEM holding an xt match or target: the
// expression name ("match"/"target") and, nested inside it, the extension
// name, revision and payload.
func xtExprAttr(t *testing.T, kind, name string, rev uint32, info []byte) netlink.Attribute {
	t.Helper()
	nameAttr, revAttr, infoAttr := uint16(unix.NFTA_MATCH_NAME), uint16(unix.NFTA_MATCH_REV), uint16(unix.NFTA_MATCH_INFO)
	if kind == "target" {
		nameAttr, revAttr, infoAttr = unix.NFTA_TARGET_NAME, unix.NFTA_TARGET_REV, unix.NFTA_TARGET_INFO
	}
	revBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(revBytes, rev)
	inner := mustMarshal(t, []netlink.Attribute{
		{Type: nameAttr, Data: []byte(name + "\x00")},
		{Type: revAttr, Data: revBytes},
		{Type: infoAttr, Data: info},
	})
	elem := mustMarshal(t, []netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte(kind + "\x00")},
		{Type: unix.NFTA_EXPR_DATA | nlaNested, Data: inner},
	})
	return netlink.Attribute{Type: unix.NFTA_LIST_ELEM | nlaNested, Data: elem}
}

// nativeExprAttr is an expression that is not an xt one, which must not
// take a place in the xt sequence.
func nativeExprAttr(t *testing.T, name string) netlink.Attribute {
	t.Helper()
	elem := mustMarshal(t, []netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte(name + "\x00")},
		{Type: unix.NFTA_EXPR_DATA | nlaNested, Data: mustMarshal(t, []netlink.Attribute{{Type: 1, Data: []byte{0, 0, 0, 1}}})},
	})
	return netlink.Attribute{Type: unix.NFTA_LIST_ELEM | nlaNested, Data: elem}
}

func ruleMsg(t *testing.T, family uint8, table, chain string, handle uint64, exprs []netlink.Attribute) netlink.Message {
	t.Helper()
	handleBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(handleBytes, handle)
	body := mustMarshal(t, []netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
		{Type: unix.NFTA_RULE_HANDLE, Data: handleBytes},
		{Type: unix.NFTA_RULE_EXPRESSIONS | nlaNested, Data: mustMarshal(t, exprs)},
	})
	return netlink.Message{Data: append([]byte{family, unix.NFNETLINK_V0, 0, 0}, body...)}
}

func TestParseRulePayloadsReadsAMatchAndATarget(t *testing.T) {
	msgs := []netlink.Message{ruleMsg(t, unix.NFPROTO_IPV4, "filter", "INPUT", 42, []netlink.Attribute{
		xtExprAttr(t, "match", "conntrack", 3, []byte{0xde, 0xad}),
		xtExprAttr(t, "target", "DNAT", 0, []byte{0xbe, 0xef}),
	})}
	got := parseRulePayloads(msgs)
	ps := got[ruleKey{Family: unix.NFPROTO_IPV4, Table: "filter", Chain: "INPUT", Handle: 42}]
	if len(ps) != 2 {
		t.Fatalf("payloads = %+v, want two", ps)
	}
	if ps[0].Name != "conntrack" || ps[0].Rev != 3 || string(ps[0].Info) != "\xde\xad" {
		t.Errorf("payload 0 = %+v", ps[0])
	}
	if ps[1].Name != "DNAT" || ps[1].Rev != 0 || string(ps[1].Info) != "\xbe\xef" {
		t.Errorf("payload 1 = %+v", ps[1])
	}
}

// The order among xt expressions is the only thing correlation has to go
// on, so a native expression between two xt ones must not shift it.
func TestParseRulePayloadsKeepsTheXtOrderAcrossNativeExpressions(t *testing.T) {
	msgs := []netlink.Message{ruleMsg(t, unix.NFPROTO_IPV4, "filter", "INPUT", 7, []netlink.Attribute{
		nativeExprAttr(t, "meta"),
		xtExprAttr(t, "match", "first", 1, []byte{1}),
		nativeExprAttr(t, "cmp"),
		xtExprAttr(t, "match", "second", 1, []byte{2}),
		nativeExprAttr(t, "counter"),
	})}
	ps := parseRulePayloads(msgs)[ruleKey{Family: unix.NFPROTO_IPV4, Table: "filter", Chain: "INPUT", Handle: 7}]
	if len(ps) != 2 || ps[0].Name != "first" || ps[1].Name != "second" {
		t.Fatalf("payloads = %+v, want first then second", ps)
	}
}

// A rule of the same handle in another chain, table or family is a
// different rule. Handles are only unique within a chain.
func TestParseRulePayloadsKeepsRulesApart(t *testing.T) {
	msgs := []netlink.Message{
		ruleMsg(t, unix.NFPROTO_IPV4, "filter", "INPUT", 1, []netlink.Attribute{xtExprAttr(t, "match", "a", 0, []byte{1})}),
		ruleMsg(t, unix.NFPROTO_IPV4, "filter", "OUTPUT", 1, []netlink.Attribute{xtExprAttr(t, "match", "b", 0, []byte{2})}),
		ruleMsg(t, unix.NFPROTO_IPV6, "filter", "INPUT", 1, []netlink.Attribute{xtExprAttr(t, "match", "c", 0, []byte{3})}),
	}
	got := parseRulePayloads(msgs)
	if len(got) != 3 {
		t.Fatalf("got %d rules, want 3 distinct: %+v", len(got), got)
	}
}

func TestParseRulePayloadsRecordsNothingForARuleWithNoXtExpressions(t *testing.T) {
	msgs := []netlink.Message{ruleMsg(t, unix.NFPROTO_IPV4, "filter", "INPUT", 9, []netlink.Attribute{
		nativeExprAttr(t, "meta"), nativeExprAttr(t, "cmp"),
	})}
	if got := parseRulePayloads(msgs); len(got) != 0 {
		t.Fatalf("payloads = %+v, want none", got)
	}
}

func TestParseRulePayloadsSkipsAMessageItCannotRead(t *testing.T) {
	msgs := []netlink.Message{{Data: []byte{1}}, {Data: []byte{2, 0, 0, 0, 7, 7}}}
	if got := parseRulePayloads(msgs); len(got) != 0 {
		t.Fatalf("payloads = %+v, want none", got)
	}
}

func xtExpr(name string, rev uint32, raw string) facts.Expr {
	return facts.Expr{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: name, Rev: rev, Raw: raw}}
}

// Correlation is by position among xt expressions. A native expression in
// between must not shift it, which is the whole reason the payload reader
// skips them without counting them.
func TestAttachXtPayloadsMatchesByPositionAmongXtExpressions(t *testing.T) {
	exprs := []facts.Expr{
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "iifname"}},
		xtExpr("conntrack", 3, ""),
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq"}},
		xtExpr("DNAT", 0, ""),
	}
	attachXtPayloads(exprs, []xtPayload{
		{Name: "conntrack", Rev: 3, Info: []byte{0xde, 0xad}},
		{Name: "DNAT", Rev: 0, Info: []byte{0xbe, 0xef}},
	})
	if exprs[1].Xt.Raw != "dead" {
		t.Errorf("conntrack raw = %q, want dead", exprs[1].Xt.Raw)
	}
	if exprs[3].Xt.Raw != "beef" {
		t.Errorf("DNAT raw = %q, want beef", exprs[3].Xt.Raw)
	}
}

// The payload the library already handed over is the same bytes, so
// nothing is gained by replacing it and something is risked.
func TestAttachXtPayloadsDoesNotOverwriteWhatIsAlreadyThere(t *testing.T) {
	exprs := []facts.Expr{xtExpr("recent", 1, "cafe")}
	attachXtPayloads(exprs, []xtPayload{{Name: "recent", Rev: 1, Info: []byte{0xde, 0xad}}})
	if exprs[0].Xt.Raw != "cafe" {
		t.Errorf("raw = %q, want the collector's own bytes left alone", exprs[0].Xt.Raw)
	}
}

// If the sequences disagree, the assumption correlation rests on is wrong
// for this rule, and attaching the rest would be attaching bytes to the
// wrong expressions. Stop, rather than guess.
func TestAttachXtPayloadsStopsAtTheFirstDisagreement(t *testing.T) {
	exprs := []facts.Expr{xtExpr("conntrack", 3, ""), xtExpr("addrtype", 1, "")}
	attachXtPayloads(exprs, []xtPayload{
		{Name: "comment", Rev: 0, Info: []byte{1}}, // not what whyopen holds
		{Name: "addrtype", Rev: 1, Info: []byte{2}},
	})
	if exprs[0].Xt.Raw != "" || exprs[1].Xt.Raw != "" {
		t.Fatalf("payloads attached after a disagreement: %q, %q", exprs[0].Xt.Raw, exprs[1].Xt.Raw)
	}
}

// A revision mismatch is the same kind of disagreement: the payload layout
// depends on it, so bytes from another revision are not this expression's.
func TestAttachXtPayloadsStopsOnARevisionMismatch(t *testing.T) {
	exprs := []facts.Expr{xtExpr("conntrack", 3, "")}
	attachXtPayloads(exprs, []xtPayload{{Name: "conntrack", Rev: 2, Info: []byte{1}}})
	if exprs[0].Xt.Raw != "" {
		t.Errorf("raw = %q, want nothing attached across a revision mismatch", exprs[0].Xt.Raw)
	}
}

func TestAttachXtPayloadsHandlesFewerPayloadsThanExpressions(t *testing.T) {
	exprs := []facts.Expr{xtExpr("a", 0, ""), xtExpr("b", 0, "")}
	attachXtPayloads(exprs, []xtPayload{{Name: "a", Rev: 0, Info: []byte{1}}})
	if exprs[0].Xt.Raw != "01" || exprs[1].Xt.Raw != "" {
		t.Errorf("raw = %q, %q", exprs[0].Xt.Raw, exprs[1].Xt.Raw)
	}
}
