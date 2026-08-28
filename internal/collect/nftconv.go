//go:build linux

// Package collect snapshots a host into a facts.Facts document. It is the
// only package that talks to netlink, /proc and Docker.
package collect

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// xt conntrack state bits, from xt_conntrack.h and confirmed against a live
// ruleset: "ct state related,established" is StateMask 0x6.
const (
	ctStateInvalid     = 0x1
	ctStateEstablished = 0x2
	ctStateRelated     = 0x4
	ctStateNew         = 0x8
)

// bitName pairs a mask bit with the name whyopen records for it. These are
// ordered slices rather than maps on purpose: a facts document is meant to
// be committed as a golden fixture and diffed between cron runs, and Go
// randomises map iteration, so ranging a map here made the output order
// differ from run to run over identical input.
type bitName struct {
	bit  uint16
	name string
}

var ctStateNames = []bitName{
	{ctStateInvalid, "invalid"},
	{ctStateEstablished, "established"},
	{ctStateRelated, "related"},
	{ctStateNew, "new"},
}

// xtConntrackStateFlag is XT_CONNTRACK_STATE in MatchFlags. Every other bit
// (--ctorigdstport, --ctproto, --ctexpire and the rest) constrains something
// whyopen does not model, with one exception below.
const xtConntrackStateFlag = 0x1

// xtConntrackStateAliasFlag is XT_CONNTRACK_STATE_ALIAS, which libxt_state
// sets alongside XT_CONNTRACK_STATE so iptables can print the match back as
// "-m state" rather than "-m conntrack". It is bookkeeping and constrains
// nothing: a "-m state --state RELATED,ESTABLISHED" rule arrives here as
// conntrack rev 3 with MatchFlags 0x2001, and treating the alias bit as an
// unmodelled constraint made every such rule unknown.
const xtConntrackStateAliasFlag = 0x2000

// xt addrtype flags, from the Flags field of the rev 1 struct in
// xt_addrtype.h. The two LIMIT_IFACE bits scope the match to the packet's
// in or out interface, which whyopen's address-role model does not
// represent.
const (
	xtAddrTypeInvertSource  = 0x1
	xtAddrTypeInvertDest    = 0x2
	xtAddrTypeLimitIfaceIn  = 0x4
	xtAddrTypeLimitIfaceOut = 0x8
)

// xt addrtype type bits, from xt_addrtype.h. Dest 0x4 is LOCAL.
var addrTypeNames = []bitName{
	{0x1, "unspec"},
	{0x2, "unicast"},
	{0x4, "local"},
	{0x8, "broadcast"},
	{0x10, "anycast"},
	{0x20, "multicast"},
}

// ConvertExprs maps netlink expressions onto whyopen's serializable union.
// An xt extension without a typed decoder is preserved by name with Decoded
// false; a netlink expression with no case at all becomes facts.ExprUnknown.
// Either way the evaluator can see that it must refuse to guess, which it
// could not do if the expression were simply dropped.
func ConvertExprs(exprs []expr.Any) []facts.Expr {
	out := make([]facts.Expr, 0, len(exprs))
	for _, e := range exprs {
		out = append(out, convertExpr(e))
	}
	return out
}

func convertExpr(e expr.Any) facts.Expr {
	switch v := e.(type) {
	case *expr.Payload:
		return facts.Expr{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{
			DestRegister: v.DestRegister,
			Base:         payloadBaseName(v.Base),
			Offset:       v.Offset,
			Len:          v.Len,
		}}
	case *expr.Cmp:
		return facts.Expr{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{
			Op:       cmpOpName(v.Op),
			Register: v.Register,
			Data:     hex.EncodeToString(v.Data),
		}}
	case *expr.Meta:
		return facts.Expr{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{
			Key: metaKeyName(v.Key), Register: v.Register,
		}}
	case *expr.Bitwise:
		return facts.Expr{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{
			SourceRegister: v.SourceRegister,
			DestRegister:   v.DestRegister,
			Len:            v.Len,
			Mask:           hex.EncodeToString(v.Mask),
			Xor:            hex.EncodeToString(v.Xor),
		}}
	case *expr.Verdict:
		return facts.Expr{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{
			Kind: verdictKindName(v.Kind), Chain: v.Chain,
		}}
	case *expr.Match:
		return facts.Expr{Kind: facts.ExprXt, Xt: convertXt("match", v.Name, v.Rev, v.Info)}
	case *expr.Target:
		return facts.Expr{Kind: facts.ExprXt, Xt: convertXt("target", v.Name, v.Rev, v.Info)}
	case *expr.Reject:
		// A native nft reject carries no expr.Verdict, so without this case
		// it would fall to the default arm and the rule would look like it
		// had no terminal statement at all. Its effect on reachability is a
		// drop; the Note keeps the distinction visible in the document.
		return facts.Expr{Kind: facts.ExprVerdict, Note: "reject",
			Verdict: &facts.VerdictExpr{Kind: "reject"}}
	case *expr.Log:
		// A log statement writes a line and falls through. It constrains
		// nothing and terminates nothing, so it is the one native expression
		// besides counters and limits that is genuinely transparent.
		return facts.Expr{Kind: facts.ExprOther, Note: "log"}
	case *expr.Counter:
		return facts.Expr{Kind: facts.ExprOther, Note: "counter"}
	case *expr.Limit:
		return facts.Expr{Kind: facts.ExprOther, Note: "limit"}
	default:
		// Everything without a decoder is marked unknown, never ExprOther:
		// ExprOther is transparent to the evaluator, and an expression
		// whyopen has not decoded may well constrain the match (an
		// anonymous set lookup, a range) or terminate the rule.
		return facts.Expr{Kind: facts.ExprUnknown, Note: fmt.Sprintf("%T", e)}
	}
}

func convertXt(kind, name string, rev uint32, info xt.InfoAny) *facts.XtExpr {
	x := &facts.XtExpr{Kind: kind, Name: name, Rev: rev}
	switch i := info.(type) {
	case *xt.NatRange2:
		x.Decoded = true
		x.DNAT = natRange(i.NatRange)
	case *xt.NatRange:
		x.Decoded = true
		x.DNAT = natRange(*i)
	case *xt.ConntrackMtinfo3:
		x.Conntrack, x.Decoded = conntrack(i.MatchFlags, i.InvertFlags, uint16(i.StateMask))
	case *xt.ConntrackMtinfo2:
		x.Conntrack, x.Decoded = conntrack(i.MatchFlags, i.InvertFlags, uint16(i.StateMask))
	case *xt.ConntrackMtinfo1:
		x.Conntrack, x.Decoded = conntrack(i.MatchFlags, i.InvertFlags, uint16(i.StateMask))
	case *xt.AddrTypeV1:
		flags := uint32(i.Flags)
		// Rev 1 carries the inverts in Flags rather than in their own
		// fields, and it is the revision iptables-nft actually emits (see
		// docs/decisions/0001-nftables-ruleset-source.md), so ignoring
		// them evaluated an inverted rule with inverted semantics at full
		// confidence.
		x.Decoded = flags&(xtAddrTypeLimitIfaceIn|xtAddrTypeLimitIfaceOut) == 0
		x.AddrType = &facts.AddrTypeInfo{
			DestTypes:    addrTypes(i.Dest),
			SourceTypes:  addrTypes(i.Source),
			InvertDest:   flags&xtAddrTypeInvertDest != 0,
			InvertSource: flags&xtAddrTypeInvertSource != 0,
		}
	case *xt.AddrType:
		x.Decoded = true
		x.AddrType = &facts.AddrTypeInfo{
			DestTypes:    addrTypes(i.Dest),
			SourceTypes:  addrTypes(i.Source),
			InvertDest:   i.InvertDest,
			InvertSource: i.InvertSource,
		}
	}
	return x
}

func natRange(r xt.NatRange) *facts.DNATInfo {
	return &facts.DNATInfo{
		MinIP:   ipString(r.MinIP),
		MaxIP:   ipString(r.MaxIP),
		MinPort: r.MinPort,
		MaxPort: r.MaxPort,
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// conntrack decodes an xt conntrack payload and reports whether it decoded
// all of it. whyopen models the state bits and nothing else, so a match that
// also constrains --ctorigdstport, --ctproto or --ctexpire is only partly
// read; reporting it as decoded would let the evaluator resolve the rule on
// state alone and silently discard the rest of the condition.
func conntrack(matchFlags, invertFlags, stateMask uint16) (*facts.ConntrackInfo, bool) {
	ct := &facts.ConntrackInfo{
		MatchesState: matchFlags&xtConntrackStateFlag != 0,
		Invert:       invertFlags&xtConntrackStateFlag != 0,
	}
	decoded := matchFlags&^uint16(xtConntrackStateFlag|xtConntrackStateAliasFlag) == 0
	if !ct.MatchesState {
		return ct, decoded
	}
	for _, s := range ctStateNames {
		if stateMask&s.bit != 0 {
			ct.States = append(ct.States, s.name)
		}
	}
	return ct, decoded
}

func addrTypes(mask uint16) []string {
	var out []string
	for _, t := range addrTypeNames {
		if mask&t.bit != 0 {
			out = append(out, t.name)
		}
	}
	return out
}

func payloadBaseName(b expr.PayloadBase) string {
	switch b {
	case expr.PayloadBaseLLHeader:
		return "link"
	case expr.PayloadBaseNetworkHeader:
		return "network"
	case expr.PayloadBaseTransportHeader:
		return "transport"
	}
	return "unknown"
}

func cmpOpName(op expr.CmpOp) string {
	switch op {
	case expr.CmpOpEq:
		return "eq"
	case expr.CmpOpNeq:
		return "neq"
	case expr.CmpOpLt:
		return "lt"
	case expr.CmpOpLte:
		return "lte"
	case expr.CmpOpGt:
		return "gt"
	case expr.CmpOpGte:
		return "gte"
	}
	return "unknown"
}

func metaKeyName(k expr.MetaKey) string {
	switch k {
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyL4PROTO:
		return "l4proto"
	case expr.MetaKeyNFPROTO:
		return "nfproto"
	}
	return "unknown"
}

func verdictKindName(k expr.VerdictKind) string {
	switch k {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictJump:
		return "jump"
	case expr.VerdictGoto:
		return "goto"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictQueue:
		return "queue"
	}
	return "unknown"
}
