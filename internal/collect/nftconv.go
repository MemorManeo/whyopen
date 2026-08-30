//go:build linux

// Package collect snapshots a host into a facts.Facts document. It is the
// only package that talks to netlink, /proc and Docker.
package collect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"
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

// xt recent check_set bits, captured from a live kernel and recorded in
// docs/decisions/0003-xt-recent-layout.md: --set sets 0x02, --update sets
// 0x04, --rcheck sets 0x01. --remove's bit value was never captured (the
// pattern the other three follow would put it at 0x08, but that is an
// inference, not evidence), so whyopen does not guess a fourth pattern: a
// --remove rule is left undecoded rather than assumed.
const (
	xtRecentCheckBit  = 0x1
	xtRecentSetBit    = 0x2
	xtRecentUpdateBit = 0x4
)

// xt recent payload layout at revision 1, captured from a live kernel and
// recorded in docs/decisions/0003-xt-recent-layout.md. Any other revision,
// or a different length at revision 1, is not covered by that capture.
const (
	xtRecentRev1Len     = 232
	xtRecentSecondsOff  = 0
	xtRecentHitCountOff = 4
	xtRecentCheckSetOff = 8
	xtRecentInvertOff   = 9
	xtRecentNameOff     = 10
	xtRecentNameLen     = 200
)

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
	case *expr.Ct:
		return convertCt(v)
	case *expr.Lookup:
		return convertLookup(v)
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

// convertCt decodes a native `ct` expression. Only CtKeySTATE loaded into a
// destination register is modelled, following the posture of the recent and
// addrtype cases: enumerate exactly what is understood and refuse
// everything else, rather than guess. A native ct expression carries no
// payload bytes of its own the way an xt extension does, so there is
// nothing to fall back to for a key this build does not model, or for a
// source-register load (which writes ct metadata, e.g. "ct mark set",
// rather than reading it); both must leave the expression undecoded so the
// verdict becomes unknown instead of silently ignoring what the key
// actually constrains.
func convertCt(v *expr.Ct) facts.Expr {
	if v.Key != expr.CtKeySTATE || v.SourceRegister {
		return facts.Expr{Kind: facts.ExprUnknown, Note: fmt.Sprintf("%T", v)}
	}
	return facts.Expr{Kind: facts.ExprCt, Ct: &facts.CtExpr{
		Key:      "state",
		Register: v.Register,
	}}
}

// convertLookup decodes a native `lookup` expression unconditionally: it
// carries IsDestRegSet through faithfully, but does not itself refuse a
// map-style lookup on it. Whether a plain membership lookup can be resolved
// depends on the set it names, which is not visible here (the collector
// converts one rule at a time), so that judgement, an interval set, a map,
// a concatenated key type, or a set this document does not carry at all,
// belongs entirely to internal/model/match.go, which has the full
// facts.Ruleset to consult. IsDestRegSet is one of the two independent
// signals that evaluator checks for a map lookup, alongside the named
// set's own IsMap flag; see facts.LookupExpr's doc comment for why both
// exist.
func convertLookup(v *expr.Lookup) facts.Expr {
	return facts.Expr{Kind: facts.ExprLookup, Lookup: &facts.LookupExpr{
		SourceRegister: v.SourceRegister,
		Set:            v.SetName,
		SetID:          v.SetID,
		Invert:         v.Invert,
		IsDestRegSet:   v.IsDestRegSet,
	}}
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
		dst, dstOK := addrTypes(i.Dest)
		src, srcOK := addrTypes(i.Source)
		x.Decoded = flags&(xtAddrTypeLimitIfaceIn|xtAddrTypeLimitIfaceOut) == 0 && dstOK && srcOK
		x.AddrType = &facts.AddrTypeInfo{
			DestTypes:    dst,
			SourceTypes:  src,
			InvertDest:   flags&xtAddrTypeInvertDest != 0,
			InvertSource: flags&xtAddrTypeInvertSource != 0,
		}
	case *xt.AddrType:
		dst, dstOK := addrTypes(i.Dest)
		src, srcOK := addrTypes(i.Source)
		x.Decoded = dstOK && srcOK
		x.AddrType = &facts.AddrTypeInfo{
			DestTypes:    dst,
			SourceTypes:  src,
			InvertDest:   i.InvertDest,
			InvertSource: i.InvertSource,
		}
	case *xt.Unknown:
		// Everything the nftables library cannot name arrives here as the
		// payload the kernel sent. Keep it: it is the only form in which a
		// later build with a better decoder can make anything of this
		// snapshot, and discarding it is what made a facts document lossy
		// across decoder generations.
		x.Raw = hex.EncodeToString([]byte(*i))
		decodeXtRaw(x)
	}
	return x
}

// decodeXtRaw runs whyopen's own byte-level decoders over a preserved
// payload and reports whether one of them resolved it. These are the
// extensions the nftables library has no type for, so their layout was
// captured from a live kernel and recorded in docs/decisions rather than
// taken from the library.
//
// It is the single place both the collector and Redecode decode from
// bytes, so a document read back later resolves exactly as one collected
// now would.
func decodeXtRaw(x *facts.XtExpr) bool {
	if x.Decoded || x.Raw == "" {
		return false
	}
	raw, err := hex.DecodeString(x.Raw)
	if err != nil {
		return false
	}
	switch x.Name {
	case "recent":
		if info, ok := recentInfo(x.Rev, raw); ok {
			x.Recent, x.Decoded = info, true
			return true
		}
	}
	return false
}

// Redecode re-derives every xt expression a document preserved the payload
// of, and returns how many it changed. It is what makes
// collect-once-evaluate-later hold across decoder generations: one
// document read by two builds differs exactly as their decoders differ.
//
// Where there is a payload, this build decodes it, even over an answer the
// collecting build recorded. That is decision 0007's contract change and
// it rests on one fact: the payload is what the collecting build saw, so a
// reading build with a better decoder is better placed to read it, not
// worse. Where there is no payload the collector's answer stands
// untouched, because nothing can check it.
func Redecode(f *facts.Facts) int {
	n := 0
	for ti := range f.Ruleset.Tables {
		family := f.Ruleset.Tables[ti].Family
		for ci := range f.Ruleset.Tables[ti].Chains {
			for ri := range f.Ruleset.Tables[ti].Chains[ci].Rules {
				exprs := f.Ruleset.Tables[ti].Chains[ci].Rules[ri].Exprs
				for ei := range exprs {
					if exprs[ei].Kind != facts.ExprXt || exprs[ei].Xt == nil {
						continue
					}
					if redecodeXt(exprs[ei].Xt, family) {
						n++
					}
				}
			}
		}
	}
	return n
}

// redecodeXt rebuilds one xt expression from its preserved payload,
// through the same library unmarshaler and the same conversion the
// collector used, and reports whether anything about it changed.
func redecodeXt(x *facts.XtExpr, family string) bool {
	if x.Raw == "" {
		return false
	}
	raw, err := hex.DecodeString(x.Raw)
	if err != nil {
		return false
	}
	info, err := xt.Unmarshal(x.Name, xtFamily(family), x.Rev, raw)
	if err != nil {
		// Not a decode whyopen can improve on. The document keeps what it
		// had, which is the conservative answer and the same one it gave
		// before the payload was preserved at all.
		return false
	}
	fresh := convertXt(x.Kind, x.Name, x.Rev, info)
	fresh.Raw = x.Raw
	if reflect.DeepEqual(*fresh, *x) {
		return false
	}
	*x = *fresh
	return true
}

// xtFamily maps a facts table family to the one xt.Unmarshal takes, since
// several extensions lay their payload out differently per family.
func xtFamily(family string) xt.TableFamily {
	switch family {
	case "ip6":
		return xt.TableFamily(unix.NFPROTO_IPV6)
	case "inet":
		return xt.TableFamily(unix.NFPROTO_INET)
	case "netdev":
		return xt.TableFamily(unix.NFPROTO_NETDEV)
	}
	return xt.TableFamily(unix.NFPROTO_IPV4)
}

// recentInfo decodes an xt recent match payload at the layout captured in
// docs/decisions/0003-xt-recent-layout.md: seconds and hit_count as
// little-endian u32, a one-byte mode flag, a one-byte invert flag, then a
// NUL-terminated name. Only revision 1 at the captured length decodes, and
// only when check_set is one of the three exact bit patterns the capture
// confirmed; any other value, including a --remove rule, is left undecoded
// rather than guessed.
func recentInfo(rev uint32, data []byte) (*facts.RecentInfo, bool) {
	if rev != 1 || len(data) != xtRecentRev1Len {
		return nil, false
	}
	mode, ok := recentModeName(data[xtRecentCheckSetOff])
	if !ok {
		return nil, false
	}
	name := data[xtRecentNameOff : xtRecentNameOff+xtRecentNameLen]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	return &facts.RecentInfo{
		Mode:     mode,
		Seconds:  binary.LittleEndian.Uint32(data[xtRecentSecondsOff:]),
		HitCount: binary.LittleEndian.Uint32(data[xtRecentHitCountOff:]),
		Invert:   data[xtRecentInvertOff] != 0,
		Name:     string(name),
	}, true
}

// recentModeName maps a check_set byte to the xt recent mode it names. Only
// the three bit patterns the capture confirmed are recognised; anything
// else is not one of the five names whyopen models and must not be guessed.
func recentModeName(checkSet byte) (string, bool) {
	switch checkSet {
	case xtRecentSetBit:
		return "set", true
	case xtRecentUpdateBit:
		return "update", true
	case xtRecentCheckBit:
		return "rcheck", true
	}
	return "", false
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

// addrTypes names the type bits in an addrtype mask and reports whether it
// named all of them. xt_addrtype.h defines more types than whyopen models
// (BLACKHOLE, UNREACHABLE, PROHIBIT, THROW, NAT, XRESOLVE), and a mask
// carrying one of those used to be silently reduced to the bits whyopen
// did recognise and then evaluated at full confidence: the same mistake
// the invert flags made before decision 0001 caught them.
func addrTypes(mask uint16) (names []string, complete bool) {
	var named uint16
	for _, t := range addrTypeNames {
		if mask&t.bit != 0 {
			names = append(names, t.name)
			named |= t.bit
		}
	}
	return names, named == mask
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
