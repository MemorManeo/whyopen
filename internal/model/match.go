package model

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// ifnameLen is IFNAMSIZ: nft loads interface names into a fixed-size buffer.
const ifnameLen = 16

// MatchRule evaluates one rule against the packet. It returns OutcomeUnknown
// the moment it meets anything it cannot resolve, so a verdict is never built
// on a guess. sets is the rule's own table's sets (docs/decisions/0005),
// needed to resolve a facts.ExprLookup; a rule with none can pass nil.
func MatchRule(pkt *Packet, r facts.Rule, sets []facts.Set) (Outcome, Action) {
	regs := map[uint32][]byte{}
	act := Action{Kind: "none"}

	for i, e := range r.Exprs {
		switch e.Kind {
		case facts.ExprPayload:
			b, ok := payloadBytes(pkt, e.Payload)
			if !ok {
				return OutcomeUnknown, act
			}
			regs[e.Payload.DestRegister] = b

		case facts.ExprMeta:
			b, ok := metaBytes(pkt, e.Meta.Key)
			if !ok {
				return OutcomeUnknown, act
			}
			regs[e.Meta.Register] = b

		case facts.ExprBitwise:
			src, ok := regs[e.Bitwise.SourceRegister]
			mask, err1 := hex.DecodeString(e.Bitwise.Mask)
			xor, err2 := hex.DecodeString(e.Bitwise.Xor)
			if !ok || err1 != nil || err2 != nil || len(mask) != len(xor) || len(src) < len(mask) {
				return OutcomeUnknown, act
			}
			out := make([]byte, len(mask))
			for i := range mask {
				out[i] = (src[i] & mask[i]) ^ xor[i]
			}
			regs[e.Bitwise.DestRegister] = out

		case facts.ExprCt:
			b, ok := ctBytes(pkt, e.Ct.Key)
			if !ok {
				return OutcomeUnknown, act
			}
			regs[e.Ct.Register] = b

		case facts.ExprLookup:
			if e.Lookup.IsDestRegSet {
				// The expression's own statement that this is a map lookup
				// writing a value, not a plain membership test. Checked
				// before the set is even looked up, independently of
				// facts.Set.IsMap: either signal alone must be enough to
				// refuse, since a wrong or missing correlation, or a set
				// whose flags were not read correctly, must not silently
				// fall through to the other guard.
				return OutcomeUnknown, act
			}
			reg, ok := regs[e.Lookup.SourceRegister]
			if !ok {
				return OutcomeUnknown, act
			}
			hit, ok := lookupMatch(reg, e.Lookup, sets)
			if !ok {
				return OutcomeUnknown, act
			}
			if !hit {
				return OutcomeNoMatch, act
			}

		case facts.ExprCmp:
			data, err := hex.DecodeString(e.Cmp.Data)
			if err != nil {
				return OutcomeUnknown, act
			}
			reg, ok := regs[e.Cmp.Register]
			if !ok || len(reg) < len(data) {
				return OutcomeUnknown, act
			}
			equal := bytes.Equal(reg[:len(data)], data)
			switch e.Cmp.Op {
			case "eq":
				if !equal {
					return OutcomeNoMatch, act
				}
			case "neq":
				if equal {
					return OutcomeNoMatch, act
				}
			default:
				// Ordered comparisons are used for ranges, which whyopen
				// does not model yet.
				return OutcomeUnknown, act
			}

		case facts.ExprXt:
			out, a, ok := xtExpr(pkt, e.Xt)
			if !ok {
				if skippableUnresolvedMatch(pkt, r, i) {
					return OutcomeSkipped, act
				}
				return OutcomeUnknown, act
			}
			if out == OutcomeNoMatch {
				return OutcomeNoMatch, act
			}
			if a.Kind != "none" {
				act = a
			}

		case facts.ExprVerdict:
			act = Action{Kind: e.Verdict.Kind, Chain: e.Verdict.Chain}

		case facts.ExprOther:
			// counters and limits do not decide a match. A limit can in
			// principle drop traffic, but only above a rate, so treating it
			// as transparent is the conservative direction for an exposure
			// audit: it reports reachable rather than hiding a hole.

		case facts.ExprUnknown:
			// An expression the collector had no decoder for. It may be an
			// anonymous set lookup, a range, or a terminal statement, so it
			// is the one thing that must never be treated as transparent.
			return OutcomeUnknown, act

		default:
			return OutcomeUnknown, act
		}
	}
	return OutcomeMatch, act
}

// skippableUnresolvedMatch reports whether the unresolved xt expression at
// index idx can be skipped instead of poisoning the whole verdict. That is
// true only when the rule carries no verdict at all, because then neither
// outcome of the match changes where the packet goes next. UFW's SSH rate
// limiter is exactly this shape: "tcp dport 22 ct state new xt match recent"
// with no verdict (the --set half), followed by a separate rule carrying the
// jump (the --update half).
//
// The scoping is deliberately narrow, because an unresolved element can be
// terminal in its own right. It never applies when the unresolved element is
// an xt target, nor when any other expression in the rule is a verdict, a
// facts.ExprUnknown, an xt expression that is itself unresolvable, or an xt
// expression that yields an action of its own.
func skippableUnresolvedMatch(pkt *Packet, r facts.Rule, idx int) bool {
	if x := r.Exprs[idx].Xt; x == nil || x.Kind != "match" {
		return false
	}
	for i, e := range r.Exprs {
		if i == idx {
			continue
		}
		switch e.Kind {
		case facts.ExprPayload, facts.ExprCmp, facts.ExprMeta, facts.ExprBitwise, facts.ExprOther:
			// Recognised, and with no verdict in the rule it cannot matter
			// whether they match.
		case facts.ExprXt:
			_, a, ok := xtExpr(pkt, e.Xt)
			if !ok || a.Kind != "none" {
				return false
			}
		default:
			// A verdict, a facts.ExprUnknown, or a kind from a newer schema.
			return false
		}
	}
	return true
}

// payloadBytes synthesises the requested header slice. Any offset whyopen
// does not model returns false, which becomes an unknown verdict.
func payloadBytes(pkt *Packet, p *facts.PayloadExpr) ([]byte, bool) {
	switch p.Base {
	case "network":
		if pkt.Family == "ip" {
			switch {
			case p.Offset == 9 && p.Len == 1:
				return []byte{protoNumber(pkt.Proto)}, true
			case p.Offset == 12 && p.Len == 4:
				return addrBytes(pkt.Src, 4)
			case p.Offset == 16 && p.Len == 4:
				return addrBytes(pkt.Dst, 4)
			}
			return nil, false
		}
		switch {
		case p.Offset == 6 && p.Len == 1:
			return []byte{protoNumber(pkt.Proto)}, true
		case p.Offset == 8 && p.Len == 16:
			return addrBytes(pkt.Src, 16)
		case p.Offset == 24 && p.Len == 16:
			return addrBytes(pkt.Dst, 16)
		}
		return nil, false

	case "transport":
		switch {
		case p.Offset == 0 && p.Len == 2:
			return []byte{byte(pkt.SrcPort >> 8), byte(pkt.SrcPort)}, true
		case p.Offset == 2 && p.Len == 2:
			return []byte{byte(pkt.DstPort >> 8), byte(pkt.DstPort)}, true
		}
		return nil, false
	}
	return nil, false
}

func addrBytes(a netip.Addr, want int) ([]byte, bool) {
	b := a.AsSlice()
	if len(b) != want {
		return nil, false
	}
	return b, true
}

func metaBytes(pkt *Packet, key string) ([]byte, bool) {
	switch key {
	case "iifname":
		return ifname(pkt.InIface), true
	case "oifname":
		return ifname(pkt.OutIface), true
	case "l4proto":
		return []byte{protoNumber(pkt.Proto)}, true
	case "nfproto":
		if pkt.Family == "ip" {
			return []byte{2}, true // NFPROTO_IPV4
		}
		return []byte{10}, true // NFPROTO_IPV6
	}
	return nil, false
}

func ifname(s string) []byte {
	b := make([]byte, ifnameLen)
	copy(b, s)
	return b
}

func protoNumber(proto string) byte {
	if proto == "udp" {
		return 17
	}
	return 6
}

// ctStateNewBit is NF_CT_STATE_BIT(IP_CT_NEW): 1 << (IP_CT_NEW %
// IP_CT_IS_REPLY + 1) = 1 << (2 % 3 + 1) = 0x8, per this machine's
// linux/netfilter/nf_conntrack_common.h. It is the same enum
// internal/collect/nftconv.go's ctStateNew already uses for the xt
// conntrack extension (provenance in docs/decisions/0001), and
// google/nftables's own expr.CtStateBitNEW constant (expr/ct.go) agrees.
// model cannot import collect (it is stdlib-and-facts only, see the package
// doc), so the value is repeated here rather than shared.
const ctStateNewBit uint32 = 0x8

// ctBytes synthesises the register content a native `ct` expression loads.
// whyopen's synthetic packet is always the first connection from a source
// the ruleset has never seen, so its conntrack state is always exactly the
// NEW bit, never a union of bits. Only the state key is modelled, matching
// the collector: any other key never reaches here, because
// internal/collect/nftconv.go's convertCt leaves it facts.ExprUnknown, but
// a hand-built or forward-compatible facts document could still name one,
// so it is refused here too rather than guessed at.
//
// The register is 4 bytes wide in the host's native byte order:
// github.com/google/nftables's own Ct+Bitwise fixtures (nftables_test.go,
// integration/nft_test.go) build the mask/xor operands with
// binaryutil.NativeEndian.PutUint32 at Len 4. A native register is raw
// kernel memory with no netlink byte-swap applied on the way out, so
// encoding the value the same way here is what makes the existing
// Bitwise/Cmp machinery, written to resolve whatever mask and comparison
// value a real kernel produced, resolve correctly against it.
func ctBytes(pkt *Packet, key string) ([]byte, bool) {
	if key != "state" || pkt.CtState != "new" {
		return nil, false
	}
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, ctStateNewBit)
	return b, true
}

// lookupMatch resolves a Lookup as a flat membership test: does reg, the
// current value of the register the Lookup reads, equal one of the named
// set's element keys, byte for byte, honouring inversion. The second return
// reports whether it could be resolved at all. The caller (MatchRule)
// refuses e.Lookup.IsDestRegSet before ever calling this function, since a
// map-style lookup is not a membership test at all; that guard is
// independent of everything checked here, so a set that happens to look
// flat and complete cannot mask a lookup that is, by its own expression
// fields, not a plain membership test.
//
// This is deliberately narrow, matching the posture of xtExpr's recent and
// addrtype cases: enumerate exactly what is understood and refuse
// everything else, rather than guess. Refused outright: a set this document
// does not carry at all (deleted mid-read, or its elements failed to read,
// see internal/collect/ruleset.go); an interval (range) set; a map or
// verdict map, whose elements carry a value the caller would need to act on
// rather than a plain membership answer; a concatenated key type; a set
// whose elements are not all the same length (not a flat set of comparable
// keys); an element whose key does not decode as hex; a register shorter
// than the set's key width, the same conservative call ExprCmp already
// makes for an undersized register; and, deliberately, a set with no
// elements at all, even though a truly empty set would answer every
// membership test the same way (never a member): nothing in decision
// 0004's census exercised one, and trusting an empty read as genuinely
// empty rather than as a symptom of some partial enumeration failure is not
// a call this evaluator has evidence to make. A wrongly resolved set
// lookup is a false verdict about a firewall, the worst thing this tool
// can produce, so every one of these yields "cannot resolve" rather than a
// guessed no-match.
func lookupMatch(reg []byte, lk *facts.LookupExpr, sets []facts.Set) (hit bool, ok bool) {
	s, found := findSet(lk, sets)
	if !found || s.Interval || s.IsMap || s.Concatenation || len(s.Elements) == 0 {
		return false, false
	}

	keys := make([][]byte, 0, len(s.Elements))
	keyLen := -1
	for _, e := range s.Elements {
		if e.Val != "" || e.KeyEnd != "" {
			// A map or interval element that slipped past the set-level
			// flags above; refuse defensively rather than trust the flags
			// alone.
			return false, false
		}
		key, err := hex.DecodeString(e.Key)
		if err != nil {
			return false, false
		}
		if keyLen == -1 {
			keyLen = len(key)
		} else if len(key) != keyLen {
			return false, false // not a flat set of equal-length keys
		}
		keys = append(keys, key)
	}
	if len(reg) < keyLen {
		return false, false
	}

	member := false
	for _, key := range keys {
		if bytes.Equal(reg[:keyLen], key) {
			member = true
			break
		}
	}
	if lk.Invert {
		member = !member
	}
	return member, true
}

// findSet resolves a Lookup's set reference against the sets read for its
// table. A named set (docs/decisions/0004's census: "@myset" in nft syntax)
// is matched by name; an anonymous set (an inline "{ ... }") carries no
// usable name of its own, so it is matched by ID instead, the same
// correlation facts.Set.ID's doc comment describes.
func findSet(lk *facts.LookupExpr, sets []facts.Set) (facts.Set, bool) {
	for _, s := range sets {
		if lk.Set != "" && s.Name == lk.Set {
			return s, true
		}
		if lk.Set == "" && lk.SetID != 0 && s.ID == lk.SetID {
			return s, true
		}
	}
	return facts.Set{}, false
}

// xtExpr resolves an iptables-nft compatibility expression. The third return
// reports whether it could be resolved at all.
func xtExpr(pkt *Packet, x *facts.XtExpr) (Outcome, Action, bool) {
	none := Action{Kind: "none"}

	if x.Kind == "target" {
		switch x.Name {
		case "DNAT":
			if !x.Decoded || x.DNAT == nil {
				return OutcomeUnknown, none, false
			}
			ip, err := netip.ParseAddr(x.DNAT.MinIP)
			if err != nil {
				return OutcomeUnknown, none, false
			}
			return OutcomeMatch, Action{Kind: "dnat", DNAT: &DNAT{IP: ip, Port: x.DNAT.MinPort}}, true
		case "REJECT":
			return OutcomeMatch, Action{Kind: "drop"}, true
		case "LOG":
			// Non-terminal: logs and falls through to the next expression.
			return OutcomeMatch, none, true
		case "MASQUERADE":
			// Source NAT in postrouting. It never decides inbound delivery,
			// and whyopen does not score postrouting.
			return OutcomeMatch, Action{Kind: "accept"}, true
		}
		return OutcomeUnknown, none, false
	}

	switch x.Name {
	case "conntrack":
		if !x.Decoded || x.Conntrack == nil || !x.Conntrack.MatchesState {
			return OutcomeUnknown, none, false
		}
		hit := slices.Contains(x.Conntrack.States, pkt.CtState)
		if x.Conntrack.Invert {
			hit = !hit
		}
		if hit {
			return OutcomeMatch, none, true
		}
		return OutcomeNoMatch, none, true

	case "addrtype":
		if !x.Decoded || x.AddrType == nil {
			return OutcomeUnknown, none, false
		}
		dst, src := x.AddrType.DestTypes, x.AddrType.SourceTypes
		if len(dst) == 0 && len(src) == 0 {
			return OutcomeUnknown, none, false
		}
		if !knownAddrTypes(dst) || !knownAddrTypes(src) {
			return OutcomeUnknown, none, false
		}

		// The synthetic packet's address roles are known with certainty: the
		// destination is local when it is one of this host's own addresses,
		// unicast otherwise (a DNAT-rewritten destination is a routable
		// container address that is not on this host); the source is always
		// a unicast address in the internet zone. Neither role is ever
		// broadcast, anycast or multicast, so a rule demanding one of those
		// is a fact we can resolve, not a guess.
		dstRole := "unicast"
		if pkt.DstIsLocal {
			dstRole = "local"
		}
		srcRole := "unicast"

		dstHit := true
		if len(dst) > 0 {
			dstHit = slices.Contains(dst, dstRole)
			if x.AddrType.InvertDest {
				dstHit = !dstHit
			}
		}
		srcHit := true
		if len(src) > 0 {
			srcHit = slices.Contains(src, srcRole)
			if x.AddrType.InvertSource {
				srcHit = !srcHit
			}
		}
		if dstHit && srcHit {
			return OutcomeMatch, none, true
		}
		return OutcomeNoMatch, none, true

	case "recent":
		if !x.Decoded || x.Recent == nil {
			return OutcomeUnknown, none, false
		}
		// whyopen's synthetic packet is always a first connection from a
		// source the recent list has never seen, which is what makes each
		// mode decidable: set records the source and always matches; every
		// checking mode (check, rcheck, update) cannot match an empty list;
		// remove has nothing to remove. Only "set" hits.
		//
		// A mode name this build does not model, whether a typo or a value
		// written by a later version through the --facts path, is the
		// genuine "cannot resolve" case. Reading it as a silent no-match
		// would resolve a constraint whyopen cannot evaluate, so it
		// poisons the verdict instead.
		var hit bool
		switch x.Recent.Mode {
		case "set":
			hit = true
		case "check", "rcheck", "update", "remove":
			hit = false
		default:
			return OutcomeUnknown, none, false
		}
		if x.Recent.Invert {
			hit = !hit
		}
		if hit {
			return OutcomeMatch, none, true
		}
		return OutcomeNoMatch, none, true

	case "icmp", "icmp6":
		// Cannot match a TCP or UDP packet, whatever its payload says.
		return OutcomeNoMatch, none, true

	case "rt":
		// xt rt matches on an IPv6 routing header. The synthetic packet is a
		// bare TCP or UDP segment with no extension headers, so it carries
		// no routing header and this match provably cannot fire. UFW ships
		// "rt type 0 counter drop" as the second rule of ufw6-before-input
		// on every IPv6 installation, so treating it as unresolvable made
		// every IPv6 verdict on a stock UFW host unknown, which is precisely
		// the dual-stack blind spot whyopen exists to report on.
		return OutcomeNoMatch, none, true

	case "hl":
		// xt hl matches the IPv6 hop limit. Its payload decodes to
		// xt.Unknown, so the operator is not visible here, but every use UFW
		// makes of it asserts an on-link packet (--hl-eq 255) for neighbour
		// discovery. A packet sourced from the internet zone has crossed at
		// least one router, so its hop limit is below 255 and the match
		// cannot fire. This reasoning is sound only for the drop-shaped and
		// on-link-accept rules UFW ships. A hand-written rule with another
		// operator can be wrong in either direction: "hl --hl-gt 1 -j ACCEPT"
		// in a drop-policy chain really does accept, and skipping it reports
		// the port filtered when it is open.
		return OutcomeNoMatch, none, true
	}
	return OutcomeUnknown, none, false
}

// knownAddrTypes reports whether every name in types is one of the six
// values the xt addrtype match understands. An unrecognised name is the
// genuine "cannot resolve" case: the caller must return Unknown rather than
// silently ignoring the constraint.
func knownAddrTypes(types []string) bool {
	for _, t := range types {
		switch t {
		case "unspec", "unicast", "local", "broadcast", "anycast", "multicast":
		default:
			return false
		}
	}
	return true
}
