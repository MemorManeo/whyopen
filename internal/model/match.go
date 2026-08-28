package model

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// ifnameLen is IFNAMSIZ: nft loads interface names into a fixed-size buffer.
const ifnameLen = 16

// MatchRule evaluates one rule against the packet. It returns OutcomeUnknown
// the moment it meets anything it cannot resolve, so a verdict is never built
// on a guess.
func MatchRule(pkt *Packet, r facts.Rule) (Outcome, Action) {
	regs := map[uint32][]byte{}
	act := Action{Kind: "none"}

	for _, e := range r.Exprs {
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
			return OutcomeMatch, Action{Kind: "dnat", DNAT: &dnat{IP: ip, Port: x.DNAT.MinPort}}, true
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
		// cannot fire. Where a hand-written rule uses another operator this
		// errs towards reporting the port reachable, which is the safe
		// direction for an exposure audit: it never hides a hole.
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
