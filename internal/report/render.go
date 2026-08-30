// Package report turns verdicts into something a human reads at 2am.
package report

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// RenderRule reconstructs an nft-like one-liner from the stored expressions.
// It is for human eyes only: whyopen never re-emits a rule.
func RenderRule(r facts.Rule) string {
	var parts []string
	var pending string     // what the next cmp is comparing against
	var pendingMask string // hex mask from a bitwise expr between payload and cmp, e.g. a subnet match

	for _, e := range r.Exprs {
		switch e.Kind {
		case facts.ExprMeta:
			pending = e.Meta.Key
		case facts.ExprPayload:
			pending = payloadName(e.Payload)
		case facts.ExprBitwise:
			pendingMask = e.Bitwise.Mask
		case facts.ExprCt:
			pending = renderCtKey(e.Ct.Key)
		case facts.ExprFib:
			pending = renderFibField(e.Fib)
			pendingMask = ""

		case facts.ExprRange:
			parts = append(parts, renderRange(pending, e.Range))
			pending, pendingMask = "", ""

		case facts.ExprLookup:
			parts = append(parts, renderLookup(pending, e.Lookup))
			pending, pendingMask = "", ""
		case facts.ExprCmp:
			if pending == "" {
				continue
			}
			if pendingMask != "" {
				parts = append(parts, maskedCmp(pending, e.Cmp.Data, pendingMask))
				pending, pendingMask = "", ""
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %s %s", pending, opSymbol(e.Cmp.Op), cmpValue(pending, e.Cmp.Data)))
			pending = ""
		case facts.ExprXt:
			parts = append(parts, renderXt(e.Xt))
		case facts.ExprUnknown:
			// Never omit an expression whyopen could not decode: doing so
			// makes --explain read as though the rule were fully
			// understood, which is exactly the rule that produced the
			// unknown verdict the reader is trying to understand.
			parts = append(parts, "<unresolved: "+unresolvedName(e.Note)+">")
		case facts.ExprVerdict:
			if e.Verdict.Chain != "" {
				parts = append(parts, e.Verdict.Kind+" "+e.Verdict.Chain)
			} else {
				parts = append(parts, e.Verdict.Kind)
			}
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("handle %d (no renderable expressions)", r.Handle)
	}
	// opSymbol returns "" for eq, which leaves a double space where the
	// symbol would have gone (e.g. "daddr  203.0.113.10"). Collapse it.
	return strings.ReplaceAll(strings.Join(parts, " "), "  ", " ")
}

// unresolvedName is the collector's Note, which carries the original Go
// type name. An older facts document may not have one.
func unresolvedName(note string) string {
	if note == "" {
		return "unnamed expression"
	}
	return note
}

func payloadName(p *facts.PayloadExpr) string {
	switch {
	// IPv6 first: its address offsets (8 and 24) do not collide with
	// IPv4's, and the length is what tells the two headers apart.
	case p.Base == "network" && p.Offset == 8 && p.Len == 16:
		return "saddr"
	case p.Base == "network" && p.Offset == 24 && p.Len == 16:
		return "daddr"
	case p.Base == "network" && p.Offset == 12:
		return "saddr"
	case p.Base == "network" && p.Offset == 16:
		return "daddr"
	case p.Base == "network" && (p.Offset == 9 || p.Offset == 6):
		return "protocol"
	case p.Base == "transport" && p.Offset == 0:
		return "sport"
	case p.Base == "transport" && p.Offset == 2:
		return "dport"
	}
	return fmt.Sprintf("%s@%d,%d", p.Base, p.Offset, p.Len)
}

// renderCtKey names the field a native `ct` expression loaded, the way
// payloadName does for a payload load. "state" is the only key whyopen's
// collector ever emits (see facts.CtExpr); the fallback exists only so a
// hand-built or forward-compatible facts document still renders something
// legible rather than an empty field name.
func renderCtKey(key string) string {
	if key == "state" {
		return "ct state"
	}
	return "ct " + key
}

// renderFibField names the fib question so the comparison that follows
// reads as nft spells it: "fib daddr type local", "fib saddr . iif oif
// missing".
func renderFibField(f *facts.FibExpr) string {
	if f.Query == "addrtype" {
		return "fib " + f.Source + " type"
	}
	key := "fib " + f.Source
	if f.MatchesIface {
		key += " . iif"
	}
	return key + " oif"
}

// renderRange spells a range the way nft does, "dport 3000-4000" or
// "dport != 3000-4000", with the bounds read in the field's own units
// rather than left as the hex the register holds.
func renderRange(field string, r *facts.RangeExpr) string {
	if field == "" {
		field = "<unnamed field>"
	}
	bounds := cmpValue(field, r.From) + "-" + cmpValue(field, r.To)
	if r.Op == "neq" {
		return field + " != " + bounds
	}
	return field + " " + bounds
}

// renderLookup names the set a Lookup expression tests membership against.
// field is whatever the preceding Meta/Payload/Ct expression named (e.g.
// "dport"), the same "pending" field name a Cmp would otherwise consume; a
// Lookup with nothing preceding it (a hand-built facts document) still
// renders the set reference on its own. An anonymous set carries no usable
// name (docs/decisions/0004's census), so it renders by ID instead.
func renderLookup(field string, lk *facts.LookupExpr) string {
	name := "@" + lk.Set
	if lk.Set == "" {
		name = fmt.Sprintf("anonymous set %d", lk.SetID)
	}
	verb := "in"
	if lk.Invert {
		verb = "not in"
	}
	if field == "" {
		return fmt.Sprintf("%s %s", verb, name)
	}
	return fmt.Sprintf("%s %s %s", field, verb, name)
}

func opSymbol(op string) string {
	if op == "neq" {
		return "!="
	}
	return ""
}

func cmpValue(field, data string) string {
	b, err := hex.DecodeString(data)
	if err != nil {
		return data
	}
	// A fib result reads as a name rather than as the number the register
	// holds: the address types are RTN_* values, and the presence lookup
	// is what nft calls "missing" when it is zero.
	if strings.HasPrefix(field, "fib ") {
		v := uint32(0)
		if len(b) == 4 {
			v = binary.NativeEndian.Uint32(b)
		}
		if strings.HasSuffix(field, " type") {
			switch v {
			case 1:
				return "unicast"
			case 2:
				return "local"
			case 3:
				return "broadcast"
			case 4:
				return "anycast"
			case 5:
				return "multicast"
			}
			return data
		}
		if v == 0 {
			return "missing"
		}
		return "present"
	}

	// An interface index is a number, and whyopen has no name to put in
	// its place here: the renderer sees one rule, not the host.
	if field == "iif" || field == "oif" {
		if len(b) == 4 {
			return fmt.Sprintf("index %d", binary.NativeEndian.Uint32(b))
		}
		return data
	}

	switch field {
	case "iifname", "oifname":
		return `"` + strings.TrimRight(string(b), "\x00") + `"`
	case "sport", "dport":
		if len(b) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(b))
		}
	case "saddr", "daddr":
		// Both families, through the same parser the rest of the tool
		// uses. An IPv6 address rendered as raw hex was unreadable
		// exactly where --explain is meant to help.
		if ip, ok := netip.AddrFromSlice(b); ok {
			return ip.String()
		}
	case "protocol":
		if len(b) == 1 {
			switch b[0] {
			case 6:
				return "tcp"
			case 17:
				return "udp"
			}
		}
	}
	return "0x" + data
}

// maskedCmp renders a payload/bitwise/cmp triple: the standard nft shape for
// a subnet or masked match. A contiguous mask (all ones then all zeros, read
// from the start) is a prefix and renders as CIDR; anything else renders as
// an explicit masked equality, because whyopen must never claim more
// precision than the rule actually has.
func maskedCmp(field, data, maskHex string) string {
	mask, errM := hex.DecodeString(maskHex)
	val, errD := hex.DecodeString(data)
	if errM != nil || errD != nil || len(mask) != len(val) {
		return fmt.Sprintf("%s & 0x%s == 0x%s", field, maskHex, data)
	}
	if n, ok := prefixLen(mask); ok {
		return fmt.Sprintf("%s %s/%d", field, cmpValue(field, data), n)
	}
	return fmt.Sprintf("%s & 0x%s == 0x%s", field, maskHex, data)
}

// prefixLen reports the length of the leading run of set bits in mask,
// provided every bit after the first zero is also zero. That shape is what
// a CIDR prefix looks like as a bitmask; anything else (a hole, a mask that
// starts with a zero bit) is not representable as a prefix length.
func prefixLen(mask []byte) (int, bool) {
	n := 0
	seenZero := false
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				if seenZero {
					return 0, false
				}
				n++
			} else {
				seenZero = true
			}
		}
	}
	return n, true
}

func renderXt(x *facts.XtExpr) string {
	switch {
	case x.Name == "DNAT" && x.DNAT != nil:
		return fmt.Sprintf("dnat to %s:%d", x.DNAT.MinIP, x.DNAT.MinPort)
	case x.Name == "conntrack" && x.Conntrack != nil && x.Conntrack.MatchesState:
		return "ct state " + strings.Join(x.Conntrack.States, ",")
	case x.Name == "addrtype" && x.AddrType != nil:
		return "fib daddr type " + strings.Join(x.AddrType.DestTypes, ",")
	case x.Name == "recent" && x.Recent != nil:
		return renderRecent(x.Recent)
	}
	if x.Kind == "target" {
		return strings.ToLower(x.Name)
	}
	return "match " + x.Name + " (undecoded)"
}

// renderRecent reconstructs the iptables option spelling, e.g.
// "recent --update --seconds 30 --hitcount 6 --name SSH".
func renderRecent(r *facts.RecentInfo) string {
	parts := []string{"recent"}
	if r.Invert {
		parts = append(parts, "!")
	}
	parts = append(parts, "--"+r.Mode)
	if r.Seconds > 0 {
		parts = append(parts, "--seconds", fmt.Sprintf("%d", r.Seconds))
	}
	if r.HitCount > 0 {
		parts = append(parts, "--hitcount", fmt.Sprintf("%d", r.HitCount))
	}
	if r.Name != "" {
		parts = append(parts, "--name", r.Name)
	}
	return strings.Join(parts, " ")
}
