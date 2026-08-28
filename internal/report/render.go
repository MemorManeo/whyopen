// Package report turns verdicts into something a human reads at 2am.
package report

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// RenderRule reconstructs an nft-like one-liner from the stored expressions.
// It is for human eyes only: whyopen never re-emits a rule.
func RenderRule(r facts.Rule) string {
	var parts []string
	var pending string // what the next cmp is comparing against

	for _, e := range r.Exprs {
		switch e.Kind {
		case facts.ExprMeta:
			pending = e.Meta.Key
		case facts.ExprPayload:
			pending = payloadName(e.Payload)
		case facts.ExprCmp:
			if pending == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %s %s", pending, opSymbol(e.Cmp.Op), cmpValue(pending, e.Cmp.Data)))
			pending = ""
		case facts.ExprXt:
			parts = append(parts, renderXt(e.Xt))
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

func payloadName(p *facts.PayloadExpr) string {
	switch {
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
	switch field {
	case "iifname", "oifname":
		return `"` + strings.TrimRight(string(b), "\x00") + `"`
	case "sport", "dport":
		if len(b) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(b))
		}
	case "saddr", "daddr":
		if len(b) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
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

func renderXt(x *facts.XtExpr) string {
	switch {
	case x.Name == "DNAT" && x.DNAT != nil:
		return fmt.Sprintf("dnat to %s:%d", x.DNAT.MinIP, x.DNAT.MinPort)
	case x.Name == "conntrack" && x.Conntrack != nil && x.Conntrack.MatchesState:
		return "ct state " + strings.Join(x.Conntrack.States, ",")
	case x.Name == "addrtype" && x.AddrType != nil:
		return "fib daddr type " + strings.Join(x.AddrType.DestTypes, ",")
	}
	if x.Kind == "target" {
		return strings.ToLower(x.Name)
	}
	return "match " + x.Name + " (undecoded)"
}
