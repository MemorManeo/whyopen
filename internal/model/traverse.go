package model

import (
	"sort"
	"strconv"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// maxJumpDepth bounds chain recursion. A real ruleset nests a handful deep;
// anything past this is a loop, and a loop is reported as unknown, never as
// a hang.
const maxJumpDepth = 32

// Hit is one rule the packet actually reached, in traversal order.
type Hit struct {
	Family   string     `json:"family"`
	Table    string     `json:"table"`
	Chain    string     `json:"chain"`
	Hook     string     `json:"hook,omitempty"`
	Priority int32      `json:"priority"`
	Handle   uint64     `json:"handle"`
	Action   string     `json:"action"`
	Rule     facts.Rule `json:"-"`
}

// Result is the outcome of one hook.
type Result struct {
	Kind   string // accept | drop | unknown
	Reason string
	DNAT   *dnat
}

// Traverse pushes the packet through every base chain registered on one hook,
// in ascending priority order, and returns the resulting verdict with the
// ordered list of rules that produced it.
func Traverse(rs facts.Ruleset, family, hook string, pkt *Packet) (Result, []Hit) {
	type baseChain struct {
		table string
		chain facts.Chain
	}
	var bases []baseChain
	for _, t := range rs.Tables {
		if t.Family != family && t.Family != "inet" {
			continue
		}
		for _, ch := range t.Chains {
			if ch.Base && ch.Hook == hook {
				bases = append(bases, baseChain{table: t.Name, chain: ch})
			}
		}
	}
	// Ascending priority; table and chain name only to keep output stable.
	sort.SliceStable(bases, func(i, j int) bool {
		if bases[i].chain.Priority != bases[j].chain.Priority {
			return bases[i].chain.Priority < bases[j].chain.Priority
		}
		if bases[i].table != bases[j].table {
			return bases[i].table < bases[j].table
		}
		return bases[i].chain.Name < bases[j].chain.Name
	})

	w := &walker{rs: rs, family: family, pkt: pkt}
	for _, b := range bases {
		res := w.walkChain(b.table, b.chain, 0)
		switch res.Kind {
		case "drop", "unknown":
			// Terminal for the whole hook.
			return res, w.hits
		case "accept":
			// Continue to the next base chain: in nftables an accept in one
			// base chain does not skip the others on the same hook.
		default:
			// Defense in depth: walkChain now resolves a base chain's
			// return (see basePolicyResult) the same as fallthrough, so a
			// base chain should never yield anything but accept, drop, or
			// unknown here. If it somehow does, say so rather than
			// silently treating it as a pass to the next base chain.
			return Result{Kind: "unknown", Reason: "base chain " + b.table + "/" + b.chain.Name + " yielded unexpected verdict " + res.Kind}, w.hits
		}
	}
	return Result{Kind: "accept", DNAT: w.dnat}, w.hits
}

type walker struct {
	rs     facts.Ruleset
	family string
	pkt    *Packet
	hits   []Hit
	dnat   *dnat
}

func (w *walker) findChain(table, name string) (facts.Chain, bool) {
	for _, t := range w.rs.Tables {
		if t.Name != table || (t.Family != w.family && t.Family != "inet") {
			continue
		}
		for _, ch := range t.Chains {
			if ch.Name == name {
				return ch, true
			}
		}
	}
	return facts.Chain{}, false
}

// basePolicyResult resolves what a base chain does once nothing earlier has
// already decided the verdict: a drop policy drops, anything else accepts.
// In real nftables this is what happens both when a chain's rules run out
// (natural fallthrough) and when a rule inside it issues an explicit
// return, so both callers share this.
func basePolicyResult(table string, ch facts.Chain, reason string) Result {
	if ch.Policy == "drop" {
		return Result{Kind: "drop", Reason: reason}
	}
	return Result{Kind: "accept"}
}

// walkChain returns accept, drop, unknown, or none for a chain that fell
// through without a verdict.
func (w *walker) walkChain(table string, ch facts.Chain, depth int) Result {
	if depth > maxJumpDepth {
		return Result{Kind: "unknown", Reason: "chain nesting exceeded " + itoa(maxJumpDepth) + ", the ruleset may contain a jump loop"}
	}

	for _, r := range ch.Rules {
		out, act := MatchRule(w.pkt, r)
		if out == OutcomeNoMatch {
			continue
		}
		w.hits = append(w.hits, Hit{
			Family: w.family, Table: table, Chain: ch.Name, Hook: ch.Hook,
			Priority: ch.Priority, Handle: r.Handle, Action: act.Kind, Rule: r,
		})
		if out == OutcomeUnknown {
			return Result{Kind: "unknown", Reason: "rule " + itoa64(r.Handle) + " in " + table + "/" + ch.Name + " uses an expression whyopen cannot resolve"}
		}

		switch act.Kind {
		case "accept":
			return Result{Kind: "accept"}
		case "drop", "reject":
			// A reject answers the sender with an ICMP error or a TCP reset
			// instead of discarding the packet silently. For reachability
			// the two are the same: the listener never sees the packet.
			verb := "dropped"
			if act.Kind == "reject" {
				verb = "rejected"
			}
			return Result{Kind: "drop", Reason: verb + " by " + table + "/" + ch.Name + " rule " + itoa64(r.Handle)}
		case "dnat":
			w.dnat = act.DNAT
			return Result{Kind: "accept", DNAT: act.DNAT}
		case "return":
			if ch.Base {
				// In a base chain, return is equivalent to falling off the
				// end of it: the chain's policy applies.
				return basePolicyResult(table, ch, "return hit the drop policy of "+table+"/"+ch.Name)
			}
			return Result{Kind: "none"}
		case "jump":
			target, ok := w.findChain(table, act.Chain)
			if !ok {
				return Result{Kind: "unknown", Reason: "jump to unknown chain " + act.Chain}
			}
			sub := w.walkChain(table, target, depth+1)
			if sub.Kind != "none" {
				return sub
			}
			// Fell off the end of the target chain: continue after the jump.
		case "goto":
			target, ok := w.findChain(table, act.Chain)
			if !ok {
				return Result{Kind: "unknown", Reason: "goto unknown chain " + act.Chain}
			}
			sub := w.walkChain(table, target, depth+1)
			if sub.Kind != "none" {
				return sub
			}
			// goto does not return to the caller.
			return Result{Kind: "none"}
		case "continue", "none":
			// Next rule.
		default:
			return Result{Kind: "unknown", Reason: "unhandled verdict " + act.Kind}
		}
	}

	if ch.Base {
		return basePolicyResult(table, ch, "fell through to the drop policy of "+table+"/"+ch.Name)
	}
	return Result{Kind: "none"}
}

func itoa(i int) string      { return strconv.Itoa(i) }
func itoa64(i uint64) string { return strconv.FormatUint(i, 10) }
