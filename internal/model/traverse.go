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

// knownHooks are the five netfilter hooks whyopen can place a base chain on.
// A base chain named with anything else cannot be assigned to a hook, and a
// hook walked without it is an incomplete walk.
var knownHooks = map[string]bool{
	"prerouting": true, "input": true, "forward": true,
	"output": true, "postrouting": true,
}

// Result is the outcome of one hook: accept, drop or unknown. walkChain uses
// two further kinds internally, neither of which can escape a base chain:
// "none" for a regular chain that fell through, and "unwind" for a goto that
// fell through, which resumes at the base chain's policy rather than in any
// calling chain.
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
			if !ch.Base {
				continue
			}
			if !knownHooks[ch.Hook] {
				// The chain is registered on some hook, and whyopen cannot
				// tell which. Leaving it out of the walk would produce a
				// confident verdict from a hook it had only partly seen.
				return Result{Kind: "unknown", Reason: "base chain " + t.Name + "/" + ch.Name +
					" is registered on a hook whyopen does not recognise (" + strconv.Quote(ch.Hook) +
					"), so no hook can be walked completely"}, nil
			}
			if ch.Hook == hook {
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

// tableSets returns the named table's sets, so a rule's Lookup expression
// has something to resolve against (docs/decisions/0005). A jump or goto
// never crosses a table boundary, so the table name that reached walkChain
// is always the right one to resolve against, whichever chain within it is
// currently being walked.
func (w *walker) tableSets(table string) []facts.Set {
	for _, t := range w.rs.Tables {
		if t.Name != table || (t.Family != w.family && t.Family != "inet") {
			continue
		}
		return t.Sets
	}
	return nil
}

// basePolicyResult resolves what a base chain does once nothing earlier has
// already decided the verdict. In real nftables this is what happens when a
// chain's rules run out (natural fallthrough), when a rule inside it issues
// an explicit return, and when a goto below it falls through, so all three
// callers share this. reason describes which of the three happened, and is
// used only for a drop.
func basePolicyResult(ch facts.Chain, reason string) Result {
	switch ch.Policy {
	case "accept":
		return Result{Kind: "accept"}
	case "drop":
		return Result{Kind: "drop", Reason: reason}
	}
	// nftables has no third base chain policy, so this is a policy whyopen
	// failed to read rather than one it can apply. Treating it as accept,
	// which the old "anything that is not drop" test did, reports the chain
	// as open on no evidence at all.
	return Result{Kind: "unknown", Reason: "base chain " + ch.Name + " has policy " + strconv.Quote(ch.Policy) +
		", which is neither accept nor drop, so whyopen cannot say what happens to a packet that reaches the end of it"}
}

// unwind carries a goto's fallthrough up to the base chain that owns the
// hook. A goto does not return to the chain that issued it, so no caller
// resumes and the packet lands on the base chain's policy. Resuming in the
// calling chain instead under-reported exposure, which is the one direction
// this tool must not fail in.
func (w *walker) unwind(table string, ch facts.Chain) Result {
	if !ch.Base {
		return Result{Kind: "unwind"}
	}
	return basePolicyResult(ch, "a goto fell through to the drop policy of "+table+"/"+ch.Name)
}

// walkChain returns accept, drop or unknown, "none" for a regular chain that
// fell through without a verdict, or "unwind" for a goto that fell through,
// which must not resume in any caller and is resolved at the base chain.
func (w *walker) walkChain(table string, ch facts.Chain, depth int) Result {
	if depth > maxJumpDepth {
		return Result{Kind: "unknown", Reason: "chain nesting exceeded " + itoa(maxJumpDepth) + ", the ruleset may contain a jump loop"}
	}

	sets := w.tableSets(table)
	for _, r := range ch.Rules {
		out, act := MatchRule(w.pkt, r, sets)
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
				return basePolicyResult(ch, "return hit the drop policy of "+table+"/"+ch.Name)
			}
			return Result{Kind: "none"}
		case "jump":
			target, ok := w.findChain(table, act.Chain)
			if !ok {
				return Result{Kind: "unknown", Reason: "jump to unknown chain " + act.Chain}
			}
			sub := w.walkChain(table, target, depth+1)
			if sub.Kind == "unwind" {
				// A goto below this jump fell through. A goto never returns
				// to its own caller, and that is transitive: this chain does
				// not resume either.
				return w.unwind(table, ch)
			}
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
			if sub.Kind == "none" || sub.Kind == "unwind" {
				// goto never returns to the caller: when the target chain
				// falls through, traversal continues at the base chain's
				// policy, not at the rule after the goto.
				return w.unwind(table, ch)
			}
			return sub
		case "continue", "none":
			// Next rule.
		default:
			return Result{Kind: "unknown", Reason: "unhandled verdict " + act.Kind}
		}
	}

	if ch.Base {
		return basePolicyResult(ch, "fell through to the drop policy of "+table+"/"+ch.Name)
	}
	return Result{Kind: "none"}
}

func itoa(i int) string      { return strconv.Itoa(i) }
func itoa64(i uint64) string { return strconv.FormatUint(i, 10) }
