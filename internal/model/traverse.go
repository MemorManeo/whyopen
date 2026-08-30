package model

import (
	"sort"
	"strconv"
	"strings"

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

// ingressUnmodelled reports whether an ingress base chain could see this
// packet, in which case no verdict can be drawn.
//
// The ingress hook runs before prerouting, on the device its chain is
// attached to, and whyopen does not model it: it sees raw frames, before
// the IP-level context this evaluator works in, and a chain there can drop
// the packet before any rule below is reached. Its hook number is
// NF_NETDEV_INGRESS, which is also NF_INET_PRE_ROUTING, so such a chain
// used to be named "prerouting" and then skipped as a table of the wrong
// family: whyopen reported ports reachable that the kernel was dropping.
//
// Only the packets the chain can actually see are affected. The hook is
// per device, so a chain on another interface leaves this verdict alone,
// which is what keeps one ingress chain from making every port on the host
// unknown. A chain naming no device is treated as seeing everything.
//
// The devices come from a netlink request whyopen issues itself, because
// the nftables library drops the attribute when it reads a chain back
// (docs/decisions/0006-reading-chain-devices.md). When that read does not
// happen, the chain carries no devices and is treated as seeing every
// packet, which is what whyopen did for every ingress chain before it
// could read them at all.
//
// The egress hook is deliberately not treated this way. It acts on the
// reply, and this model is about whether the inbound packet reaches the
// socket, the same reason the output hook is never walked.
func ingressUnmodelled(rs facts.Ruleset, pkt *Packet) (Result, bool) {
	for _, t := range rs.Tables {
		for _, ch := range t.Chains {
			if !ch.Base || ch.Hook != "ingress" {
				continue
			}
			if !chainSeesIface(ch.Devices, pkt.InIface) {
				continue
			}
			where := "on device " + strings.Join(ch.Devices, ", ")
			if len(ch.Devices) == 0 {
				where = "on a device whyopen could not read, so it is treated as every device"
			}
			return Result{Kind: "unknown", Reason: "base chain " + t.Name + "/" + ch.Name +
				" is on the ingress hook (" + where + "), which whyopen does not model: it runs before" +
				" prerouting and can drop the packet before any rule whyopen walks"}, true
		}
	}
	return Result{}, false
}

// chainSeesIface reports whether a per-device hook could see a packet
// arriving on iface. A chain with no devices recorded is one whyopen
// could not read the devices of, and it is read as seeing everything:
// the conservative direction, and the only honest one.
func chainSeesIface(devices []string, iface string) bool {
	if len(devices) == 0 || iface == "" {
		return true
	}
	for _, d := range devices {
		if d == iface {
			return true
		}
	}
	return false
}

// knownHooks are the five netfilter hooks whyopen can place a base chain on.
// A base chain named with anything else cannot be assigned to a hook, and a
// hook walked without it is an incomplete walk.
// ingress and egress are named here so a chain on one is not reported as
// an unrecognised hook: ingress is handled by ingressUnmodelled before any
// walk begins, and egress acts on the reply, which this model does not
// follow. Both live in the netdev family, whose tables the walk below
// skips anyway, and inet gained its own ingress hook in kernel 5.10.
var knownHooks = map[string]bool{
	"ingress":    true,
	"egress":     true,
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
	DNAT   *DNAT
}

// Traverse pushes the packet through every base chain registered on one hook,
// in ascending priority order, and returns the resulting verdict with the
// ordered list of rules that produced it.
func Traverse(rs facts.Ruleset, family, hook string, pkt *Packet) (Result, []Hit) {
	if res, blocked := ingressUnmodelled(rs, pkt); blocked {
		return res, nil
	}
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
	dnat   *DNAT
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

func (w *walker) record(table string, ch facts.Chain, r facts.Rule, action string) {
	w.hits = append(w.hits, Hit{
		Family: w.family, Table: table, Chain: ch.Name, Hook: ch.Hook,
		Priority: ch.Priority, Handle: r.Handle, Action: action, Rule: r,
	})
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
		if out == OutcomeSkipped {
			// Recorded, then stepped over: the rule decides nothing, but
			// it is a rule the packet reached and the one a reader
			// chasing an unresolved expression will go looking for.
			w.record(table, ch, r, "skipped")
			continue
		}
		w.record(table, ch, r, act.Kind)
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
