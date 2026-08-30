// Package model evaluates whether a packet from a given source zone reaches
// a listener, using only a facts snapshot. It is pure: no netlink, no /proc,
// no Docker, no clock. That is what makes it testable.
package model

import "net/netip"

// Packet is the synthetic probe pushed through the ruleset. CtState is always
// "new": whyopen asks whether a fresh inbound connection can be established,
// which is what makes "ct state related,established accept" correctly fail to
// match.
type Packet struct {
	Family     string // ip | ip6
	Proto      string // tcp | udp
	Src        netip.Addr
	Dst        netip.Addr
	SrcPort    uint16
	DstPort    uint16
	InIface    string
	OutIface   string
	CtState    string
	DstIsLocal bool
	// DNATApplied says a rule earlier on this packet's path rewrote its
	// destination, which is what `ct status dnat` asks about. whyopen is
	// the thing that applied the rewrite, so this is not an assumption
	// about conntrack: it is what happened in the traversal.
	//
	// It is set for the hook walked after the rewrite, not within the
	// prerouting walk that performs it, so a `ct status dnat` rule placed
	// after the DNAT rule in the same chain reads as not-yet-rewritten.
	// That errs toward reporting the packet as continuing rather than as
	// stopped, which is the safe direction for an exposure audit.
	DNATApplied bool
	// SrcRouteDev is the device the host would route a reply to Src out
	// of, or empty when whyopen could not resolve one. It answers a fib
	// presence lookup and nothing else. Empty is not "no route exists":
	// it is "whyopen cannot say", which is why the evaluator refuses
	// rather than concluding the route is missing
	// (docs/decisions/0012-fib-and-routes.md).
	SrcRouteDev string
}

// Action is what a matching rule does.
type Action struct {
	Kind  string // accept | drop | return | jump | goto | continue | dnat | none
	Chain string
	DNAT  *DNAT
}

// DNAT is the single resolved rewrite target for a matched DNAT rule. Unlike
// facts.DNATInfo, which genuinely describes a port range (MinPort/MaxPort),
// a DNAT value names one concrete port whyopen will follow, so the field is
// just Port. It is exported so that report can render it: the verdict
// schema report writes is deliberately its own shape, not this type
// marshalled, but it still has to read this one.
type DNAT struct {
	IP   netip.Addr
	Port uint16
}

type Outcome int

const (
	OutcomeMatch Outcome = iota
	OutcomeNoMatch
	OutcomeUnknown
	// OutcomeSkipped is a rule carrying an expression whyopen cannot
	// resolve, in a rule with no verdict, so neither outcome of the match
	// changes where the packet goes. It steers traversal exactly like
	// OutcomeNoMatch and exists only so the rule can still be recorded in
	// the path: a reader chasing an unresolved expression should see the
	// rule that carried it, not a gap where it was.
	OutcomeSkipped
)

func (o Outcome) String() string {
	switch o {
	case OutcomeMatch:
		return "match"
	case OutcomeNoMatch:
		return "no-match"
	case OutcomeSkipped:
		return "skipped"
	}
	return "unknown"
}
