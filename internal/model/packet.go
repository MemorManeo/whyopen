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
}

// Action is what a matching rule does.
type Action struct {
	Kind  string // accept | drop | return | jump | goto | continue | dnat | none
	Chain string
	DNAT  *dnat
}

type dnat struct {
	IP      netip.Addr
	MinPort uint16
}

type Outcome int

const (
	OutcomeMatch Outcome = iota
	OutcomeNoMatch
	OutcomeUnknown
)

func (o Outcome) String() string {
	switch o {
	case OutcomeMatch:
		return "match"
	case OutcomeNoMatch:
		return "no-match"
	}
	return "unknown"
}
