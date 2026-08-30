package model

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// forwardKind is the Endpoint.Kind of a port this host forwards somewhere
// else. It is neither a socket nor a publish, and unlike both of those
// nothing on this host owns it: the service is on a machine whyopen
// cannot see.
const forwardKind = "forward"

// ForwardNotes are the destination rewrites in the ruleset whose
// forwarded ports whyopen will not turn into rows: a rule that constrains
// no port at all forwards every one of them, and a range forwards more
// than a table should list.
//
// They are warnings rather than verdicts because whyopen reports one port
// per row and these name no single port. Saying nothing was the bug this
// whole scan exists to fix, so what cannot become a row has to become a
// sentence.
func ForwardNotes(f facts.Facts) []facts.Warning {
	_, notes := forwards(f)
	return notes
}

// forwards derives endpoints from the destination rewrites in the ruleset,
// which is whyopen's third source of ports after listening sockets and
// Docker publishes.
//
// Both of those describe this host: each ends at a process whyopen can
// name. A router or a VM host that forwards a port to a machine on its LAN
// has neither, and such a port used to produce no row at all, not even an
// unknown one. A reader saw no entry and concluded nothing was exposed
// while the host forwarded the port to a machine the table never mentioned.
//
// The scan only produces candidates. Whether such a port is reachable is
// decided by the same traversal every other endpoint goes through, so a
// rule this finds that never actually matches (it is gated on an interface
// the internet does not arrive on, say) yields an honest filtered verdict
// rather than a wrong reachable one. That asymmetry is the design: over-
// producing here is corrected downstream, under-producing is the silence
// this is meant to end.
func forwards(f facts.Facts) ([]Endpoint, []facts.Warning) {
	var eps []Endpoint
	var notes []facts.Warning
	seen := map[string]bool{}
	said := map[string]bool{}

	for _, t := range f.Ruleset.Tables {
		if len(tableFamilies(t.Family)) == 0 {
			continue
		}
		for _, ch := range t.Chains {
			// Only prerouting. A rewrite in output acts on traffic this
			// host sent, and postrouting is where source NAT lives;
			// neither decides whether a packet from outside arrives.
			if !ch.Base || ch.Hook != "prerouting" {
				continue
			}
			s := &fwdScan{table: t}
			s.walkChain(ch, fwdMatch{}, 0)
			for _, e := range s.eps {
				k := fmt.Sprintf("%s/%s/%d", e.Family, e.Proto, e.Port)
				if seen[k] {
					// Two rules forwarding one port are one row. The
					// traversal takes the first that matches, and this
					// keeps the label on the row from claiming otherwise.
					continue
				}
				seen[k] = true
				eps = append(eps, e)
			}
			for _, n := range s.notes {
				// One rule can be reached from two base chains on the same
				// hook. It is still one rule, and saying so twice would
				// read as two rewrites.
				if said[n.Message] {
					continue
				}
				said[n.Message] = true
				notes = append(notes, n)
			}
		}
	}
	return eps, notes
}

// fwdScan walks one base chain, and the chains it jumps to, collecting the
// rewrites it finds. It resolves sets against its own table, the same way
// the traversal does: a jump never crosses a table boundary.
type fwdScan struct {
	table facts.Table
	eps   []Endpoint
	notes []facts.Warning
}

// fwdMatch is what the rules above a rewrite have said about the packets
// it rewrites: which transport protocol, and which destination ports. It
// is carried across a jump the way the traversal carries its packet,
// because Docker writes the port constraint and the rewrite in a chain the
// base chain jumps to.
type fwdMatch struct {
	// proto is tcp, udp, or other for a protocol with no ports at all.
	// Empty means nothing constrained it.
	proto  string
	ports  []uint16
	refuse string // why the ports cannot be enumerated; empty when they can
}

// fwdField is what a register holds, as far as this scan cares. It reads
// the same expressions MatchRule does but asks a different question:
// MatchRule asks whether one packet matches, this asks which packets could,
// so it tracks which field a register was loaded from rather than a value.
type fwdField int

const (
	fwdUnset fwdField = iota
	fwdDport
	fwdL4Proto
	fwdOther
)

func (s *fwdScan) walkChain(ch facts.Chain, m fwdMatch, depth int) {
	if depth > maxJumpDepth {
		return
	}
	for _, r := range ch.Rules {
		s.rule(ch, r, m, depth)
	}
}

func (s *fwdScan) findChain(name string) (facts.Chain, bool) {
	for _, ch := range s.table.Chains {
		if ch.Name == name {
			return ch, true
		}
	}
	return facts.Chain{}, false
}

// rule reads one rule: what it constrains, and whether it rewrites. The
// inherited match is taken by value, so what this rule adds applies to it
// and to the chains it jumps to, and not to the rules after it.
func (s *fwdScan) rule(ch facts.Chain, r facts.Rule, m fwdMatch, depth int) {
	regs := map[uint32]fwdField{}
	imm := map[uint32]string{} // what the nat expression below will name by register

	for _, e := range r.Exprs {
		switch e.Kind {
		case facts.ExprPayload:
			regs[e.Payload.DestRegister] = payloadField(e.Payload)

		case facts.ExprMeta:
			if e.Meta.Key == "l4proto" {
				regs[e.Meta.Register] = fwdL4Proto
			} else {
				regs[e.Meta.Register] = fwdOther
			}

		case facts.ExprCt:
			regs[e.Ct.Register] = fwdOther

		case facts.ExprFib:
			regs[e.Fib.Register] = fwdOther

		case facts.ExprBitwise:
			// A port compared through a mask is a shape this scan does not
			// read. Everything else masks a field it has no interest in,
			// a subnet match most often.
			if regs[e.Bitwise.SourceRegister] == fwdDport {
				m.refuse = "its destination port is compared through a bitmask"
			}
			regs[e.Bitwise.DestRegister] = fwdOther

		case facts.ExprCmp:
			m = cmpConstraint(m, regs[e.Cmp.Register], e.Cmp)

		case facts.ExprLookup:
			if regs[e.Lookup.SourceRegister] != fwdDport {
				continue
			}
			ports, ok := setPorts(s.table.Sets, e.Lookup)
			if !ok {
				m.refuse = "its destination ports come from a set whyopen cannot read as a flat list of ports"
				continue
			}
			m.ports = append(m.ports, ports...)

		case facts.ExprRange:
			if regs[e.Range.Register] == fwdDport {
				m.refuse = "its destination port is matched against a range"
			}

		case facts.ExprImmediate:
			// Remembered rather than read as a constraint: it is the value
			// the nat expression below names by register.
			imm[e.Immediate.Register] = e.Immediate.Data
			regs[e.Immediate.Register] = fwdOther

		case facts.ExprNAT:
			if e.NAT.Type != "dnat" {
				continue
			}
			s.emit(ch, r, m, nativeTarget(e.NAT, imm))
			return

		case facts.ExprXt:
			if e.Xt.Kind == "target" && e.Xt.Name == "DNAT" && e.Xt.Decoded && e.Xt.DNAT != nil {
				s.emit(ch, r, m, xtTarget(e.Xt.DNAT))
				return
			}

		case facts.ExprVerdict:
			if e.Verdict.Kind == "jump" || e.Verdict.Kind == "goto" {
				if target, ok := s.findChain(e.Verdict.Chain); ok {
					s.walkChain(target, m, depth+1)
				}
			}
			// Any verdict ends the rule, and a rule that carries one
			// carries no rewrite.
			return
		}
	}
}

// cmpConstraint folds one comparison into what is known about the packets
// a rule can rewrite. Only equality is read: a port derived from an
// ordered comparison is a range, and a protocol derived from a negation is
// a set of protocols, and inventing rows for either is the guessing this
// tool refuses everywhere else.
func cmpConstraint(m fwdMatch, field fwdField, c *facts.CmpExpr) fwdMatch {
	switch field {
	case fwdDport:
		if c.Op != "eq" {
			m.refuse = "its destination port is matched with " + c.Op + " rather than an equality, which is a range"
			return m
		}
		p, ok := portFromHex(c.Data)
		if !ok {
			m.refuse = "its destination port is compared against something that is not a port"
			return m
		}
		m.ports = append(m.ports, p)
	case fwdL4Proto:
		if c.Op != "eq" {
			m.refuse = "its transport protocol is matched with " + c.Op + " rather than an equality, so which protocols it forwards is not decidable from the rule"
			return m
		}
		m.proto = protoFromHex(c.Data)
	}
	return m
}

// payloadField names the header field a payload load reads, for the two
// fields this scan cares about: the destination port, and the protocol
// byte both families carry at their own offset.
func payloadField(p *facts.PayloadExpr) fwdField {
	switch {
	case p.Base == "transport" && p.Offset == 2 && p.Len == 2:
		return fwdDport
	case p.Base == "network" && p.Len == 1 && (p.Offset == 9 || p.Offset == 6):
		return fwdL4Proto
	}
	return fwdOther
}

// setPorts reads the ports a Lookup names, which is how
// `tcp dport { 80, 443 } dnat to ...` reaches this scan. It is as narrow
// as lookupMatch in match.go: a flat set of two-byte keys and nothing
// else, so an interval set, a map, a concatenated key type or a set this
// document does not carry is refused rather than half-read. A refusal
// becomes a note, not silence.
func setPorts(sets []facts.Set, lk *facts.LookupExpr) ([]uint16, bool) {
	if lk.Invert || lk.IsDestRegSet {
		return nil, false
	}
	s, found := findSet(lk, sets)
	if !found || s.Interval || s.IsMap || s.Concatenation || len(s.Elements) == 0 {
		return nil, false
	}
	out := make([]uint16, 0, len(s.Elements))
	for _, el := range s.Elements {
		if el.Val != "" || el.KeyEnd != "" || el.IntervalEnd {
			return nil, false
		}
		p, ok := portFromHex(el.Key)
		if !ok {
			return nil, false
		}
		out = append(out, p)
	}
	return out, true
}

// fwdTarget is the machine a rewrite sends the packet to, as far as the
// scan could resolve it. A zero port means the rewrite keeps the port the
// packet arrived on, which is what `dnat to <addr>` without a port does.
type fwdTarget struct {
	addr netip.Addr
	port uint16
}

// dest names where the rewrite sends the packet. An address whyopen could
// not resolve is said rather than left out: the traversal refuses such a
// rule too, so the row it lands on will be unknown, and a note that named
// nothing would send the reader looking for a target that is not there.
func (t fwdTarget) dest() string {
	switch {
	case !t.addr.IsValid():
		return "an address whyopen could not resolve"
	case t.port == 0:
		return t.addr.String()
	}
	return fmt.Sprintf("%s:%d", t.addr, t.port)
}

// label is what the row says in place of an owner. There is no process and
// no container on this host to name, so it names the destination instead.
func (t fwdTarget) label() string { return "forwarded to " + t.dest() }

func nativeTarget(n *facts.NATExpr, imm map[uint32]string) fwdTarget {
	var t fwdTarget
	if raw, ok := imm[n.AddrRegister]; ok {
		if b, err := hex.DecodeString(raw); err == nil {
			if ip, ok := netip.AddrFromSlice(b); ok {
				t.addr = ip
			}
		}
	}
	if n.ProtoRegister != 0 {
		if p, ok := portFromHex(imm[n.ProtoRegister]); ok {
			t.port = p
		}
	}
	return t
}

func xtTarget(d *facts.DNATInfo) fwdTarget {
	t := fwdTarget{port: d.MinPort}
	if ip, err := netip.ParseAddr(d.MinIP); err == nil {
		t.addr = ip
	}
	return t
}

// emit turns one rewrite into rows, or into the note that says why it
// could not become rows.
func (s *fwdScan) emit(ch facts.Chain, r facts.Rule, m fwdMatch, t fwdTarget) {
	if m.proto == "other" {
		// A rewrite for a protocol that has no ports. whyopen's whole
		// vocabulary is tcp and udp ports, so there is no row this could
		// become and nothing a note would tell a reader.
		return
	}
	where := fmt.Sprintf("%s %s/%s rule %d rewrites the destination to %s",
		s.table.Family, s.table.Name, ch.Name, r.Handle, t.dest())
	switch {
	case m.refuse != "":
		s.note(where + ", but " + m.refuse +
			", so whyopen cannot name the ports it forwards and no row above covers them")
		return
	case len(m.ports) == 0:
		s.note(where + " with no port constraint at all, so it forwards every port;" +
			" whyopen reports one port per row and cannot list them")
		return
	}
	for _, family := range s.families(t) {
		for _, proto := range fwdProtos(m.proto) {
			for _, port := range m.ports {
				s.eps = append(s.eps, Endpoint{
					Kind: forwardKind, Family: family, Proto: proto, Port: port,
					// No bind address: the rewrite applies wherever the
					// rule matches, which the traversal works out per
					// address rather than this scan guessing at it.
					Owner: t.label(),
				})
			}
		}
	}
}

func (s *fwdScan) note(msg string) {
	s.notes = append(s.notes, facts.Warning{Source: "forwarded-ports", Message: msg})
}

// families is which address families a rewrite can apply to. The table
// says it for two of the three; an inet table serves both, and there the
// target decides, since a packet cannot be rewritten to an address of the
// other family.
func (s *fwdScan) families(t fwdTarget) []string {
	fams := tableFamilies(s.table.Family)
	if s.table.Family != "inet" || !t.addr.IsValid() {
		return fams
	}
	if t.addr.Is4() || t.addr.Is4In6() {
		return []string{"ip"}
	}
	return []string{"ip6"}
}

func tableFamilies(family string) []string {
	switch family {
	case "ip":
		return []string{"ip"}
	case "ip6":
		return []string{"ip6"}
	case "inet":
		return []string{"ip", "ip6"}
	}
	return nil
}

// fwdProtos is which transport protocols a rewrite covers. A rule that
// constrains none matches whatever transport header the packet carries, so
// both are reported: over-reporting an exposure is the direction this tool
// errs in, and each row still gets its verdict from the traversal.
func fwdProtos(proto string) []string {
	if proto == "" {
		return []string{"tcp", "udp"}
	}
	return []string{proto}
}

func portFromHex(s string) (uint16, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

// protoFromHex names the protocol a one-byte comparison tests, by the
// IPPROTO_* numbers the header carries. Anything else is a protocol with
// no ports for whyopen to report.
func protoFromHex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 1 {
		return "other"
	}
	switch b[0] {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return "other"
}
