package model

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// hexPort renders a port the way a register carries one: two bytes, big
// endian. It is the width and order both a dport comparison and the
// immediate behind a `dnat to <addr>:<port>` are recorded in.
func hexPort(p uint16) string {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, p)
	return hex.EncodeToString(b)
}

func hexProto(proto string) string {
	if proto == "udp" {
		return "11" // IPPROTO_UDP
	}
	return "06" // IPPROTO_TCP
}

// forwardRule is `<proto> dport <port> dnat to <addr>:<toPort>` as the
// kernel compiles it: the protocol and port comparisons, then the two
// immediates that fill the registers the nat expression names. The
// rewrite half on its own is nativeDNATRule in match_test.go; this is the
// whole rule, because the scan under test reads the match half too.
func forwardRule(handle uint64, proto string, port uint16, addrHex string, toPort uint16) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "l4proto", Register: 1}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: hexProto(proto)}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: hexPort(port)}},
		{Kind: facts.ExprImmediate, Immediate: &facts.ImmediateExpr{Register: 1, Data: addrHex}},
		{Kind: facts.ExprImmediate, Immediate: &facts.ImmediateExpr{Register: 2, Data: hexPort(toPort)}},
		{Kind: facts.ExprNAT, NAT: &facts.NATExpr{Type: "dnat", Family: "ip", AddrRegister: 1, ProtoRegister: 2}},
	}}
}

// natPrerouting is the hook a destination rewrite has to be on for the
// scan to read it, and the only one whyopen walks for inbound traffic.
func natPrerouting(rules ...facts.Rule) facts.Table {
	return facts.Table{Family: "ip", Name: "nat", Chains: []facts.Chain{{
		Name: "prerouting", Base: true, Hook: "prerouting", Priority: -100, Policy: "accept",
		Rules: rules,
	}}}
}

func rulesetOf(ts ...facts.Table) facts.Facts {
	return facts.Facts{SchemaVersion: facts.SchemaVersion, Ruleset: facts.Ruleset{Tables: ts}}
}

// 192.0.2.50, the address the hand-written rewrites in this file forward to.
const targetHex = "c0000232"

// A router or a VM host forwards a port to a machine on its LAN. Nothing
// on this host listens on it and no container publishes it, so before
// this scan the port produced no row at all: not unknown, silence.
func TestForwardedPortBecomesAnEndpoint(t *testing.T) {
	eps, notes := forwards(rulesetOf(natPrerouting(forwardRule(5, "tcp", 8080, targetHex, 80))))

	if len(notes) != 0 {
		t.Fatalf("notes = %+v, want none: the rule names exactly one port", notes)
	}
	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want 1: %+v", len(eps), eps)
	}
	e := eps[0]
	if e.Kind != forwardKind || e.Family != "ip" || e.Proto != "tcp" || e.Port != 8080 {
		t.Errorf("endpoint = %+v, want a forward on tcp/8080 over ip", e)
	}
	// The owner is the only place the table can say where the packet
	// goes, since no process and no container on this host owns it.
	if !strings.Contains(e.Owner, "192.0.2.50:80") {
		t.Errorf("owner = %q, want it to name the machine behind the rewrite", e.Owner)
	}
	// A bind address would be a claim the rule never made: the rewrite
	// applies at whatever address it matches, which the traversal decides.
	if e.BindIP != "" {
		t.Errorf("bind = %q, want empty: the rule constrains no address", e.BindIP)
	}
}

// A rewrite keeping the original port (`dnat to <addr>`, no port) names no
// proto register. The forwarded port is still the one the rule matched.
func TestForwardKeepingTheOriginalPortIsStillAnEndpoint(t *testing.T) {
	r := forwardRule(6, "tcp", 8081, targetHex, 0)
	r.Exprs = append(r.Exprs[:4], facts.Expr{Kind: facts.ExprImmediate,
		Immediate: &facts.ImmediateExpr{Register: 1, Data: targetHex}},
		facts.Expr{Kind: facts.ExprNAT, NAT: &facts.NATExpr{Type: "dnat", Family: "ip", AddrRegister: 1}})

	eps, notes := forwards(rulesetOf(natPrerouting(r)))
	if len(eps) != 1 || len(notes) != 0 {
		t.Fatalf("eps = %+v, notes = %+v, want one endpoint and no note", eps, notes)
	}
	if eps[0].Port != 8081 {
		t.Errorf("port = %d, want 8081", eps[0].Port)
	}
	if !strings.Contains(eps[0].Owner, "192.0.2.50") || strings.Contains(eps[0].Owner, ":") {
		t.Errorf("owner = %q, want the address alone: the rule rewrites no port", eps[0].Owner)
	}
}

// Docker's publishes are the same rewrite written by iptables-nft: an xt
// DNAT target, reached by a jump from the base chain, with the port
// constraint on the rule that carries the target.
func TestForwardFromAnXtDNATTargetBehindAJump(t *testing.T) {
	eps, _ := forwards(rulesetOf(dockerNATTo("0.0.0.0", 6000, "10.99.0.5")))

	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want 1: %+v", len(eps), eps)
	}
	if eps[0].Port != 6000 || eps[0].Proto != "tcp" {
		t.Errorf("endpoint = %+v, want tcp/6000", eps[0])
	}
	if !strings.Contains(eps[0].Owner, "10.99.0.5:6000") {
		t.Errorf("owner = %q, want the rewrite target", eps[0].Owner)
	}
}

// `tcp dport { 80, 443 } dnat to ...`: a flat set names its ports, so
// each becomes a row. This is as narrow as lookupMatch deliberately is,
// and the two refusals below are the other half of that.
func TestForwardOverAPortSetNamesEveryPort(t *testing.T) {
	r := forwardRule(7, "tcp", 0, targetHex, 80)
	r.Exprs[3] = facts.Expr{Kind: facts.ExprLookup,
		Lookup: &facts.LookupExpr{SourceRegister: 1, Set: "web"}}
	tbl := natPrerouting(r)
	tbl.Sets = []facts.Set{portSet("web", 1, 80, 443)}

	eps, notes := forwards(rulesetOf(tbl))
	if len(notes) != 0 {
		t.Fatalf("notes = %+v, want none: the set names its ports", notes)
	}
	got := map[uint16]bool{}
	for _, e := range eps {
		got[e.Port] = true
	}
	if len(eps) != 2 || !got[80] || !got[443] {
		t.Fatalf("ports = %v (%d endpoints), want 80 and 443", got, len(eps))
	}
}

// An interval set is refused for the same reason a range is: whyopen
// reports one port per row and will not invent the rows in between.
func TestForwardOverAnIntervalSetIsANote(t *testing.T) {
	r := forwardRule(8, "tcp", 0, targetHex, 80)
	r.Exprs[3] = facts.Expr{Kind: facts.ExprLookup,
		Lookup: &facts.LookupExpr{SourceRegister: 1, Set: "wide"}}
	tbl := natPrerouting(r)
	set := portSet("wide", 2, 1000)
	set.Interval = true
	tbl.Sets = []facts.Set{set}

	eps, notes := forwards(rulesetOf(tbl))
	if len(eps) != 0 || len(notes) != 1 {
		t.Fatalf("eps = %+v, notes = %+v, want no endpoint and one note", eps, notes)
	}
}

// A range forwards more ports than a table should list, so it is said
// once as a warning rather than expanded. Both shapes a range arrives in
// are refused: the ordered pair the common form compiles to
// (docs/decisions/0011), and the range expression the negated form emits.
func TestForwardOverAPortRangeIsANote(t *testing.T) {
	ordered := forwardRule(9, "tcp", 1024, targetHex, 80)
	ordered.Exprs[3] = facts.Expr{Kind: facts.ExprCmp,
		Cmp: &facts.CmpExpr{Op: "gte", Register: 1, Data: hexPort(1024)}}

	negated := forwardRule(10, "tcp", 1024, targetHex, 80)
	negated.Exprs[3] = facts.Expr{Kind: facts.ExprRange,
		Range: &facts.RangeExpr{Op: "eq", Register: 1, From: hexPort(1024), To: hexPort(2048)}}

	for _, r := range []facts.Rule{ordered, negated} {
		eps, notes := forwards(rulesetOf(natPrerouting(r)))
		if len(eps) != 0 {
			t.Errorf("rule %d: eps = %+v, want none: a range is not a row", r.Handle, eps)
		}
		if len(notes) != 1 {
			t.Fatalf("rule %d: notes = %+v, want exactly one", r.Handle, notes)
		}
		// The note has to be findable in the ruleset, or the reader
		// cannot go look at the rule it is about.
		want := fmt.Sprintf("nat/prerouting rule %d", r.Handle)
		if !strings.Contains(notes[0].Message, want) {
			t.Errorf("rule %d: note = %q, want it to name %q", r.Handle, notes[0].Message, want)
		}
	}
}

// A rewrite with no port constraint forwards every port. That is the
// largest exposure in this whole vocabulary and the one whyopen cannot
// put in a table, so it is exactly what a warning is for.
func TestForwardWithNoPortConstraintIsANote(t *testing.T) {
	r := facts.Rule{Handle: 11, Exprs: []facts.Expr{
		{Kind: facts.ExprImmediate, Immediate: &facts.ImmediateExpr{Register: 1, Data: targetHex}},
		{Kind: facts.ExprNAT, NAT: &facts.NATExpr{Type: "dnat", Family: "ip", AddrRegister: 1}},
	}}

	eps, notes := forwards(rulesetOf(natPrerouting(r)))
	if len(eps) != 0 || len(notes) != 1 {
		t.Fatalf("eps = %+v, notes = %+v, want no endpoint and one note", eps, notes)
	}
	if !strings.Contains(notes[0].Message, "every port") {
		t.Errorf("note = %q, want it to say the rule forwards every port", notes[0].Message)
	}
	if !strings.Contains(notes[0].Message, "192.0.2.50") {
		t.Errorf("note = %q, want it to name where the packets go", notes[0].Message)
	}
}

// Only a destination rewrite on the inbound path counts. Source NAT
// happens in postrouting, which whyopen does not walk, and a rewrite in
// the output hook acts on traffic this host sent.
func TestOnlyPreroutingDestinationRewritesAreScanned(t *testing.T) {
	snat := facts.Rule{Handle: 12, Exprs: []facts.Expr{
		{Kind: facts.ExprImmediate, Immediate: &facts.ImmediateExpr{Register: 1, Data: targetHex}},
		{Kind: facts.ExprNAT, NAT: &facts.NATExpr{Type: "snat", Family: "ip", AddrRegister: 1}},
	}}
	out := natPrerouting(forwardRule(13, "tcp", 9999, targetHex, 80))
	out.Chains[0].Hook = "output"

	eps, notes := forwards(rulesetOf(natPrerouting(snat), out))
	if len(eps) != 0 || len(notes) != 0 {
		t.Fatalf("eps = %+v, notes = %+v, want nothing from either", eps, notes)
	}
}

// The address family comes from the table, and for an inet table from the
// rewrite target: a packet cannot be rewritten to an address of the other
// family.
func TestForwardFamilyFollowsTheTableAndTheTarget(t *testing.T) {
	v6 := natPrerouting(forwardRule(14, "tcp", 8080, targetHex, 80))
	v6.Family = "ip6"
	if eps, _ := forwards(rulesetOf(v6)); len(eps) != 1 || eps[0].Family != "ip6" {
		t.Fatalf("eps = %+v, want one ip6 endpoint", eps)
	}

	both := natPrerouting(forwardRule(15, "tcp", 8080, targetHex, 80))
	both.Family = "inet"
	if eps, _ := forwards(rulesetOf(both)); len(eps) != 1 || eps[0].Family != "ip" {
		t.Fatalf("eps = %+v, want one ip endpoint: the target is an IPv4 address", eps)
	}
}

// Two rules forwarding the same port produce one row. The traversal takes
// the first rule that matches, and so does the label on the row.
func TestTwoRulesForwardingOnePortAreOneEndpoint(t *testing.T) {
	eps, _ := forwards(rulesetOf(natPrerouting(
		forwardRule(16, "tcp", 8080, targetHex, 80),
		forwardRule(17, "tcp", 8080, "c0000233", 80),
	)))
	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want 1: %+v", len(eps), eps)
	}
	if !strings.Contains(eps[0].Owner, "192.0.2.50") {
		t.Errorf("owner = %q, want the first rule's target", eps[0].Owner)
	}
}

// A port that already has a row keeps it. That endpoint's own evaluation
// walks the same prerouting hook and follows the same rewrite, so a
// second row would say the same thing twice under a different name, which
// is what a Docker host would otherwise get for every published port.
func TestAForwardedPortWithASocketIsNotReportedTwice(t *testing.T) {
	f := hostFacts()
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{natPrerouting(forwardRule(18, "tcp", 8080, targetHex, 80))}}
	f.Sockets = []facts.Socket{{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 8080, Unit: "svc.service"}}

	var kinds []string
	for _, e := range endpoints(f) {
		if e.Port == 8080 {
			kinds = append(kinds, e.Kind)
		}
	}
	if len(kinds) != 1 || kinds[0] != "socket" {
		t.Fatalf("endpoints on 8080 = %v, want the socket alone", kinds)
	}
}

// routerFacts is hostFacts plus the LAN the rewrites above forward into,
// which is what a router or a VM host looks like: a global address on one
// side, a private network on the other, and forwarding between them.
func routerFacts() facts.Facts {
	f := hostFacts()
	f.Host.Interfaces = append(f.Host.Interfaces, facts.Interface{
		Name: "lan0", Index: 4, Up: true,
		Addresses: []facts.Addr{{IP: "192.0.2.1", Prefix: 24, Family: "ip", Scope: "private"}},
	})
	return f
}

// forwardFilter accepts everything it forwards and delivers nothing
// locally, so the forward hook is the only thing deciding the verdict.
func forwardFilter() facts.Table {
	return facts.Table{Family: "inet", Name: "filter", Chains: []facts.Chain{
		{Name: "forward", Base: true, Hook: "forward", Policy: "accept"},
		{Name: "input", Base: true, Hook: "input", Policy: "drop"},
	}}
}

// The whole point: a port with no socket and no publish behind it, which
// this host forwards to a machine on its LAN, is reported and reported as
// reachable. Before the scan it produced no row at all, and a reader saw
// silence where the biggest exposure on the host was.
func TestForwardedPortIsReachableThroughTheForwardHook(t *testing.T) {
	f := routerFacts()
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{
		natPrerouting(forwardRule(20, "tcp", 8080, targetHex, 80)),
		forwardFilter(),
	}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(vs), vs)
	}
	v := vs[0]
	if v.Endpoint.Port != 8080 || v.Endpoint.Kind != forwardKind {
		t.Fatalf("endpoint = %+v, want the forwarded port", v.Endpoint)
	}
	if v.Result != "reachable" {
		t.Fatalf("result = %s (%s), want reachable: the rewrite lands on the LAN and the forward hook accepts",
			v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "192.0.2.50:80") {
		t.Errorf("reason = %q, want it to name where the packet goes", v.Reason)
	}
	// Every other reachable verdict ends at a socket on this host. This
	// one ends at the edge of what whyopen can see, and saying so is the
	// difference between a fact and a promise it cannot keep.
	if !strings.Contains(v.Reason, "not that anything answers") {
		t.Errorf("reason = %q, want it to stop short of claiming a listener", v.Reason)
	}
}

// The scan finds a rewrite anywhere in prerouting, including one gated on
// an address this host does not answer for. The traversal is what decides
// whether it applies, and where it does not the row says so rather than
// falling through to a locally delivered verdict for a port nothing here
// listens on.
func TestForwardedPortIsFilteredWhereNothingRewritesIt(t *testing.T) {
	r := forwardRule(21, "tcp", 8080, targetHex, 80)
	// ip daddr 192.0.2.9, an address on the LAN rather than the public one.
	r.Exprs = append([]facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "c0000209"}},
	}, r.Exprs...)

	f := routerFacts()
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{natPrerouting(r), forwardFilter()}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(vs), vs)
	}
	if vs[0].Result != "filtered" {
		t.Fatalf("result = %s (%s), want filtered: the rule matches another address",
			vs[0].Result, vs[0].Reason)
	}
	if !strings.Contains(vs[0].Reason, "nothing rewrites 8080/tcp here") {
		t.Errorf("reason = %q, want it to say the rewrite did not apply", vs[0].Reason)
	}
}
