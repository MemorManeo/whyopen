//go:build integration && linux

package integration

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/MemorManeo/whyopen/internal/probe"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/MemorManeo/whyopen/internal/collect"
	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// TestCaptureRecentPayload is a capture, not an assertion. It creates each
// variant of an xt recent match and prints what the kernel stored, so the
// decoder in the next task is written against real bytes. Run it with -v and
// copy the output into docs/decisions/0003.
//
// It asserts only that the payloads differ between variants; if they did not,
// the extension could not be decoded at all and the next task is impossible.
func TestCaptureRecentPayload(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables")

	ns := newNetns(t)
	// The two rules ufw limit ssh emits, plus the check variant for coverage.
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22",
		"-m", "conntrack", "--ctstate", "NEW", "-m", "recent", "--set", "--name", "SSH")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22",
		"-m", "conntrack", "--ctstate", "NEW",
		"-m", "recent", "--update", "--seconds", "30", "--hitcount", "6", "--name", "SSH",
		"-j", "DROP")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "23",
		"-m", "recent", "--rcheck", "--seconds", "60", "--name", "OTHER")

	payloads := captureXtPayloads(t, ns, "recent")
	if len(payloads) < 3 {
		t.Fatalf("expected at least 3 recent matches, got %d", len(payloads))
	}
	for i, p := range payloads {
		t.Logf("recent[%d] rev=%d len=%d hex=%s", i, p.rev, len(p.info), hex.EncodeToString(p.info))
	}
	for i := 0; i < len(payloads); i++ {
		for j := i + 1; j < len(payloads); j++ {
			if hex.EncodeToString(payloads[i].info) == hex.EncodeToString(payloads[j].info) {
				t.Fatalf("payloads[%d] and payloads[%d] are byte-identical, so those two modes cannot be told apart", i, j)
			}
		}
	}
}

type xtPayload struct {
	rev  uint32
	info []byte
}

// captureXtPayloads reads the raw bytes of every xt match with the given name.
// It reaches for the netlink library directly rather than going through the
// collector, because the collector deliberately discards payloads it cannot
// decode, which is exactly what we are here to look at.
func captureXtPayloads(t *testing.T, ns string, name string) []xtPayload {
	t.Helper()
	var out []xtPayload
	inNetns(t, ns, func() {
		c, err := nftables.New()
		if err != nil {
			t.Fatalf("netlink: %v", err)
		}
		tables, err := c.ListTables()
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, tbl := range tables {
			chains, err := c.ListChainsOfTableFamily(tbl.Family)
			if err != nil {
				continue
			}
			for _, ch := range chains {
				if ch.Table.Name != tbl.Name || ch.Table.Family != tbl.Family {
					continue
				}
				rules, err := c.GetRules(tbl, ch)
				if err != nil {
					continue
				}
				for _, r := range rules {
					for _, e := range r.Exprs {
						m, ok := e.(*expr.Match)
						if !ok || m.Name != name {
							continue
						}
						if u, ok := m.Info.(*xt.Unknown); ok {
							out = append(out, xtPayload{rev: m.Rev, info: []byte(*u)})
						}
					}
				}
			}
		}
	})
	return out
}

// TestCaptureFirewalldExpressions is a capture, not an assertion of
// behaviour. UFW and Docker reach the kernel through iptables-nft, so
// whyopen already decodes the xt compatibility expressions they produce.
// firewalld, and any hand-written nft ruleset, goes straight to native
// nftables expressions instead, and whyopen has almost no decoder for
// those. This test does not install firewalld: what matters is the
// ruleset shape it emits, not the daemon, so the shape is written directly
// with nft -f inside a namespace, using the constructs firewalld actually
// generates: an inet family table, a base chain with a hook and priority,
// named and anonymous sets, both the comma-list and brace-list forms of a
// ct state match, a meta l4proto match, jumps and a goto into zone chains,
// and an iifname match both directly and through a named set.
//
// It records the Go type of every expression google/nftables returns for
// every rule, split into what whyopen's own converter already decodes and
// what it reports as unknown, and logs nft's own "list ruleset" text
// alongside it. The two are meant to be compared by eye: google/nftables
// silently drops any kernel expression whose name is not in its own
// exprFromName table (it returns nil and the caller skips it), so a
// statement visible in the nft text with no matching Go type in the log
// below is that gap, not a bug in this test.
//
// It also enforces decision 0004's two specific claims by name, named
// individually rather than merely counted: a stray count would stay green
// as long as some other shape happened to be undecoded, letting a
// regression in either decoder go unnoticed. Native ct state (*expr.Ct)
// was decoded for the comma-list shape ("ct state established,related
// accept"). Set membership (*expr.Lookup, produced here by the interface
// set, the port set, the "meta l4proto { tcp, udp }" match and the
// anonymous ct-state set the brace-list rule compiles to) was decoded too
// (both in v0.2, this record's original scope), which is what let the
// brace-list shape ("ct state { established, related } accept") resolve at
// all: it depends on both decoders, since it compiles to Ct followed by
// Lookup rather than the comma-list's Ct/Bitwise/Cmp. With both native
// types this ruleset exercises now decoded, every expression it produces
// is expected to be known; this guard used to double as a staleness check
// for that (failing if nothing at all was left unknown, since that would
// mean this synthetic ruleset no longer exercised what it was written to),
// but with nothing left undecoded here by design, it now checks only that
// Ct and Lookup specifically have not regressed back to unknown.
func TestCaptureFirewalldExpressions(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft")

	ns := newNetns(t)

	// Leaf chains are declared before the chains that jump into them so
	// this file does not depend on nft resolving a forward reference
	// within the same batch.
	const firewalldRuleset = `
table inet whyopen_fw {
	set zone_public_ifaces {
		type ifname
		elements = { "wan0" }
	}

	set zone_public_ports {
		type inet_service
		elements = { 22, 8080 }
	}

	chain filter_IN_public_allow {
		ct state { established, related } accept
		tcp dport @zone_public_ports accept
		meta l4proto { tcp, udp } counter accept
	}

	chain filter_IN_public_deny {
		tcp dport 31337 counter drop
	}

	chain filter_IN_public {
		jump filter_IN_public_allow
		jump filter_IN_public_deny
	}

	chain filter_INPUT_ZONES {
		iifname @zone_public_ifaces goto filter_IN_public
		goto filter_IN_public
	}

	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state established,related accept
		ct state invalid drop
		iifname "lo" accept
		jump filter_INPUT_ZONES
		reject with icmpx type admin-prohibited
	}
}
`
	applyNftRuleset(t, ns, firewalldRuleset)

	listing := nsRun(t, ns, "nft", "-a", "list", "ruleset")
	t.Logf("nft -a list ruleset:\n%s", listing)

	census := captureFirewalldExprs(t, ns)
	if census.ruleCount == 0 {
		t.Fatalf("no rules found over netlink; the ruleset did not apply")
	}
	logExprCounts(t, "decoded", census.known)
	logExprCounts(t, "unknown", census.unknown)

	// Ct and Lookup are decision 0004's two named native types (both
	// decoded in v0.2), asserted individually and in both directions so
	// that either one regressing back to unknown fails this test rather
	// than being masked by the other still being decoded.
	for _, want := range []string{
		fmt.Sprintf("%T", &expr.Ct{}),
		fmt.Sprintf("%T", &expr.Lookup{}),
	} {
		if census.known[want] == 0 {
			t.Fatalf("expected %s among the expressions whyopen decodes, found none: its decoder may have regressed. Known census: %v", want, census.known)
		}
		if census.unknown[want] != 0 {
			t.Fatalf("expected %s to no longer be reported unknown, but it still was. Unknown census: %v", want, census.unknown)
		}
	}
	// With both decoded, this specific ruleset is expected to produce no
	// unknown expressions at all (see decision 0004's "Update (v0.2,
	// continued): Lookup" section): every construct it was written to
	// exercise now has a case.
	// A nonempty census here means some OTHER expression in this ruleset
	// stopped decoding, or the nftables library started emitting a shape
	// this test was not written to expect; either way it needs a look, not
	// a silent pass.
	if len(census.unknown) != 0 {
		t.Fatalf("expected no unknown expressions left for this ruleset now that Ct and Lookup both decode, got: %v", census.unknown)
	}
}

// applyNftRuleset writes ruleset to a file and loads it inside the
// namespace with nft -f. nsRun's underlying exec.Command has no stdin
// support, and a file also matches how firewalld itself applies a
// ruleset: one atomic load, not a sequence of incremental edits.
func applyNftRuleset(t *testing.T, ns string, ruleset string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ruleset.nft")
	if err := os.WriteFile(path, []byte(ruleset), 0o644); err != nil {
		t.Fatalf("write ruleset: %v", err)
	}
	nsRun(t, ns, "nft", "-f", path)
}

// exprCensus tallies, by Go type name, every expression google/nftables
// returned for the applied ruleset, split by whether whyopen's own
// converter (collect.ConvertExprs) decodes it or reports it unknown.
type exprCensus struct {
	ruleCount int
	known     map[string]int
	unknown   map[string]int
}

// captureFirewalldExprs reads every rule of every chain of every table in
// the namespace over netlink, the same call sequence collectIn's binary
// uses internally, but keeps the raw expr.Any values so it can report the
// Go type of each one rather than only whyopen's decoded facts.Expr.
func captureFirewalldExprs(t *testing.T, ns string) exprCensus {
	t.Helper()
	c := exprCensus{known: map[string]int{}, unknown: map[string]int{}}
	inNetns(t, ns, func() {
		conn, err := nftables.New()
		if err != nil {
			t.Fatalf("netlink: %v", err)
		}
		tables, err := conn.ListTables()
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, tbl := range tables {
			chains, err := conn.ListChainsOfTableFamily(tbl.Family)
			if err != nil {
				continue
			}
			for _, ch := range chains {
				if ch.Table.Name != tbl.Name || ch.Table.Family != tbl.Family {
					continue
				}
				rules, err := conn.GetRules(tbl, ch)
				if err != nil {
					continue
				}
				for _, r := range rules {
					c.ruleCount++
					converted := collect.ConvertExprs(r.Exprs)
					types := make([]string, 0, len(r.Exprs))
					for i, e := range r.Exprs {
						goType := fmt.Sprintf("%T", e)
						types = append(types, goType)
						if i < len(converted) && converted[i].Kind == facts.ExprUnknown {
							c.unknown[goType]++
						} else {
							c.known[goType]++
						}
					}
					t.Logf("table=%s chain=%s handle=%d exprs=%v", tbl.Name, ch.Name, r.Handle, types)
				}
			}
		}
	})
	return c
}

// logExprCounts logs a sorted, deterministic view of a census map. Sorted
// because Go randomises map iteration and this output is meant to be
// copied into a decision record by hand.
func logExprCounts(t *testing.T, label string, counts map[string]int) {
	t.Helper()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%s: %s x%d", label, k, counts[k])
	}
}

// TestCaptureRanges is a capture, not an assertion. `tcp dport 1024-2048`
// is the last ordinary construct whyopen reports unknown, and decision
// 0004's firewalld capture never produced one because nothing in that
// ruleset wrote a range. This writes several deliberately and prints what
// google/nftables returns for each, so the decoder is written against what
// the kernel actually stores rather than against what the header implies.
//
// It asserts only that a range reaches whyopen at all: if the library
// dropped it the way it drops expressions it cannot name, no decoder is
// possible and that is the finding.
func TestCaptureRanges(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft")

	ns := newNetns(t)
	applyNftRuleset(t, ns, `
table inet cap {
	set ports_interval {
		type inet_service
		flags interval
		elements = { 100-200, 8080 }
	}

	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 1024-2048 accept
		tcp dport != 3000-4000 accept
		tcp dport @ports_interval accept
		tcp dport { 5000-5100, 6000 } accept
	}
}
`)

	inNetns(t, ns, func() {
		conn, err := nftables.New()
		if err != nil {
			t.Fatalf("netlink: %v", err)
		}
		tables, err := conn.ListTables()
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, tbl := range tables {
			if tbl.Name != "cap" {
				continue
			}
			// The sets first: an interval set's elements are how a range
			// is stored when it is a set member, and whether the kernel
			// hands back a key with an end or two elements with a flag is
			// exactly what cannot be guessed.
			sets, err := conn.GetSets(tbl)
			if err != nil {
				t.Fatalf("get sets: %v", err)
			}
			for _, s := range sets {
				t.Logf("set %q anon=%v interval=%v ismap=%v keytype=%s/%d bytes",
					s.Name, s.Anonymous, s.Interval, s.IsMap, s.KeyType.Name, s.KeyType.Bytes)
				elems, err := conn.GetSetElements(s)
				if err != nil {
					t.Logf("  elements: %v", err)
					continue
				}
				for i, e := range elems {
					t.Logf("  elem[%d] key=%s keyend=%s intervalend=%v val=%s",
						i, hex.EncodeToString(e.Key), hex.EncodeToString(e.KeyEnd), e.IntervalEnd, hex.EncodeToString(e.Val))
				}
			}

			chains, err := conn.ListChainsOfTableFamily(tbl.Family)
			if err != nil {
				t.Fatalf("list chains: %v", err)
			}
			for _, ch := range chains {
				if ch.Table.Name != tbl.Name {
					continue
				}
				rules, err := conn.GetRules(tbl, ch)
				if err != nil {
					t.Fatalf("get rules: %v", err)
				}
				sawRange := false
				for _, r := range rules {
					var types []string
					for _, e := range r.Exprs {
						types = append(types, fmt.Sprintf("%T", e))
						if rng, ok := e.(*expr.Range); ok {
							sawRange = true
							t.Logf("rule %d: expr.Range op=%d register=%d from=%s to=%s",
								r.Handle, rng.Op, rng.Register,
								hex.EncodeToString(rng.FromData), hex.EncodeToString(rng.ToData))
						}
						if lk, ok := e.(*expr.Lookup); ok {
							t.Logf("rule %d: expr.Lookup set=%q id=%d invert=%v",
								r.Handle, lk.SetName, lk.SetID, lk.Invert)
						}
					}
					t.Logf("rule %d exprs: %v", r.Handle, types)
				}
				if !sawRange {
					t.Error("no *expr.Range in any rule: either the kernel compiled these ranges " +
						"to something else, or the library dropped them before whyopen could see them")
				}
			}
		}
	})
}

// TestCaptureRecentRemove captures the one xt recent check_set bit pattern
// decision 0003 could not: --remove. The other three were captured from a
// live kernel and the fourth was left undecoded rather than inferred from
// the pattern they follow, which is why a --remove rule still reports
// unknown. This is the capture that closes it.
func TestCaptureRecentRemove(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables")

	ns := newNetns(t)
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22",
		"-m", "recent", "--remove", "--name", "SSH")
	// A second variant, so the capture shows which bits are the mode and
	// which are the name, rather than one payload with nothing to compare.
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "23",
		"-m", "recent", "--remove", "--name", "OTHER")

	payloads := captureXtPayloads(t, ns, "recent")
	if len(payloads) < 2 {
		t.Fatalf("expected 2 recent matches, got %d", len(payloads))
	}
	for i, p := range payloads {
		t.Logf("recent-remove[%d] rev=%d len=%d hex=%s", i, p.rev, len(p.info), hex.EncodeToString(p.info))
	}
}

// TestCaptureTopOfRangeInterval is the capture decision 0011 said this
// would need. An interval reaching the top of the type's range has an
// exclusive end of 65536, which does not fit in the two bytes an
// inet_service key has, so whyopen refuses it rather than assume the end
// wraps to zero and is distinguishable from the sentinel below the first
// interval. This writes one and prints what the kernel actually stores.
func TestCaptureTopOfRangeInterval(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft")

	ns := newNetns(t)
	applyNftRuleset(t, ns, `
table inet cap2 {
	set to_the_top {
		type inet_service
		flags interval
		elements = { 1024-65535 }
	}

	set from_the_bottom {
		type inet_service
		flags interval
		elements = { 0-1023 }
	}

	# The shapes that decide whether a wrapped end can be told apart from
	# the sentinel below the first interval: one where a top interval sits
	# beside an ordinary one, and one where the set also starts at zero, so
	# key 0 would have to be both a start and an end.
	set top_and_middle {
		type inet_service
		flags interval
		elements = { 100-200, 1024-65535 }
	}

	set bottom_and_top {
		type inet_service
		flags interval
		elements = { 0-100, 1024-65535 }
	}

	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport @to_the_top accept
		tcp dport @from_the_bottom accept
		tcp dport @top_and_middle accept
		tcp dport @bottom_and_top accept
		tcp dport 1024-65535 accept
	}
}
`)

	inNetns(t, ns, func() {
		conn, err := nftables.New()
		if err != nil {
			t.Fatalf("netlink: %v", err)
		}
		tables, err := conn.ListTables()
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, tbl := range tables {
			if tbl.Name != "cap2" {
				continue
			}
			sets, err := conn.GetSets(tbl)
			if err != nil {
				t.Fatalf("get sets: %v", err)
			}
			for _, s := range sets {
				t.Logf("set %q interval=%v", s.Name, s.Interval)
				elems, err := conn.GetSetElements(s)
				if err != nil {
					t.Logf("  elements: %v", err)
					continue
				}
				for i, e := range elems {
					t.Logf("  elem[%d] key=%s keyend=%s intervalend=%v",
						i, hex.EncodeToString(e.Key), hex.EncodeToString(e.KeyEnd), e.IntervalEnd)
				}
			}
			chains, _ := conn.ListChainsOfTableFamily(tbl.Family)
			for _, ch := range chains {
				if ch.Table.Name != tbl.Name {
					continue
				}
				rules, _ := conn.GetRules(tbl, ch)
				for _, r := range rules {
					var types []string
					for _, e := range r.Exprs {
						types = append(types, fmt.Sprintf("%T", e))
						if c, ok := e.(*expr.Cmp); ok {
							t.Logf("rule %d: cmp op=%d data=%s", r.Handle, c.Op, hex.EncodeToString(c.Data))
						}
					}
					t.Logf("rule %d exprs: %v", r.Handle, types)
				}
			}
		}
	})
}

// TestCaptureFib captures firewalld's reverse-path check, the one
// construct a running daemon emits that whyopen cannot decode. It makes
// every IPv6 verdict on such a host unknown, so it is the largest
// user-visible gap left, and closing it starts here: what the expression
// carries, and what the rule around it does with the result.
//
// Both the rule firewalld writes and the plainer `fib daddr type local`
// shape are applied, because the second is what the addrtype match
// whyopen already decodes compiles to natively, and knowing whether they
// arrive the same way decides how much of this is one decoder.
func TestCaptureFib(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft")

	ns := newNetns(t)
	applyNftRuleset(t, ns, `
table inet cap3 {
	chain prerouting {
		type filter hook prerouting priority -300; policy accept;
		meta nfproto ipv6 fib saddr . mark . iif oif missing drop
		fib daddr type local accept
		fib saddr oif missing drop
	}
}
`)

	inNetns(t, ns, func() {
		conn, err := nftables.New()
		if err != nil {
			t.Fatalf("netlink: %v", err)
		}
		tables, err := conn.ListTables()
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, tbl := range tables {
			if tbl.Name != "cap3" {
				continue
			}
			chains, _ := conn.ListChainsOfTableFamily(tbl.Family)
			for _, ch := range chains {
				if ch.Table.Name != tbl.Name {
					continue
				}
				rules, _ := conn.GetRules(tbl, ch)
				for _, r := range rules {
					var types []string
					for _, e := range r.Exprs {
						types = append(types, fmt.Sprintf("%T", e))
						switch v := e.(type) {
						case *expr.Fib:
							t.Logf("rule %d: fib register=%d oif=%v oifname=%v addrtype=%v saddr=%v daddr=%v mark=%v iif=%v oifflag=%v present=%v",
								r.Handle, v.Register, v.ResultOIF, v.ResultOIFNAME, v.ResultADDRTYPE,
								v.FlagSADDR, v.FlagDADDR, v.FlagMARK, v.FlagIIF, v.FlagOIF, v.FlagPRESENT)
						case *expr.Cmp:
							t.Logf("rule %d: cmp op=%d register=%d data=%s", r.Handle, v.Op, v.Register, hex.EncodeToString(v.Data))
						}
					}
					t.Logf("rule %d exprs: %v", r.Handle, types)
				}
			}
		}
	})
}

// TestCaptureHandWrittenRuleset is a census, in the shape decision 0004
// used for firewalld and the firewalld CI job then used against the real
// daemon. Both of those covered a ruleset some *program* writes. This one
// covers the third audience the README claims, a ruleset a person wrote,
// and nothing has ever checked what that costs whyopen.
//
// The rules are the ones hardening guides actually tell people to write.
// It asserts nothing about which of them decode: it prints the census, so
// that what is missing is a list to work from rather than a surprise a
// user reports.
func TestCaptureHandWrittenRuleset(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft")

	ns := newNetns(t)
	applyNftRuleset(t, ns, `
table inet srv {
	set blocklist {
		type ipv4_addr
		flags interval
		elements = { 192.0.2.0/24 }
	}

	set admin_ifaces {
		type ifname
		elements = { "wg0" }
	}

	chain input {
		type filter hook input priority 0; policy drop;

		ct state established,related accept
		ct state invalid drop
		iif lo accept
		ip protocol icmp accept
		ip6 nexthdr icmpv6 accept
		ip saddr @blocklist drop
		iifname @admin_ifaces accept
		tcp dport { 22, 80, 443 } accept
		udp dport 51820 accept
		tcp dport 8080 limit rate 10/minute accept
		tcp flags syn / fin,syn,rst,ack accept
		meta skuid 0 accept
		ip saddr 10.0.0.0/8 tcp dport 3306 accept
		counter comment "fell through"
	}
}
`)

	census := captureFirewalldExprs(t, ns)
	t.Logf("hand-written ruleset: %d rules", census.ruleCount)
	for name, n := range census.known {
		t.Logf("  decoded   %s x%d", name, n)
	}
	for name, n := range census.unknown {
		t.Logf("  UNDECODED %s x%d", name, n)
	}
	if census.ruleCount == 0 {
		t.Fatal("no rules read, so this census asserted nothing")
	}
}

// TestCaptureSkuidOnInput answers a question by experiment rather than by
// reading documentation. `meta skuid` names the owner of the socket a
// packet belongs to, which is a natural thing to write in an output
// chain; whether it means anything on the input path, where the socket
// has not been looked up yet, decides whether whyopen can resolve it or
// must keep refusing it and leaving every verdict below unknown.
//
// The kernel is asked directly: a chain that drops by default and accepts
// only `meta skuid 0`, a listener owned by root behind it, and a real
// probe across the veth. If the port answers, the match resolved on the
// input path and whyopen could model it, because a facts document already
// carries every socket's uid. If it does not, the match never fires
// inbound and whyopen could resolve it as a plain no-match.
//
// It began by asserting only that the two outcomes were told apart. The
// answer settled decision 0013, and it now asserts both the kernel's
// behaviour and whyopen agreeing with it.
func TestCaptureSkuidOnInput(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft", "python3")

	ns := newNetns(t)
	listenIn(t, ns, "0.0.0.0", "8080")
	applyNftRuleset(t, ns, `
table inet skuidcap {
	chain input {
		type filter hook input priority 0; policy drop;
		meta skuid 0 accept
	}
}
`)

	// The probe runs in the root namespace, so this crosses the veth as a
	// real packet rather than being reasoned about.
	res := probe.Run(context.Background(), probe.Options{
		Target: "203.0.113.10", Ports: []uint16{8080}, Timeout: 3 * time.Second,
	})
	if len(res) != 1 {
		t.Fatalf("probe returned %d results", len(res))
	}
	// The finding, recorded in decision 0013: the match did not fire, so
	// the port fell through to the drop policy. This began as a capture
	// that logged whichever way it went; now that whyopen models it, the
	// experiment is worth keeping as the assertion it became.
	if res[0].State != probe.StateFiltered {
		t.Fatalf("probe = %s (%s), want filtered: `meta skuid 0` should not match on the input "+
			"path, and if it now does, decision 0013 needs revisiting", res[0].State, res[0].Detail)
	}

	// And whyopen has to say the same thing the wire did. Agreeing with a
	// probe on the same host is the strongest check this suite can make of
	// a model that exists to predict exactly that.
	v := verdictFor(evaluate(collectIn(t, ns)), 8080, "ip")
	if v == nil {
		t.Fatal("no verdict for 8080")
	}
	if v.Result != "filtered" {
		t.Fatalf("whyopen says 8080 is %s (%s), but the probe found it filtered", v.Result, v.Reason)
	}
}

// TestCaptureNativeDNAT captures what a hand-written `dnat to` compiles
// to. Docker reaches the kernel through iptables-nft, so its port
// forwards arrive as an xt DNAT target whyopen has decoded since v0.1; a
// router or VM host writing the rule itself produces a native nat
// expression instead, which whyopen does not decode at all.
//
// expr.NAT carries register numbers rather than an address, so the
// address and port must be loaded by something before it. What that
// something is, and in which registers, is the thing to capture.
func TestCaptureNativeDNAT(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft")

	ns := newNetns(t)
	applyNftRuleset(t, ns, `
table ip natcap {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 8080 dnat to 192.0.2.50:80
		tcp dport 8081 dnat to 192.0.2.51
		tcp dport 8082 redirect to :90
	}
}
`)

	inNetns(t, ns, func() {
		conn, err := nftables.New()
		if err != nil {
			t.Fatalf("netlink: %v", err)
		}
		tables, err := conn.ListTables()
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, tbl := range tables {
			if tbl.Name != "natcap" {
				continue
			}
			chains, _ := conn.ListChainsOfTableFamily(tbl.Family)
			for _, ch := range chains {
				if ch.Table.Name != tbl.Name {
					continue
				}
				rules, _ := conn.GetRules(tbl, ch)
				for _, r := range rules {
					var types []string
					for _, e := range r.Exprs {
						types = append(types, fmt.Sprintf("%T", e))
						switch v := e.(type) {
						case *expr.Immediate:
							t.Logf("rule %d: immediate reg=%d data=%s", r.Handle, v.Register, hex.EncodeToString(v.Data))
						case *expr.NAT:
							t.Logf("rule %d: nat type=%d family=%d addrmin=%d addrmax=%d protomin=%d protomax=%d specified=%v",
								r.Handle, v.Type, v.Family, v.RegAddrMin, v.RegAddrMax, v.RegProtoMin, v.RegProtoMax, v.Specified)
						}
					}
					t.Logf("rule %d exprs: %v", r.Handle, types)
				}
			}
		}
	})
}
