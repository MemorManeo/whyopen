//go:build integration && linux

package integration

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

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
// It also enforces decision 0004's two specific claims by name: that
// native ct state (*expr.Ct, which has no case in ConvertExprs at all) and
// set membership (*expr.Lookup, likewise undecoded, produced here by the
// interface set, the port set and the "meta l4proto { tcp, udp }" match
// independently of one another) are both still among the expressions
// whyopen reports as unknown. Naming the two types is the point: merely
// counting distinct undecoded types would stay green once v0.2 decodes
// these two, as long as any other two shapes were still undecoded, and
// 0004 would go stale in silence.
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

	if len(census.unknown) == 0 {
		t.Fatalf("expected at least one expression whyopen currently reports as unknown, found none: either this shape no longer reaches the kernel as written, or whyopen has grown a decoder for everything this ruleset produces and this record is stale")
	}
	// The two types decision 0004 names as undecoded, asserted individually
	// so that decoding either one fails this test rather than being masked
	// by some other shape that happens to remain unknown.
	for _, want := range []string{
		fmt.Sprintf("%T", &expr.Ct{}),
		fmt.Sprintf("%T", &expr.Lookup{}),
	} {
		if census.unknown[want] == 0 {
			t.Fatalf("expected %s among the expressions whyopen reports as unknown, found none: decision 0004's claims no longer hold and docs/decisions/0004-firewalld-expressions.md needs revisiting. Unknown census: %v", want, census.unknown)
		}
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
