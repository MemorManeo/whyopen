//go:build integration && linux

package integration

import (
	"encoding/hex"
	"testing"

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
