//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// All must never abort on a partial failure: a snapshot with warnings is
// more useful than no snapshot, and the warnings travel with the verdict.
func TestAllDegradesToWarnings(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	// No net/tcp, no docker socket, and netlink will fail unprivileged.
	got, err := All(Options{ProcRoot: proc, DockerSocket: filepath.Join(t.TempDir(), "absent.sock")})
	if err != nil {
		t.Fatalf("All returned a hard error on a degraded host: %v", err)
	}
	if got.SchemaVersion != facts.SchemaVersion {
		t.Fatalf("schema version = %d", got.SchemaVersion)
	}
	if got.CapturedAt.IsZero() {
		t.Fatalf("captured_at not set")
	}
	// Assert the exact set of sources, not just that some warning exists: a
	// regression that dropped one collector's warnings entirely would pass a
	// len > 0 check while hiding a whole unread part of the host.
	seen := map[string]bool{}
	for _, w := range got.Warnings {
		seen[w.Source] = true
	}
	want := []string{"docker", "host", "sockets"}
	if got.Ruleset.ReadFailed {
		// Netlink is unreadable without CAP_NET_ADMIN, which is the usual
		// case for this test. Under root the read succeeds and warns about
		// nothing, so the expectation follows what actually happened.
		want = append(want, "ruleset")
	}
	for _, src := range want {
		if !seen[src] {
			t.Fatalf("no warning from %q; sources seen: %v", src, sortedKeys(seen))
		}
		delete(seen, src)
	}
	if len(seen) != 0 {
		t.Fatalf("unexpected warning sources: %v", sortedKeys(seen))
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
