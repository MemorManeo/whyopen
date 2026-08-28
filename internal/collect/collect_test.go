//go:build linux

package collect

import (
	"os"
	"path/filepath"
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
	var sources []string
	for _, w := range got.Warnings {
		sources = append(sources, w.Source)
	}
	if len(sources) == 0 {
		t.Fatalf("expected warnings from the unreadable sources, got none")
	}
}
