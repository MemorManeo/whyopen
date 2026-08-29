//go:build integration && linux

package integration

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// This test runs against the host's own network, not a namespace, because
// running Docker inside a namespace is its own project. It is safe on an
// ephemeral CI runner and deliberately not something to run on a machine you
// care about: it publishes a port on all interfaces for the duration.
func TestRealDockerPublishIsReported(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "docker")

	// A CI runner sits behind NAT with only private addresses, and whyopen
	// correctly refuses to conclude anything about a host with no global
	// address. Give it one so the test asserts something.
	run(t, "ip", "link", "add", "whyopen0", "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "whyopen0").Run() })
	run(t, "ip", "addr", "add", "203.0.113.10/32", "dev", "whyopen0")
	run(t, "ip", "link", "set", "whyopen0", "up")

	const name = "whyopen-integration"
	exec.Command("docker", "rm", "-f", name).Run()
	run(t, "docker", "run", "-d", "--name", name,
		"-p", "0.0.0.0:18080:80", "nginx:alpine")
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })

	out, err := exec.Command(binaryPath, "collect").Output()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var f facts.Facts
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("decode facts: %v", err)
	}
	if f.Ruleset.ReadFailed {
		t.Fatalf("ruleset read failed: %+v", f.Warnings)
	}

	v := verdictFor(evaluate(f), 18080, "ip")
	if v == nil {
		t.Fatalf("no verdict for the published port; docker publishes seen: %+v", f.Docker.Containers)
	}
	if v.Result != "reachable" {
		t.Fatalf("a container published on 0.0.0.0 reported %s, want reachable: %s", v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "DNAT") {
		t.Errorf("expected the reason to name the DNAT rewrite, got %q", v.Reason)
	}
	if v.Endpoint.Owner != name {
		t.Errorf("owner = %q, want the container name %q", v.Endpoint.Owner, name)
	}
}
