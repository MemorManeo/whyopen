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
//
// It does not set an INPUT deny policy the way the namespace sibling
// (TestPublishOnAllInterfacesIsReachableDespiteInputDeny) does, on purpose.
// This test runs in the runner's root namespace, not an isolated one; an
// INPUT drop policy there with no established-accept rule would also cut the
// Actions agent's own return traffic and hang or fail the job in a way that
// looks unrelated to this test. The "reachable despite an input-chain deny"
// half of the claim is already proven safely by that sibling; this test's
// job is only to prove the same forward-hook mechanism holds against rules
// Docker itself wrote, not to re-prove the deny half here too.
func TestRealDockerPublishIsReported(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "docker")

	// A CI runner sits behind NAT with only private addresses, and whyopen
	// correctly refuses to conclude anything about a host with no global
	// address. Give it one so the test asserts something.
	//
	// Pre-delete it for the same reason the namespace harness pre-deletes
	// its netns and this test pre-sweeps its container: a run killed by a
	// CI timeout skips its own cleanup, and a leftover whyopen0 would fail
	// this add with "File exists" for a reason unrelated to the code under
	// test. It matters more here than for the namespace, because the
	// leftover interface keeps carrying a global-scope address and so
	// changes what whyopen reports about the host itself. Its absence is
	// the common case, not a failure.
	exec.Command("ip", "link", "del", "whyopen0").Run()
	run(t, "ip", "link", "add", "whyopen0", "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "whyopen0").Run() })
	run(t, "ip", "addr", "add", "203.0.113.10/32", "dev", "whyopen0")
	run(t, "ip", "link", "set", "whyopen0", "up")

	// Cleanup is registered before the container is created, not after,
	// because "docker run -d" can create the container and then fail to
	// start it (a collision on port 18080 from a stale prior run is the
	// realistic case), and run() calls t.Fatalf, which runs t.Cleanup but
	// never returns to this function. Without the early registration that
	// path would leave a container behind, still publishing a port. "docker
	// rm -f" against a container that does not exist is harmless, which is
	// why the pre-emptive sweep below already works and why registering
	// early costs nothing.
	const name = "whyopen-integration"
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	exec.Command("docker", "rm", "-f", name).Run()
	run(t, "docker", "run", "-d", "--name", name,
		"-p", "0.0.0.0:18080:80", "nginx:alpine")

	// Combined output, and both failures report it, for the reason
	// collectIn takes it: a CI log is the only evidence this run leaves.
	out, err := exec.Command(binaryPath, "collect").CombinedOutput()
	if err != nil {
		t.Fatalf("collect: %v\noutput:\n%s", err, out)
	}
	var f facts.Facts
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("decode facts: %v\noutput:\n%s", err, out)
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

	// The reason string names DNAT regardless of which hook the packet was
	// evaluated against, so it cannot by itself distinguish a real forward
	// traversal from a regression that misclassifies the container's bridge
	// address as local and evaluates against input instead. Assert on the
	// path directly, the way TestPublishOnAllInterfacesIsReachableDespiteInputDeny
	// does in ruleset_test.go: a forward hit must be present and no input
	// hit may appear.
	var sawForward, sawInput bool
	for _, h := range v.Path {
		switch h.Hook {
		case "forward":
			sawForward = true
		case "input":
			sawInput = true
		}
	}
	if !sawForward || sawInput {
		t.Errorf("path hooks wrong (forward=%v input=%v): the DNAT'd packet must take the forward hook only",
			sawForward, sawInput)
	}
}

// The last fixture the original spec named and no test had: a dead
// publish, a DNAT with nothing listening behind it. Every other test in
// this suite starts a listener, because whyopen derives endpoints from
// listening sockets and Docker publishes, so this is the one shape none of
// them reaches: nginx listens on 80, and this publishes 9999.
//
// What it pins down is that whyopen reports the firewall path and does not
// overstate it. The endpoint exists and is reachable, because that is a
// claim about the rules: nothing between the internet and the container
// stops the packet. Whether anything answers is a different question, and
// whyopen cannot see into the container's own namespace to ask it. This is
// exactly the gap `check --probe-from` exists to close, and it is why a
// reachable verdict on a publish is not a promise that a service is there.
func TestDeadPublishIsReportedWithoutOverstatingIt(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "docker")

	exec.Command("ip", "link", "del", "whyopen1").Run()
	run(t, "ip", "link", "add", "whyopen1", "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "whyopen1").Run() })
	run(t, "ip", "addr", "add", "203.0.113.11/32", "dev", "whyopen1")
	run(t, "ip", "link", "set", "whyopen1", "up")

	const name = "whyopen-dead-publish"
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	exec.Command("docker", "rm", "-f", name).Run()
	// 9999 is published and nothing in the container is listening on it.
	run(t, "docker", "run", "-d", "--name", name,
		"-p", "0.0.0.0:18081:9999", "nginx:alpine")

	out, err := exec.Command(binaryPath, "collect").CombinedOutput()
	if err != nil {
		t.Fatalf("collect: %v\noutput:\n%s", err, out)
	}
	var f facts.Facts
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("decode facts: %v\noutput:\n%s", err, out)
	}

	v := verdictFor(evaluate(f), 18081, "ip")
	if v == nil {
		t.Fatalf("no verdict for a publish with nothing behind it; publishes seen: %+v", f.Docker.Containers)
	}
	if v.Result != "reachable" {
		t.Fatalf("dead publish reported %s, want reachable: the rules do not stop the packet, "+
			"and whether anything answers is not something the ruleset can say: %s", v.Result, v.Reason)
	}
	// The reason has to name the rewrite, so a reader can see the packet is
	// being sent into a container whose listeners whyopen cannot see.
	if !strings.Contains(v.Reason, "DNAT") {
		t.Errorf("reason = %q, want it to name the DNAT rewrite", v.Reason)
	}
	if v.DNAT == nil || v.DNAT.Port != 9999 {
		t.Errorf("DNAT = %+v, want the rewrite to 9999 recorded", v.DNAT)
	}
	if v.Endpoint.Kind != "publish" {
		t.Errorf("kind = %q, want publish: there is no socket on this host to have found", v.Endpoint.Kind)
	}
}
