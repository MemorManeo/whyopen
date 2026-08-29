//go:build integration && linux

// Package integration exercises whyopen against a real kernel. These tests
// create network namespaces, apply real rulesets and run the real binary, so
// they need root and are excluded from the default build by a tag. The
// shipped code stays read-only; only this suite mutates anything.
package integration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

// binaryPath is the whyopen binary under test, built once by TestMain.
var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "whyopen-it")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "whyopen")

	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/whyopen")
	build.Dir = "../.."
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build whyopen: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: creates network namespaces and firewall rules")
	}
}

func requireTools(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("needs %q on PATH", n)
		}
	}
}

// run executes a command and fails the test on a non-zero exit, reporting the
// combined output, which is where iptables and nft put their diagnostics.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// newNetns creates a namespace wired to a veth pair whose namespace side
// carries a global-scope documentation address. Global scope is what makes
// whyopen treat it as internet-facing: an RFC1918 address would be classified
// private and every verdict would be filtered for the wrong reason.
func newNetns(t *testing.T) string {
	t.Helper()
	// Interface names are capped at 15 bytes, so keep the suffix short.
	ns := fmt.Sprintf("wo%d", os.Getpid()%100000)
	hostSide := "veth-" + ns
	nsSide := "vethn-" + ns

	// The name derives from the pid, so it can recur across runs. A run
	// killed by a CI timeout skips its own cleanup and leaves the namespace
	// behind, which would otherwise fail this add with "File exists" for a
	// reason that has nothing to do with the code under test. Its absence
	// here is the common case, not a failure.
	exec.Command("ip", "netns", "del", ns).Run()

	run(t, "ip", "netns", "add", ns)
	t.Cleanup(func() {
		exec.Command("ip", "netns", "del", ns).Run()
		exec.Command("ip", "link", "del", hostSide).Run()
	})

	run(t, "ip", "link", "add", hostSide, "type", "veth", "peer", "name", nsSide)
	run(t, "ip", "link", "set", nsSide, "netns", ns)
	run(t, "ip", "addr", "add", "203.0.113.1/24", "dev", hostSide)
	run(t, "ip", "link", "set", hostSide, "up")

	nsRun(t, ns, "ip", "link", "set", "lo", "up")
	nsRun(t, ns, "ip", "addr", "add", "203.0.113.10/24", "dev", nsSide)
	nsRun(t, ns, "ip", "link", "set", nsSide, "up")
	return ns
}

func nsRun(t *testing.T, ns string, name string, args ...string) string {
	t.Helper()
	return run(t, "ip", append([]string{"netns", "exec", ns, name}, args...)...)
}

// collectIn runs the real binary inside the namespace and decodes its facts
// document. Running the binary rather than calling the collector in-process
// avoids setns and thread pinning, and tests the path a user actually takes.
func collectIn(t *testing.T, ns string) facts.Facts {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", ns, binaryPath, "collect").Output()
	if err != nil {
		t.Fatalf("collect in %s: %v", ns, err)
	}
	var f facts.Facts
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatalf("decode facts: %v", err)
	}
	if f.Ruleset.ReadFailed {
		t.Fatalf("ruleset read failed inside the namespace, warnings: %+v", f.Warnings)
	}
	return f
}

// verdictFor finds one verdict, or nil. Tests assert on the pointer being
// non-nil so a missing endpoint fails loudly rather than silently passing.
func verdictFor(vs []model.Verdict, port uint16, family string) *model.Verdict {
	for i := range vs {
		if vs[i].Endpoint.Port == port && vs[i].Family == family {
			return &vs[i]
		}
	}
	return nil
}

// evaluate is the standard pipeline the tests assert against.
func evaluate(f facts.Facts) []model.Verdict {
	return model.Evaluate(f, model.InternetZone())
}

// startBackground runs a long-lived process inside the namespace and kills it
// during cleanup. It waits up to 10 seconds for the process to write ready as
// a line on its stderr before returning, so tests never race the listener. A
// line that does not match ready fails the test with what was actually read,
// which surfaces a startup traceback where it is useful instead of letting it
// masquerade as readiness; an early exit or a stall past the deadline fails
// the test immediately too, rather than hanging until the suite's own
// timeout kills the whole binary.
func startBackground(t *testing.T, ns string, ready string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns, name}, args...)...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	// A single goroutine owns cmd.Wait for the rest of this helper's life:
	// calling it more than once, or concurrently with itself from a second
	// goroutine, races the *exec.Cmd internal state. Cleanup below waits on
	// waitDone rather than calling Wait itself, so kill-and-wait still
	// happens, just funnelled through this one call site.
	var waitErr error
	waitDone := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(waitDone)
	}()
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-waitDone
	})

	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		if scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	select {
	case line := <-lines:
		if line != ready {
			t.Fatalf("%s did not signal readiness on stderr: got %q, want %q", name, line, ready)
		}
	case <-waitDone:
		t.Fatalf("%s exited before signalling readiness: %v", name, waitErr)
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not signal readiness within 10s", name)
	}
}
