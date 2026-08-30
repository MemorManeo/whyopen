//go:build integration && firewalld && linux

// This file is behind its own build tag because it needs a running
// firewalld, which the ordinary integration job neither has nor wants:
// starting firewalld rewrites the host's whole ruleset. It runs in a CI
// job of its own, on a runner that exists to be rearranged.
//
// It closes the largest untested claim whyopen makes. Everything the tool
// decodes for firewalld was captured from a firewalld-*shaped* ruleset
// applied by hand (decision 0004), which was a deliberate choice, since
// the ruleset is what whyopen reads and the daemon is not. But "shaped
// like" is a claim about a real daemon that nobody had checked.
package integration

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

func requireFirewalld(t *testing.T) {
	t.Helper()
	requireRoot(t)
	requireTools(t, "firewall-cmd", "ip")
	out, err := exec.Command("firewall-cmd", "--state").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "running") {
		t.Fatalf("firewalld is not running (%v): this suite exists to test against the daemon, "+
			"so a missing daemon is a failure of the job rather than a reason to skip", err)
	}
}

func collectHere(t *testing.T) facts.Facts {
	t.Helper()
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
	return f
}

// Every native expression a real firewalld emits must decode. This is
// decision 0004's census run against the daemon instead of against a
// ruleset written to imitate it: if firewalld reaches for something the
// hand-written one never did, this is where it shows up.
func TestFirewalldEmitsNothingWhyopenCannotDecode(t *testing.T) {
	requireFirewalld(t)

	f := collectHere(t)
	unknown := map[string]int{}
	undecodedXt := map[string]int{}
	rules := 0
	for _, tbl := range f.Ruleset.Tables {
		for _, ch := range tbl.Chains {
			for _, r := range ch.Rules {
				rules++
				for _, e := range r.Exprs {
					switch {
					case e.Kind == facts.ExprUnknown:
						unknown[e.Note]++
						// Where it is, so the construct can be found in
						// the nft text dumped below and decoded against
						// what firewalld actually wrote.
						t.Logf("undecoded %s at %s/%s handle %d", e.Note, tbl.Name, ch.Name, r.Handle)
					case e.Kind == facts.ExprXt && e.Xt != nil && !e.Xt.Decoded:
						undecodedXt[e.Xt.Name]++
					}
				}
			}
		}
	}
	// The ruleset in nft's own words, so a failure here is a capture and
	// not just a count: the handles logged above locate the construct.
	if out, err := exec.Command("nft", "-a", "list", "ruleset").CombinedOutput(); err == nil {
		t.Logf("nft -a list ruleset:\n%s", out)
	}
	t.Logf("firewalld ruleset: %d rules across %d tables", rules, len(f.Ruleset.Tables))
	if rules == 0 {
		t.Fatal("no rules at all, so this asserted nothing: firewalld cannot have been running")
	}
	// Logged rather than asserted: an xt extension whyopen leaves
	// undecoded is a known, documented gap with a name attached, and on a
	// CI runner these come from Docker rather than from firewalld.
	if len(undecodedXt) > 0 {
		t.Logf("undecoded xt extensions (not firewalld's, on a runner that also has Docker): %v", undecodedXt)
	}
	// Documented gaps, each one a construct whyopen refuses for a reason
	// rather than has not got to. Anything outside this list is a real
	// finding and fails the job, which is what this test is for.
	//
	// *expr.Fib: firewalld's IPv6 reverse-path check, `fib saddr . mark .
	// iif oif missing drop`. Whether that lookup finds a route back to
	// whyopen's synthetic source depends on the host's routing table,
	// which whyopen does not collect, so it cannot be answered. It sits
	// behind a `meta nfproto ipv6` test, so it only reaches IPv6 verdicts.
	documented := map[string]bool{"*expr.Fib": true}
	for name, count := range unknown {
		if !documented[name] {
			t.Errorf("firewalld emitted %s (%d times), which whyopen cannot decode and does not document", name, count)
		}
	}
}

// The verdicts, not just the parsing. A port firewalld was told to open is
// reachable and one it was not is filtered, which is the claim a user
// actually relies on.
func TestFirewalldOpenPortIsReachableAndOthersAreNot(t *testing.T) {
	requireFirewalld(t)

	// A CI runner sits behind NAT with only private addresses, and whyopen
	// correctly refuses to conclude anything about a host with no global
	// address. Give it one, the same way the Docker suite does.
	exec.Command("ip", "link", "del", "whyopen2").Run()
	run(t, "ip", "link", "add", "whyopen2", "type", "dummy")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "whyopen2").Run() })
	run(t, "ip", "addr", "add", "203.0.113.20/32", "dev", "whyopen2")
	run(t, "ip", "link", "set", "whyopen2", "up")

	const open, closed = "18085", "18086"
	run(t, "firewall-cmd", "--add-port="+open+"/tcp")
	t.Cleanup(func() { exec.Command("firewall-cmd", "--remove-port="+open+"/tcp").Run() })

	for _, port := range []string{open, closed} {
		cmd := exec.Command("python3", "-c", fmt.Sprintf(
			"import socket,time;s=socket.socket();s.setsockopt(1,2,1);s.bind(('0.0.0.0',%s));s.listen(8);time.sleep(300)", port))
		if err := cmd.Start(); err != nil {
			t.Fatalf("listener on %s: %v", port, err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
	}
	waitForListeners(t, open, closed)

	vs := model.Evaluate(collectHere(t), model.InternetZone())
	openV := verdictFor(vs, 18085, "ip")
	closedV := verdictFor(vs, 18086, "ip")
	if openV == nil || closedV == nil {
		t.Fatalf("missing verdicts: open=%+v closed=%+v", openV, closedV)
	}
	if openV.Result != "reachable" {
		t.Errorf("%s = %s (%s), want reachable: firewalld was told to open it", open, openV.Result, openV.Reason)
	}
	if closedV.Result != "filtered" {
		t.Errorf("%s = %s (%s), want filtered: firewalld was not told to open it", closed, closedV.Result, closedV.Reason)
	}
}

func waitForListeners(t *testing.T, ports ...string) {
	t.Helper()
	for _, p := range ports {
		ok := false
		for i := 0; i < 100; i++ {
			out, _ := exec.Command("ss", "-ltn").CombinedOutput()
			if strings.Contains(string(out), ":"+p+" ") {
				ok = true
				break
			}
			exec.Command("sleep", "0.05").Run()
		}
		if !ok {
			t.Fatalf("listener on %s never came up", p)
		}
	}
}
