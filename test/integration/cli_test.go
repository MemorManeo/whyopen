//go:build integration && linux

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runBinary runs the whyopen under test and returns its combined output and
// its exit code. The exit code is the whole point of most of these tests:
// it is what cron and CI consume, and nothing else in the suite asserts it.
func runBinary(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var ee *exec.ExitError
	if !asExit(err, &ee) {
		t.Fatalf("run %v: %v\noutput:\n%s", args, err, out)
	}
	return string(out), ee.ExitCode()
}

func asExit(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func inNs(ns string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", ns}, args...)
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// openAndDroppedNetns is a namespace with two listeners, one of which the
// ruleset drops, so the model and a probe both have something to find.
func openAndDroppedNetns(t *testing.T) string {
	t.Helper()
	ns := newNetns(t)
	listenIn(t, ns, "0.0.0.0", "8080")
	listenIn(t, ns, "0.0.0.0", "9090")
	applyNftRuleset(t, ns, `
table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 9090 drop
	}
}
`)
	return ns
}

// The exit code a policy produces, against a ruleset a kernel is actually
// enforcing rather than a document describing one.
func TestPolicyExitCodesAgainstARealRuleset(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft", "python3")

	ns := openAndDroppedNetns(t)
	dir := t.TempDir()

	strict := writeFile(t, dir, "strict.yaml", "version: 1\nzones:\n  internet:\n    allow: []\n", 0o644)
	out, code := runBinary(t, nil, inNs(ns, binaryPath, "check", "-policy", strict)...)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: 8080 is reachable and nothing is allowed\n%s", code, out)
	}
	if !strings.Contains(out, "8080/tcp") || !strings.Contains(out, "violation") {
		t.Errorf("output does not report the violation:\n%s", out)
	}

	allowed := writeFile(t, dir, "allow.yaml", "version: 1\nzones:\n  internet:\n    allow: [8080/tcp]\n", 0o644)
	out, code = runBinary(t, nil, inNs(ns, binaryPath, "check", "-policy", allowed)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0: the one reachable port is allowed\n%s", code, out)
	}

	broken := writeFile(t, dir, "broken.yaml", "version: 1\nfail_on_unkown: true\n", 0o644)
	out, code = runBinary(t, nil, inNs(ns, binaryPath, "check", "-policy", broken)...)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 for a policy whyopen cannot read\n%s", code, out)
	}
}

// The JSON document, produced from a live collection rather than from a
// committed fixture, since the fixture cannot catch a field the collector
// stops filling in.
func TestJSONDocumentFromALiveCollection(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft", "python3")

	ns := openAndDroppedNetns(t)
	out, code := runBinary(t, nil, inNs(ns, binaryPath, "check", "-json")...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}

	var doc struct {
		SchemaVersion int    `json:"schema_version"`
		Whyopen       string `json:"whyopen"`
		Hostname      string `json:"hostname"`
		Zone          string `json:"zone"`
		Verdicts      []struct {
			Port   uint16 `json:"port"`
			Result string `json:"result"`
			Reason string `json:"reason"`
		} `json:"verdicts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not a verdict document: %v\n%s", err, out)
	}
	if doc.SchemaVersion == 0 || doc.Whyopen == "" || doc.Hostname == "" || doc.Zone != "internet" {
		t.Errorf("document header = %+v", doc)
	}
	seen := map[uint16]string{}
	for _, v := range doc.Verdicts {
		seen[v.Port] = v.Result
		if v.Reason == "" {
			t.Errorf("port %d carries no reason", v.Port)
		}
	}
	if seen[8080] != "reachable" {
		t.Errorf("8080 = %q, want reachable", seen[8080])
	}
	if seen[9090] != "filtered" {
		t.Errorf("9090 = %q, want filtered: the ruleset drops it", seen[9090])
	}
}

// A real probe over a real link. The test process runs in the root
// namespace and the veth's other end is the namespace's address, so this
// crosses an actual network path rather than talking to itself.
func TestProbeAcrossTheVeth(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft", "python3")

	// The namespace only has to exist and hold its listeners; this test
	// speaks to it over the wire rather than from inside it.
	_ = openAndDroppedNetns(t)

	out, code := runBinary(t, nil, binaryPath, "probe", "-target", "203.0.113.10",
		"-ports", "8080,9090", "-timeout", "2s", "-json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}

	var doc struct {
		Results []struct {
			Port  uint16 `json:"port"`
			State string `json:"state"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not a probe document: %v\n%s", err, out)
	}
	got := map[uint16]string{}
	for _, r := range doc.Results {
		got[r.Port] = r.State
	}
	if got[8080] != "open" {
		t.Errorf("8080 = %q, want open: a listener is behind it and nothing drops it", got[8080])
	}
	if got[9090] != "filtered" {
		t.Errorf("9090 = %q, want filtered: the ruleset drops it, so nothing answers", got[9090])
	}
}

// stubSSH puts an `ssh` on PATH that runs the whyopen under test locally
// instead of on another machine. It stands in for the second machine, not
// for ssh itself: what is under test is that check builds the right
// command, reads the document back, and merges what it says.
func stubSSH(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "ssh", "#!/bin/sh\n"+
		"# Drop the ssh destination and the remote binary name, then run\n"+
		"# the whyopen under test in their place.\n"+
		"shift\nshift\nexec \"$WHYOPEN_BIN\" \"$@\"\n", 0o755)
	return append(os.Environ(),
		"PATH="+dir+":"+os.Getenv("PATH"),
		"WHYOPEN_BIN="+binaryPath)
}

// The whole probe path: check collects, asks the other machine, and folds
// real answers into the verdict set. Here the model and reality agree,
// which is the case that must stay quiet.
func TestCheckProbeFromConfirmsTheModel(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft", "python3")

	ns := openAndDroppedNetns(t)
	factsPath := filepath.Join(t.TempDir(), "facts.json")
	out, code := runBinary(t, nil, inNs(ns, binaryPath, "collect", "-o", factsPath)...)
	if code != 0 {
		t.Fatalf("collect exit = %d\n%s", code, out)
	}

	out, code = runBinary(t, stubSSH(t), binaryPath, "check", "-facts", factsPath,
		"-probe-from", "ssh://vantage.example", "-json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	var doc struct {
		Verdicts []struct {
			Port   uint16 `json:"port"`
			Result string `json:"result"`
			Reason string `json:"reason"`
		} `json:"verdicts"`
		Probe *struct {
			Source        string `json:"source"`
			Disagreements []any  `json:"disagreements"`
		} `json:"probe"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not a verdict document: %v\n%s", err, out)
	}
	if doc.Probe == nil || doc.Probe.Source != "ssh://vantage.example" {
		t.Fatalf("probe block = %+v", doc.Probe)
	}
	if len(doc.Probe.Disagreements) != 0 {
		t.Errorf("disagreements = %v, want none: the model and the kernel agree here", doc.Probe.Disagreements)
	}
	for _, v := range doc.Verdicts {
		if v.Port == 8080 && !strings.Contains(v.Reason, "probed") {
			t.Errorf("8080 reason = %q, want it to say a probe decided it", v.Reason)
		}
	}
}

// The finding a probe exists for. The document is collected while 8080 is
// open and the ruleset then changes underneath it, so the model says
// reachable and reality does not. A stale document stands in here for the
// real case, a firewall between the two that the document could never
// describe, because whyopen being wrong on purpose is not something a
// ruleset can be written to cause.
func TestCheckProbeFromReportsADisagreement(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "nft", "python3")

	ns := openAndDroppedNetns(t)
	factsPath := filepath.Join(t.TempDir(), "facts.json")
	if out, code := runBinary(t, nil, inNs(ns, binaryPath, "collect", "-o", factsPath)...); code != 0 {
		t.Fatalf("collect exit = %d\n%s", code, out)
	}

	// Reality moves on: 8080 is dropped now, and the document does not know.
	nsRun(t, ns, "nft", "insert", "rule", "inet", "filter", "input", "tcp", "dport", "8080", "drop")

	out, code := runBinary(t, stubSSH(t), binaryPath, "check", "-facts", factsPath,
		"-probe-from", "ssh://vantage.example")
	if code != 0 {
		t.Fatalf("exit = %d, want 0: a disagreement is not a policy failure\n%s", code, out)
	}
	if !strings.Contains(out, "disagree") || !strings.Contains(out, "8080/tcp") {
		t.Fatalf("output does not report the disagreement:\n%s", out)
	}
	// The direction matters: the ruleset in the document allows it and
	// nothing answered, so the diagnosis must point away from this host.
	if !strings.Contains(out, "between the probe and this host") {
		t.Errorf("diagnosis does not point upstream:\n%s", out)
	}
}
