package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// The committed snapshot of a real UFW and Docker host: 80/tcp and
// 443/tcp reachable on both families, 22/tcp unknown on both, the rest
// filtered. Using it here means the exit codes are exercised against the
// verdict mix a real host produces, not one assembled to suit them.
const goldenFacts = "../../testdata/facts/ufw-docker-host.json"

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckExitsOKWhenEveryReachablePortIsAllowed(t *testing.T) {
	pol := writeTemp(t, "whyopen.yaml", "version: 1\nzones:\n  internet:\n    allow: [80/tcp, 443/tcp]\n")
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", pol}); got != exitOK {
		t.Fatalf("exit = %d, want %d (exitOK)", got, exitOK)
	}
}

func TestCheckExitsViolationForAReachablePortOutsideThePolicy(t *testing.T) {
	pol := writeTemp(t, "whyopen.yaml", "version: 1\nzones:\n  internet:\n    allow: [80/tcp]\n")
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", pol}); got != exitViolation {
		t.Fatalf("exit = %d, want %d (exitViolation) for 443/tcp reachable and not allowed", got, exitViolation)
	}
}

func TestCheckExitsUnknownWhenFailOnUnknownIsSet(t *testing.T) {
	doc := "version: 1\nzones:\n  internet:\n    allow: [80/tcp, 443/tcp]\nfail_on_unknown: true\n"
	pol := writeTemp(t, "whyopen.yaml", doc)
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", pol}); got != exitUnknown {
		t.Fatalf("exit = %d, want %d (exitUnknown) for the two unresolved 22/tcp verdicts", got, exitUnknown)
	}
}

// A violation is something whyopen concluded; an unknown is something it
// could not. The concluded finding is the one worth reporting.
func TestCheckPrefersTheViolationExitOverTheUnknownOne(t *testing.T) {
	pol := writeTemp(t, "whyopen.yaml", "version: 1\nfail_on_unknown: true\n")
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", pol}); got != exitViolation {
		t.Fatalf("exit = %d, want %d (exitViolation) when a run has both", got, exitViolation)
	}
}

// An allowed port that is not reachable is a stale expectation, reported
// but never a failure: the host is not less safe than the policy asked
// for.
func TestCheckDoesNotFailOnAStaleAllowEntry(t *testing.T) {
	doc := "version: 1\nzones:\n  internet:\n    allow: [80/tcp, 443/tcp, 9999/tcp]\n"
	pol := writeTemp(t, "whyopen.yaml", doc)
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", pol}); got != exitOK {
		t.Fatalf("exit = %d, want %d (exitOK)", got, exitOK)
	}
}

// A policy whyopen cannot read is a tool error, not a pass: exiting 0
// there would silently stop enforcing the moment someone fat-fingers the
// file.
func TestCheckExitsErrorOnAPolicyItCannotRead(t *testing.T) {
	bad := writeTemp(t, "whyopen.yaml", "version: 1\nfail_on_unkown: true\n")
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", bad}); got != exitError {
		t.Fatalf("exit = %d, want %d (exitError) for a policy with an unknown key", got, exitError)
	}
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", missing}); got != exitError {
		t.Fatalf("exit = %d, want %d (exitError) for a policy file that is not there", got, exitError)
	}
}

// Without -policy nothing changes: the flag is what opts a run in.
func TestCheckWithoutAPolicyStillExitsOK(t *testing.T) {
	if got := runCheck([]string{"-facts", goldenFacts}); got != exitOK {
		t.Fatalf("exit = %d, want %d (exitOK)", got, exitOK)
	}
}

func TestPolicyInitSeedsTheReachablePortsAndNotTheUnresolvedOne(t *testing.T) {
	out := filepath.Join(t.TempDir(), "whyopen.yaml")
	if got := runPolicy([]string{"init", "-facts", goldenFacts, "-o", out}); got != exitOK {
		t.Fatalf("exit = %d, want %d (exitOK)", got, exitOK)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"- 80/tcp", "- 443/tcp"} {
		if !strings.Contains(got, want) {
			t.Errorf("generated policy is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "- 22/tcp") {
		t.Errorf("generated policy allows 22/tcp, which whyopen could not resolve:\n%s", got)
	}
	if !strings.Contains(got, "#   22/tcp") {
		t.Errorf("generated policy does not name 22/tcp as unresolved:\n%s", got)
	}
}

// The file init writes must be one check accepts. Here it exits 2 rather
// than 0, because init sets fail_on_unknown and this host has an
// unresolved port: the generated policy is honest about the host, not
// flattering to it.
func TestPolicyInitProducesAPolicyCheckCanRead(t *testing.T) {
	out := filepath.Join(t.TempDir(), "whyopen.yaml")
	if got := runPolicy([]string{"init", "-facts", goldenFacts, "-o", out}); got != exitOK {
		t.Fatalf("init exit = %d, want %d", got, exitOK)
	}
	if got := runCheck([]string{"-facts", goldenFacts, "-policy", out}); got != exitUnknown {
		t.Fatalf("check exit = %d, want %d (exitUnknown): no violation, but 22/tcp is unresolved", got, exitUnknown)
	}
}

// A policy generated from a snapshot whose ruleset could not be read
// would have an empty allow list, and adopting it would fail every port
// on the host for a reason that has nothing to do with the host.
func TestPolicyInitRefusesAnUnreadableRuleset(t *testing.T) {
	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Ruleset:       facts.Ruleset{ReadFailed: true},
		Sockets: []facts.Socket{
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTemp(t, "facts.json", string(b))
	if got := runPolicy([]string{"init", "-facts", path}); got != exitError {
		t.Fatalf("exit = %d, want %d (exitError)", got, exitError)
	}
}

// A facts document is disposable and regenerable; a policy file carries
// edits a human made and cannot. init writes one, it does not replace one.
func TestPolicyInitRefusesToOverwriteAnExistingFile(t *testing.T) {
	existing := writeTemp(t, "whyopen.yaml", "version: 1\n# my edits\n")
	if got := runPolicy([]string{"init", "-facts", goldenFacts, "-o", existing}); got != exitError {
		t.Fatalf("exit = %d, want %d (exitError)", got, exitError)
	}
	b, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "my edits") {
		t.Fatalf("the existing policy was overwritten:\n%s", b)
	}
}

// forwardEveryPortFacts is a host whose ruleset rewrites the destination
// of every port to a machine on its LAN. whyopen reports forwarded ports
// one row at a time and can name none of these, so the run has something
// real it cannot show, which is exactly what fail_on_unknown is for.
func forwardEveryPortFacts(t *testing.T) string {
	t.Helper()
	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Host: facts.Host{
			Hostname: "router",
			Interfaces: []facts.Interface{{Name: "eth0", Index: 2, Up: true, Addresses: []facts.Addr{
				{IP: "203.0.113.10", Prefix: 24, Family: "ip", Scope: "global"},
			}}},
			Sysctls: facts.Sysctls{IPv4Forward: true},
		},
		Ruleset: facts.Ruleset{Tables: []facts.Table{{
			Family: "ip", Name: "nat", Chains: []facts.Chain{{
				Name: "prerouting", Base: true, Hook: "prerouting", Policy: "accept",
				Rules: []facts.Rule{{Handle: 1, Exprs: []facts.Expr{
					{Kind: facts.ExprImmediate, Immediate: &facts.ImmediateExpr{Register: 1, Data: "c0000232"}},
					{Kind: facts.ExprNAT, NAT: &facts.NATExpr{Type: "dnat", Family: "ip", AddrRegister: 1}},
				}}},
			}},
		}}},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, "facts.json", string(b))
}

// The guardrail half of decision 0014. Such a rewrite produces no row, so
// no allow entry can cover it and no violation can be raised for it; a
// policy that fails on what whyopen could not resolve has to fail on this
// too, or a host forwarding every port to somewhere passes a run green.
func TestCheckExitsUnknownForAForwardItCannotReduceToPorts(t *testing.T) {
	path := forwardEveryPortFacts(t)

	pol := writeTemp(t, "strict.yaml", "version: 1\nfail_on_unknown: true\n")
	if got := runCheck([]string{"-facts", path, "-policy", pol}); got != exitUnknown {
		t.Fatalf("exit = %d, want %d (exitUnknown) for a rule that forwards every port", got, exitUnknown)
	}

	// Without the flag it is a warning and nothing more: the exit codes
	// are a 1.0 promise, and this changes none of them on its own.
	lax := writeTemp(t, "lax.yaml", "version: 1\n")
	if got := runCheck([]string{"-facts", path, "-policy", lax}); got != exitOK {
		t.Fatalf("exit = %d, want %d (exitOK) without fail_on_unknown", got, exitOK)
	}
	if got := runCheck([]string{"-facts", path}); got != exitOK {
		t.Fatalf("exit = %d, want %d (exitOK) with no policy at all", got, exitOK)
	}
}

// The generated file has to name what it could not account for. A policy
// adopted from a host that forwards every port to somewhere would
// otherwise cover only the ports that became rows, and read as though it
// covered the host.
func TestPolicyInitNamesAForwardItCouldNotReduceToPorts(t *testing.T) {
	path := forwardEveryPortFacts(t)

	var code int
	out := captureStdout(t, func() {
		code = runPolicy([]string{"init", "-facts", path})
	})
	if code != exitOK {
		t.Fatalf("policy init exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(out, "192.0.2.50") || !strings.Contains(out, "forwards every port") {
		t.Fatalf("generated policy says nothing about the rewrite it could not name:\n%s", out)
	}
}
