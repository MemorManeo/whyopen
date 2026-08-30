package report

import (
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/MemorManeo/whyopen/internal/policy"
	"github.com/MemorManeo/whyopen/internal/probe"
)

func TestPolicyNamesTheFamilyAndOwnerOfAViolation(t *testing.T) {
	var sb strings.Builder
	Policy(&sb, policy.Result{Violations: []model.Verdict{
		{Endpoint: model.Endpoint{Port: 8080, Proto: "tcp", Owner: "node"}, Family: "ip6", Result: "reachable"},
	}}, "whyopen.yaml")
	out := sb.String()
	for _, want := range []string{"violation", "8080/tcp", "IPv6", "node", "whyopen.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q, which is what the reader acts on:\n%s", want, out)
		}
	}
}

// A stale entry has to say what turned up instead, or the reader cannot
// tell a port that closed from one that never existed.
func TestPolicySaysWhatAStaleEntryFoundInstead(t *testing.T) {
	var sb strings.Builder
	Policy(&sb, policy.Result{Stale: []policy.Stale{
		{Entry: policy.Entry{Port: 5432, Proto: "tcp"}, Found: "filtered"},
		{Entry: policy.Entry{Port: 9100, Proto: "tcp"}},
	}}, "whyopen.yaml")
	out := sb.String()
	if !strings.Contains(out, "filtered") {
		t.Errorf("a stale entry that is filtered does not say so:\n%s", out)
	}
	if !strings.Contains(out, "listening") {
		t.Errorf("a stale entry with no listener does not say so:\n%s", out)
	}
}

// Unknown verdicts are already in the main table. Repeating them here is
// only worth the reader's attention when they can fail the run.
func TestPolicyShowsUnknownsOnlyWhenTheyCanFailTheRun(t *testing.T) {
	unknowns := []model.Verdict{
		{Endpoint: model.Endpoint{Port: 22, Proto: "tcp"}, Family: "ip", Result: "unknown"},
	}
	var quiet strings.Builder
	Policy(&quiet, policy.Result{Unknown: unknowns}, "whyopen.yaml")
	if strings.Contains(quiet.String(), "22/tcp") {
		t.Errorf("unknown listed although fail_on_unknown is off:\n%s", quiet.String())
	}
	var loud strings.Builder
	Policy(&loud, policy.Result{Unknown: unknowns, FailOnUnknown: true}, "whyopen.yaml")
	if !strings.Contains(loud.String(), "22/tcp") {
		t.Errorf("unknown not listed although it will fail the run:\n%s", loud.String())
	}
}

func TestPolicySaysSoOnACleanRun(t *testing.T) {
	var sb strings.Builder
	Policy(&sb, policy.Result{}, "whyopen.yaml")
	out := sb.String()
	if !strings.Contains(out, "whyopen.yaml") || !strings.Contains(out, "allowed") {
		t.Errorf("a clean run says nothing about the policy that passed:\n%s", out)
	}
}

// A disagreement between the model and a probe is the most valuable thing
// a probe run produces, so it prints above everything else and says which
// way it went.
func TestProbeReportsDisagreementsWithTheirDiagnosis(t *testing.T) {
	var sb strings.Builder
	Probe(&sb, []probe.Disagreement{{
		Port: 8080, Proto: "tcp", Family: "ip", Modelled: "filtered", Probed: probe.StateOpen,
		Diagnosis: "the model is missing something",
	}}, "vantage.example")
	out := sb.String()
	for _, want := range []string{"8080/tcp", "filtered", "open", "missing something", "vantage.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// Agreement is worth one line: it is the run that proves the model right,
// and silence would read as a probe that did not happen.
func TestProbeSaysSoWhenTheModelAndRealityAgree(t *testing.T) {
	var sb strings.Builder
	Probe(&sb, nil, "vantage.example")
	if !strings.Contains(sb.String(), "agree") {
		t.Errorf("a run with no disagreement says nothing:\n%s", sb.String())
	}
}

// A run can exit 2 for something that never became a row: a rewrite
// forwarding ports whyopen cannot name. The policy block is where every
// non-zero exit gets its visible reason, so it has to say so there too,
// and it must not print the all-clear line while doing it.
func TestPolicyReportsAForwardItCouldNotReduceToPorts(t *testing.T) {
	res := policy.Result{
		FailOnUnknown: true,
		Unreadable:    []facts.Warning{{Source: "forwarded-ports", Message: "forwards every port to 192.0.2.50"}},
	}
	var sb strings.Builder
	Policy(&sb, res, "whyopen.yaml")
	out := sb.String()
	if strings.Contains(out, "every reachable port is allowed") {
		t.Fatalf("the all-clear printed for a run that exits 2:\n%s", out)
	}
	if !strings.Contains(out, "fail_on_unknown") || !strings.Contains(out, "forward") {
		t.Errorf("output does not say why the run failed:\n%s", out)
	}

	// Without the flag it changes no exit code, and the warnings block
	// above has already said it.
	res.FailOnUnknown = false
	sb.Reset()
	Policy(&sb, res, "whyopen.yaml")
	if !strings.Contains(sb.String(), "every reachable port is allowed") {
		t.Errorf("without fail_on_unknown the run is clean and should say so:\n%s", sb.String())
	}
}
