package report

import (
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/MemorManeo/whyopen/internal/policy"
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
