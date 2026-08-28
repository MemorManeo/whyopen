package model

import (
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

func acceptRule(handle uint64) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}}}}
}

func dropRule(handle uint64) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}}}}
}

func jumpRule(handle uint64, chain string) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "jump", Chain: chain}}}}
}

func returnRule(handle uint64) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "return"}}}}
}

// In nftables, accept in one base chain does NOT skip the other base chains
// registered on the same hook. A later base chain can still drop. This is the
// single most misunderstood rule in the system and the reason a UFW box can
// look closed while Docker holds a port open.
func TestAcceptInOneBaseChainDoesNotSkipTheNext(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "early", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: -10, Policy: "accept",
			Rules: []facts.Rule{acceptRule(1)},
		}}},
		{Family: "ip", Name: "late", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(2)},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" {
		t.Fatalf("result = %q, want drop: the later base chain must still run", res.Kind)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want both base chains visited: %+v", len(hits), hits)
	}
}

// Drop is terminal immediately: nothing after it runs.
func TestDropIsTerminal(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(1), acceptRule(2)},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" || len(hits) != 1 {
		t.Fatalf("result=%q hits=%d, want drop after exactly one hit", res.Kind, len(hits))
	}
}

// A base chain that falls through applies its policy.
func TestBaseChainPolicyApplies(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "drop",
		}}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the drop policy to apply", res.Kind)
	}
}

// A jump that falls off the end of the target chain returns to the caller.
func TestJumpReturnsToCaller(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{
				Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{jumpRule(1, "ufw-user-input"), dropRule(2)},
			},
			{Name: "ufw-user-input", Rules: []facts.Rule{}},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the rule after the jump to run", res.Kind)
	}
}

// inet chains apply to both families.
func TestInetTableAppliesToIPv4(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "inet", Name: "filter", Chains: []facts.Chain{{
			Name: "input", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(1)},
		}}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the inet chain to apply to an ip packet", res.Kind)
	}
}

// An unresolvable rule poisons the verdict rather than being skipped.
func TestUnknownRulePoisonsTheVerdict(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{{Handle: 1, Exprs: []facts.Expr{
				{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
				{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
			}}},
		}}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "unknown" {
		t.Fatalf("result = %q, want unknown", res.Kind)
	}
}

// A jump loop must terminate rather than hang.
func TestJumpLoopTerminates(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{jumpRule(1, "a")}},
			{Name: "a", Rules: []facts.Rule{jumpRule(2, "b")}},
			{Name: "b", Rules: []facts.Rule{jumpRule(3, "a")}},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "unknown" {
		t.Fatalf("result = %q, want unknown rather than a hang", res.Kind)
	}
}

// An explicit return in a base chain is equivalent to falling off the end
// of it: the chain's policy applies. A drop policy must drop the packet.
func TestReturnInBaseChainWithDropPolicyDrops(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{returnRule(1)},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" {
		t.Fatalf("result = %q, want drop: an explicit return in a base chain must apply its drop policy", res.Kind)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1: %+v", len(hits), hits)
	}
}

// The same, with an accept policy, must not terminate the hook: the next
// base chain still runs, proving the accept path continues rather than
// short-circuiting.
func TestReturnInBaseChainWithAcceptPolicyContinuesToNextBaseChain(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "early", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: -10, Policy: "accept",
			Rules: []facts.Rule{returnRule(1)},
		}}},
		{Family: "ip", Name: "late", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(2)},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" {
		t.Fatalf("result = %q, want drop: return with an accept policy must not short-circuit the hook", res.Kind)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want both base chains visited: %+v", len(hits), hits)
	}
}

// An explicit return in a regular chain reached by jump must still resume
// at the rule after the jump, the same as falling off the end of the
// target chain does (TestJumpReturnsToCaller).
func TestReturnInRegularChainResumesAfterJump(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{
				Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{jumpRule(1, "ufw-user-input"), dropRule(2)},
			},
			{Name: "ufw-user-input", Rules: []facts.Rule{returnRule(3)}},
		}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" {
		t.Fatalf("result = %q, want the rule after the jump to run after an explicit return", res.Kind)
	}
	if len(hits) != 3 {
		t.Fatalf("hits = %d, want the jump, the return, and the drop all recorded: %+v", len(hits), hits)
	}
}
