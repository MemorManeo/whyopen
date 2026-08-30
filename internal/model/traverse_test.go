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

// C1, the reviewer's end-to-end scenario: an input base chain with policy
// drop whose only rule is "tcp dport { 22, 80 } accept". The set lookup used
// to be dropped on the floor, leaving "dport (loaded, never compared) accept",
// which matched unconditionally and reported a Postgres socket on 5432 as
// reachable. It must be unknown.
func TestUnknownExprInAnAcceptRuleDoesNotOpenADropPolicyChain(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "input", Base: true, Hook: "input", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{{Handle: 1, Exprs: []facts.Expr{
				{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
				{Kind: facts.ExprUnknown, Note: "*expr.Lookup"},
				{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
			}}},
		}}},
	}}
	res, _ := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "unknown" {
		t.Fatalf("result = %q (%s), want unknown: the set lookup was never resolved", res.Kind, res.Reason)
	}
}

// A native nft reject is terminal. It carries no verdict expression, so
// before C1 it was silently dropped and the rule looked like a no-op.
func TestNativeRejectIsTerminal(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "input", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{
				{Handle: 1, Exprs: []facts.Expr{
					{Kind: facts.ExprVerdict, Note: "reject", Verdict: &facts.VerdictExpr{Kind: "reject"}}}},
				acceptRule(2),
			},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" {
		t.Fatalf("result = %q, want drop: a reject stops the packet", res.Kind)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want the reject to be terminal: %+v", len(hits), hits)
	}
}

func gotoRule(handle uint64, chain string) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "goto", Chain: chain}}}}
}

// I4: a goto in a base chain whose target falls through used to return
// Kind "none", which Traverse turned into an unknown blaming an internal
// string. nftables applies the base chain's policy there.
func TestGotoFallthroughAppliesTheBasePolicy(t *testing.T) {
	rs := func(policy string) facts.Ruleset {
		return facts.Ruleset{Tables: []facts.Table{
			{Family: "ip", Name: "filter", Chains: []facts.Chain{
				{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: policy,
					Rules: []facts.Rule{gotoRule(1, "ufw-user-input")}},
				{Name: "ufw-user-input"},
			}},
		}}
	}
	if res, _ := Traverse(rs("drop"), "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the drop policy to apply after a goto fell through", res.Kind)
	}
	if res, _ := Traverse(rs("accept"), "ip", "input", testPacket()); res.Kind != "accept" {
		t.Fatalf("result = %q, want the accept policy to apply after a goto fell through", res.Kind)
	}
}

// I4, the direction that matters: a goto nested under a jump must not
// resume in the calling chain. Base policy accept, "jump mid", mid does
// "goto sub", sub is empty, and the base chain has a later drop rule.
// nftables applies the accept policy; returning to the base chain and
// hitting the drop under-reported exposure.
func TestGotoUnderAJumpDoesNotReturnToTheCaller(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{jumpRule(1, "mid"), dropRule(2)}},
			{Name: "mid", Rules: []facts.Rule{gotoRule(3, "sub")}},
			{Name: "sub"},
		}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "accept" {
		t.Fatalf("result = %q (%s), want accept: a goto never returns, so the base policy decides", res.Kind, res.Reason)
	}
	for _, h := range hits {
		if h.Handle == 2 {
			t.Fatalf("the rule after the jump must not run once a goto has left the chain: %+v", hits)
		}
	}
}

// The same shape with a drop policy: the unwind must reach the base chain's
// policy, not stop at the chain that issued the jump.
func TestGotoUnderAJumpUnwindsToTheBasePolicy(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "drop",
				Rules: []facts.Rule{jumpRule(1, "mid"), acceptRule(2)}},
			{Name: "mid", Rules: []facts.Rule{gotoRule(3, "sub")}},
			{Name: "sub"},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the base chain's drop policy", res.Kind)
	}
}

// A verdict inside the goto target still decides, exactly as a jump's does.
func TestGotoTargetVerdictDecides(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{gotoRule(1, "sub"), acceptRule(2)}},
			{Name: "sub", Rules: []facts.Rule{dropRule(3)}},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the goto target's drop", res.Kind)
	}
}

func TestGotoUnknownChainIsUnknown(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{gotoRule(1, "absent")}},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "unknown" {
		t.Fatalf("result = %q, want unknown for a goto to a chain that is not in the snapshot", res.Kind)
	}
}

// Ledger minor: a base chain policy that is neither accept nor drop used to
// be treated as accept, reporting the chain as open on no evidence.
func TestUnmodelledBasePolicyIsUnknown(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "unknown",
		}}},
	}}
	res, _ := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "unknown" || res.Reason == "" {
		t.Fatalf("result = %+v, want an explained unknown", res)
	}
}

// Ledger minor: a base chain whose hook whyopen could not name was silently
// left out of the walk, so the hook was scored as though the chain did not
// exist.
func TestBaseChainOnAnUnrecognisedHookIsNotSilentlySkipped(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept"},
			{Name: "mystery", Base: true, Hook: "unknown", Priority: 0, Policy: "drop"},
		}},
	}}
	res, _ := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "unknown" || res.Reason == "" {
		t.Fatalf("result = %+v, want an explained unknown rather than a walk that omits the chain", res)
	}
}

// A rule skipped as harmless is still a rule the packet reached. Leaving
// it out of the path put a gap in --explain at exactly the rule a reader
// chasing an unresolved expression is most likely to be looking for: the
// one UFW's rate limiter emits.
func TestSkippedRuleIsRecordedInThePath(t *testing.T) {
	verdictless := facts.Rule{Handle: 19, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "0016"}},
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprOther, Note: "counter"},
	}}
	accept := facts.Rule{Handle: 20, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	rs := facts.Ruleset{Tables: []facts.Table{{Family: "ip", Name: "filter", Chains: []facts.Chain{{
		Name: "INPUT", Base: true, Hook: "input", Policy: "drop",
		Rules: []facts.Rule{verdictless, accept},
	}}}}}

	pkt := testPacket()
	pkt.DstPort = 22
	res, hits := Traverse(rs, "ip", "input", pkt)
	if res.Kind != "accept" {
		t.Fatalf("result = %+v, want accept: the skipped rule decides nothing", res)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want both rules: the skipped one and the accept", len(hits))
	}
	if hits[0].Handle != 19 || hits[0].Action != "skipped" {
		t.Errorf("hits[0] = %+v, want handle 19 marked skipped", hits[0])
	}
	if hits[1].Handle != 20 || hits[1].Action != "accept" {
		t.Errorf("hits[1] = %+v, want the accept", hits[1])
	}
}
