package policy

import (
	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

// Stale is an allow entry nothing reachable matched.
type Stale struct {
	Entry Entry
	Found string // filtered, or empty when nothing is listening
}

// Result is what a policy run found. It carries verdicts rather than
// summaries so the report can name the family and the owner of each one.
type Result struct {
	Violations []model.Verdict
	Stale      []Stale
	Unknown    []model.Verdict

	// Unreadable is what the run could not express as a verdict at all,
	// as opposed to Unknown, which is a port whyopen listed and could not
	// decide. Today that is a destination rewrite whose forwarded ports it
	// cannot name: a rule with no port constraint forwards every port
	// (docs/decisions/0014-forwarded-ports-as-endpoints.md). A guardrail
	// that ignores what it cannot see is a false green, which is the
	// reason fail_on_unknown exists, so these fail a run the same way an
	// unknown verdict does.
	Unreadable []facts.Warning

	// FailOnUnknown is the policy's own setting, carried here so the
	// renderer and the exit code do not each need the policy too.
	FailOnUnknown bool
}

// Check compares a verdict set against a policy. Only a reachable verdict
// can violate: filtered and unknown are not things an allow list has an
// opinion about. It never decides an exit code; that belongs to the
// caller, which also knows whether the ruleset was readable at all.
//
// unreadable is what the run could not turn into verdicts at all, which
// the policy cannot judge port by port but must not ignore either. It is
// passed in rather than derived here because this package is pure over
// verdicts and knows nothing about rulesets.
func Check(p Policy, vs []model.Verdict, unreadable []facts.Warning) Result {
	allowed := make(map[Entry]bool, len(p.Allow))
	for _, e := range p.Allow {
		allowed[e] = true
	}

	res := Result{FailOnUnknown: p.FailOnUnknown, Unreadable: unreadable}
	// What each port was seen doing, so a stale line can say what turned
	// up in place of the reachable verdict the operator expected.
	seen := map[Entry]map[string]bool{}
	for _, v := range vs {
		e := Entry{Port: v.Endpoint.Port, Proto: v.Endpoint.Proto}
		if seen[e] == nil {
			seen[e] = map[string]bool{}
		}
		seen[e][v.Result] = true

		switch v.Result {
		case "reachable":
			if !allowed[e] {
				res.Violations = append(res.Violations, v)
			}
		case "unknown":
			res.Unknown = append(res.Unknown, v)
		}
	}

	for _, e := range p.Allow {
		s := seen[e]
		// An unknown verdict is not evidence that the entry is dead. The
		// port is already in res.Unknown, which is what fail_on_unknown
		// acts on; calling it stale as well would report a conclusion
		// whyopen did not reach.
		if s["reachable"] || s["unknown"] {
			continue
		}
		found := ""
		if s["filtered"] {
			found = "filtered"
		}
		res.Stale = append(res.Stale, Stale{Entry: e, Found: found})
	}
	return res
}
