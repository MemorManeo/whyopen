package policy

import "github.com/MemorManeo/whyopen/internal/model"

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

	// FailOnUnknown is the policy's own setting, carried here so the
	// renderer and the exit code do not each need the policy too.
	FailOnUnknown bool
}

// Check compares a verdict set against a policy. Only a reachable verdict
// can violate: filtered and unknown are not things an allow list has an
// opinion about. It never decides an exit code; that belongs to the
// caller, which also knows whether the ruleset was readable at all.
func Check(p Policy, vs []model.Verdict) Result {
	allowed := make(map[Entry]bool, len(p.Allow))
	for _, e := range p.Allow {
		allowed[e] = true
	}

	res := Result{FailOnUnknown: p.FailOnUnknown}
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
