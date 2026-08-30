package facts

import "fmt"

// Validate reports the first structural problem in a document that came
// from outside this process.
//
// A facts document is something whyopen invites people to attach to bug
// reports and replay with `check -facts`, so a hand-edited, truncated or
// generated one reaches the evaluator and the renderer unmodified. Both
// dereference the per-kind object an expression's Kind promises is there
// (match.go's e.Cmp.Data, render.go's e.Meta.Key), so a document naming a
// kind without carrying its object crashes the tool. That must be an
// error naming where the problem is, not a panic.
//
// It deliberately does not check what the values mean. A port of 0 or a
// family whyopen does not model produces an honest verdict or none at
// all, and inventing rules about them here would reject documents the
// evaluator handles perfectly well.
func Validate(f Facts) error {
	for _, t := range f.Ruleset.Tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				for i, e := range r.Exprs {
					if err := e.validate(); err != nil {
						return fmt.Errorf("table %s, chain %s, rule %d, expression %d: %w",
							t.Name, c.Name, r.Handle, i, err)
					}
				}
			}
		}
	}
	return nil
}

func (e Expr) validate() error {
	var missing bool
	switch e.Kind {
	case ExprPayload:
		missing = e.Payload == nil
	case ExprCmp:
		missing = e.Cmp == nil
	case ExprMeta:
		missing = e.Meta == nil
	case ExprBitwise:
		missing = e.Bitwise == nil
	case ExprCt:
		missing = e.Ct == nil
	case ExprLookup:
		missing = e.Lookup == nil
	case ExprRange:
		missing = e.Range == nil
	case ExprVerdict:
		missing = e.Verdict == nil
	case ExprXt:
		missing = e.Xt == nil
	case ExprOther, ExprUnknown:
		// Neither carries an object of its own; Note is a plain string.
	default:
		// A kind from a future build. The evaluator's default case already
		// refuses to resolve a rule carrying one, the same answer it gives
		// for an undecoded expression, so it is not a structural problem.
	}
	if missing {
		return fmt.Errorf("kind %q carries no %q object, which the evaluator would dereference", e.Kind, e.Kind)
	}
	return nil
}
