package facts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Every kind whose evaluation dereferences a per-kind pointer. A document
// that names the kind without carrying the object is what turns
// `check -facts` into a panic instead of a verdict.
func TestValidateRefusesAKindWithoutItsObject(t *testing.T) {
	for _, kind := range []ExprKind{ExprPayload, ExprCmp, ExprMeta, ExprBitwise, ExprCt, ExprLookup, ExprVerdict, ExprXt} {
		t.Run(string(kind), func(t *testing.T) {
			f := Facts{SchemaVersion: SchemaVersion, Ruleset: Ruleset{Tables: []Table{{
				Family: "ip", Name: "filter", Chains: []Chain{{
					Name: "INPUT", Base: true, Hook: "input", Policy: "accept",
					Rules: []Rule{{Handle: 42, Exprs: []Expr{{Kind: kind}}}},
				}},
			}}}}
			err := Validate(f)
			if err == nil {
				t.Fatalf("Validate accepted a %q expression with no %q object", kind, kind)
			}
			for _, want := range []string{"filter", "INPUT", "42", string(kind)} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q, so it will not locate the problem", err, want)
				}
			}
		})
	}
}

// These two carry no object of their own: Note is a plain string.
func TestValidateAcceptsTheObjectlessKinds(t *testing.T) {
	for _, kind := range []ExprKind{ExprOther, ExprUnknown} {
		f := Facts{Ruleset: Ruleset{Tables: []Table{{Chains: []Chain{{
			Rules: []Rule{{Exprs: []Expr{{Kind: kind, Note: "counter"}}}}}}}}}}
		if err := Validate(f); err != nil {
			t.Errorf("Validate rejected a %q expression: %v", kind, err)
		}
	}
}

// A kind from a future build is not a structural error. The evaluator
// already refuses to resolve a rule carrying one, which is the same
// answer it gives for an undecoded expression.
func TestValidateAcceptsAnUnrecognisedKind(t *testing.T) {
	f := Facts{Ruleset: Ruleset{Tables: []Table{{Chains: []Chain{{
		Rules: []Rule{{Exprs: []Expr{{Kind: ExprKind("quota")}}}}}}}}}}
	if err := Validate(f); err != nil {
		t.Errorf("Validate rejected an unrecognised kind: %v", err)
	}
}

// The committed snapshot of a real host is the strongest evidence that
// the validator does not reject documents whyopen itself writes.
func TestValidateAcceptsTheGoldenFixture(t *testing.T) {
	b, err := os.ReadFile("../../testdata/facts/ufw-docker-host.json")
	if err != nil {
		t.Fatal(err)
	}
	var f Facts
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if err := Validate(f); err != nil {
		t.Fatalf("Validate rejected a document whyopen collected: %v", err)
	}
}
