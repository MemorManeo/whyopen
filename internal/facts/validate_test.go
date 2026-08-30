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
	for _, kind := range []ExprKind{ExprPayload, ExprCmp, ExprMeta, ExprBitwise, ExprCt, ExprLookup, ExprRange, ExprFib, ExprImmediate, ExprNAT, ExprVerdict, ExprXt} {
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

// Every version this build ever wrote must stay readable by it. A build
// that refuses the documents its own predecessors wrote breaks the one
// promise the raw payloads exist to keep: collect once, evaluate later.
func TestSupportedSchemaAcceptsEveryVersionUpToThisOne(t *testing.T) {
	for v := 1; v <= SchemaVersion; v++ {
		if err := SupportedSchema(v); err != nil {
			t.Errorf("SupportedSchema(%d) = %v, want nil", v, err)
		}
	}
}

// A newer document is the one case where refusing is right: this build
// cannot know what changed in it, and reading it on the assumption that
// nothing important did is how a tool reports a confident wrong answer.
func TestSupportedSchemaRefusesANewerDocument(t *testing.T) {
	err := SupportedSchema(SchemaVersion + 1)
	if err == nil {
		t.Fatal("SupportedSchema accepted a document from a later build")
	}
	if !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("error = %q, want it to say what to do about it", err)
	}
}

// No version at all is not an old document, it is not a facts document.
func TestSupportedSchemaRefusesAVersionlessDocument(t *testing.T) {
	for _, v := range []int{0, -1} {
		err := SupportedSchema(v)
		if err == nil {
			t.Fatalf("SupportedSchema(%d) accepted a document with no usable version", v)
		}
		if !strings.Contains(err.Error(), "schema_version") {
			t.Errorf("error = %q, want it to name the field that is missing", err)
		}
	}
}
