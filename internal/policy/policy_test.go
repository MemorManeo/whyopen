package policy

import (
	"strings"
	"testing"
)

const specExample = `version: 1
zones:
  internet:
    allow:
      - 22/tcp
      - 80/tcp
      - 443/tcp
fail_on_unknown: true
`

func TestLoadParsesTheSpecExample(t *testing.T) {
	p, err := Load(strings.NewReader(specExample))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !p.FailOnUnknown {
		t.Error("fail_on_unknown = false, want true")
	}
	want := []Entry{{Port: 22, Proto: "tcp"}, {Port: 80, Proto: "tcp"}, {Port: 443, Proto: "tcp"}}
	if len(p.Allow) != len(want) {
		t.Fatalf("allow = %v, want %v", p.Allow, want)
	}
	for i, e := range want {
		if p.Allow[i] != e {
			t.Errorf("allow[%d] = %v, want %v", i, p.Allow[i], e)
		}
	}
}

// A policy with no allow list at all is a legitimate one, the strictest
// there is: nothing may be reachable. It is not an error.
func TestLoadAcceptsAnEmptyAllowList(t *testing.T) {
	p, err := Load(strings.NewReader("version: 1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(p.Allow) != 0 {
		t.Fatalf("allow = %v, want empty", p.Allow)
	}
}

// Every refusal below exists for one reason: a policy file decides whether
// a run passes, so a key or a value whyopen does not understand must stop
// the run rather than be silently ignored into a false green.
func TestLoadRefusals(t *testing.T) {
	cases := []struct {
		name, doc, wantErr string
	}{
		{"unknown top-level key", "version: 1\nfail_on_unkown: true\n", "fail_on_unkown"},
		{"unknown zone", "version: 1\nzones:\n  lan:\n    allow: [22/tcp]\n", "lan"},
		{"unknown zone key", "version: 1\nzones:\n  internet:\n    deny: [22/tcp]\n", "deny"},
		{"missing version", "zones:\n  internet:\n    allow: [22/tcp]\n", "version"},
		{"future version", "version: 2\n", "version"},
		{"entry without a proto", "version: 1\nzones:\n  internet:\n    allow: [22]\n", "22"},
		{"entry naming a service", "version: 1\nzones:\n  internet:\n    allow: [ssh/tcp]\n", "ssh/tcp"},
		{"port zero", "version: 1\nzones:\n  internet:\n    allow: [0/tcp]\n", "0/tcp"},
		{"port past 65535", "version: 1\nzones:\n  internet:\n    allow: [70000/tcp]\n", "70000/tcp"},
		{"unmodelled proto", "version: 1\nzones:\n  internet:\n    allow: [22/sctp]\n", "sctp"},
		{"port range", "version: 1\nzones:\n  internet:\n    allow: [8000-8100/tcp]\n", "8000-8100/tcp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(c.doc))
			if err == nil {
				t.Fatalf("Load(%q) = nil error, want a refusal", c.doc)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not name %q, so it will not tell the reader what to fix", err, c.wantErr)
			}
		})
	}
}

// Two spellings of the same expectation are not a conflict worth failing a
// run over, but the parsed policy must not carry the duplicate.
func TestLoadDedupesEntries(t *testing.T) {
	p, err := Load(strings.NewReader("version: 1\nzones:\n  internet:\n    allow: [443/tcp, 443/tcp]\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(p.Allow) != 1 {
		t.Fatalf("allow = %v, want one entry", p.Allow)
	}
}
