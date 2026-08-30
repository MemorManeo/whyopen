package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

// The generated allow list is the host's current reachable set and
// nothing else: seeding it with a port whyopen could not resolve would
// write "allow whatever I could not verify" into the file that decides
// whether future runs pass.
func TestInitSeedsOnlyReachablePorts(t *testing.T) {
	p, unknown := Init([]model.Verdict{
		reachable(443, "tcp", "ip", "nginx.service"),
		reachable(443, "tcp", "ip6", "nginx.service"),
		verdict(5432, "tcp", "ip", "filtered"),
		verdict(22, "tcp", "ip", "unknown"),
	})
	want := []Entry{{Port: 443, Proto: "tcp"}}
	if !reflect.DeepEqual(p.Allow, want) {
		t.Fatalf("allow = %v, want %v (both families of 443 collapsed, filtered and unknown left out)", p.Allow, want)
	}
	if !reflect.DeepEqual(unknown, []Entry{{Port: 22, Proto: "tcp"}}) {
		t.Fatalf("unknown = %v, want 22/tcp reported separately for the comment block", unknown)
	}
}

// A guardrail that ignores what it cannot see is a false green, so the
// generated file opts in to failing on unresolved ports.
func TestInitSetsFailOnUnknown(t *testing.T) {
	p, _ := Init(nil)
	if !p.FailOnUnknown {
		t.Error("fail_on_unknown = false, want true in a generated policy")
	}
}

func TestInitSortsTheAllowList(t *testing.T) {
	p, _ := Init([]model.Verdict{
		reachable(443, "tcp", "ip", "nginx.service"),
		reachable(22, "tcp", "ip", "ssh.service"),
		reachable(22, "udp", "ip", "wg"),
	})
	want := []Entry{{Port: 22, Proto: "tcp"}, {Port: 22, Proto: "udp"}, {Port: 443, Proto: "tcp"}}
	if !reflect.DeepEqual(p.Allow, want) {
		t.Fatalf("allow = %v, want %v", p.Allow, want)
	}
}

// The file whyopen writes must be one whyopen reads back unchanged. This
// is the test that keeps the generator and the parser from drifting apart.
func TestMarshalRoundTripsThroughLoad(t *testing.T) {
	p := Policy{Allow: []Entry{{Port: 22, Proto: "tcp"}, {Port: 443, Proto: "tcp"}}, FailOnUnknown: true}
	got, err := Load(strings.NewReader(string(Marshal(p, []Entry{{Port: 9000, Proto: "tcp"}}, nil))))
	if err != nil {
		t.Fatalf("Load of a generated file: %v\n%s", err, Marshal(p, nil, nil))
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("round trip = %+v, want %+v", got, p)
	}
}

func TestMarshalNamesTheUnresolvedPorts(t *testing.T) {
	out := string(Marshal(Policy{FailOnUnknown: true}, []Entry{{Port: 9000, Proto: "tcp"}}, nil))
	if !strings.Contains(out, "9000/tcp") {
		t.Errorf("generated file does not name the unresolved port, so its fail_on_unknown looks arbitrary:\n%s", out)
	}
}

// An empty allow list is the strictest policy there is, and the generator
// must still emit a file that parses.
func TestMarshalOfAnEmptyPolicyParses(t *testing.T) {
	out := Marshal(Policy{FailOnUnknown: true}, nil, nil)
	got, err := Load(strings.NewReader(string(out)))
	if err != nil {
		t.Fatalf("Load of a generated empty policy: %v\n%s", err, out)
	}
	if len(got.Allow) != 0 {
		t.Fatalf("allow = %v, want empty", got.Allow)
	}
}

// A rewrite forwarding ports whyopen cannot name is exposure no allow
// entry can describe, and `policy init` is written at the moment someone
// is deciding what their host may expose. Saying nothing there would let
// them adopt a policy that silently covers only the ports that became
// rows.
func TestMarshalNamesAForwardItCouldNotReduceToPorts(t *testing.T) {
	note := facts.Warning{Source: "forwarded-ports", Message: "ip nat/prerouting rule 6 rewrites the destination to 192.0.2.51 with no port constraint at all, so it forwards every port; whyopen reports one port per row and cannot list them"}
	out := string(Marshal(Policy{FailOnUnknown: true}, nil, []facts.Warning{note}))

	if !strings.Contains(out, "192.0.2.51") || !strings.Contains(out, "forwards every port") {
		t.Errorf("generated file does not say what it could not account for:\n%s", out)
	}
	// The message is one long sentence and the file is a document someone
	// reads, so it is wrapped rather than run off the edge.
	for _, line := range strings.Split(out, "\n") {
		if len(line) > commentWidth+8 {
			t.Errorf("line runs to %d characters, wider than this file is written to: %q", len(line), line)
		}
	}
	// Above all it has to stay a policy whyopen can read back.
	if _, err := Load(strings.NewReader(out)); err != nil {
		t.Fatalf("Load of a generated file carrying the block: %v\n%s", err, out)
	}
}
