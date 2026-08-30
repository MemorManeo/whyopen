package policy

import (
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

func reachable(port uint16, proto, family, owner string) model.Verdict {
	return model.Verdict{
		Endpoint: model.Endpoint{Port: port, Proto: proto, Owner: owner},
		Family:   family,
		Result:   "reachable",
	}
}

func verdict(port uint16, proto, family, result string) model.Verdict {
	return model.Verdict{
		Endpoint: model.Endpoint{Port: port, Proto: proto},
		Family:   family,
		Result:   result,
	}
}

func TestCheckFlagsAReachablePortThatIsNotAllowed(t *testing.T) {
	p := Policy{Allow: []Entry{{Port: 443, Proto: "tcp"}}}
	res := Check(p, []model.Verdict{
		reachable(443, "tcp", "ip", "nginx.service"),
		reachable(8080, "tcp", "ip", "node"),
	}, nil)
	if len(res.Violations) != 1 {
		t.Fatalf("violations = %v, want only 8080/tcp", res.Violations)
	}
	if res.Violations[0].Endpoint.Port != 8080 {
		t.Errorf("violation port = %d, want 8080", res.Violations[0].Endpoint.Port)
	}
}

// Each verdict is its own fact about the host: the same port open on both
// families is two things to fix, and the family and owner are what the
// reader acts on, so they are not collapsed into one line.
func TestCheckReportsEachFamilySeparately(t *testing.T) {
	res := Check(Policy{}, []model.Verdict{
		reachable(8080, "tcp", "ip", "node"),
		reachable(8080, "tcp", "ip6", "node"),
	}, nil)
	if len(res.Violations) != 2 {
		t.Fatalf("violations = %d, want one per family", len(res.Violations))
	}
}

// An allow list is per protocol. Allowing 22/tcp says nothing about
// 22/udp, and reading it as though it did would hide an open port.
func TestCheckDoesNotLetOneProtoAllowTheOther(t *testing.T) {
	p := Policy{Allow: []Entry{{Port: 22, Proto: "tcp"}}}
	res := Check(p, []model.Verdict{reachable(22, "udp", "ip", "wg")}, nil)
	if len(res.Violations) != 1 {
		t.Fatalf("violations = %v, want 22/udp flagged", res.Violations)
	}
}

// Only reachable verdicts can violate: filtered and unknown are not
// something the allow list has an opinion about.
func TestCheckIgnoresFilteredAndUnknownForViolations(t *testing.T) {
	res := Check(Policy{}, []model.Verdict{
		verdict(5432, "tcp", "ip", "filtered"),
		verdict(9000, "tcp", "ip", "unknown"),
	}, nil)
	if len(res.Violations) != 0 {
		t.Fatalf("violations = %v, want none", res.Violations)
	}
}

func TestCheckReportsAnAllowedPortThatIsFilteredAsStale(t *testing.T) {
	p := Policy{Allow: []Entry{{Port: 5432, Proto: "tcp"}}}
	res := Check(p, []model.Verdict{verdict(5432, "tcp", "ip", "filtered")}, nil)
	if len(res.Stale) != 1 {
		t.Fatalf("stale = %v, want 5432/tcp", res.Stale)
	}
	if res.Stale[0].Found != "filtered" {
		t.Errorf("stale found = %q, want %q so the line can say what was seen instead", res.Stale[0].Found, "filtered")
	}
}

func TestCheckReportsAnAllowedPortWithNoListenerAsStale(t *testing.T) {
	p := Policy{Allow: []Entry{{Port: 9100, Proto: "tcp"}}}
	res := Check(p, nil, nil)
	if len(res.Stale) != 1 {
		t.Fatalf("stale = %v, want 9100/tcp", res.Stale)
	}
	if res.Stale[0].Found != "" {
		t.Errorf("stale found = %q, want empty for a port nothing is listening on", res.Stale[0].Found)
	}
}

// An expectation cannot be called stale on the strength of a verdict that
// says whyopen could not tell. The port stays in the unknown set, which
// fail_on_unknown acts on, and is not also reported as a dead entry.
func TestCheckDoesNotCallAnUnknownPortStale(t *testing.T) {
	p := Policy{Allow: []Entry{{Port: 22, Proto: "tcp"}}}
	res := Check(p, []model.Verdict{verdict(22, "tcp", "ip", "unknown")}, nil)
	if len(res.Stale) != 0 {
		t.Fatalf("stale = %v, want none: whyopen does not know whether the entry is stale", res.Stale)
	}
	if len(res.Unknown) != 1 {
		t.Fatalf("unknown = %v, want the 22/tcp verdict", res.Unknown)
	}
}

func TestCheckCollectsEveryUnknownVerdict(t *testing.T) {
	res := Check(Policy{}, []model.Verdict{
		verdict(22, "tcp", "ip", "unknown"),
		verdict(22, "tcp", "ip6", "unknown"),
		verdict(80, "tcp", "ip", "reachable"),
	}, nil)
	if len(res.Unknown) != 2 {
		t.Fatalf("unknown = %d, want both families of 22/tcp", len(res.Unknown))
	}
}

// The result carries the setting so that the two things that act on it,
// the renderer and the exit code, do not each have to be handed the
// policy as well.
func TestCheckCarriesFailOnUnknown(t *testing.T) {
	res := Check(Policy{FailOnUnknown: true}, nil, nil)
	if !res.FailOnUnknown {
		t.Error("result FailOnUnknown = false, want the policy's own setting")
	}
}

// A rewrite whyopen could not reduce to ports is not a verdict, so it can
// never be a violation, and it is not an unknown verdict either: no port
// was listed for it at all. It is carried separately so the exit code can
// treat it the way fail_on_unknown treats an unknown, without the report
// having to invent a port for it.
func TestCheckCarriesWhatNeverBecameAVerdict(t *testing.T) {
	notes := []facts.Warning{{Source: "forwarded-ports", Message: "forwards every port"}}
	p := Policy{Allow: []Entry{{Port: 80, Proto: "tcp"}}, FailOnUnknown: true}
	res := Check(p, []model.Verdict{reachable(80, "tcp", "ip", "nginx")}, notes)

	if len(res.Unreadable) != 1 {
		t.Fatalf("unreadable = %v, want the one note", res.Unreadable)
	}
	if len(res.Unknown) != 0 {
		t.Errorf("unknown = %v, want none: no port was listed for it", res.Unknown)
	}
	if len(res.Violations) != 0 {
		t.Errorf("violations = %v, want none: an allow list cannot judge it", res.Violations)
	}
}
