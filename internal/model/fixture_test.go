package model

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// fixturePath holds a real snapshot from an Ubuntu 24.04 host running UFW
// 0.36 and Docker 29 with seven bridge networks: 5 tables, 89 chains, 275
// rules, 36 listening sockets, 12 containers. Public addresses, the
// hostname, interface names, container names and unit names are redacted
// into documentation ranges and generic names, every replacement preserving
// byte length so that rule data comparing an interface name still compares
// the same number of bytes. The redaction was verified to leave every
// verdict unchanged.
//
// The fixture records what the binary that captured it could see, not what
// the binary reading it today can decode: the collector discards the raw
// payload of any extension it cannot decode, so an xt match that arrived
// undecoded is serialized as {"decoded": false} with nothing left to
// re-decode later. That is why the two "recent" matches on port 22 (the
// two rules ufw limit ssh emits) still resolve unknown below even now that
// the evaluator understands xt recent: this file predates that decoder, and
// no decoder, however correct, can recover bytes that were never kept. A
// facts document is in this sense lossy for anything the capturing build
// could not decode; see docs/superpowers/plans/NEXT.md's "Smaller items"
// for the follow-up (preserve the raw payload) that this fixture motivated.
// TestUFWLimitSSHResolvesReachable in test/integration/ruleset_test.go
// proves the decoder itself against a live kernel instead.
const fixturePath = "../../testdata/facts/ufw-docker-host.json"

func loadFixture(t *testing.T) facts.Facts {
	t.Helper()
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f facts.Facts
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if f.SchemaVersion != facts.SchemaVersion {
		t.Fatalf("fixture schema %d, this build reads %d", f.SchemaVersion, facts.SchemaVersion)
	}
	return f
}

// The unit tests all build tiny hand-made rulesets. This one runs the
// evaluator against a full-size real ruleset, which is the only place a
// scaling or ordering defect would show up.
func TestFixtureVerdictDistribution(t *testing.T) {
	vs := Evaluate(loadFixture(t), InternetZone())

	counts := map[string]int{}
	for _, v := range vs {
		counts[v.Result]++
	}
	want := map[string]int{"reachable": 4, "filtered": 33, "unknown": 2}
	if len(vs) != 39 {
		t.Fatalf("got %d verdicts, want 39", len(vs))
	}
	for result, n := range want {
		if counts[result] != n {
			t.Errorf("%s = %d, want %d (all: %v)", result, counts[result], n, counts)
		}
	}
}

// The host serves HTTP and HTTPS on both families and nothing else is open.
func TestFixtureOnlyWebPortsAreReachable(t *testing.T) {
	vs := Evaluate(loadFixture(t), InternetZone())

	got := map[string]bool{}
	for _, v := range vs {
		if v.Result == "reachable" {
			got[v.Family+"/"+strconv.Itoa(int(v.Endpoint.Port))] = true
		}
	}
	for _, want := range []string{"ip/80", "ip6/80", "ip/443", "ip6/443"} {
		if !got[want] {
			t.Errorf("expected %s reachable, got %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("unexpected extra reachable ports: %v", got)
	}
}

// Both unknowns are ssh, and both still blame an undecoded "recent" match,
// even though the evaluator can decode xt recent now: this fixture's copy
// of that match was captured before the decoder existed and carries no raw
// payload to decode (see the fixturePath comment above). If this starts
// failing, either the fixture was recaptured with a build that can decode
// recent (delete this test) or something else regressed into unknown (do
// not delete it).
func TestFixtureUnknownsAreOnlySSHRateLimiting(t *testing.T) {
	for _, v := range Evaluate(loadFixture(t), InternetZone()) {
		if v.Result != "unknown" {
			continue
		}
		if v.Endpoint.Port != 22 {
			t.Errorf("unexpected unknown on port %d: %s", v.Endpoint.Port, v.Reason)
		}
		if !strings.Contains(v.Reason, "cannot resolve") {
			t.Errorf("port 22 unknown for an unexpected reason: %s", v.Reason)
		}
	}
}

// Every published container port on this host is bound to loopback, which is
// the remediated state. A regression that mistook a loopback publish for an
// exposed one would show up here first.
func TestFixtureEveryDockerPublishIsFiltered(t *testing.T) {
	f := loadFixture(t)
	published := map[uint16]bool{}
	for _, c := range f.Docker.Containers {
		for _, p := range c.Publishes {
			published[p.HostPort] = true
		}
	}
	if len(published) == 0 {
		t.Fatal("fixture has no published ports, it cannot guard anything")
	}
	for _, v := range Evaluate(f, InternetZone()) {
		if published[v.Endpoint.Port] && v.Result != "filtered" {
			t.Errorf("published port %d is %s, want filtered: %s",
				v.Endpoint.Port, v.Result, v.Reason)
		}
	}
}
