package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type stubRunner struct {
	doc string
	err error
}

func (s stubRunner) Run(context.Context, string, []string) ([]byte, error) {
	return []byte(s.doc), s.err
}

func withRunner(t *testing.T, r stubRunner) {
	t.Helper()
	saved := probeRunner
	probeRunner = r
	t.Cleanup(func() { probeRunner = saved })
}

// The fixture's 22/tcp is unknown because of an expression whyopen cannot
// resolve. A probe that finds it open resolves it, which is the whole
// reason probing exists.
func TestCheckProbeResolvesAnUnknownPort(t *testing.T) {
	withRunner(t, stubRunner{doc: `{"schema_version":1,"target":"203.0.113.10","results":[
		{"port":22,"proto":"tcp","state":"open"},
		{"port":80,"proto":"tcp","state":"open"},
		{"port":443,"proto":"tcp","state":"open"}]}`})

	var code int
	out := captureStdout(t, func() {
		code = runCheck([]string{"-facts", goldenFacts, "-json", "-probe-from", "ssh://vantage.example"})
	})
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	var doc struct {
		Verdicts []struct {
			Port   uint16 `json:"port"`
			Family string `json:"family"`
			Result string `json:"result"`
			Reason string `json:"reason"`
		} `json:"verdicts"`
		Probe *struct {
			Source        string `json:"source"`
			Disagreements []struct {
				Port     uint16 `json:"port"`
				Modelled string `json:"modelled"`
			} `json:"disagreements"`
		} `json:"probe"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not the verdict document: %v\n%s", err, out)
	}
	var seen bool
	for _, v := range doc.Verdicts {
		if v.Port != 22 || v.Family != "ip" {
			continue
		}
		seen = true
		if v.Result != "reachable" {
			t.Errorf("22/tcp = %q, want reachable: the probe got in", v.Result)
		}
		if !strings.Contains(v.Reason, "probed") {
			t.Errorf("reason = %q, want it to say a probe decided it", v.Reason)
		}
	}
	if !seen {
		t.Fatal("no IPv4 verdict for 22/tcp")
	}
	if doc.Probe == nil || doc.Probe.Source != "ssh://vantage.example" {
		t.Fatalf("probe block = %+v", doc.Probe)
	}
	// An unknown that the probe resolved is not a disagreement: the model
	// never claimed anything about it.
	for _, d := range doc.Probe.Disagreements {
		if d.Port == 22 {
			t.Errorf("22/tcp reported as a disagreement, but the model said unknown")
		}
	}
}

// The finding that matters most: the ruleset was read as closed and the
// port is open. It has to reach the policy too, or a run that saw reality
// would still pass on the model's word.
func TestCheckProbeTurnsAnOpenPortIntoAPolicyViolation(t *testing.T) {
	withRunner(t, stubRunner{doc: `{"schema_version":1,"target":"203.0.113.10","results":[
		{"port":3000,"proto":"tcp","state":"open"}]}`})
	pol := writeTemp(t, "whyopen.yaml", "version: 1\nzones:\n  internet:\n    allow: [80/tcp, 443/tcp]\n")

	var code int
	out := captureStdout(t, func() {
		code = runCheck([]string{"-facts", goldenFacts, "-policy", pol, "-probe-from", "ssh://vantage.example"})
	})
	if code != exitViolation {
		t.Fatalf("exit = %d, want %d (exitViolation): 3000/tcp is open and not allowed", code, exitViolation)
	}
	if !strings.Contains(out, "3000/tcp") || !strings.Contains(out, "disagree") {
		t.Errorf("output does not surface the disagreement:\n%s", out)
	}
}

// A probe that could not run must not look like a run that agreed. The
// request was to check the model against reality, and it did not happen.
func TestCheckProbeFailureIsAToolError(t *testing.T) {
	withRunner(t, stubRunner{err: errors.New("ssh: connect to host vantage.example port 22: Connection refused")})
	if got := runCheck([]string{"-facts", goldenFacts, "-probe-from", "ssh://vantage.example"}); got != exitError {
		t.Fatalf("exit = %d, want %d (exitError)", got, exitError)
	}
}

func TestCheckProbeRefusesASourceThatIsNotSSH(t *testing.T) {
	if got := runCheck([]string{"-facts", goldenFacts, "-probe-from", "vantage.example"}); got != exitError {
		t.Fatalf("exit = %d, want %d (exitError) for a source with no ssh:// scheme", got, exitError)
	}
}
