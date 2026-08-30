package main

import (
	"encoding/json"
	"io"
	"os"
	"testing"
)

// captureStdout runs f with os.Stdout replaced by a pipe and returns what
// it wrote. The verdict document is the one output whose exact bytes are a
// promise to another program, so the wiring that produces it is worth
// testing through the real file descriptor.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	w.Close()
	os.Stdout = saved
	return <-done
}

func TestCheckJSONWritesTheVerdictDocument(t *testing.T) {
	var code int
	out := captureStdout(t, func() {
		code = runCheck([]string{"-facts", goldenFacts, "-json"})
	})
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	var doc struct {
		SchemaVersion int    `json:"schema_version"`
		Hostname      string `json:"hostname"`
		Zone          string `json:"zone"`
		Verdicts      []struct {
			Port   uint16 `json:"port"`
			Result string `json:"result"`
			Path   []any  `json:"path"`
		} `json:"verdicts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not the verdict document: %v\n%s", err, out)
	}
	if doc.SchemaVersion == 0 || doc.Zone != "internet" || doc.Hostname == "" {
		t.Errorf("document header = %+v", doc)
	}
	if len(doc.Verdicts) != 39 {
		t.Errorf("verdicts = %d, want the fixture's 39", len(doc.Verdicts))
	}
	if doc.Verdicts[0].Result != "reachable" {
		t.Errorf("first verdict = %q, want the worst first", doc.Verdicts[0].Result)
	}
	for _, v := range doc.Verdicts {
		if len(v.Path) != 0 {
			t.Fatalf("port %d carries a path without --explain", v.Port)
		}
	}
}

// --explain narrows the document to one port and is what asks for the
// path, in JSON exactly as in the table.
func TestCheckJSONWithExplainCarriesOnePortAndItsPath(t *testing.T) {
	out := captureStdout(t, func() {
		runCheck([]string{"-facts", goldenFacts, "-json", "-explain", "443"})
	})
	var doc struct {
		Verdicts []struct {
			Port uint16 `json:"port"`
			Path []struct {
				Chain string `json:"chain"`
				Rule  string `json:"rule"`
			} `json:"path"`
		} `json:"verdicts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not the verdict document: %v\n%s", err, out)
	}
	if len(doc.Verdicts) != 2 {
		t.Fatalf("verdicts = %d, want both families of 443/tcp", len(doc.Verdicts))
	}
	for _, v := range doc.Verdicts {
		if v.Port != 443 {
			t.Errorf("port = %d, want only 443", v.Port)
		}
		if len(v.Path) == 0 {
			t.Errorf("port %d carries no path under --explain", v.Port)
		}
	}
}

// The judgement travels with the verdicts, and the exit code is unchanged
// by the output mode.
func TestCheckJSONCarriesThePolicyAndKeepsTheExitCode(t *testing.T) {
	pol := writeTemp(t, "whyopen.yaml", "version: 1\nzones:\n  internet:\n    allow: [80/tcp]\n")
	var code int
	out := captureStdout(t, func() {
		code = runCheck([]string{"-facts", goldenFacts, "-json", "-policy", pol})
	})
	if code != exitViolation {
		t.Fatalf("exit = %d, want %d (exitViolation), same as the table mode", code, exitViolation)
	}
	var doc struct {
		Policy *struct {
			Source     string `json:"source"`
			Violations []struct {
				Port uint16 `json:"port"`
			} `json:"violations"`
		} `json:"policy"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not the verdict document: %v\n%s", err, out)
	}
	if doc.Policy == nil || len(doc.Policy.Violations) != 2 {
		t.Fatalf("policy = %+v, want both families of 443/tcp as violations", doc.Policy)
	}
}
