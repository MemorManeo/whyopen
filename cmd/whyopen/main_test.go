package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// RULING 24: check --explain must exit exitError exactly like the table
// view when the ruleset could not be read. The exit code is the
// machine-readable signal cron and CI actually consume, and an explain
// trace built on an unreadable ruleset is no more trustworthy than the
// table is: two output modes reporting different exit codes for the same
// underlying failure would be a bug in its own right.
func TestCheckExitsErrorWhenRulesetUnreadable(t *testing.T) {
	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Ruleset:       facts.Ruleset{ReadFailed: true},
		Sockets: []facts.Socket{
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := runCheck([]string{"-facts", path}); got != exitError {
		t.Fatalf("check exit = %d, want %d (exitError) for an unreadable ruleset", got, exitError)
	}
	if got := runCheck([]string{"-facts", path, "-explain", "22"}); got != exitError {
		t.Fatalf("check --explain exit = %d, want %d (exitError), the same failure as the table view", got, exitError)
	}
}

// The same document with a readable (even if empty) ruleset must not trip
// the tool-error exit in either mode.
func TestCheckExitsOKWhenRulesetReadable(t *testing.T) {
	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Ruleset:       facts.Ruleset{},
		Sockets: []facts.Socket{
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := runCheck([]string{"-facts", path}); got != exitOK {
		t.Fatalf("check exit = %d, want %d (exitOK) for a readable ruleset", got, exitOK)
	}
	if got := runCheck([]string{"-facts", path, "-explain", "22"}); got != exitOK {
		t.Fatalf("check --explain exit = %d, want %d (exitOK) for a readable ruleset", got, exitOK)
	}
}
