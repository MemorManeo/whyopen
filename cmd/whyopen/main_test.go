package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
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

// A release binary carries -X values from the linker, and those are the
// most precise thing available: the build information the go command
// embeds must never override them.
func TestResolveVersionPrefersLinkerValues(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0000000000000000000000000000000000000000"},
			{Key: "vcs.time", Value: "2000-01-01T00:00:00Z"},
		},
	}
	got := resolveVersion(versionInfo{Version: "v0.2.0", Commit: "abc1234", Date: "2026-08-30T09:00:00Z"}, info, true)
	want := versionInfo{Version: "v0.2.0", Commit: "abc1234", Date: "2026-08-30T09:00:00Z"}
	if got != want {
		t.Fatalf("resolveVersion = %+v, want the linker's own values %+v", got, want)
	}
}

// `go install module@version` injects nothing, but the go command records
// the module version it installed. Reporting "dev" for it, as whyopen did
// through v0.1.0, understates what the binary knows about itself.
func TestResolveVersionFallsBackToModuleVersion(t *testing.T) {
	info := &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}}
	got := resolveVersion(defaultVersionInfo(), info, true)
	if got.Version != "v0.2.0" {
		t.Fatalf("resolveVersion version = %q, want %q from the embedded module version", got.Version, "v0.2.0")
	}
}

// A plain `go build` in a checkout records "(devel)" as the module
// version, which names nothing: the VCS stamp is the only real identity
// such a binary has, so commit and date come from there and the version
// stays at its honest default.
func TestResolveVersionUsesVCSStampForADevelBuild(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: "b9d7dd5859fe68e8a56ed51cf1e8e1717f89343c"},
			{Key: "vcs.time", Value: "2026-08-29T16:03:00Z"},
		},
	}
	got := resolveVersion(defaultVersionInfo(), info, true)
	want := versionInfo{
		Version: "dev",
		Commit:  "b9d7dd5859fe68e8a56ed51cf1e8e1717f89343c",
		Date:    "2026-08-29T16:03:00Z",
	}
	if got != want {
		t.Fatalf("resolveVersion = %+v, want %+v", got, want)
	}
}

// No build information at all (a binary stripped of it, or a test binary
// on a toolchain that records none) leaves every default in place rather
// than inventing a value.
func TestResolveVersionWithoutBuildInfo(t *testing.T) {
	got := resolveVersion(defaultVersionInfo(), nil, false)
	if got != defaultVersionInfo() {
		t.Fatalf("resolveVersion = %+v, want the defaults %+v unchanged", got, defaultVersionInfo())
	}
}

// A facts document is something whyopen tells people to attach to bug
// reports, so it reaches the evaluator exactly as it was written. One
// naming an expression kind without the object that kind promises used to
// panic in both output modes, in match.go and in RenderRule respectively.
// It has to be a refusal that names the rule instead.
func TestCheckRefusesAStructurallyBrokenFactsDocument(t *testing.T) {
	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		// A global address, or the verdict short-circuits before any rule
		// is walked and the broken expression is never reached.
		Host: facts.Host{Interfaces: []facts.Interface{{
			Name: "eth0", Index: 2, Up: true,
			Addresses: []facts.Addr{{IP: "203.0.113.10", Prefix: 24, Family: "ip", Scope: "global"}},
		}}},
		Ruleset: facts.Ruleset{Tables: []facts.Table{{
			Family: "ip", Name: "filter", Chains: []facts.Chain{{
				Name: "INPUT", Base: true, Hook: "input", Policy: "accept",
				Rules: []facts.Rule{{Handle: 42, Exprs: []facts.Expr{{Kind: facts.ExprCmp}}}},
			}},
		}}},
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
		t.Fatalf("check exit = %d, want %d (exitError)", got, exitError)
	}
	if got := runCheck([]string{"-facts", path, "-explain", "22"}); got != exitError {
		t.Fatalf("check --explain exit = %d, want %d (exitError)", got, exitError)
	}
}
